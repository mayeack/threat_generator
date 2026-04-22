from __future__ import annotations

import logging
from typing import Any, Optional

from jsonschema import ValidationError

from .client import AnthropicClient, LLMConfig
from .exceptions import LLMDisabled, LLMError, LLMUnavailable, LLMValidationError
from .prompts import CAMPAIGN_DESCRIPTIONS, build_campaign_prompt
from .schemas import validate_campaign_plan

logger = logging.getLogger(__name__)


class LLMCampaignPlanner:
    """Requests multi-step narratives for threat campaigns on demand.

    Returns a validated plan dict of the form defined by CAMPAIGN_PLAN_SCHEMA,
    or None if the LLM is unavailable. Callers must gracefully fall back to
    the built-in hardcoded campaign logic when None is returned.
    """

    def __init__(self, client: AnthropicClient, cfg: LLMConfig) -> None:
        self.client = client
        self.cfg = cfg
        self.enabled: bool = cfg.enabled and client.key_present
        self.last_error: Optional[str] = None

    async def plan(self, campaign_id: str, iocs: dict[str, Any]) -> Optional[dict[str, Any]]:
        if not self.enabled:
            return None
        description = CAMPAIGN_DESCRIPTIONS.get(campaign_id, campaign_id)
        system, user = build_campaign_prompt(campaign_id, description, iocs)
        try:
            response = await self.client.generate_json(
                system=system,
                user=user,
                model=self.cfg.campaign_model,
                max_tokens=self.cfg.max_tokens_campaign,
            )
        except LLMDisabled as exc:
            self.enabled = False
            self.last_error = str(exc)
            return None
        except (LLMUnavailable, LLMValidationError, LLMError) as exc:
            self.last_error = str(exc)
            logger.warning(
                "campaign_plan_failed",
                extra={"campaign": campaign_id, "error": type(exc).__name__},
            )
            return None

        try:
            validate_campaign_plan(response)
        except ValidationError as exc:
            self.last_error = f"schema: {exc.message}"
            logger.warning(
                "campaign_plan_schema_fail",
                extra={"campaign": campaign_id, "path": list(exc.absolute_path)},
            )
            return None

        self.last_error = None
        return response
