from __future__ import annotations

"""JSON Schemas for validating LLM-produced scenarios and campaign plans.

Treat every model response as untrusted input (see codeguard-0-mcp-security
and codeguard-0-input-validation-injection). Before any scenario reaches a
formatter, it must pass the matching schema below. Unknown fields are
permitted so generators can ignore extras, but all required fields must be
present and typed correctly.
"""

from typing import Any

from jsonschema import Draft202012Validator


_STRING = {"type": "string", "maxLength": 512}
_SHORT_STRING = {"type": "string", "maxLength": 128}
_TINY_STRING = {"type": "string", "maxLength": 64}


WINEVENTLOG_SCENARIO_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["event_code", "narrative"],
    "properties": {
        "event_code": {"type": "integer", "enum": [4624, 4625, 4634, 4672, 4688, 4738, 4768, 4769, 5140, 5145]},
        "narrative": _STRING,
        "logon_type": {"type": "integer", "minimum": 0, "maximum": 11},
        "process_path": {"type": "string", "maxLength": 260},
        "parent_process_path": {"type": "string", "maxLength": 260},
        "command_line": {"type": "string", "maxLength": 1024},
        "token_elevation": {"type": "string", "enum": ["%%1936", "%%1937", "%%1938"]},
        "logon_process": _TINY_STRING,
        "auth_package": _TINY_STRING,
        "failure_reason": _SHORT_STRING,
        "privileges": {
            "type": "array",
            "items": _TINY_STRING,
            "minItems": 1,
            "maxItems": 10,
        },
        "external_source": {"type": "boolean"},
        "use_admin_user": {"type": "boolean"},
    },
    "additionalProperties": True,
}


SYSMON_SCENARIO_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["event_id", "narrative"],
    "properties": {
        "event_id": {"type": "integer", "enum": [1, 3, 7, 11, 13]},
        "narrative": _STRING,
        "image": {"type": "string", "maxLength": 260},
        "parent_image": {"type": "string", "maxLength": 260},
        "command_line": {"type": "string", "maxLength": 1024},
        "parent_command_line": {"type": "string", "maxLength": 1024},
        "current_directory": {"type": "string", "maxLength": 260},
        "integrity_level": {"type": "string", "enum": ["Low", "Medium", "High", "System"]},
        "loaded_dll": {"type": "string", "maxLength": 260},
        "dll_signed": {"type": "boolean"},
        "target_filename": {"type": "string", "maxLength": 260},
        "registry_key": {"type": "string", "maxLength": 260},
        "registry_value": _STRING,
        "destination_domain": _SHORT_STRING,
        "destination_port": {"type": "integer", "minimum": 1, "maximum": 65535},
        "protocol": {"type": "string", "enum": ["tcp", "udp"]},
        "rule_name": _STRING,
        "use_external_destination": {"type": "boolean"},
    },
    "additionalProperties": True,
}


LINUX_SECURE_SCENARIO_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["event_type", "narrative"],
    "properties": {
        "event_type": {
            "type": "string",
            "enum": ["ssh_accept", "ssh_fail", "ssh_disconnect", "sudo", "pam_session"],
        },
        "narrative": _STRING,
        "auth_method": {"type": "string", "enum": ["publickey", "password", "keyboard-interactive"]},
        "disconnect_reason": _SHORT_STRING,
        "sudo_command": {"type": "string", "maxLength": 256},
        "session_action": {"type": "string", "enum": ["opened", "closed"]},
        "use_external_source": {"type": "boolean"},
    },
    "additionalProperties": True,
}


DNS_SCENARIO_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["domain", "query_type", "reply_code"],
    "properties": {
        "domain": {"type": "string", "maxLength": 253},
        "query_type": {"type": "string", "enum": ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR"]},
        "reply_code": {"type": "string", "enum": ["NoError", "NXDomain", "ServFail", "Refused"]},
        "is_internal_domain": {"type": "boolean"},
        "ttl": {"type": "integer", "minimum": 10, "maximum": 86400},
        "narrative": _STRING,
    },
    "additionalProperties": True,
}


HTTP_SCENARIO_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["method", "status", "uri_path", "site"],
    "properties": {
        "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]},
        "status": {"type": "integer", "minimum": 100, "maximum": 599},
        "uri_path": {"type": "string", "maxLength": 512},
        "site": {"type": "string", "maxLength": 253},
        "is_internal": {"type": "boolean"},
        "user_agent": {"type": "string", "maxLength": 512},
        "content_type": _SHORT_STRING,
        "server": _SHORT_STRING,
        "narrative": _STRING,
    },
    "additionalProperties": True,
}


FIREWALL_SCENARIO_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["message_id", "narrative"],
    "properties": {
        "message_id": {
            "type": ["string", "integer"],
            "enum": [
                "302013",
                "302014",
                "302015",
                "106023",
                "106100",
                "305011",
                "305012",
                "411001",
                "199005",
                "105004",
                302013,
                302014,
                302015,
                106023,
                106100,
                305011,
                305012,
                411001,
                199005,
                105004,
            ],
        },
        "narrative": _STRING,
        "direction": {"type": "string", "enum": ["outbound", "inbound", "dmz"]},
        "protocol": {"type": "string", "enum": ["tcp", "udp"]},
        "dst_port": {"type": "integer", "minimum": 1, "maximum": 65535},
        "acl_name": _SHORT_STRING,
        "interface": {"type": "string", "enum": ["inside", "outside", "dmz"]},
    },
    "additionalProperties": True,
}


SOURCETYPE_SCHEMAS: dict[str, dict[str, Any]] = {
    "wineventlog": WINEVENTLOG_SCENARIO_SCHEMA,
    "sysmon": SYSMON_SCENARIO_SCHEMA,
    "linux_secure": LINUX_SECURE_SCENARIO_SCHEMA,
    "stream:dns": DNS_SCENARIO_SCHEMA,
    "stream:http": HTTP_SCENARIO_SCHEMA,
    "cisco:asa": FIREWALL_SCENARIO_SCHEMA,
}


BATCH_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["scenarios"],
    "properties": {
        "scenarios": {
            "type": "array",
            "minItems": 1,
            "maxItems": 200,
            "items": {"type": "object"},
        }
    },
    "additionalProperties": True,
}


CAMPAIGN_PLAN_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["steps"],
    "properties": {
        "summary": _STRING,
        "steps": {
            "type": "array",
            "minItems": 1,
            "maxItems": 12,
            "items": {
                "type": "object",
                "required": ["sourcetype", "scenario"],
                "properties": {
                    "sourcetype": {
                        "type": "string",
                        "enum": ["wineventlog", "sysmon", "linux_secure", "stream:dns", "stream:http", "cisco:asa"],
                    },
                    "scenario": {"type": "object"},
                    "use_victim_host": {"type": "boolean"},
                    "use_c2_ip": {"type": "boolean"},
                    "use_c2_domain": {"type": "boolean"},
                },
                "additionalProperties": True,
            },
        },
    },
    "additionalProperties": True,
}


_VALIDATORS: dict[str, Draft202012Validator] = {
    name: Draft202012Validator(schema) for name, schema in SOURCETYPE_SCHEMAS.items()
}
_BATCH_VALIDATOR = Draft202012Validator(BATCH_SCHEMA)
_PLAN_VALIDATOR = Draft202012Validator(CAMPAIGN_PLAN_SCHEMA)


def validate_scenario(sourcetype: str, scenario: Any) -> None:
    """Raise jsonschema.ValidationError if scenario does not match its schema."""
    validator = _VALIDATORS.get(sourcetype)
    if validator is None:
        raise ValueError(f"unknown sourcetype: {sourcetype}")
    validator.validate(scenario)


def validate_batch(batch: Any) -> None:
    _BATCH_VALIDATOR.validate(batch)


def validate_campaign_plan(plan: Any) -> None:
    _PLAN_VALIDATOR.validate(plan)
