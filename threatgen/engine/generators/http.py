from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from threatgen.engine.llm.cache import VariationCache

from ..formatters.json_fmt import JSONFormatter
from ..topology import Topology
from .base import BaseGenerator

METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]
METHOD_WEIGHTS = [65, 15, 5, 2, 8, 5]

STATUS_CODES = [200, 201, 204, 301, 302, 304, 400, 401, 403, 404, 500, 502, 503]
STATUS_WEIGHTS = [55, 5, 3, 3, 5, 8, 3, 2, 2, 8, 2, 2, 2]

STATUS_TEXT = {
    200: "OK", 201: "Created", 204: "No Content", 301: "Moved Permanently",
    302: "Found", 304: "Not Modified", 400: "Bad Request", 401: "Unauthorized",
    403: "Forbidden", 404: "Not Found", 500: "Internal Server Error",
    502: "Bad Gateway", 503: "Service Unavailable",
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0)",
]

INTERNAL_PATHS = [
    "/api/v1/status", "/api/v1/users", "/api/v1/tasks",
    "/intranet/dashboard", "/intranet/wiki", "/login",
    "/assets/css/main.css", "/assets/js/app.js",
    "/health", "/metrics",
]

EXTERNAL_PATHS = [
    "/", "/api/v2/check", "/search", "/images/logo.png",
    "/static/bundle.js", "/graphql", "/oauth/token",
]

SERVERS = ["nginx/1.24.0", "Apache/2.4.58", "Microsoft-IIS/10.0", "gunicorn/21.2.0"]
CONTENT_TYPES = ["text/html", "application/json", "text/css", "application/javascript", "image/png"]


class HTTPGenerator(BaseGenerator):
    sourcetype = "http"

    def __init__(self, topology: Topology, cache: Optional[VariationCache] = None) -> None:
        super().__init__(topology, cache)
        self.fmt = JSONFormatter()

    def _generate_pattern(self, ts: datetime) -> list[str]:
        is_internal = self.rng.random() < 0.60
        method = self.rng.choices(METHODS, weights=METHOD_WEIGHTS, k=1)[0]
        status = self.rng.choices(STATUS_CODES, weights=STATUS_WEIGHTS, k=1)[0]
        path = self.rng.choice(INTERNAL_PATHS if is_internal else EXTERNAL_PATHS)
        if is_internal:
            dmz = self.topo.random_dmz_server()
            site = self.topo.fqdn(dmz.hostname)
        else:
            site = self.rng.choice([
                "www.google.com", "login.microsoftonline.com",
                "outlook.office365.com", "api.github.com", "cdn.cloudflare.com",
            ])
        return self._render(ts, method, status, path, site, is_internal, None, None, None)

    def render_from_scenario(self, scenario: dict[str, Any], ts: datetime) -> list[str]:
        method = str(scenario.get("method") or "GET").upper()
        if method not in METHODS + ["PATCH"]:
            method = "GET"
        try:
            status = int(scenario.get("status") or 200)
        except (TypeError, ValueError):
            status = 200
        if not 100 <= status <= 599:
            status = 200
        path = str(scenario.get("uri_path") or "/")[:512]
        site = str(scenario.get("site") or "www.example.com")[:253]
        is_internal = bool(scenario.get("is_internal", False))
        ua = scenario.get("user_agent")
        ct = scenario.get("content_type")
        srv = scenario.get("server")
        return self._render(ts, method, status, path, site, is_internal, ua, ct, srv)

    def _render(
        self,
        ts: datetime,
        method: str,
        status: int,
        path: str,
        site: str,
        is_internal: bool,
        user_agent: Optional[str],
        content_type: Optional[str],
        server: Optional[str],
    ) -> list[str]:
        if is_internal:
            dmz = self.topo.random_dmz_server()
            dest_ip = dmz.ip
            dest_port = self.rng.choice(dmz.ports) if dmz.ports else 443
        else:
            dest_ip = self.topo.random_external_ip()
            dest_port = self.rng.choice([80, 443])

        host = self.topo.random_windows_host() if self.rng.random() < 0.7 else None
        src_ip = host.ip if host else self.topo.random_linux_host().ip

        bytes_in = self.rng.randint(200, 2000)
        bytes_out = self.rng.randint(500, 50000)
        time_taken = self.rng.randint(5000, 500000)

        data = {
            "bytes": bytes_in + bytes_out,
            "src_ip": src_ip,
            "src_port": self.topo.random_ephemeral_port(),
            "bytes_in": bytes_in,
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "bytes_out": bytes_out,
            "time_taken": time_taken,
            "transport": "tcp",
            "flow_id": self.topo.random_guid(),
            "http_method": method,
            "status": status,
            "uri_path": path,
            "site": site,
            "http_user_agent": (user_agent or self.rng.choice(USER_AGENTS))[:512],
            "http_content_type": (content_type or self.rng.choice(CONTENT_TYPES))[:128],
            "http_comment": f"HTTP/1.1 {status} {STATUS_TEXT.get(status, 'OK')}",
            "server": (server or self.rng.choice(SERVERS))[:128],
            "protocol_stack": "ip:tcp:http",
        }

        line = self.fmt.format(ts, data=data)
        return [line]
