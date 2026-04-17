from __future__ import annotations

from urllib.parse import urlparse, urlunparse
from urllib.request import HTTPErrorProcessor, Request, build_opener

from phantom.models import Finding, ModuleResult, NormalizedTarget
from phantom.plugins.base import BasePlugin, PluginContext

SENSITIVE_PATHS = [
    # Credentials & config
    "/.env", "/.env.local", "/.env.backup", "/.env.prod",
    "/config.php", "/wp-config.php", "/config.yml", "/config.yaml",
    "/database.yml", "/settings.py", "/secrets.yml", "/application.yml",
    # Source control
    "/.git/HEAD", "/.git/config", "/.svn/entries", "/.hg/hgrc",
    # Admin interfaces
    "/admin", "/admin/", "/administrator", "/admin/login",
    "/wp-admin/", "/wp-login.php", "/phpmyadmin/", "/pma/",
    # Debug & diagnostics
    "/phpinfo.php", "/info.php", "/test.php", "/debug",
    "/server-status", "/server-info",
    # API & documentation
    "/api/v1", "/swagger.json", "/swagger-ui.html",
    "/openapi.json", "/graphql", "/graphiql",
    "/actuator/env", "/actuator/health", "/actuator/metrics",
    # Monitoring
    "/metrics", "/_cat/indices",
    # Backup files
    "/backup.zip", "/backup.tar.gz", "/dump.sql", "/db.sql",
]

CRITICAL_PATHS = frozenset({
    "/.env", "/.env.local", "/.env.backup", "/.env.prod",
    "/config.php", "/wp-config.php", "/database.yml",
    "/.git/HEAD", "/.git/config",
    "/phpinfo.php", "/actuator/env",
    "/dump.sql", "/db.sql", "/backup.zip", "/backup.tar.gz",
})


class _NoRedirect(HTTPErrorProcessor):
    def http_response(self, request, response):
        return response
    https_response = http_response


class CommonPathsPlugin(BasePlugin):
    name = "common_paths"
    action_type = "http_probe"
    description = "Probe for exposed sensitive files, admin panels, and debug endpoints."

    def execute(self, context: PluginContext, target: NormalizedTarget, observations: dict) -> ModuleResult:
        http_data = observations.get("http") or {}
        base_url = http_data.get("url")
        if not base_url:
            return ModuleResult()

        parsed = urlparse(base_url)
        base = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
        opener = build_opener(_NoRedirect)
        timeout = context.config.roe.network_timeout_seconds
        ua = context.config.roe.user_agent
        found: dict[str, int] = {}
        findings: list[Finding] = []

        for path in SENSITIVE_PATHS:
            url = base + path
            req = Request(url=url, method="HEAD", headers={"User-Agent": ua})
            try:
                with opener.open(req, timeout=timeout) as resp:
                    status = resp.status
            except Exception:
                status = 0

            if status in {200, 201, 204, 301, 302, 307, 403}:
                found[path] = status
                is_critical = path in CRITICAL_PATHS
                severity = "critical" if is_critical and status == 200 else ("high" if status == 200 else "medium")
                score = (9.5 if is_critical and status == 200
                         else 7.5 if status == 200
                         else 4.5)
                findings.append(Finding(
                    title=f"Sensitive path reachable: {path}",
                    description=self._describe(path, status),
                    category="exposed_resources",
                    severity=severity,
                    score=score,
                    target=url,
                    source_module=self.name,
                    evidence={"path": path, "http_status": status, "url": url},
                    recommendation=self._recommend(path),
                ))

        return ModuleResult(findings=findings, observations={"exposed_paths": found})

    def _describe(self, path: str, status: int) -> str:
        s = f"HTTP {status}"
        if "/.git" in path:
            return f"{s}: Git metadata accessible. Full source code history and committed secrets may be recoverable with git-dumper."
        if "/.env" in path or "config" in path.lower():
            return f"{s}: Configuration file reachable. May expose database credentials, API keys, or secret tokens."
        if "admin" in path or "phpmyadmin" in path:
            return f"{s}: Administrative interface reachable from the network. Brute-force or default credentials may provide full control."
        if "phpinfo" in path or "actuator" in path:
            return f"{s}: Diagnostic endpoint exposes server configuration, environment variables, and potentially secret values."
        if "backup" in path or "dump" in path or "sql" in path:
            return f"{s}: Backup or database dump reachable. Full application data and credentials may be downloadable."
        if "swagger" in path or "graphql" in path or "openapi" in path:
            return f"{s}: API documentation exposed. Reveals all endpoints, parameter names, and data models to unauthenticated users."
        return f"{s}: Sensitive resource is reachable from the network without authentication."

    def _recommend(self, path: str) -> str:
        if "/.git" in path:
            return "Block web access to .git/: deny from all in .htaccess or location block. Never deploy with .git present."
        if "/.env" in path:
            return "Move .env above the web root or restrict via server config. Use a secrets manager in production."
        if "admin" in path or "phpmyadmin" in path:
            return "Restrict admin panels to trusted IPs, enforce MFA, and move to a non-default path."
        if "phpinfo" in path or "actuator" in path:
            return "Disable debug endpoints in production. If required, protect with IP allowlist and authentication."
        if "backup" in path or "dump" in path:
            return "Remove backup files from the web root. Store them in off-network storage with access controls."
        return "Restrict public access to this path via server configuration or strong authentication."
