from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse, urlunparse, urlunsplit
from urllib.request import HTTPErrorProcessor, Request, build_opener

from phantom.models import BasePlugin, Finding, ModuleResult, NormalizedTarget, PluginContext


class _NoRedirect(HTTPErrorProcessor):
    def http_response(self, request, response):
        return response
    https_response = http_response


class _TitleParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._capture = False
        self.title = ""

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag.lower() == "title":
            self._capture = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._capture = False

    def handle_data(self, data: str) -> None:
        if self._capture:
            self.title += data.strip()


SECURITY_HEADERS: dict[str, dict] = {
    "Strict-Transport-Security": {
        "description": "HSTS is missing. Without it, browsers may connect over plain HTTP, enabling protocol downgrade and cookie hijacking attacks.",
        "severity": "medium", "score": 5.5,
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "description": "No CSP header. Without it, the page is vulnerable to XSS, data injection, and clickjacking via script and resource injection.",
        "severity": "medium", "score": 6.0,
        "recommendation": "Define a strict Content-Security-Policy with default-src 'self' and explicit allowlists for scripts and styles.",
    },
    "X-Frame-Options": {
        "description": "Missing X-Frame-Options. The page can be embedded in an iframe from any origin, enabling clickjacking attacks.",
        "severity": "medium", "score": 5.0,
        "recommendation": "Add: X-Frame-Options: DENY (or SAMEORIGIN if iframing from same domain is needed).",
    },
    "X-Content-Type-Options": {
        "description": "Missing X-Content-Type-Options: nosniff. Browsers may MIME-sniff responses and execute malicious content as scripts.",
        "severity": "low", "score": 3.0,
        "recommendation": "Add: X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "description": "No Referrer-Policy set. Full URLs including paths and query parameters may leak to third-party sites.",
        "severity": "low", "score": 2.5,
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "description": "No Permissions-Policy. Browser features like camera, microphone and geolocation may be accessible to embedded scripts.",
        "severity": "low", "score": 2.5,
        "recommendation": "Add: Permissions-Policy: geolocation=(), camera=(), microphone=()",
    },
}

LEAKY_HEADERS = {"server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"}

SENSITIVE_PATHS = [
    "/.env", "/.env.local", "/.env.backup", "/.env.prod",
    "/config.php", "/wp-config.php", "/config.yml", "/config.yaml",
    "/database.yml", "/settings.py", "/secrets.yml", "/application.yml",
    "/.git/HEAD", "/.git/config", "/.svn/entries", "/.hg/hgrc",
    "/admin", "/admin/", "/administrator", "/admin/login",
    "/wp-admin/", "/wp-login.php", "/phpmyadmin/", "/pma/",
    "/phpinfo.php", "/info.php", "/test.php", "/debug",
    "/server-status", "/server-info",
    "/api/v1", "/swagger.json", "/swagger-ui.html",
    "/openapi.json", "/graphql", "/graphiql",
    "/actuator/env", "/actuator/health", "/actuator/metrics",
    "/metrics", "/_cat/indices",
    "/backup.zip", "/backup.tar.gz", "/dump.sql", "/db.sql",
]

CRITICAL_PATHS = frozenset({
    "/.env", "/.env.local", "/.env.backup", "/.env.prod",
    "/config.php", "/wp-config.php", "/database.yml",
    "/.git/HEAD", "/.git/config",
    "/phpinfo.php", "/actuator/env",
    "/dump.sql", "/db.sql", "/backup.zip", "/backup.tar.gz",
})


class HttpProbePlugin(BasePlugin):
    name = "http_probe"
    action_type = "http_probe"

    def execute(self, context: PluginContext, target: NormalizedTarget, observations: dict[str, Any]) -> ModuleResult:
        url = self._build_url(target, observations)
        if not url:
            return ModuleResult()
        method = context.roe.validate_http_method("HEAD")
        ua = context.config.roe.user_agent
        timeout = context.config.roe.network_timeout_seconds
        opener = build_opener(_NoRedirect)
        request = Request(url=url, method=method, headers={"User-Agent": ua})
        try:
            with opener.open(request, timeout=timeout) as response:
                status = response.status
                headers = dict(response.headers.items())
                body = b""
        except HTTPError as error:
            status = error.code
            headers = dict(error.headers.items())
            body = b""
        except URLError:
            return ModuleResult()
        title = ""
        if method == "HEAD" and status < 400:
            get_req = Request(url=url, method=context.roe.validate_http_method("GET"), headers={"User-Agent": ua})
            try:
                with opener.open(get_req, timeout=timeout) as response:
                    body = response.read(4096)
            except (HTTPError, URLError):
                body = b""
        if body:
            parser = _TitleParser()
            parser.feed(body.decode("utf-8", errors="ignore"))
            title = parser.title.strip()
        findings: list[Finding] = []
        scheme = target.scheme or ("https" if 443 in observations.get("open_ports", []) else "http")
        if scheme == "http":
            findings.append(Finding(
                title="Cleartext HTTP endpoint observed",
                description="A reachable HTTP endpoint was detected without transport encryption.",
                category="transport", severity="medium", score=5.8,
                target=url, source_module=self.name,
                evidence={"status": status, "headers": headers, "title": title},
                recommendation="Verify whether HTTPS should be enforced and whether credentials or sensitive data are exposed over HTTP.",
            ))
        elif scheme == "https" and "Strict-Transport-Security" not in headers:
            findings.append(Finding(
                title="HTTPS endpoint missing HSTS",
                description="The endpoint replied over HTTPS but did not advertise Strict-Transport-Security.",
                category="transport", severity="low", score=3.6,
                target=url, source_module=self.name,
                evidence={"status": status, "headers": headers, "title": title},
                recommendation="Consider enabling HSTS after validating application and subdomain readiness.",
            ))
        server_header = headers.get("Server") or headers.get("server")
        if server_header:
            findings.append(Finding(
                title="HTTP fingerprint available",
                description="The endpoint discloses server fingerprinting data in HTTP response headers.",
                category="fingerprinting", severity="info", score=1.8,
                target=url, source_module=self.name,
                evidence={"server": server_header, "status": status, "title": title},
                recommendation="Reduce verbose server disclosure where practical.",
            ))
        return ModuleResult(findings=findings, observations={"http": {"url": url, "status": status, "headers": headers, "title": title}})

    def _build_url(self, target: NormalizedTarget, observations: dict) -> str | None:
        if target.scheme and target.hostname:
            netloc = target.hostname if not target.port else f"{target.hostname}:{target.port}"
            return urlunsplit((target.scheme, netloc, target.path or "/", "", ""))
        if not target.hostname and not target.ip:
            return None
        host = target.hostname or target.ip
        open_ports = observations.get("open_ports", [])
        if 443 in open_ports:
            return f"https://{host}/"
        if 80 in open_ports:
            return f"http://{host}/"
        if 8443 in open_ports:
            return f"https://{host}:8443/"
        if 8080 in open_ports:
            return f"http://{host}:8080/"
        return None


class HeadersAuditPlugin(BasePlugin):
    name = "headers_audit"
    action_type = "http_probe"

    def execute(self, context: PluginContext, target: NormalizedTarget, observations: dict[str, Any]) -> ModuleResult:
        http_data = observations.get("http") or {}
        headers: dict[str, str] = http_data.get("headers") or {}
        if not headers:
            return ModuleResult()
        headers_lower = {k.lower(): v for k, v in headers.items()}
        findings: list[Finding] = []
        present: list[str] = []
        missing: list[str] = []
        for header, meta in SECURITY_HEADERS.items():
            if header.lower() in headers_lower:
                present.append(header)
            else:
                missing.append(header)
                findings.append(Finding(
                    title=f"Missing security header: {header}",
                    description=meta["description"],
                    category="security_headers", severity=meta["severity"], score=meta["score"],
                    target=http_data.get("url", target.label()), source_module=self.name,
                    evidence={"missing_header": header},
                    recommendation=meta["recommendation"],
                ))
        leaked = {k: headers_lower[k] for k in LEAKY_HEADERS if k in headers_lower}
        if leaked:
            findings.append(Finding(
                title="Server technology disclosed via HTTP headers",
                description=(
                    f"Response headers reveal server stack: {', '.join(f'{k}: {v}' for k, v in leaked.items())}. "
                    "This enables attackers to find version-specific exploits without additional probing."
                ),
                category="fingerprinting", severity="low", score=3.5,
                target=http_data.get("url", target.label()), source_module=self.name,
                evidence={"disclosed_headers": leaked},
                recommendation="Remove or obfuscate Server, X-Powered-By and framework version headers.",
            ))
        return ModuleResult(findings=findings, observations={"security_headers": {"present": present, "missing": missing}})


class TlsCheckPlugin(BasePlugin):
    name = "tls_check"
    action_type = "tcp_connect"

    def execute(self, context: PluginContext, target: NormalizedTarget, observations: dict[str, Any]) -> ModuleResult:
        open_ports: list[int] = observations.get("open_ports", [])
        host = target.hostname or target.ip
        if not host:
            return ModuleResult()
        if target.scheme == "https" and target.port:
            tls_port = target.port
        elif 443 in open_ports:
            tls_port = 443
        elif 8443 in open_ports:
            tls_port = 8443
        else:
            return ModuleResult()
        timeout = context.config.roe.network_timeout_seconds
        findings: list[Finding] = []
        tls_info: dict = {}
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_OPTIONAL
            with socket.create_connection((host, tls_port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert() or {}
                    cipher = ssock.cipher()
                    version = ssock.version()
            tls_info = {"version": version, "cipher": cipher[0] if cipher else None, "key_bits": cipher[2] if cipher else None}
            not_after = cert.get("notAfter")
            if not_after:
                try:
                    expiry_ts = ssl.cert_time_to_seconds(not_after)
                    expiry = datetime.fromtimestamp(expiry_ts, tz=timezone.utc)
                    days_left = (expiry - datetime.now(timezone.utc)).days
                    tls_info["cert_expiry"] = not_after
                    tls_info["cert_days_left"] = days_left
                    if days_left < 0:
                        findings.append(Finding(
                            title="TLS certificate expired",
                            description=f"Certificate expired {abs(days_left)} days ago. Browsers reject this connection.",
                            category="tls", severity="critical", score=9.0,
                            target=f"https://{host}:{tls_port}", source_module=self.name,
                            evidence=tls_info,
                            recommendation="Renew the TLS certificate immediately.",
                        ))
                    elif days_left < 30:
                        findings.append(Finding(
                            title=f"TLS certificate expires in {days_left} days",
                            description="Certificate nearing expiry. Failure to renew will break all HTTPS connectivity.",
                            category="tls", severity="medium", score=5.0,
                            target=f"https://{host}:{tls_port}", source_module=self.name,
                            evidence=tls_info,
                            recommendation="Schedule certificate renewal before expiry.",
                        ))
                except (ValueError, OSError):
                    pass
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))
            tls_info["subject_cn"] = subject.get("commonName")
            tls_info["issuer_cn"] = issuer.get("commonName")
            if subject and subject == issuer:
                findings.append(Finding(
                    title="Self-signed TLS certificate",
                    description="The certificate is self-signed and not trusted by clients. Susceptible to MITM attacks.",
                    category="tls", severity="medium", score=5.5,
                    target=f"https://{host}:{tls_port}", source_module=self.name,
                    evidence=tls_info,
                    recommendation="Replace with a certificate from a trusted CA (e.g., Let's Encrypt).",
                ))
            if version in {"TLSv1", "TLSv1.1"}:
                findings.append(Finding(
                    title=f"Deprecated TLS version negotiated: {version}",
                    description=f"Server accepted {version} which has known cryptographic weaknesses (BEAST, POODLE).",
                    category="tls", severity="high", score=7.5,
                    target=f"https://{host}:{tls_port}", source_module=self.name,
                    evidence=tls_info,
                    recommendation="Disable TLS 1.0 and 1.1. Enforce TLS 1.2+ with TLS 1.3 preferred.",
                ))
            if cipher and cipher[2] and cipher[2] < 128:
                findings.append(Finding(
                    title=f"Weak cipher negotiated ({cipher[2]}-bit key)",
                    description=f"The negotiated cipher uses a {cipher[2]}-bit key, below the 128-bit minimum.",
                    category="tls", severity="high", score=7.0,
                    target=f"https://{host}:{tls_port}", source_module=self.name,
                    evidence=tls_info,
                    recommendation="Configure server to only offer ECDHE/DHE cipher suites with 128-bit+ keys.",
                ))
            if not findings:
                findings.append(Finding(
                    title="TLS configuration summary",
                    description=f"TLS on port {tls_port}: {version}, cipher {cipher[0] if cipher else 'unknown'}.",
                    category="tls", severity="info", score=1.0,
                    target=f"https://{host}:{tls_port}", source_module=self.name,
                    evidence=tls_info,
                    recommendation="Monitor certificate expiry and cipher suite configuration periodically.",
                ))
        except (ssl.SSLError, socket.timeout, OSError):
            return ModuleResult()
        return ModuleResult(findings=findings, observations={"tls": tls_info})


class CommonPathsPlugin(BasePlugin):
    name = "common_paths"
    action_type = "http_probe"

    def execute(self, context: PluginContext, target: NormalizedTarget, observations: dict[str, Any]) -> ModuleResult:
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
                score = 9.5 if is_critical and status == 200 else (7.5 if status == 200 else 4.5)
                findings.append(Finding(
                    title=f"Sensitive path reachable: {path}",
                    description=self._describe(path, status),
                    category="exposed_resources", severity=severity, score=score,
                    target=url, source_module=self.name,
                    evidence={"path": path, "http_status": status, "url": url},
                    recommendation=self._recommend(path),
                ))
        return ModuleResult(findings=findings, observations={"exposed_paths": found})

    def _describe(self, path: str, status: int) -> str:
        s = f"HTTP {status}"
        if "/.git" in path:
            return f"{s}: Git metadata accessible. Full source code history and committed secrets may be recoverable."
        if "/.env" in path or "config" in path.lower():
            return f"{s}: Configuration file reachable. May expose database credentials, API keys, or secret tokens."
        if "admin" in path or "phpmyadmin" in path:
            return f"{s}: Administrative interface reachable. Brute-force or default credentials may provide full control."
        if "phpinfo" in path or "actuator" in path:
            return f"{s}: Diagnostic endpoint exposes server configuration and potentially secret values."
        if "backup" in path or "dump" in path or "sql" in path:
            return f"{s}: Backup or database dump reachable. Full application data may be downloadable."
        if "swagger" in path or "graphql" in path or "openapi" in path:
            return f"{s}: API documentation exposed. Reveals all endpoints and data models to unauthenticated users."
        return f"{s}: Sensitive resource is reachable from the network without authentication."

    def _recommend(self, path: str) -> str:
        if "/.git" in path:
            return "Block web access to .git/. Never deploy with .git present in the web root."
        if "/.env" in path:
            return "Move .env above the web root or restrict via server config. Use a secrets manager in production."
        if "admin" in path or "phpmyadmin" in path:
            return "Restrict admin panels to trusted IPs, enforce MFA, and move to a non-default path."
        if "phpinfo" in path or "actuator" in path:
            return "Disable debug endpoints in production. If required, protect with IP allowlist and authentication."
        if "backup" in path or "dump" in path:
            return "Remove backup files from the web root. Store them in off-network storage with access controls."
        return "Restrict public access to this path via server configuration or strong authentication."


class AttackPathSimulationPlugin(BasePlugin):
    name = "attack_path_simulation"
    action_type = "analysis"

    def execute(self, context: PluginContext, target: NormalizedTarget, observations: dict[str, Any]) -> ModuleResult:
        findings: list[Finding] = []
        http_data = observations.get("http") or {}
        title = (http_data.get("title") or "").lower()
        headers = http_data.get("headers") or {}
        if http_data.get("url", "").startswith("http://"):
            findings.append(Finding(
                title="Simulated path: interceptable web entrypoint",
                description="Observed cleartext transport suggests a theoretical path from network access to session or credential exposure without performing exploitation.",
                category="simulation", severity="medium", score=5.2,
                target=http_data["url"], source_module=self.name,
                evidence={"path": ["network_position", "cleartext_http", "possible_session_exposure"]},
                recommendation="Validate whether sensitive workflows are accessible over cleartext transport and enforce encrypted transport where required.",
            ))
        if any(kw in title for kw in ["admin", "login", "dashboard", "grafana", "jenkins"]):
            findings.append(Finding(
                title="Simulated path: exposed administrative surface",
                description="Page metadata suggests an administrative or authentication surface that warrants controlled review under the engagement scope.",
                category="simulation", severity="medium", score=4.9,
                target=http_data.get("url", target.label()), source_module=self.name,
                evidence={"title": http_data.get("title", ""), "headers": headers},
                recommendation="Review access controls, MFA coverage and configuration exposure for this administrative surface.",
            ))
        return ModuleResult(findings=findings)
