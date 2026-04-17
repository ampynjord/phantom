from __future__ import annotations

import socket

from phantom.models import Finding, ModuleResult, NormalizedTarget
from phantom.plugins.base import BasePlugin, PluginContext

PORT_PROBES: dict[int, bytes] = {
    21:    b"",
    22:    b"",
    25:    b"EHLO phantom\r\n",
    80:    b"HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n",
    110:   b"",
    143:   b"",
    3306:  b"",
    6379:  b"PING\r\n",
    9200:  b"GET / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n",
}
GENERIC_PROBE = b"HEAD / HTTP/1.0\r\nConnection: close\r\n\r\n"


class BannerGrabPlugin(BasePlugin):
    name = "banner_grab"
    action_type = "tcp_connect"
    description = "Identify service versions by grabbing banners on open ports."

    def execute(self, context: PluginContext, target: NormalizedTarget, observations: dict) -> ModuleResult:
        open_ports: list[int] = observations.get("open_ports", [])
        if not open_ports:
            return ModuleResult()

        host = target.hostname or target.ip
        if not host:
            return ModuleResult()

        timeout = context.config.roe.network_timeout_seconds
        services: dict[str, str] = {}
        findings: list[Finding] = []

        for port in open_ports:
            banner = self._grab(host, port, timeout)
            if not banner:
                continue
            services[str(port)] = banner
            vuln = self._assess(banner, port, host)
            if vuln:
                findings.append(Finding(
                    title=vuln["title"],
                    description=vuln["description"],
                    category="service_exposure",
                    severity=vuln["severity"],
                    score=vuln["score"],
                    target=f"{host}:{port}",
                    source_module=self.name,
                    evidence={"port": port, "banner": banner[:300]},
                    recommendation=vuln["recommendation"],
                ))

        if services and not findings:
            findings.append(Finding(
                title="Service inventory collected",
                description=f"Identified {len(services)} service(s) by banner grabbing.",
                category="reconnaissance",
                severity="info",
                score=1.5,
                target=target.label(),
                source_module=self.name,
                evidence={"services": services},
                recommendation="Review identified service versions against known CVEs.",
            ))

        return ModuleResult(findings=findings, observations={"services": services})

    def _grab(self, host: str, port: int, timeout: float) -> str:
        probe = PORT_PROBES.get(port, GENERIC_PROBE)
        if b"{host}" in probe:
            probe = probe.replace(b"{host}", host.encode())
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((host, port))
                if probe:
                    sock.sendall(probe)
                sock.settimeout(min(timeout, 2.0))
                raw = sock.recv(1024)
            return raw.decode("utf-8", errors="replace").strip()
        except (socket.timeout, OSError):
            return ""

    def _assess(self, banner: str, port: int, host: str) -> dict | None:
        bl = banner.lower()
        if port == 6379 and ("+pong" in bl or "redis" in bl):
            return {
                "title": "Redis accessible without authentication",
                "description": (
                    "Redis on port 6379 responded to PING with no authentication challenge. "
                    "An attacker can read/write all cached data, extract secrets, or achieve RCE "
                    "by overwriting cron jobs or SSH authorized_keys via CONFIG SET."
                ),
                "severity": "critical",
                "score": 9.5,
                "recommendation": "Bind Redis to 127.0.0.1, enable requirepass, disable dangerous commands (CONFIG, DEBUG, SLAVEOF).",
            }
        if port == 9200 and ("{" in banner or "elasticsearch" in bl):
            return {
                "title": "Elasticsearch exposed without authentication",
                "description": (
                    "Elasticsearch API on port 9200 responded with no auth. "
                    "All indices are readable and writable. An attacker can exfiltrate or destroy all indexed data."
                ),
                "severity": "critical",
                "score": 9.5,
                "recommendation": "Enable X-Pack security (xpack.security.enabled: true), add basic auth, restrict to private network.",
            }
        if port == 27017 and "\x00" in banner:
            return {
                "title": "MongoDB potentially exposed without authentication",
                "description": (
                    "MongoDB port responded to a probe. Older MongoDB instances allow unauthenticated access by default. "
                    "An attacker could read, write or delete all databases."
                ),
                "severity": "high",
                "score": 8.5,
                "recommendation": "Enable MongoDB authentication (security.authorization: enabled), bind to localhost only.",
            }
        if port == 21 and ("ftp" in bl or "220" in banner):
            if "anonymous" in bl:
                return {
                    "title": "FTP anonymous login allowed",
                    "description": "FTP service allows anonymous access. Files may be readable or writable without credentials.",
                    "severity": "high",
                    "score": 7.5,
                    "recommendation": "Disable anonymous FTP access, migrate to SFTP.",
                }
        if any(kw in bl for kw in ["apache/", "nginx/", "iis/", "openssh_"]):
            return {
                "title": "Precise service version disclosed in banner",
                "description": f"Banner reveals exact software version: '{banner[:120]}'. Enables targeted CVE exploitation.",
                "severity": "low",
                "score": 3.5,
                "recommendation": "Suppress version numbers in service banners (ServerTokens Prod for Apache, server_tokens off for Nginx).",
            }
        return None
