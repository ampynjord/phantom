from __future__ import annotations

import socket
from typing import Any

from phantom.models import BasePlugin, Finding, ModuleResult, NormalizedTarget, PluginContext

COMMON_SUBDOMAINS = [
    "www", "mail", "smtp", "imap", "ftp", "vpn", "remote",
    "admin", "portal", "api", "app", "dev", "staging", "test",
    "git", "gitlab", "jenkins", "ci", "grafana", "kibana",
    "prometheus", "monitor", "cloud", "static", "cdn",
]

PORT_PROBES: dict[int, bytes] = {
    21: b"", 22: b"", 25: b"EHLO phantom\r\n",
    80: b"HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n",
    110: b"", 143: b"", 3306: b"",
    6379: b"PING\r\n",
    9200: b"GET / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n",
}


class DnsEnumPlugin(BasePlugin):
    name = "dns_enum"
    action_type = "dns_lookup"

    def execute(self, context: PluginContext, target: NormalizedTarget, observations: dict[str, Any]) -> ModuleResult:
        if not target.hostname:
            return ModuleResult()
        main_addresses = self._resolve(target.hostname)
        found: dict[str, list[str]] = {}
        base = self._base(target.hostname)
        if base and context.config.scope.domain_allowlist:
            for sub in COMMON_SUBDOMAINS:
                fqdn = f"{sub}.{base}"
                if fqdn != target.hostname:
                    addrs = self._resolve(fqdn)
                    if addrs:
                        found[fqdn] = addrs
        findings: list[Finding] = []
        if found:
            findings.append(Finding(
                title="Additional reachable subdomains discovered",
                description=f"{len(found)} subdomain(s) expand the attack surface beyond the primary target.",
                category="reconnaissance", severity="info", score=2.5,
                target=target.label(), source_module=self.name,
                evidence={"subdomains": found},
                recommendation="Audit each subdomain for the same security controls. Decommission unused subdomains.",
            ))
        return ModuleResult(findings=findings, observations={"resolved_addresses": main_addresses, "discovered_subdomains": found})

    def _resolve(self, hostname: str) -> list[str]:
        try:
            return sorted({e[4][0] for e in socket.getaddrinfo(hostname, None)})
        except (socket.gaierror, OSError):
            return []

    def _base(self, hostname: str) -> str | None:
        parts = hostname.rstrip(".").split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else None


class TcpConnectPlugin(BasePlugin):
    name = "tcp_connect"
    action_type = "tcp_connect"

    def execute(self, context: PluginContext, target: NormalizedTarget, observations: dict[str, Any]) -> ModuleResult:
        host = target.hostname or target.ip
        if not host:
            return ModuleResult()
        candidate = [target.port] if target.port else context.config.roe.default_ports
        ports = context.roe.validate_ports([p for p in candidate if p is not None])
        open_ports: list[int] = []
        for port in ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(context.config.roe.network_timeout_seconds)
                if s.connect_ex((host, port)) == 0:
                    open_ports.append(port)
        findings: list[Finding] = []
        if open_ports:
            findings.append(Finding(
                title="Approved TCP services detected",
                description="One or more approved service ports responded to a TCP connect test.",
                category="attack_surface", severity="low", score=3.2,
                target=target.label(), source_module=self.name,
                evidence={"open_ports": open_ports},
                recommendation="Confirm service ownership and hardening status for each exposed port.",
            ))
        return ModuleResult(findings=findings, observations={"open_ports": open_ports})


class BannerGrabPlugin(BasePlugin):
    name = "banner_grab"
    action_type = "tcp_connect"

    def execute(self, context: PluginContext, target: NormalizedTarget, observations: dict[str, Any]) -> ModuleResult:
        open_ports = observations.get("open_ports", [])
        host = target.hostname or target.ip
        if not open_ports or not host:
            return ModuleResult()
        timeout = context.config.roe.network_timeout_seconds
        services: dict[str, str] = {}
        findings: list[Finding] = []
        for port in open_ports:
            banner = self._grab(host, port, timeout)
            if not banner:
                continue
            services[str(port)] = banner
            vuln = self._assess(banner, port)
            if vuln:
                findings.append(Finding(
                    title=vuln["title"], description=vuln["description"],
                    category="service_exposure", severity=vuln["severity"], score=vuln["score"],
                    target=f"{host}:{port}", source_module=self.name,
                    evidence={"port": port, "banner": banner[:300]},
                    recommendation=vuln["recommendation"],
                ))
        if services and not findings:
            findings.append(Finding(
                title="Service version disclosure in banner",
                description=f"Banners grabbed from {len(services)} service(s) — review against known CVEs.",
                category="reconnaissance", severity="low", score=3.5,
                target=target.label(), source_module=self.name,
                evidence={"services": services},
                recommendation="Suppress exact version strings from service banners.",
            ))
        return ModuleResult(findings=findings, observations={"services": services})

    def _grab(self, host: str, port: int, timeout: float) -> str:
        probe = PORT_PROBES.get(port, b"HEAD / HTTP/1.0\r\nConnection: close\r\n\r\n")
        if b"{host}" in probe:
            probe = probe.replace(b"{host}", host.encode())
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((host, port))
                if probe:
                    s.sendall(probe)
                s.settimeout(min(timeout, 2.0))
                return s.recv(1024).decode("utf-8", errors="replace").strip()
        except (socket.timeout, OSError):
            return ""

    def _assess(self, banner: str, port: int) -> dict | None:
        bl = banner.lower()
        if port == 6379 and ("+pong" in bl or "redis" in bl):
            return {"title": "Redis accessible without authentication",
                    "description": "Redis responded with no auth. RCE possible via CONFIG SET (cron/SSH key overwrite).",
                    "severity": "critical", "score": 9.5,
                    "recommendation": "Bind to 127.0.0.1, enable requirepass, disable dangerous commands."}
        if port == 9200 and ("{" in banner or "elasticsearch" in bl):
            return {"title": "Elasticsearch exposed without authentication",
                    "description": "All indices are readable/writable without authentication.",
                    "severity": "critical", "score": 9.5,
                    "recommendation": "Enable X-Pack security, add auth, restrict to private network."}
        if port == 27017 and "\x00" in banner:
            return {"title": "MongoDB potentially unauthenticated",
                    "description": "MongoDB port responded — older versions allow unauthenticated access.",
                    "severity": "high", "score": 8.5,
                    "recommendation": "Enable security.authorization, bind to localhost."}
        if port == 21 and "anonymous" in bl:
            return {"title": "FTP anonymous login allowed",
                    "description": "FTP accepts anonymous login — files may be accessible without credentials.",
                    "severity": "high", "score": 7.5,
                    "recommendation": "Disable anonymous FTP, migrate to SFTP."}
        if any(kw in bl for kw in ["apache/", "nginx/", "iis/", "openssh_"]):
            return {"title": "Precise service version disclosed in banner",
                    "description": f"Banner reveals exact version: '{banner[:120]}'. Enables targeted CVE exploitation.",
                    "severity": "low", "score": 3.5,
                    "recommendation": "Suppress version numbers in banners (ServerTokens Prod, server_tokens off)."}
        return None
