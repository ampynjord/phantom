from __future__ import annotations

import socket

from phantom.models import Finding, ModuleResult, NormalizedTarget
from phantom.plugins.base import BasePlugin, PluginContext

COMMON_SUBDOMAINS = [
    "www", "mail", "smtp", "imap", "ftp", "vpn", "remote",
    "admin", "portal", "api", "app", "dev", "staging", "test",
    "git", "gitlab", "jenkins", "ci", "grafana", "kibana",
    "prometheus", "monitor", "cloud", "static", "cdn",
]


class DnsEnumPlugin(BasePlugin):
    name = "dns_enum"
    action_type = "dns_lookup"
    description = "Enumerate DNS records and probe common subdomains for additional attack surface."

    def execute(self, context: PluginContext, target: NormalizedTarget, observations: dict) -> ModuleResult:
        if not target.hostname:
            return ModuleResult()

        findings: list[Finding] = []
        main_addresses = self._resolve(target.hostname)
        discovered_subdomains: dict[str, list[str]] = {}

        base_domain = self._base_domain(target.hostname)
        if base_domain and context.config.scope.domain_allowlist:
            for sub in COMMON_SUBDOMAINS:
                fqdn = f"{sub}.{base_domain}"
                if fqdn == target.hostname:
                    continue
                addrs = self._resolve(fqdn)
                if addrs:
                    discovered_subdomains[fqdn] = addrs

        if discovered_subdomains:
            findings.append(Finding(
                title="Additional reachable subdomains discovered",
                description=(
                    f"{len(discovered_subdomains)} subdomain(s) resolve and expand the attack surface "
                    f"beyond the primary target."
                ),
                category="reconnaissance",
                severity="info",
                score=2.5,
                target=target.label(),
                source_module=self.name,
                evidence={"subdomains": discovered_subdomains},
                recommendation=(
                    "Audit each discovered subdomain for the same security controls as the main target. "
                    "Decommission unused subdomains."
                ),
            ))

        return ModuleResult(
            findings=findings,
            observations={
                "resolved_addresses": main_addresses,
                "discovered_subdomains": discovered_subdomains,
            },
        )

    def _resolve(self, hostname: str) -> list[str]:
        try:
            return sorted({entry[4][0] for entry in socket.getaddrinfo(hostname, None)})
        except (socket.gaierror, OSError):
            return []

    def _base_domain(self, hostname: str) -> str | None:
        parts = hostname.rstrip(".").split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else None
