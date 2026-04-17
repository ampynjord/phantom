from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from phantom.models import NormalizedTarget


class ScopeError(ValueError):
    pass


class ScopeEnforcer:
    def __init__(self, domains: list[str], networks: list[str]) -> None:
        self.domains = [entry.lower().strip(".") for entry in domains]
        self.networks = [ipaddress.ip_network(entry, strict=False) for entry in networks]

    def validate(self, raw_target: str) -> NormalizedTarget:
        target = raw_target.strip()
        if not target:
            raise ScopeError("Empty target is not allowed")

        if "://" in target:
            return self._validate_url(target)

        try:
            ipaddress.ip_address(target)
        except ValueError:
            return self._validate_hostname(target)
        return self._validate_ip(target)

    def _validate_url(self, raw_url: str) -> NormalizedTarget:
        parsed = urlparse(raw_url)
        if parsed.scheme not in {"http", "https"}:
            raise ScopeError("Only http and https URLs are allowed")
        hostname = parsed.hostname
        if not hostname:
            raise ScopeError("URL must contain a hostname")
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            self._assert_host_allowed(hostname)
        else:
            self._validate_ip(hostname)
        return NormalizedTarget(
            raw=raw_url,
            target_type="url",
            hostname=hostname,
            scheme=parsed.scheme,
            port=parsed.port,
            path=parsed.path or "/",
        )

    def _validate_ip(self, raw_ip: str) -> NormalizedTarget:
        address = ipaddress.ip_address(raw_ip)
        if not any(address in network for network in self.networks):
            raise ScopeError(f"IP target {raw_ip} is out of scope")
        return NormalizedTarget(raw=raw_ip, target_type="ip", ip=raw_ip)

    def _validate_hostname(self, hostname: str) -> NormalizedTarget:
        host = hostname.lower().strip(".")
        self._assert_host_allowed(host)
        return NormalizedTarget(raw=hostname, target_type="hostname", hostname=host)

    def _assert_host_allowed(self, hostname: str) -> None:
        if not self.domains:
            raise ScopeError("Hostname scope requires a domain allowlist")
        if not any(hostname == domain or hostname.endswith(f".{domain}") for domain in self.domains):
            raise ScopeError(f"Hostname target {hostname} is out of scope")
