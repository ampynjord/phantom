from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from phantom.config import RulesOfEngagement
from phantom.models import NormalizedTarget


class ScopeError(ValueError):
    pass


class RulesOfEngagementError(ValueError):
    pass


SAFE_ACTIONS = {"dns_lookup", "tcp_connect", "http_probe", "analysis"}


class ScopeEnforcer:
    def __init__(self, domains: list[str], networks: list[str]) -> None:
        self.domains = [d.lower().strip(".") for d in domains]
        self.networks = [ipaddress.ip_network(n, strict=False) for n in networks]

    def validate(self, raw: str) -> NormalizedTarget:
        target = raw.strip()
        if not target:
            raise ScopeError("Empty target")
        if "://" in target:
            return self._url(target)
        try:
            ipaddress.ip_address(target)
            return self._ip(target)
        except ValueError:
            return self._hostname(target)

    def _url(self, raw: str) -> NormalizedTarget:
        p = urlparse(raw)
        if p.scheme not in {"http", "https"}:
            raise ScopeError("Only http/https URLs are allowed")
        if not p.hostname:
            raise ScopeError("URL must have a hostname")
        try:
            ipaddress.ip_address(p.hostname)
            self._ip(p.hostname)
        except ValueError:
            self._assert_host(p.hostname)
        return NormalizedTarget(raw=raw, target_type="url", hostname=p.hostname,
                                scheme=p.scheme, port=p.port, path=p.path or "/")

    def _ip(self, raw: str) -> NormalizedTarget:
        addr = ipaddress.ip_address(raw)
        if not any(addr in net for net in self.networks):
            raise ScopeError(f"IP {raw} is out of scope")
        return NormalizedTarget(raw=raw, target_type="ip", ip=raw)

    def _hostname(self, hostname: str) -> NormalizedTarget:
        h = hostname.lower().strip(".")
        self._assert_host(h)
        return NormalizedTarget(raw=hostname, target_type="hostname", hostname=h)

    def _assert_host(self, host: str) -> None:
        if not self.domains:
            raise ScopeError("Hostname scope requires a domain allowlist")
        if not any(host == d or host.endswith(f".{d}") for d in self.domains):
            raise ScopeError(f"Hostname {host} is out of scope")


class RoEValidator:
    def __init__(self, roe: RulesOfEngagement) -> None:
        self.roe = roe

    def validate_module(self, name: str, action_type: str) -> None:
        if name not in self.roe.allowed_modules:
            raise RulesOfEngagementError(f"Module {name!r} not permitted by RoE")
        if action_type not in SAFE_ACTIONS:
            raise RulesOfEngagementError(f"Action {action_type!r} not permitted")

    validate_plugin = validate_module

    def validate_ports(self, ports: list[int]) -> list[int]:
        if len(ports) > self.roe.max_ports_per_target:
            raise RulesOfEngagementError("Port count exceeds RoE limit")
        for p in ports:
            if not 1 <= p <= 65535:
                raise RulesOfEngagementError(f"Invalid port {p}")
        return ports

    def validate_http_method(self, method: str) -> str:
        m = method.upper()
        if m not in {e.upper() for e in self.roe.http_methods}:
            raise RulesOfEngagementError(f"HTTP method {m} not permitted")
        return m
