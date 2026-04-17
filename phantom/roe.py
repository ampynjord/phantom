from __future__ import annotations

from phantom.config import RulesOfEngagement


class RulesOfEngagementError(ValueError):
    pass


SAFE_ACTIONS = {"dns_lookup", "tcp_connect", "http_probe", "analysis"}


class RoEValidator:
    def __init__(self, roe: RulesOfEngagement) -> None:
        self.roe = roe

    def validate_module(self, module_name: str, action_type: str) -> None:
        if module_name not in self.roe.allowed_modules:
            raise RulesOfEngagementError(f"Module {module_name} is not permitted by RoE")
        if action_type not in SAFE_ACTIONS:
            raise RulesOfEngagementError(f"Action type {action_type} is not permitted")

    def validate_ports(self, ports: list[int]) -> list[int]:
        if len(ports) > self.roe.max_ports_per_target:
            raise RulesOfEngagementError("Requested port count exceeds RoE limit")
        for port in ports:
            if port < 1 or port > 65535:
                raise RulesOfEngagementError(f"Invalid TCP port {port}")
        return ports

    def validate_http_method(self, method: str) -> str:
        allowed = {entry.upper() for entry in self.roe.http_methods}
        method_upper = method.upper()
        if method_upper not in allowed:
            raise RulesOfEngagementError(f"HTTP method {method_upper} is not permitted")
        return method_upper
