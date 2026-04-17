from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


DEFAULT_MODULES = [
    "dns_enum",
    "tcp_connect",
    "banner_grab",
    "http_probe",
    "headers_audit",
    "tls_check",
    "common_paths",
    "attack_path_simulation",
]

DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143,
    443, 445, 3306, 3389, 5432, 6379,
    8080, 8443, 8888, 9200, 27017,
]


@dataclass(slots=True)
class ScopePolicy:
    domain_allowlist: list[str] = field(default_factory=list)
    ip_allowlist: list[str] = field(default_factory=list)


@dataclass(slots=True)
class RulesOfEngagement:
    allowed_modules: list[str] = field(default_factory=lambda: DEFAULT_MODULES.copy())
    max_ports_per_target: int = 20
    network_timeout_seconds: float = 3.0
    http_methods: list[str] = field(default_factory=lambda: ["HEAD", "GET"])
    default_ports: list[int] = field(default_factory=lambda: DEFAULT_PORTS.copy())
    user_agent: str = "Mozilla/5.0 (compatible; PhantomScanner/1.0)"
    llm_provider: str = "mistral"
    llm_model: str = "mistral-small-latest"
    llm_timeout_seconds: float = 20.0


@dataclass(slots=True)
class PhantomConfig:
    engagement_name: str
    targets: list[str]
    scope: ScopePolicy
    roe: RulesOfEngagement

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "PhantomConfig":
        scope_payload = payload.get("scope") or {}
        roe_payload = payload.get("roe") or {}
        targets = payload.get("targets") or []

        scope = ScopePolicy(
            domain_allowlist=[entry.lower() for entry in scope_payload.get("domain_allowlist", [])],
            ip_allowlist=scope_payload.get("ip_allowlist", []),
        )
        roe = RulesOfEngagement(
            allowed_modules=roe_payload.get("allowed_modules", DEFAULT_MODULES.copy()),
            max_ports_per_target=int(roe_payload.get("max_ports_per_target", 20)),
            network_timeout_seconds=float(roe_payload.get("network_timeout_seconds", 3.0)),
            http_methods=[method.upper() for method in roe_payload.get("http_methods", ["HEAD", "GET"])],
            default_ports=[int(port) for port in roe_payload.get("default_ports", DEFAULT_PORTS.copy())],
            user_agent=roe_payload.get("user_agent", "Mozilla/5.0 (compatible; PhantomScanner/1.0)"),
            llm_provider=roe_payload.get("llm_provider", "mistral"),
            llm_model=roe_payload.get("llm_model", "mistral-small-latest"),
            llm_timeout_seconds=float(roe_payload.get("llm_timeout_seconds", 20.0)),
        )
        return cls(
            engagement_name=payload.get("engagement_name", "phantom-engagement"),
            targets=targets,
            scope=scope,
            roe=roe,
        )
