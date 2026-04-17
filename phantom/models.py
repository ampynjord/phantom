from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class NormalizedTarget:
    raw: str
    target_type: str
    hostname: str | None = None
    ip: str | None = None
    scheme: str | None = None
    port: int | None = None
    path: str = "/"

    def label(self) -> str:
        if self.scheme and self.hostname:
            port_part = f":{self.port}" if self.port else ""
            return f"{self.scheme}://{self.hostname}{port_part}{self.path}"
        return self.hostname or self.ip or self.raw


@dataclass(slots=True)
class Finding:
    title: str
    description: str
    category: str
    severity: str
    score: float
    target: str
    source_module: str
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ActionRecord:
    timestamp: str
    module: str
    action: str
    target: str
    status: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ModuleResult:
    findings: list[Finding] = field(default_factory=list)
    observations: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class DecisionStep:
    module: str
    priority: int
    reason: str
    status: str = "planned"
    source: str = "heuristic"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ExecutionState:
    target: NormalizedTarget
    observations: dict[str, Any] = field(default_factory=dict)
    executed_modules: list[str] = field(default_factory=list)
    decision_trace: list[DecisionStep] = field(default_factory=list)


@dataclass(slots=True)
class ReportBundle:
    run_id: str
    engagement_name: str
    generated_at: str
    findings: list[dict[str, Any]]
    timeline: list[dict[str, Any]]
    targets: list[str]
    target_summaries: list[dict[str, Any]]
    analyst_reports: list[dict[str, Any]]
    summary: dict[str, Any]
    files: dict[str, str]
