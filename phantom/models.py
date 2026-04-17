from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from phantom.config import PhantomConfig


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


class AuditLogger:
    def __init__(self, log_path: Path) -> None:
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.timeline: list[ActionRecord] = []

    def log(self, module: str, action: str, target: str, status: str, details: dict | None = None) -> None:
        record = ActionRecord(timestamp=utc_now(), module=module, action=action,
                              target=target, status=status, details=details or {})
        self.timeline.append(record)
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record.to_dict(), ensure_ascii=True) + "\n")


def summarize_findings(findings: list[Finding]) -> dict:
    severities = Counter(f.severity for f in findings)
    highest = max((f.score for f in findings), default=0.0)
    average = round(sum(f.score for f in findings) / len(findings), 2) if findings else 0.0
    return {
        "count": len(findings),
        "highest_score": round(max(0.0, min(highest, 10.0)), 1),
        "average_score": round(max(0.0, min(average, 10.0)), 1),
        "severity_breakdown": dict(severities),
    }


@dataclass(slots=True)
class PluginContext:
    config: PhantomConfig
    audit: Any
    validator: Any
    roe: Any


class BasePlugin:
    name = "base"
    action_type = "analysis"

    def execute(self, context: PluginContext, target: NormalizedTarget, observations: dict[str, Any]) -> ModuleResult:
        raise NotImplementedError

