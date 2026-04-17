from __future__ import annotations

import json
from pathlib import Path

from phantom.models import ActionRecord, utc_now


class AuditLogger:
    def __init__(self, log_path: Path) -> None:
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.timeline: list[ActionRecord] = []

    def log(self, module: str, action: str, target: str, status: str, details: dict | None = None) -> None:
        record = ActionRecord(
            timestamp=utc_now(),
            module=module,
            action=action,
            target=target,
            status=status,
            details=details or {},
        )
        self.timeline.append(record)
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record.to_dict(), ensure_ascii=True) + "\n")
