from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from phantom.config import PhantomConfig
from phantom.models import ModuleResult, NormalizedTarget


@dataclass(slots=True)
class PluginContext:
    config: PhantomConfig
    audit: Any
    validator: Any
    roe: Any


class BasePlugin:
    name = "base"
    action_type = "analysis"
    description = ""

    def describe(self) -> dict[str, str]:
        return {
            "name": self.name,
            "action_type": self.action_type,
            "description": self.description,
        }

    def execute(self, context: PluginContext, target: NormalizedTarget, observations: dict[str, Any]) -> ModuleResult:
        raise NotImplementedError
