from __future__ import annotations

from phantom.models import NormalizedTarget
from phantom.roe import RoEValidator
from phantom.scope import ScopeEnforcer


class ExecutionValidator:
    def __init__(self, scope: ScopeEnforcer, roe: RoEValidator) -> None:
        self.scope = scope
        self.roe = roe

    def validate_target(self, raw_target: str) -> NormalizedTarget:
        return self.scope.validate(raw_target)

    def validate_plugin(self, module_name: str, action_type: str) -> None:
        self.roe.validate_module(module_name, action_type)
