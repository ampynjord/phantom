from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from phantom.audit import AuditLogger
from phantom.config import PhantomConfig
from phantom.engine.analyst import MistralAnalyst
from phantom.engine.decision import DecisionEngine
from phantom.engine.validator import ExecutionValidator
from phantom.models import ExecutionState, Finding, ReportBundle, utc_now
from phantom.plugins.base import BasePlugin, PluginContext
from phantom.reporting.render import ReportWriter
from phantom.risk import summarize_findings
from phantom.roe import RoEValidator, RulesOfEngagementError
from phantom.scope import ScopeEnforcer, ScopeError


class PhantomRunner:
    def __init__(self, config: PhantomConfig, plugins: list[BasePlugin]) -> None:
        self.config = config
        self.plugins = {plugin.name: plugin for plugin in plugins}
        self.scope = ScopeEnforcer(config.scope.domain_allowlist, config.scope.ip_allowlist)
        self.roe = RoEValidator(config.roe)
        self.validator = ExecutionValidator(self.scope, self.roe)
        self.decision_engine = DecisionEngine()
        self.analyst = MistralAnalyst(config)
        self.run_id = uuid.uuid4().hex[:12]
        self.base_dir = Path.cwd()
        self.audit = AuditLogger(self.base_dir / "logs" / f"{self.run_id}.log")
        self.report_writer = ReportWriter(self.base_dir, self.run_id)

    def run(self) -> dict:
        all_findings: list[Finding] = []
        validated_targets: list[str] = []
        target_summaries: list[dict[str, Any]] = []
        analyst_reports: list[dict[str, Any]] = []

        for raw_target in self.config.targets:
            try:
                target = self.validator.validate_target(raw_target)
            except ScopeError as error:
                self.audit.log("scope", "validate_target", raw_target, "blocked", {"reason": str(error)})
                continue

            validated_targets.append(target.label())
            state = ExecutionState(target=target)
            target_findings: list[Finding] = []

            while True:
                planned_steps = [
                    step for step in self.decision_engine.next_steps(state)
                    if step.module not in state.executed_modules
                ]
                if not planned_steps:
                    self.audit.log(
                        "decision_engine", "terminate_target", target.label(), "completed",
                        {"reason": self.decision_engine.explain_termination(state)},
                    )
                    break
                already_tracked = {s.module for s in state.decision_trace}
                state.decision_trace.extend(s for s in planned_steps if s.module not in already_tracked)
                selected_step = planned_steps[0]
                self.audit.log("decision_engine", "select_module", target.label(), "planned", {
                    "module": selected_step.module, "priority": selected_step.priority,
                    "reason": selected_step.reason, "source": selected_step.source,
                })
                for deferred in planned_steps[1:]:
                    self.audit.log("decision_engine", "defer_module", target.label(), "planned", {
                        "module": deferred.module, "priority": deferred.priority,
                        "reason": deferred.reason, "source": deferred.source,
                    })
                module_name = selected_step.module
                plugin = self.plugins.get(module_name)
                if not plugin:
                    state.executed_modules.append(module_name)
                    continue
                try:
                    self.validator.validate_plugin(plugin.name, plugin.action_type)
                except RulesOfEngagementError as error:
                    self.audit.log(plugin.name, "validate_plugin", target.label(), "blocked", {"reason": str(error)})
                    self._mark_status(state, plugin.name, "blocked")
                    state.executed_modules.append(plugin.name)
                    continue
                context = PluginContext(config=self.config, audit=self.audit, validator=self.validator, roe=self.roe)
                self.audit.log(plugin.name, "pre_execute", target.label(), "allowed", {})
                try:
                    result = plugin.execute(context, state.target, state.observations)
                except Exception as error:
                    self.audit.log(plugin.name, "execute", target.label(), "error", {"reason": str(error)})
                    self._mark_status(state, plugin.name, "error")
                    state.executed_modules.append(plugin.name)
                    continue
                target_findings.extend(result.findings)
                state.observations.update(result.observations)
                state.executed_modules.append(plugin.name)
                self._mark_status(state, plugin.name, "executed")
                self.audit.log(plugin.name, "post_execute", target.label(), "completed", {
                    "finding_count": len(result.findings),
                    "observation_keys": list(result.observations.keys()),
                })

            all_findings.extend(target_findings)

            # LLM post-analysis per target
            self.audit.log("analyst", "start", target.label(), "running", {})
            ar = self.analyst.analyze(target.label(), target_findings, state.observations)
            analyst_reports.append({"target": target.label(), **ar.to_dict()})
            self.audit.log("analyst", "complete", target.label(), "completed", {
                "risk_level": ar.risk_level, "source": ar.source,
                "attack_vector_count": len(ar.attack_vectors),
            })

            target_summaries.append(self._build_target_summary(state, target_findings))

        summary = summarize_findings(all_findings)
        bundle = ReportBundle(
            run_id=self.run_id,
            engagement_name=self.config.engagement_name,
            generated_at=utc_now(),
            findings=[f.to_dict() for f in all_findings],
            timeline=[r.to_dict() for r in self.audit.timeline],
            targets=validated_targets,
            target_summaries=target_summaries,
            analyst_reports=analyst_reports,
            summary=summary,
            files={},
        )
        bundle.files = self.report_writer.write(bundle)
        return {
            "run_id": bundle.run_id,
            "engagement_name": bundle.engagement_name,
            "generated_at": bundle.generated_at,
            "targets": bundle.targets,
            "analyst_reports": bundle.analyst_reports,
            "summary": bundle.summary,
            "findings": bundle.findings,
            "timeline": bundle.timeline,
            "files": bundle.files,
        }

    def _mark_status(self, state: ExecutionState, module_name: str, status: str) -> None:
        for step in state.decision_trace:
            if step.module == module_name and step.status == "planned":
                step.status = status
                return

    def _build_target_summary(self, state: ExecutionState, findings: list[Finding]) -> dict[str, Any]:
        open_ports = state.observations.get("open_ports", [])
        services = state.observations.get("services", {})
        http_data = state.observations.get("http") or {}
        exposed = state.observations.get("exposed_paths", {})
        return {
            "target": state.target.label(),
            "open_ports": open_ports,
            "services": services,
            "http_title": http_data.get("title"),
            "http_status": http_data.get("status"),
            "exposed_paths": exposed,
            "finding_count": len(findings),
            "executed_modules": state.executed_modules,
            "decision_trace": [step.to_dict() for step in state.decision_trace],
        }
