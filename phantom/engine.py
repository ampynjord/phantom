from __future__ import annotations

import json
import os
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

from jinja2 import Environment, FileSystemLoader, select_autoescape

from phantom.config import PhantomConfig
from phantom.guard import RoEValidator, RulesOfEngagementError, ScopeEnforcer, ScopeError
from phantom.models import (
    AuditLogger, BasePlugin, DecisionStep, ExecutionState, Finding,
    PluginContext, ReportBundle, summarize_findings, utc_now,
)


# ---------- Decision ----------

class DecisionEngine:
    def next_steps(self, state: ExecutionState) -> list[DecisionStep]:
        executed = set(state.executed_modules)
        obs = state.observations
        target = state.target
        open_ports: list[int] = obs.get("open_ports", [])
        has_web = target.scheme in {"http", "https"} or any(p in {80, 443, 8080, 8443} for p in open_ports)
        has_https = target.scheme == "https" or 443 in open_ports or 8443 in open_ports
        has_http = bool(obs.get("http"))
        queue: list[DecisionStep] = []
        if "dns_enum" not in executed and target.target_type in {"hostname", "url"}:
            queue.append(DecisionStep(module="dns_enum", priority=95, source="heuristic",
                reason="Enumerate DNS records and probe common subdomains before deeper analysis."))
        if "tcp_connect" not in executed:
            queue.append(DecisionStep(module="tcp_connect", priority=85, source="heuristic",
                reason="Map the open service attack surface across approved ports."))
        if "banner_grab" not in executed and obs.get("open_ports"):
            queue.append(DecisionStep(module="banner_grab", priority=78, source="heuristic",
                reason="Identify service versions on open ports for targeted CVE matching."))
        if "http_probe" not in executed and has_web:
            queue.append(DecisionStep(module="http_probe", priority=72, source="heuristic",
                reason="Analyze HTTP endpoint for transport and configuration issues."))
        if "headers_audit" not in executed and has_http:
            queue.append(DecisionStep(module="headers_audit", priority=65, source="heuristic",
                reason="Audit missing security headers that expose users to browser-based attacks."))
        if "tls_check" not in executed and has_https:
            queue.append(DecisionStep(module="tls_check", priority=60, source="heuristic",
                reason="Assess TLS certificate validity and cipher configuration."))
        if "common_paths" not in executed and has_http:
            queue.append(DecisionStep(module="common_paths", priority=55, source="heuristic",
                reason="Probe for exposed config files, admin panels, and debug endpoints."))
        if "attack_path_simulation" not in executed and executed:
            queue.append(DecisionStep(module="attack_path_simulation", priority=30, source="heuristic",
                reason="Correlate gathered observations into bounded attack path scenarios."))
        queue.sort(key=lambda s: s.priority, reverse=True)
        return queue

    def explain_termination(self, state: ExecutionState) -> str:
        obs = state.observations
        if obs.get("exposed_paths"):
            return "Sensitive paths identified; all approved modules completed."
        if obs.get("http"):
            return "Web surface fully analyzed; no further approved modules remain."
        if obs.get("open_ports"):
            return "Open ports assessed; no web surface was reachable for deeper analysis."
        return "No approved service responded on the configured ports."


# ---------- Analyst ----------

class AnalystReport:
    def __init__(self, narrative: str, attack_vectors: list[dict], risk_level: str, source: str) -> None:
        self.narrative = narrative
        self.attack_vectors = attack_vectors
        self.risk_level = risk_level
        self.source = source

    def to_dict(self) -> dict[str, Any]:
        return {"narrative": self.narrative, "attack_vectors": self.attack_vectors,
                "risk_level": self.risk_level, "source": self.source}


class MistralAnalyst:
    API_URL = "https://api.mistral.ai/v1/chat/completions"

    def __init__(self, config: PhantomConfig) -> None:
        self.config = config

    def analyze(self, target_label: str, findings: list[Finding], observations: dict[str, Any]) -> AnalystReport:
        key = os.getenv("MISTRAL_API_KEY")
        if not key:
            return self._heuristic(findings)
        try:
            return self._llm(key, target_label, findings, observations)
        except Exception as exc:
            import sys
            print(f"[analyst] LLM failed ({type(exc).__name__}: {exc}), using heuristic", file=sys.stderr)
            return self._heuristic(findings)

    def _llm(self, key: str, target_label: str, findings: list[Finding], observations: dict[str, Any]) -> AnalystReport:
        payload = {
            "model": self.config.roe.llm_model,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": (
                    "You are a senior penetration tester writing an authorized security assessment. "
                    "Analyze the provided findings and observations for a single target. "
                    "Respond ONLY with valid JSON: "
                    "{\"narrative\": string, \"attack_vectors\": [{\"title\": string, \"severity\": critical|high|medium|low, \"description\": string}], \"risk_level\": critical|high|medium|low|info}"
                )},
                {"role": "user", "content": json.dumps({
                    "engagement": self.config.engagement_name,
                    "target": target_label,
                    "findings": [{"title": f.title, "severity": f.severity, "score": f.score,
                                  "description": f.description[:300]} for f in findings],
                    "observations": {
                        "open_ports": observations.get("open_ports", []),
                        "tls_version": (observations.get("tls") or {}).get("version"),
                        "http_title": (observations.get("http") or {}).get("title"),
                        "exposed_paths": list(observations.get("exposed_paths", {}).keys()),
                        "missing_headers": (observations.get("security_headers") or {}).get("missing", []),
                        "subdomains": list(observations.get("discovered_subdomains", {}).keys()),
                    },
                })},
            ],
        }
        req = Request(self.API_URL, data=json.dumps(payload).encode(),
                      headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                      method="POST")
        with urlopen(req, timeout=self.config.roe.llm_timeout_seconds) as resp:
            body = json.loads(resp.read().decode())
        parsed = json.loads(body["choices"][0]["message"]["content"])
        return AnalystReport(
            narrative=str(parsed.get("narrative", "")),
            attack_vectors=[{"title": str(v.get("title", "")), "severity": str(v.get("severity", "medium")),
                             "description": str(v.get("description", ""))}
                            for v in parsed.get("attack_vectors", [])],
            risk_level=str(parsed.get("risk_level", "medium")),
            source="llm",
        )

    def _heuristic(self, findings: list[Finding]) -> AnalystReport:
        if not findings:
            return AnalystReport("No significant vulnerabilities identified.", [], "info", "heuristic")
        max_score = max(f.score for f in findings)
        risk = ("critical" if max_score >= 9 else "high" if max_score >= 7
                else "medium" if max_score >= 5 else "low" if max_score >= 3 else "info")
        vectors = [{"title": f.title, "severity": f.severity, "description": f.description}
                   for f in sorted(findings, key=lambda x: x.score, reverse=True)[:5]]
        return AnalystReport(
            narrative=(f"Assessment identified {len(findings)} finding(s) with a maximum risk score of "
                       f"{max_score}/10. Enable Mistral AI analysis (MISTRAL_API_KEY) for detailed attack chain synthesis."),
            attack_vectors=vectors,
            risk_level=risk,
            source="heuristic",
        )


# ---------- Report writer ----------

class ReportWriter:
    def __init__(self, base_dir: Path, run_id: str) -> None:
        report_dir = base_dir / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        self._run_id = run_id
        self._report_dir = report_dir
        self._log_path = base_dir / "logs" / f"{run_id}.log"
        self._env = Environment(loader=FileSystemLoader(str(base_dir / "templates")),
                                autoescape=select_autoescape(["html", "xml"]))

    def write(self, bundle: ReportBundle) -> dict[str, str]:
        json_path = self._report_dir / f"{self._run_id}.json"
        html_path = self._report_dir / f"{self._run_id}.html"
        files = {"json": str(json_path), "html": str(html_path), "log": str(self._log_path)}
        payload = asdict(bundle)
        payload["files"] = files
        json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        html_path.write_text(self._env.get_template("report.html").render(report=payload), encoding="utf-8")
        return files


# ---------- Runner ----------

class PhantomRunner:
    def __init__(self, config: PhantomConfig, plugins: list[BasePlugin]) -> None:
        self.config = config
        self.plugins = {p.name: p for p in plugins}
        self.scope = ScopeEnforcer(config.scope.domain_allowlist, config.scope.ip_allowlist)
        self.roe = RoEValidator(config.roe)
        self.decision_engine = DecisionEngine()
        self.analyst = MistralAnalyst(config)
        self.run_id = uuid.uuid4().hex[:12]
        base = Path.cwd()
        self.audit = AuditLogger(base / "logs" / f"{self.run_id}.log")
        self.report_writer = ReportWriter(base, self.run_id)

    def run(self) -> dict:
        all_findings: list[Finding] = []
        validated_targets: list[str] = []
        target_summaries: list[dict[str, Any]] = []
        analyst_reports: list[dict[str, Any]] = []

        for raw_target in self.config.targets:
            try:
                target = self.scope.validate(raw_target)
            except ScopeError as error:
                self.audit.log("scope", "validate_target", raw_target, "blocked", {"reason": str(error)})
                continue

            validated_targets.append(target.label())
            state = ExecutionState(target=target)
            target_findings: list[Finding] = []

            while True:
                planned = [s for s in self.decision_engine.next_steps(state) if s.module not in state.executed_modules]
                if not planned:
                    self.audit.log("decision_engine", "terminate_target", target.label(), "completed",
                                   {"reason": self.decision_engine.explain_termination(state)})
                    break
                tracked = {s.module for s in state.decision_trace}
                state.decision_trace.extend(s for s in planned if s.module not in tracked)
                step = planned[0]
                self.audit.log("decision_engine", "select_module", target.label(), "planned",
                               {"module": step.module, "priority": step.priority, "reason": step.reason})
                plugin = self.plugins.get(step.module)
                if not plugin:
                    state.executed_modules.append(step.module)
                    continue
                try:
                    self.roe.validate_plugin(plugin.name, plugin.action_type)
                except RulesOfEngagementError as error:
                    self.audit.log(plugin.name, "validate_plugin", target.label(), "blocked", {"reason": str(error)})
                    self._mark(state, plugin.name, "blocked")
                    state.executed_modules.append(plugin.name)
                    continue
                ctx = PluginContext(config=self.config, audit=self.audit, validator=self.roe, roe=self.roe)
                self.audit.log(plugin.name, "pre_execute", target.label(), "allowed", {})
                try:
                    result = plugin.execute(ctx, state.target, state.observations)
                except Exception as error:
                    self.audit.log(plugin.name, "execute", target.label(), "error", {"reason": str(error)})
                    self._mark(state, plugin.name, "error")
                    state.executed_modules.append(plugin.name)
                    continue
                target_findings.extend(result.findings)
                state.observations.update(result.observations)
                state.executed_modules.append(plugin.name)
                self._mark(state, plugin.name, "executed")
                self.audit.log(plugin.name, "post_execute", target.label(), "completed",
                               {"finding_count": len(result.findings), "observation_keys": list(result.observations)})

            all_findings.extend(target_findings)
            self.audit.log("analyst", "start", target.label(), "running", {})
            ar = self.analyst.analyze(target.label(), target_findings, state.observations)
            analyst_reports.append({"target": target.label(), **ar.to_dict()})
            self.audit.log("analyst", "complete", target.label(), "completed",
                           {"risk_level": ar.risk_level, "source": ar.source})
            target_summaries.append(self._build_summary(state, target_findings))

        summary = summarize_findings(all_findings)
        bundle = ReportBundle(
            run_id=self.run_id, engagement_name=self.config.engagement_name,
            generated_at=utc_now(), findings=[f.to_dict() for f in all_findings],
            timeline=[r.to_dict() for r in self.audit.timeline],
            targets=validated_targets, target_summaries=target_summaries,
            analyst_reports=analyst_reports, summary=summary, files={},
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

    def _mark(self, state: ExecutionState, module: str, status: str) -> None:
        for s in state.decision_trace:
            if s.module == module and s.status == "planned":
                s.status = status
                return

    def _build_summary(self, state: ExecutionState, findings: list[Finding]) -> dict[str, Any]:
        obs = state.observations
        http = obs.get("http") or {}
        return {
            "target": state.target.label(),
            "open_ports": obs.get("open_ports", []),
            "services": obs.get("services", {}),
            "http_title": http.get("title"),
            "http_status": http.get("status"),
            "exposed_paths": obs.get("exposed_paths", {}),
            "finding_count": len(findings),
            "executed_modules": state.executed_modules,
            "decision_trace": [s.to_dict() for s in state.decision_trace],
        }
