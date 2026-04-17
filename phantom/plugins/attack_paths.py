from __future__ import annotations

from phantom.models import Finding, ModuleResult, NormalizedTarget
from phantom.plugins.base import BasePlugin, PluginContext


class AttackPathSimulationPlugin(BasePlugin):
    name = "attack_path_simulation"
    action_type = "analysis"
    description = "Simulate non-destructive attack paths from authorized observations only."

    def execute(self, context: PluginContext, target: NormalizedTarget, observations: dict) -> ModuleResult:
        findings: list[Finding] = []
        http_data = observations.get("http") or {}
        title = (http_data.get("title") or "").lower()
        headers = http_data.get("headers") or {}

        if http_data.get("url") and http_data.get("url", "").startswith("http://"):
            findings.append(
                Finding(
                    title="Simulated path: interceptable web entrypoint",
                    description="Observed cleartext transport suggests a theoretical path from network access to session or credential exposure without performing exploitation.",
                    category="simulation",
                    severity="medium",
                    score=5.2,
                    target=http_data["url"],
                    source_module=self.name,
                    evidence={
                        "path": ["network_position", "cleartext_http", "possible_session_exposure"],
                    },
                    recommendation="Validate whether sensitive workflows are accessible over cleartext transport and enforce encrypted transport where required.",
                )
            )

        if any(keyword in title for keyword in ["admin", "login", "dashboard", "grafana", "jenkins"]):
            findings.append(
                Finding(
                    title="Simulated path: exposed administrative surface",
                    description="Page metadata suggests an administrative or authentication surface that warrants controlled review under the engagement scope.",
                    category="simulation",
                    severity="medium",
                    score=4.9,
                    target=http_data.get("url", target.label()),
                    source_module=self.name,
                    evidence={"title": http_data.get("title", ""), "headers": headers},
                    recommendation="Review access controls, MFA coverage and configuration exposure for this administrative surface.",
                )
            )

        return ModuleResult(findings=findings)
