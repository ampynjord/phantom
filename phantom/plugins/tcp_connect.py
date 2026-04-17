from __future__ import annotations

import socket

from phantom.models import Finding, ModuleResult, NormalizedTarget
from phantom.plugins.base import BasePlugin, PluginContext


class TcpConnectPlugin(BasePlugin):
    name = "tcp_connect"
    action_type = "tcp_connect"
    description = "Perform bounded TCP connect checks against approved ports only."

    def execute(self, context: PluginContext, target: NormalizedTarget, observations: dict) -> ModuleResult:
        host = target.hostname or target.ip
        if not host:
            return ModuleResult()

        candidate_ports = [target.port] if target.port else context.config.roe.default_ports
        ports = context.roe.validate_ports([port for port in candidate_ports if port is not None])
        open_ports: list[int] = []

        for port in ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
                connection.settimeout(context.config.roe.network_timeout_seconds)
                if connection.connect_ex((host, port)) == 0:
                    open_ports.append(port)

        findings = []
        if open_ports:
            findings.append(
                Finding(
                    title="Approved TCP services detected",
                    description="One or more approved service ports responded to a TCP connect test.",
                    category="attack_surface",
                    severity="low",
                    score=3.2,
                    target=target.label(),
                    source_module=self.name,
                    evidence={"open_ports": open_ports},
                    recommendation="Confirm service ownership and hardening status for each exposed port.",
                )
            )

        return ModuleResult(findings=findings, observations={"open_ports": open_ports})
