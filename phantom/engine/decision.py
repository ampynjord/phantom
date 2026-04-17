from __future__ import annotations

from phantom.models import DecisionStep, ExecutionState


class DecisionEngine:
    def next_steps(self, state: ExecutionState) -> list[DecisionStep]:
        executed = set(state.executed_modules)
        obs = state.observations
        target = state.target
        open_ports: list[int] = obs.get("open_ports", [])
        has_web = target.scheme in {"http", "https"} or any(p in {80, 443, 8080, 8443} for p in open_ports)
        has_https = target.scheme == "https" or 443 in open_ports or 8443 in open_ports
        has_http = bool(obs.get("http"))
        has_open_ports = bool(open_ports)
        queue: list[DecisionStep] = []

        if "dns_enum" not in executed and target.target_type in {"hostname", "url"}:
            queue.append(DecisionStep(module="dns_enum", priority=95,
                reason="Enumerate DNS records and probe common subdomains before deeper analysis.",
                source="heuristic"))
        if "tcp_connect" not in executed:
            queue.append(DecisionStep(module="tcp_connect", priority=85,
                reason="Map the open service attack surface across approved ports.",
                source="heuristic"))
        if "banner_grab" not in executed and has_open_ports:
            queue.append(DecisionStep(module="banner_grab", priority=78,
                reason="Identify service versions on open ports for targeted CVE matching.",
                source="heuristic"))
        if "http_probe" not in executed and has_web:
            queue.append(DecisionStep(module="http_probe", priority=72,
                reason="Analyze HTTP endpoint for transport and configuration issues.",
                source="heuristic"))
        if "headers_audit" not in executed and has_http:
            queue.append(DecisionStep(module="headers_audit", priority=65,
                reason="Audit missing security headers that expose users to browser-based attacks.",
                source="heuristic"))
        if "tls_check" not in executed and has_https:
            queue.append(DecisionStep(module="tls_check", priority=60,
                reason="Assess TLS certificate validity and cipher configuration.",
                source="heuristic"))
        if "common_paths" not in executed and has_http:
            queue.append(DecisionStep(module="common_paths", priority=55,
                reason="Probe for exposed config files, admin panels, and debug endpoints.",
                source="heuristic"))
        if "attack_path_simulation" not in executed and executed:
            queue.append(DecisionStep(module="attack_path_simulation", priority=30,
                reason="Correlate gathered observations into bounded attack path scenarios.",
                source="heuristic"))

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
        return "No approved service responded on the configured ports. Run stopped after surface mapping."
