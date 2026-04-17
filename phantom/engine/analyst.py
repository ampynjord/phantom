from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from phantom.config import PhantomConfig
from phantom.models import Finding


@dataclass(slots=True)
class AnalystReport:
    narrative: str
    attack_vectors: list[dict[str, str]]
    risk_level: str
    source: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class MistralAnalyst:
    API_URL = "https://api.mistral.ai/v1/chat/completions"

    def __init__(self, config: PhantomConfig) -> None:
        self.config = config

    def analyze(
        self,
        target_label: str,
        findings: list[Finding],
        observations: dict[str, Any],
    ) -> AnalystReport:
        api_key = os.getenv("MISTRAL_API_KEY")
        if not api_key:
            return self._heuristic(findings)
        try:
            return self._llm(api_key, target_label, findings, observations)
        except Exception as exc:
            import sys
            print(f"[analyst] LLM call failed ({type(exc).__name__}: {exc}), falling back to heuristic", file=sys.stderr)
            return self._heuristic(findings)

    def _llm(
        self,
        api_key: str,
        target_label: str,
        findings: list[Finding],
        observations: dict[str, Any],
    ) -> AnalystReport:
        findings_payload = [
            {
                "title": f.title,
                "severity": f.severity,
                "score": f.score,
                "category": f.category,
                "description": f.description[:300],
                "evidence": {k: str(v)[:150] for k, v in f.evidence.items()},
                "recommendation": f.recommendation[:200],
            }
            for f in findings
        ]
        obs_payload = {
            "open_ports": observations.get("open_ports", []),
            "services": observations.get("services", {}),
            "tls": observations.get("tls", {}),
            "http_status": (observations.get("http") or {}).get("status"),
            "http_title": (observations.get("http") or {}).get("title"),
            "exposed_paths": observations.get("exposed_paths", {}),
            "security_headers_missing": (observations.get("security_headers") or {}).get("missing", []),
            "discovered_subdomains": list(observations.get("discovered_subdomains", {}).keys()),
        }
        prompt_body = json.dumps({
            "engagement": self.config.engagement_name,
            "target": target_label,
            "findings": findings_payload,
            "observations": obs_payload,
        })
        payload = {
            "model": self.config.roe.llm_model,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a senior penetration tester writing an authorized security assessment. "
                        "Analyze the provided findings and observations for a single target. "
                        "Respond ONLY with valid JSON containing exactly these fields:\n"
                        "- narrative: string (2-4 sentences, executive-level summary of the security posture)\n"
                        "- attack_vectors: array of objects, each with: title (string), severity (critical/high/medium/low), "
                        "description (string, specific exploitation technique a real attacker would use with these findings)\n"
                        "- risk_level: string (one of: critical, high, medium, low, info)\n"
                        "Be concrete. Describe exactly how findings chain together into real attacks. "
                        "Do not repeat individual findings — synthesize them into attack scenarios."
                    ),
                },
                {"role": "user", "content": prompt_body},
            ],
        }
        request = Request(
            self.API_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urlopen(request, timeout=self.config.roe.llm_timeout_seconds) as response:
            body = json.loads(response.read().decode("utf-8"))

        content = body["choices"][0]["message"]["content"]
        parsed = json.loads(content)
        vectors = [
            {
                "title": str(v.get("title", "")),
                "severity": str(v.get("severity", "medium")),
                "description": str(v.get("description", "")),
            }
            for v in parsed.get("attack_vectors", [])
        ]
        return AnalystReport(
            narrative=str(parsed.get("narrative", "")),
            attack_vectors=vectors,
            risk_level=str(parsed.get("risk_level", "medium")),
            source="llm",
        )

    def _heuristic(self, findings: list[Finding]) -> AnalystReport:
        if not findings:
            return AnalystReport(
                narrative="No significant vulnerabilities were identified on the assessed scope.",
                attack_vectors=[],
                risk_level="info",
                source="heuristic",
            )
        max_score = max(f.score for f in findings)
        risk_level = (
            "critical" if max_score >= 9 else
            "high" if max_score >= 7 else
            "medium" if max_score >= 5 else
            "low" if max_score >= 3 else
            "info"
        )
        vectors = [
            {"title": f.title, "severity": f.severity, "description": f.description}
            for f in sorted(findings, key=lambda x: x.score, reverse=True)[:5]
        ]
        return AnalystReport(
            narrative=(
                f"Assessment identified {len(findings)} finding(s). "
                f"Highest risk score: {max_score}/10 ({risk_level.upper()}). "
                "Enable Mistral AI analysis (MISTRAL_API_KEY) for detailed attack chain synthesis."
            ),
            attack_vectors=vectors,
            risk_level=risk_level,
            source="heuristic",
        )
