from __future__ import annotations

from collections import Counter

from phantom.models import Finding


def normalize_score(score: float) -> float:
    return round(max(0.0, min(score, 10.0)), 1)


def summarize_findings(findings: list[Finding]) -> dict:
    severities = Counter(finding.severity for finding in findings)
    highest = max((finding.score for finding in findings), default=0.0)
    average = round(sum(finding.score for finding in findings) / len(findings), 2) if findings else 0.0
    return {
        "count": len(findings),
        "highest_score": normalize_score(highest),
        "average_score": normalize_score(average),
        "severity_breakdown": dict(severities),
    }
