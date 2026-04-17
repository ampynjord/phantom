from __future__ import annotations

from phantom.models import Finding, ModuleResult, NormalizedTarget
from phantom.plugins.base import BasePlugin, PluginContext

SECURITY_HEADERS: dict[str, dict] = {
    "Strict-Transport-Security": {
        "description": "HSTS is missing. Without it, browsers may connect over plain HTTP, enabling protocol downgrade and cookie hijacking attacks.",
        "severity": "medium",
        "score": 5.5,
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "description": "No CSP header. Without it, the page is vulnerable to XSS, data injection, and clickjacking via script and resource injection.",
        "severity": "medium",
        "score": 6.0,
        "recommendation": "Define a strict Content-Security-Policy with default-src 'self' and explicit allowlists for scripts and styles.",
    },
    "X-Frame-Options": {
        "description": "Missing X-Frame-Options. The page can be embedded in an iframe from any origin, enabling clickjacking attacks.",
        "severity": "medium",
        "score": 5.0,
        "recommendation": "Add: X-Frame-Options: DENY (or SAMEORIGIN if iframing from same domain is needed).",
    },
    "X-Content-Type-Options": {
        "description": "Missing X-Content-Type-Options: nosniff. Browsers may MIME-sniff responses and execute malicious content as scripts.",
        "severity": "low",
        "score": 3.0,
        "recommendation": "Add: X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "description": "No Referrer-Policy set. Full URLs including paths and query parameters may leak to third-party sites.",
        "severity": "low",
        "score": 2.5,
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "description": "No Permissions-Policy. Browser features like camera, microphone and geolocation may be accessible to embedded scripts.",
        "severity": "low",
        "score": 2.5,
        "recommendation": "Add: Permissions-Policy: geolocation=(), camera=(), microphone=()",
    },
}

LEAKY_HEADERS = {"server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"}


class HeadersAuditPlugin(BasePlugin):
    name = "headers_audit"
    action_type = "http_probe"
    description = "Audit HTTP security headers for missing or misconfigured protections."

    def execute(self, context: PluginContext, target: NormalizedTarget, observations: dict) -> ModuleResult:
        http_data = observations.get("http") or {}
        headers: dict[str, str] = http_data.get("headers") or {}
        if not headers:
            return ModuleResult()

        headers_lower = {k.lower(): v for k, v in headers.items()}
        findings: list[Finding] = []
        present: list[str] = []
        missing: list[str] = []

        for header, meta in SECURITY_HEADERS.items():
            if header.lower() in headers_lower:
                present.append(header)
            else:
                missing.append(header)
                findings.append(Finding(
                    title=f"Missing security header: {header}",
                    description=meta["description"],
                    category="security_headers",
                    severity=meta["severity"],
                    score=meta["score"],
                    target=http_data.get("url", target.label()),
                    source_module=self.name,
                    evidence={"missing_header": header},
                    recommendation=meta["recommendation"],
                ))

        leaked: dict[str, str] = {}
        for key in LEAKY_HEADERS:
            if key in headers_lower:
                leaked[key] = headers_lower[key]

        if leaked:
            findings.append(Finding(
                title="Server technology disclosed via HTTP headers",
                description=(
                    f"Response headers reveal server stack: {', '.join(f'{k}: {v}' for k, v in leaked.items())}. "
                    "This enables attackers to find version-specific exploits without additional probing."
                ),
                category="fingerprinting",
                severity="low",
                score=3.5,
                target=http_data.get("url", target.label()),
                source_module=self.name,
                evidence={"disclosed_headers": leaked},
                recommendation="Remove or obfuscate Server, X-Powered-By and framework version headers.",
            ))

        return ModuleResult(
            findings=findings,
            observations={"security_headers": {"present": present, "missing": missing}},
        )
