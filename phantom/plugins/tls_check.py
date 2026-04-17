from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from phantom.models import Finding, ModuleResult, NormalizedTarget
from phantom.plugins.base import BasePlugin, PluginContext


class TlsCheckPlugin(BasePlugin):
    name = "tls_check"
    action_type = "tcp_connect"
    description = "Analyze TLS/SSL configuration: certificate validity, version, cipher strength."

    def execute(self, context: PluginContext, target: NormalizedTarget, observations: dict) -> ModuleResult:
        open_ports: list[int] = observations.get("open_ports", [])
        host = target.hostname or target.ip
        if not host:
            return ModuleResult()

        if target.scheme == "https" and target.port:
            tls_port = target.port
        elif 443 in open_ports:
            tls_port = 443
        elif 8443 in open_ports:
            tls_port = 8443
        else:
            return ModuleResult()

        timeout = context.config.roe.network_timeout_seconds
        findings: list[Finding] = []
        tls_info: dict = {}

        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_OPTIONAL

            with socket.create_connection((host, tls_port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert() or {}
                    cipher = ssock.cipher()
                    version = ssock.version()

            tls_info = {
                "version": version,
                "cipher": cipher[0] if cipher else None,
                "key_bits": cipher[2] if cipher else None,
            }

            # Certificate expiry
            not_after = cert.get("notAfter")
            if not_after:
                try:
                    expiry_ts = ssl.cert_time_to_seconds(not_after)
                    expiry = datetime.fromtimestamp(expiry_ts, tz=timezone.utc)
                    days_left = (expiry - datetime.now(timezone.utc)).days
                    tls_info["cert_expiry"] = not_after
                    tls_info["cert_days_left"] = days_left

                    if days_left < 0:
                        findings.append(Finding(
                            title="TLS certificate expired",
                            description=f"Certificate expired {abs(days_left)} days ago. Browsers reject this connection.",
                            category="tls",
                            severity="critical",
                            score=9.0,
                            target=f"https://{host}:{tls_port}",
                            source_module=self.name,
                            evidence=tls_info,
                            recommendation="Renew the TLS certificate immediately.",
                        ))
                    elif days_left < 30:
                        findings.append(Finding(
                            title=f"TLS certificate expires in {days_left} days",
                            description="Certificate nearing expiry. Failure to renew will break all HTTPS connectivity.",
                            category="tls",
                            severity="medium",
                            score=5.0,
                            target=f"https://{host}:{tls_port}",
                            source_module=self.name,
                            evidence=tls_info,
                            recommendation="Schedule certificate renewal before expiry.",
                        ))
                except (ValueError, OSError):
                    pass

            # Self-signed check
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))
            tls_info["subject_cn"] = subject.get("commonName")
            tls_info["issuer_cn"] = issuer.get("commonName")

            if subject and subject == issuer:
                findings.append(Finding(
                    title="Self-signed TLS certificate",
                    description=(
                        "The certificate is self-signed and not trusted by clients. "
                        "Susceptible to MITM attacks where an attacker intercepts and replaces the certificate."
                    ),
                    category="tls",
                    severity="medium",
                    score=5.5,
                    target=f"https://{host}:{tls_port}",
                    source_module=self.name,
                    evidence=tls_info,
                    recommendation="Replace with a certificate from a trusted CA (e.g., Let's Encrypt, free and automated).",
                ))

            # Weak TLS version
            if version in {"TLSv1", "TLSv1.1"}:
                findings.append(Finding(
                    title=f"Deprecated TLS version negotiated: {version}",
                    description=(
                        f"Server accepted {version} which has known cryptographic weaknesses (BEAST, POODLE). "
                        "PCI-DSS 4.0 and modern browsers require TLS 1.2 minimum."
                    ),
                    category="tls",
                    severity="high",
                    score=7.5,
                    target=f"https://{host}:{tls_port}",
                    source_module=self.name,
                    evidence=tls_info,
                    recommendation="Disable TLS 1.0 and 1.1 in server configuration. Enforce TLS 1.2+ with TLS 1.3 preferred.",
                ))

            # Weak cipher
            if cipher and cipher[2] and cipher[2] < 128:
                findings.append(Finding(
                    title=f"Weak cipher negotiated ({cipher[2]}-bit key)",
                    description=f"The negotiated cipher uses a {cipher[2]}-bit key, below the 128-bit minimum.",
                    category="tls",
                    severity="high",
                    score=7.0,
                    target=f"https://{host}:{tls_port}",
                    source_module=self.name,
                    evidence=tls_info,
                    recommendation="Configure server to only offer ECDHE/DHE cipher suites with 128-bit+ keys.",
                ))

            if not findings:
                findings.append(Finding(
                    title="TLS configuration summary",
                    description=f"TLS on port {tls_port}: {version}, cipher {cipher[0] if cipher else 'unknown'}.",
                    category="tls",
                    severity="info",
                    score=1.0,
                    target=f"https://{host}:{tls_port}",
                    source_module=self.name,
                    evidence=tls_info,
                    recommendation="Monitor certificate expiry and cipher suite configuration periodically.",
                ))

        except (ssl.SSLError, socket.timeout, OSError):
            return ModuleResult()

        return ModuleResult(findings=findings, observations={"tls": tls_info})
