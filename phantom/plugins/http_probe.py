from __future__ import annotations

from html.parser import HTMLParser
from urllib.error import HTTPError, URLError
from urllib.parse import urlunsplit
from urllib.request import HTTPErrorProcessor, Request, build_opener

from phantom.models import Finding, ModuleResult, NormalizedTarget
from phantom.plugins.base import BasePlugin, PluginContext


class TitleParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._capture = False
        self.title = ""

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag.lower() == "title":
            self._capture = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._capture = False

    def handle_data(self, data: str) -> None:
        if self._capture:
            self.title += data.strip()


class NoRedirectProcessor(HTTPErrorProcessor):
    def http_response(self, request, response):
        return response

    https_response = http_response


class HttpProbePlugin(BasePlugin):
    name = "http_probe"
    action_type = "http_probe"
    description = "Issue tightly scoped HTTP HEAD or GET requests without following redirects."

    def execute(self, context: PluginContext, target: NormalizedTarget, observations: dict) -> ModuleResult:
        url = self._build_url(target, observations)
        if not url:
            return ModuleResult()

        method = context.roe.validate_http_method("HEAD")
        request = Request(url=url, method=method, headers={"User-Agent": context.config.roe.user_agent})
        opener = build_opener(NoRedirectProcessor)

        try:
            with opener.open(request, timeout=context.config.roe.network_timeout_seconds) as response:
                status = response.status
                headers = dict(response.headers.items())
                body = b""
        except HTTPError as error:
            status = error.code
            headers = dict(error.headers.items())
            body = b""
        except URLError:
            return ModuleResult()

        title = ""
        if method == "HEAD" and status < 400:
            get_request = Request(url=url, method=context.roe.validate_http_method("GET"), headers={"User-Agent": context.config.roe.user_agent})
            try:
                with opener.open(get_request, timeout=context.config.roe.network_timeout_seconds) as response:
                    body = response.read(4096)
            except (HTTPError, URLError):
                body = b""

        if body:
            parser = TitleParser()
            parser.feed(body.decode("utf-8", errors="ignore"))
            title = parser.title.strip()

        findings: list[Finding] = []
        scheme = target.scheme or ("https" if 443 in observations.get("open_ports", []) else "http")
        if scheme == "http":
            findings.append(
                Finding(
                    title="Cleartext HTTP endpoint observed",
                    description="A reachable HTTP endpoint was detected without transport encryption.",
                    category="transport",
                    severity="medium",
                    score=5.8,
                    target=url,
                    source_module=self.name,
                    evidence={"status": status, "headers": headers, "title": title},
                    recommendation="Verify whether HTTPS should be enforced and whether credentials or sensitive data are exposed over HTTP.",
                )
            )
        elif scheme == "https" and "Strict-Transport-Security" not in headers:
            findings.append(
                Finding(
                    title="HTTPS endpoint missing HSTS",
                    description="The endpoint replied over HTTPS but did not advertise Strict-Transport-Security.",
                    category="transport",
                    severity="low",
                    score=3.6,
                    target=url,
                    source_module=self.name,
                    evidence={"status": status, "headers": headers, "title": title},
                    recommendation="Consider enabling HSTS after validating application and subdomain readiness.",
                )
            )

        server_header = headers.get("Server") or headers.get("server")
        if server_header:
            findings.append(
                Finding(
                    title="HTTP fingerprint available",
                    description="The endpoint discloses server fingerprinting data in HTTP response headers.",
                    category="fingerprinting",
                    severity="info",
                    score=1.8,
                    target=url,
                    source_module=self.name,
                    evidence={"server": server_header, "status": status, "title": title},
                    recommendation="Reduce verbose server disclosure where practical.",
                )
            )

        return ModuleResult(
            findings=findings,
            observations={
                "http": {
                    "url": url,
                    "status": status,
                    "headers": headers,
                    "title": title,
                }
            },
        )

    def _build_url(self, target: NormalizedTarget, observations: dict) -> str | None:
        if target.scheme and target.hostname:
            netloc = target.hostname if not target.port else f"{target.hostname}:{target.port}"
            return urlunsplit((target.scheme, netloc, target.path or "/", "", ""))
        if not target.hostname and not target.ip:
            return None
        host = target.hostname or target.ip
        open_ports = observations.get("open_ports", [])
        if 443 in open_ports:
            return f"https://{host}/"
        if 80 in open_ports:
            return f"http://{host}/"
        if 8443 in open_ports:
            return f"https://{host}:8443/"
        if 8080 in open_ports:
            return f"http://{host}:8080/"
        return None
