from phantom.models import BasePlugin, ModuleResult, NormalizedTarget, PluginContext  # noqa: F401
from phantom.plugins.scan import BannerGrabPlugin, DnsEnumPlugin, TcpConnectPlugin
from phantom.plugins.web import (
    AttackPathSimulationPlugin, CommonPathsPlugin,
    HeadersAuditPlugin, HttpProbePlugin, TlsCheckPlugin,
)


def build_default_plugins() -> list[BasePlugin]:
    return [
        DnsEnumPlugin(),
        TcpConnectPlugin(),
        BannerGrabPlugin(),
        HttpProbePlugin(),
        HeadersAuditPlugin(),
        TlsCheckPlugin(),
        CommonPathsPlugin(),
        AttackPathSimulationPlugin(),
    ]

