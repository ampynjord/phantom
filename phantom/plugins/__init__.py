from phantom.plugins.attack_paths import AttackPathSimulationPlugin
from phantom.plugins.banner_grab import BannerGrabPlugin
from phantom.plugins.common_paths import CommonPathsPlugin
from phantom.plugins.dns_enum import DnsEnumPlugin
from phantom.plugins.headers_audit import HeadersAuditPlugin
from phantom.plugins.http_probe import HttpProbePlugin
from phantom.plugins.os_audit import OsAuditPlugin
from phantom.plugins.tcp_connect import TcpConnectPlugin
from phantom.plugins.tls_check import TlsCheckPlugin


def build_default_plugins():
    return [
        DnsEnumPlugin(),
        TcpConnectPlugin(),
        BannerGrabPlugin(),
        HttpProbePlugin(),
        HeadersAuditPlugin(),
        TlsCheckPlugin(),
        CommonPathsPlugin(),
        OsAuditPlugin(),
        AttackPathSimulationPlugin(),
    ]
