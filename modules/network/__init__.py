"""Network toolkit subpackage.

Imports are explicit (no wildcards) so that ``network.scan_ports`` and friends
are discoverable by IDEs and static tools.
"""

from .scanner import (
    DEFAULT_TIMEOUT,
    DEFAULT_WORKERS,
    auto_port_scan,
    diff_reports,
    full_port_scan,
    open_port_set,
    port_scan,
    print_report,
    render_table,
    resolve,
    reverse_lookup,
    scan_many,
    scan_port,
    scan_ports,
)
from .services import (
    COMMON_SERVICES,
    HTTP_LIKE_PORTS,
    RISKY_PORTS,
    SMART_PORTS,
    TLS_LIKE_PORTS,
    is_http_like,
    is_tls_like,
    risk_note,
    service_name,
)
from .dns import lookup as dns_lookup
from .geoip import lookup as geo_lookup
from .headers import fetch as http_headers
from .subdomain import scan as subdomain_scan
from .localnet import discover as local_scan
from .localnet import local_network_scan
from .ping import (
    detect_os,
    get_local_ip,
    get_router_ip,
    host_alive,
    ping_once,
    ping_sweep,
    ping_test,
)
from .traceroute import trace as traceroute
from .vendor import lookup as vendor_lookup
from .speedtest import speed_test
from .techdetect import detect as detect_technology

__all__ = [
    "COMMON_SERVICES", "HTTP_LIKE_PORTS", "RISKY_PORTS", "SMART_PORTS",
    "TLS_LIKE_PORTS", "is_http_like", "is_tls_like", "risk_note", "service_name",
    "DEFAULT_TIMEOUT", "DEFAULT_WORKERS",
    "auto_port_scan", "full_port_scan", "port_scan", "print_report",
    "render_table", "resolve", "reverse_lookup", "scan_many", "scan_port",
    "scan_ports", "diff_reports", "open_port_set",
    "dns_lookup", "geo_lookup", "http_headers", "subdomain_scan",
    "local_scan", "local_network_scan",
    "detect_os", "get_local_ip", "get_router_ip", "host_alive", "ping_once",
    "ping_sweep", "ping_test", "traceroute", "vendor_lookup", "speed_test",
    "detect_technology",
]
