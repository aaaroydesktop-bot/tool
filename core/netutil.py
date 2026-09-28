"""
Dependency-free parsing helpers.

Everything in this module is pure (no sockets, no Rich, no I/O), which keeps it
quick to unit-test and safe to import from anywhere.
"""

from __future__ import annotations

import ipaddress
import re

MIN_PORT = 1
MAX_PORT = 65535

# --------------------------------------------------------------------------
# PORT PRESETS
# --------------------------------------------------------------------------

# Most frequently exposed TCP ports across the internet (nmap "top" style).
TOP_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
    119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
    515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026,
    1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049,
    2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060,
    5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070,
    8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9200, 9999, 10000, 32768,
    49152, 49153, 49154, 49155, 49156, 49157, 50000,
]

COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137, 138, 139,
    143, 161, 389, 443, 445, 465, 587, 993, 995, 1433, 1521, 1723, 3306, 3389,
    5432, 5900, 6379, 8080, 8443,
]

WEB_PORTS = [80, 81, 88, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9443]

DB_PORTS = [1433, 1521, 3306, 5432, 5984, 6379, 9042, 9200, 11211, 27017]

REMOTE_PORTS = [22, 23, 513, 3389, 5900, 5985, 5986, 8291]

MAIL_PORTS = [25, 110, 143, 465, 587, 993, 995]

PRESETS: dict[str, list[int]] = {
    "top": TOP_PORTS,
    "top100": TOP_PORTS,
    "common": COMMON_PORTS,
    "web": WEB_PORTS,
    "db": DB_PORTS,
    "remote": REMOTE_PORTS,
    "mail": MAIL_PORTS,
}

_PORT_ONLY = re.compile(r"^\d+$")
_PORT_RANGE = re.compile(r"^(\d+)\s*-\s*(\d+)$")
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9\-_.]*[A-Za-z0-9])?$")


def _check_port(value: int) -> int:
    if not MIN_PORT <= value <= MAX_PORT:
        raise ValueError(f"port out of range: {value}")
    return value


def parse_ports(spec: str | int | list | tuple | range | None) -> list[int]:
    """
    Turn a human port specification into a sorted, de-duplicated list.

    Accepts ``22``, ``22,80,443``, ``1-1024``, ``top``, ``web``, ``all`` and any
    mix of them separated by commas or spaces.  ``None`` means "top ports".
    """
    if spec is None:
        return sorted(set(TOP_PORTS))

    if isinstance(spec, int):
        return [_check_port(spec)]

    if isinstance(spec, (list, tuple, set, range)):
        return sorted({_check_port(int(p)) for p in spec})

    ports: set[int] = set()

    for raw in re.split(r"[,\s]+", str(spec).strip().lower()):
        if not raw:
            continue

        if raw in ("all", "full"):
            ports.update(range(MIN_PORT, MAX_PORT + 1))
        elif raw in PRESETS:
            ports.update(PRESETS[raw])
        elif _PORT_ONLY.match(raw):
            ports.add(_check_port(int(raw)))
        else:
            match = _PORT_RANGE.match(raw)
            if not match:
                raise ValueError(f"invalid port specification: {raw!r}")
            start, end = int(match.group(1)), int(match.group(2))
            _check_port(start)
            _check_port(end)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))

    if not ports:
        raise ValueError(f"no ports found in specification: {spec!r}")

    return sorted(ports)


def format_ports(ports) -> str:
    """Collapse a port list into a compact ``22,80,443,8000-8010`` string."""
    ordered = sorted({int(p) for p in ports})
    if not ordered:
        return ""

    ranges: list[str] = []
    start = previous = ordered[0]

    for port in ordered[1:]:
        if port == previous + 1:
            previous = port
            continue
        ranges.append(str(start) if start == previous else f"{start}-{previous}")
        start = previous = port

    ranges.append(str(start) if start == previous else f"{start}-{previous}")
    return ",".join(ranges)


# --------------------------------------------------------------------------
# TARGET PARSING
# --------------------------------------------------------------------------


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_ipv4(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).version == 4
    except ValueError:
        return False


def is_valid_host(value: str) -> bool:
    if not value or len(value) > 253:
        return False
    if is_ip(value):
        return True
    return bool(_HOST_RE.match(value)) and not value.startswith(("-", "."))


def parse_target(value: str) -> tuple[str, int | None]:
    """
    Normalise a user supplied target into ``(host, port_or_None)``.

    Handles ``https://example.com/path``, ``example.com:8443``, ``[::1]:80``
    and bare hosts.
    """
    value = (value or "").strip()
    if not value:
        raise ValueError("empty target")

    # Drop the scheme, then everything from the first path/query/fragment.
    netloc = re.split(r"[/?#]", _SCHEME_RE.sub("", value), maxsplit=1)[0]

    if "@" in netloc:  # strip user:pass@
        netloc = netloc.rsplit("@", 1)[1]

    port: int | None = None

    if netloc.startswith("["):  # bracketed IPv6
        end = netloc.find("]")
        host = netloc[1:end] if end != -1 else netloc.strip("[]")
        rest = netloc[end + 1:] if end != -1 else ""
        if rest.startswith(":"):
            port = _check_port(int(rest[1:]))
    elif netloc.count(":") == 1:
        host, _, raw_port = netloc.partition(":")
        if raw_port:
            port = _check_port(int(raw_port))
    else:  # bare host or unbracketed IPv6
        host = netloc

    host = host.strip().strip(".").lower()
    if not host:
        raise ValueError(f"could not find a host in {value!r}")

    return host, port


def clean_targets(values) -> list[str]:
    """
    Normalise an iterable of raw target strings: strip comments, blanks and
    duplicates while preserving order.  Used for batch/file scanning.
    """
    seen: set[str] = set()
    result: list[str] = []

    for raw in values or []:
        line = str(raw).strip()
        if not line or line.startswith("#"):
            continue
        try:
            host, _ = parse_target(line)
        except ValueError:
            continue
        if host not in seen:
            seen.add(host)
            result.append(host)

    return result


def gateway_for(ip: str, prefix: int = 24) -> str | None:
    """Best-effort gateway guess for a private IPv4 address."""
    if not is_ipv4(ip):
        return None
    try:
        network = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
    except ValueError:
        return None
    if network.num_addresses < 2:
        return None
    return str(network.network_address + 1)


# --------------------------------------------------------------------------
# FORMATTING
# --------------------------------------------------------------------------


def human_duration(seconds: float | None) -> str:
    if seconds is None:
        return "n/a"
    seconds = float(seconds)
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 60:
        return f"{seconds:.2f} s"
    minutes, rest = divmod(seconds, 60)
    return f"{int(minutes)}m {rest:.0f}s"


def human_bytes(size: float | None) -> str:
    if size is None:
        return "n/a"
    size = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} TB"


def human_bitrate(mbps: float | None) -> str:
    if mbps is None:
        return "n/a"
    if mbps < 1:
        return f"{mbps * 1000:.0f} Kbps"
    return f"{mbps:.2f} Mbps"
