"""Port knowledge: service names and protocol hints.  Pure data, no I/O."""

from __future__ import annotations

COMMON_SERVICES = {
    7: "ECHO",
    9: "DISCARD",
    13: "DAYTIME",
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    37: "TIME",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    79: "FINGER",
    80: "HTTP",
    81: "HTTP-ALT",
    88: "KERBEROS",
    110: "POP3",
    111: "RPC",
    113: "IDENT",
    119: "NNTP",
    123: "NTP",
    135: "MSRPC",
    137: "NETBIOS-NS",
    138: "NETBIOS-DGM",
    139: "NETBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    179: "BGP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "SYSLOG",
    515: "LPD",
    548: "AFP",
    554: "RTSP",
    587: "SUBMISSION",
    631: "IPP",
    636: "LDAPS",
    873: "RSYNC",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1433: "MSSQL",
    1521: "ORACLE",
    1723: "PPTP",
    1883: "MQTT",
    1900: "SSDP",
    2049: "NFS",
    2375: "DOCKER",
    3000: "DEV-HTTP",
    3128: "SQUID",
    3306: "MYSQL",
    3389: "RDP",
    4444: "METASPLOIT",
    5060: "SIP",
    5432: "POSTGRES",
    5555: "ADB",
    5601: "KIBANA",
    5672: "AMQP",
    5900: "VNC",
    5984: "COUCHDB",
    6379: "REDIS",
    6667: "IRC",
    7001: "WEBLOGIC",
    8000: "HTTP-ALT",
    8008: "HTTP-ALT",
    8009: "AJP",
    8080: "HTTP-PROXY",
    8081: "HTTP-ALT",
    8086: "INFLUXDB",
    8443: "HTTPS-ALT",
    8888: "HTTP-ALT",
    9000: "PHP-FPM",
    9042: "CASSANDRA",
    9090: "PROMETHEUS",
    9100: "PRINTER",
    9200: "ELASTICSEARCH",
    9443: "HTTPS-ALT",
    9999: "HTTP-ALT",
    11211: "MEMCACHED",
    27017: "MONGODB",
    50000: "SAP",
}

#: Small, high-signal set used by the "smart" scan.
SMART_PORTS = sorted(COMMON_SERVICES)

#: Ports that answer a plain-text HTTP request.
HTTP_LIKE_PORTS = {
    80, 81, 88, 3000, 5000, 5601, 7001, 8000, 8008, 8080, 8081, 8086, 8888,
    9000, 9090, 9200, 9999,
}

#: Ports that normally speak TLS.
TLS_LIKE_PORTS = {443, 465, 636, 993, 995, 8443, 9443, 10443}

#: Ports whose banners are sent by the server immediately on connect.
GREETING_PORTS = {
    21, 22, 23, 25, 110, 143, 220, 465, 587, 993, 995, 3306, 5432, 6379,
    6667, 11211, 27017,
}

#: Well-known ports that are risky when exposed to the internet.
RISKY_PORTS = {
    21: "plaintext FTP",
    23: "plaintext Telnet",
    135: "MSRPC exposure",
    139: "NetBIOS exposure",
    445: "SMB exposure",
    1433: "database exposed",
    1521: "database exposed",
    2049: "NFS exposure",
    2375: "unauthenticated Docker API",
    3306: "database exposed",
    3389: "remote desktop exposed",
    4444: "common backdoor port",
    5432: "database exposed",
    5555: "Android ADB exposed",
    5900: "VNC exposed",
    6379: "Redis (often unauthenticated)",
    9200: "Elasticsearch (often unauthenticated)",
    11211: "Memcached (amplification risk)",
    27017: "MongoDB exposed",
}


def service_name(port: int) -> str:
    return COMMON_SERVICES.get(int(port), "unknown")


def is_http_like(port: int) -> bool:
    return int(port) in HTTP_LIKE_PORTS


def is_tls_like(port: int) -> bool:
    return int(port) in TLS_LIKE_PORTS


def risk_note(port: int) -> str | None:
    return RISKY_PORTS.get(int(port))
