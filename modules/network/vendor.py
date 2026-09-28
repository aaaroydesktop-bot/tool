"""MAC address vendor lookup: offline OUI table first, API as backup."""

from __future__ import annotations

import re

from rich.table import Table

from core import http
from core import report as reportlib
from core.console import console, err, info, is_quiet

#: A handful of very common OUIs so the tool works without internet access.
OFFLINE_OUI = {
    "000C29": "VMware", "00155D": "Microsoft Hyper-V", "001C42": "Parallels",
    "005056": "VMware", "080027": "VirtualBox", "525400": "QEMU/KVM (Linux)",
    "000569": "VMware", "001B21": "Intel", "3C5A37": "Samsung", "5C0A5B":
    "Samsung", "8C7712": "Samsung", "F4F5D8": "Samsung", "0017C8": "Kyocera",
    "0024E4": "Withings", "004096": "Cisco Aironet", "001B0C": "Cisco",
    "0018BA": "Cisco", "002290": "Cisco", "0026CB": "Cisco", "000393": "Apple",
    "0017F2": "Apple", "00254B": "Apple", "3C0754": "Apple", "40A6D9": "Apple",
    "68A86D": "Apple", "7CD1C3": "Apple", "8863DF": "Apple", "A4D1D2": "Apple",
    "ACBC32": "Apple", "B8E856": "Apple", "DC2B2A": "Apple", "F0DBF8": "Apple",
    "FC253F": "Apple", "001CDF": "Belkin", "080086": "TP-Link",
    "1027F5": "TP-Link", "50C7BF": "TP-Link", "A42BB0": "TP-Link",
    "C46E1F": "TP-Link", "EC086B": "TP-Link", "F4F26D": "TP-Link",
    "34E894": "ASUSTek", "2C56DC": "ASUSTek", "9C5C8E": "ASUSTek",
    "1C7B21": "Sony", "FC0FE6": "Sony", "0024E4 ": "Unknown",
    "04C5A4": "OnePlus", "64A2F9": "OnePlus", "94652D": "OnePlus",
    "F8A45F": "Xiaomi", "78110F": "Xiaomi", "8CBEBE": "Xiaomi",
    "20F41B": "Huawei", "4C5499": "Huawei", "8828B3": "Hikvision",
    "BCAD28": "Hikvision", "C4D655": "Hikvision", "D4E8B2": "Hikvision",
    "001A11": "Google", "3C5AB4": "Google", "54B2CA": "Google",
    "F4F5E8": "Google", "44650D": "Amazon", "50DCE7": "Amazon",
    "747548": "Amazon", "A002DC": "Amazon", "B47C9C": "Amazon",
    "FC65DE": "Amazon", "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi",
    "E45F01": "Raspberry Pi", "2CF432": "Espressif (IoT)", "24A160":
    "Espressif (IoT)", "84F3EB": "Espressif (IoT)", "CC50E3": "Espressif (IoT)",
    "00237F": "Planex", "247703": "Intel", "7CB27D": "Intel", "A4C494": "Intel",
    "001CB3": "Netgear", "20E52A": "Netgear", "A040A0": "Netgear",
    "000D88": "D-Link", "1CBDB9": "D-Link", "CCB255": "D-Link",
    "002275": "Belkin", "44E9DD": "Sagemcom", "6C5AB0": "Ubiquiti",
    "24A43C": "Ubiquiti", "788A20": "Ubiquiti", "44D9E7": "Ubiquiti",
    "4C5E0C": "MikroTik", "6C3B6B": "MikroTik", "74ACB9": "MikroTik",
    "00749C": "Ruijie", "1C1D86": "Ruijie", "7825AD": "Hewlett-Packard",
    "3464A9": "Hewlett-Packard", "B0A73C": "Dell", "F8BC12": "Dell",
    "001C27": "Toshiba", "0026F2": "Nokia", "3C8375": "Microsoft",
}


def normalize(mac: str) -> str:
    clean = re.sub(r"[^0-9a-fA-F]", "", mac or "").upper()
    if len(clean) != 12:
        raise ValueError(f"invalid MAC address: {mac!r}")
    return ":".join(clean[i:i + 2] for i in range(0, 12, 2))


def lookup(mac: str | None = None, online: bool = True) -> dict:
    """Resolve the vendor for ``mac`` and return a report dict."""
    if not mac:
        from core.utils import ask

        mac = ask("MAC Address")

    report = reportlib.new_report("vendor_lookup", mac)
    try:
        normalized = normalize(mac)
    except ValueError as exc:
        reportlib.add_error(report, str(exc))
        reportlib.finish(report, found=False)
        return _present(report)

    report["target"] = normalized
    prefix = normalized.replace(":", "")[:6]
    vendor = OFFLINE_OUI.get(prefix)

    if vendor:
        report["meta"]["source"] = "offline OUI table"
    elif online:
        info(f"Querying vendor for {normalized}...")
        try:
            response = http.get(f"https://api.macvendors.com/{normalized}", timeout=8)
            if response.status_code == 200 and response.text:
                vendor = response.text.strip()
                report["meta"]["source"] = "macvendors.com"
            elif response.status_code == 404:
                vendor = None
                report["meta"]["source"] = "macvendors.com (not found)"
            else:
                reportlib.add_error(report, f"vendor API returned {response.status_code}")
        except Exception as exc:
            reportlib.add_error(report, str(exc))

    reportlib.add_finding(
        report,
        mac=normalized,
        oui=prefix,
        vendor=vendor or "unresolved",
        local=bool(int(prefix[1], 16) & 0b10),
    )
    reportlib.finish(report, found=bool(vendor), vendor=vendor)
    return _present(report)


def _present(report: dict) -> dict:
    if is_quiet():
        return report
    findings = report.get("findings", [])
    if findings:
        table = Table(title="MAC Vendor Lookup", header_style="bold cyan")
        table.add_column("MAC", style="cyan")
        table.add_column("OUI", style="cyan")
        table.add_column("VENDOR", style="green")
        for finding in findings:
            table.add_row(finding["mac"], finding["oui"], str(finding["vendor"]))
        console.print(table)
    for error in report.get("errors", []):
        err(error)
    return report
