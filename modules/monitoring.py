"""
Device telemetry.

Everything is read from ``/proc`` or ``/sys`` where possible so the module works
on a stock Termux install with no extra packages; ``psutil`` and ``termux-api``
are used only as optional upgrades.
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
import time

from rich.live import Live
from rich.table import Table

from core import report as reportlib
from core.console import console, info, is_quiet, warn
from core.environment import have, is_termux, summary_line
from core.netutil import human_bytes, human_duration
from core.utils import strip_ansi

_CPU_TICKS: tuple[int, int] | None = None


# --------------------------------------------------------------------------
# PRIMITIVES
# --------------------------------------------------------------------------


def _meminfo() -> dict[str, int]:
    values: dict[str, int] = {}
    try:
        with open("/proc/meminfo", "r", errors="ignore") as handle:
            for line in handle:
                key, _, rest = line.partition(":")
                parts = rest.strip().split()
                if parts and parts[0].isdigit():
                    values[key.strip()] = int(parts[0]) * 1024  # kB -> bytes
    except OSError:
        pass
    return values


def memory() -> dict:
    """RAM usage in bytes and percent."""
    info_map = _meminfo()
    if info_map:
        total = info_map.get("MemTotal", 0)
        available = info_map.get("MemAvailable", info_map.get("MemFree", 0))
        swap_total = info_map.get("SwapTotal", 0)
        swap_free = info_map.get("SwapFree", 0)
        used = max(total - available, 0)
        return {
            "total": total,
            "available": available,
            "used": used,
            "percent": round(used / total * 100, 1) if total else 0.0,
            "swap_total": swap_total,
            "swap_used": max(swap_total - swap_free, 0),
        }

    try:  # last resort
        import psutil

        vm = psutil.virtual_memory()
        return {
            "total": vm.total, "available": vm.available, "used": vm.used,
            "percent": round(vm.percent, 1),
            "swap_total": getattr(vm, "swap_total", 0),
            "swap_used": getattr(vm, "swap_used", 0),
        }
    except Exception:
        return {"total": 0, "available": 0, "used": 0, "percent": 0.0,
                "swap_total": 0, "swap_used": 0}


def cpu_percent(interval: float = 0.0) -> float:
    """
    CPU busy percentage.

    ``/proc/stat`` gives an accurate *delta*; load average is the fallback and
    is smoothed, so it is only used when stat is unreadable.
    """
    global _CPU_TICKS
    try:
        with open("/proc/stat", "r", errors="ignore") as handle:
            first = handle.readline().split()
        numbers = [int(value) for value in first[1:]]
        idle = numbers[3] + (numbers[4] if len(numbers) > 4 else 0)
        total = sum(numbers)

        if _CPU_TICKS is None or interval <= 0:
            _CPU_TICKS = (total, idle)
            if interval <= 0:
                # Prime and return a load-average estimate for the first call.
                return _load_average_percent()

        last_total, last_idle = _CPU_TICKS
        total_delta = total - last_total
        idle_delta = idle - last_idle
        _CPU_TICKS = (total, idle)
        if total_delta <= 0:
            return _load_average_percent()
        return round((1 - idle_delta / total_delta) * 100, 1)
    except (OSError, ValueError, IndexError):
        return _load_average_percent()


def _load_average_percent() -> float:
    try:
        load = os.getloadavg()[0]
        cores = os.cpu_count() or 1
        return round(min(load / cores * 100, 100.0), 1)
    except (OSError, AttributeError):
        try:
            import psutil

            return round(psutil.cpu_percent(), 1)
        except Exception:
            return 0.0


def temperature() -> float | None:
    """SoC temperature in Celsius, when the kernel exposes it."""
    candidates = [
        "/sys/class/thermal/thermal_zone0/temp",
        "/sys/class/hwmon/hwmon0/temp1_input",
    ]
    for path in candidates:
        try:
            with open(path, "r", errors="ignore") as handle:
                raw = int(handle.read().strip())
            return round(raw / 1000, 1) if raw > 1000 else float(raw)
        except (OSError, ValueError):
            continue
    return None


def uptime() -> float | None:
    try:
        with open("/proc/uptime", "r", errors="ignore") as handle:
            return float(handle.read().split()[0])
    except (OSError, ValueError, IndexError):
        return None


def storage(path: str = ".") -> dict:
    try:
        usage = os.statvfs(path)
    except OSError:
        return {}
    total = usage.f_blocks * usage.f_frsize
    free = usage.f_bavail * usage.f_frsize
    return {
        "total": total,
        "free": free,
        "used": total - free,
        "percent": round((total - free) / total * 100, 1) if total else 0.0,
    }


def battery() -> dict:
    """Battery telemetry, preferring termux-api over sysfs."""
    if have("termux-battery-status"):
        try:
            raw = subprocess.run(
                ["termux-battery-status"], capture_output=True, text=True, timeout=8
            ).stdout
            data = json.loads(raw or "{}")
            return {
                "percent": data.get("percentage"),
                "status": data.get("status"),
                "temperature": data.get("temperature"),
                "health": data.get("health"),
                "source": "termux-api",
            }
        except Exception:
            pass

    for base in ("/sys/class/power_supply/battery", "/sys/class/power_supply/BAT0"):
        try:
            with open(os.path.join(base, "capacity")) as handle:
                percent = int(handle.read().strip())
            voltage = None
            try:
                with open(os.path.join(base, "voltage_now")) as handle:
                    voltage = int(handle.read().strip()) / 1_000_000
            except (OSError, ValueError):
                pass
            return {"percent": percent, "voltage": voltage, "source": "sysfs"}
        except (OSError, ValueError):
            continue
    return {}


def load() -> dict:
    try:
        one, five, fifteen = os.getloadavg()
    except (OSError, AttributeError):
        return {}
    return {"1m": round(one, 2), "5m": round(five, 2), "15m": round(fifteen, 2)}


# --------------------------------------------------------------------------
# SNAPSHOT / REPORT
# --------------------------------------------------------------------------


def snapshot() -> dict:
    """One-shot telemetry dictionary."""
    return {
        "cpu_percent": cpu_percent(),
        "cores": os.cpu_count(),
        "memory": memory(),
        "storage": storage(),
        "temperature": temperature(),
        "uptime": uptime(),
        "load": load(),
        "battery": battery(),
        "platform": platform.platform(),
        "termux": is_termux(),
    }


def system_info() -> dict:
    """Report-shaped system information."""
    data = snapshot()
    report = reportlib.new_report("sysinfo", platform.node() or "device", **{
        "environment": summary_line(),
    })
    reportlib.add_finding(report, metric="cpu_percent", value=data["cpu_percent"])
    reportlib.add_finding(report, metric="cpu_cores", value=data["cores"])
    reportlib.add_finding(report, metric="memory_percent", value=data["memory"]["percent"])
    reportlib.add_finding(report, metric="memory_used", value=human_bytes(data["memory"]["used"]))
    reportlib.add_finding(report, metric="memory_total", value=human_bytes(data["memory"]["total"]))
    if data["storage"]:
        reportlib.add_finding(report, metric="storage_percent", value=data["storage"]["percent"])
        reportlib.add_finding(report, metric="storage_free", value=human_bytes(data["storage"]["free"]))
    if data["temperature"] is not None:
        reportlib.add_finding(report, metric="temperature_c", value=data["temperature"])
    if data["uptime"] is not None:
        reportlib.add_finding(report, metric="uptime", value=human_duration(data["uptime"]))
    for key, value in data["load"].items():
        reportlib.add_finding(report, metric=f"load_{key}", value=value)
    if data["battery"]:
        for key, value in data["battery"].items():
            reportlib.add_finding(report, metric=f"battery_{key}", value=value)
    reportlib.finish(report, **{k: v for k, v in data.items() if not isinstance(v, dict)})
    return report


def render(data: dict | None = None) -> Table:
    data = data or snapshot()
    table = Table(title="System Monitor", header_style="bold cyan")
    table.add_column("METRIC", style="cyan")
    table.add_column("VALUE", style="green")
    table.add_row("CPU", f"{data['cpu_percent']}% ({data['cores']} cores)")
    table.add_row(
        "RAM",
        f"{data['memory']['percent']}% - "
        f"{human_bytes(data['memory']['used'])} / {human_bytes(data['memory']['total'])}",
    )
    if data["storage"]:
        table.add_row(
            "Storage",
            f"{data['storage']['percent']}% - {human_bytes(data['storage']['free'])} free",
        )
    if data["temperature"] is not None:
        table.add_row("Temperature", f"{data['temperature']} C")
    if data["uptime"] is not None:
        table.add_row("Uptime", human_duration(data["uptime"]))
    if data["load"]:
        table.add_row(
            "Load", " ".join(f"{k}={v}" for k, v in data["load"].items())
        )
    if data["battery"]:
        table.add_row(
            "Battery",
            f"{data['battery'].get('percent', '?')}% {data['battery'].get('status', '')}".strip(),
        )
    table.add_row("Platform", strip_ansi(data["platform"]))
    return table


def system_monitor(interval: float = 1.0, duration: float | None = None) -> dict:
    """Live dashboard until Ctrl+C (or ``duration`` seconds)."""
    if is_quiet():
        return system_info()

    info("Live monitor running - press Ctrl+C to stop.")
    started = time.time()
    try:
        with Live(refresh_per_second=max(1, int(1 / max(interval, 0.2))), screen=False) as live:
            while True:
                live.update(render())
                if duration and time.time() - started >= duration:
                    break
                time.sleep(interval)
    except KeyboardInterrupt:
        warn("Monitor stopped.")
    return system_info()
