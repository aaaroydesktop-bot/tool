"""
Bandwidth test.

Streams from a public endpoint and reports latency plus throughput in Mbps.
Upload is opt-in because mobile data plans are metered.
"""

from __future__ import annotations

import os
import time

from rich.progress import Progress
from rich.table import Table

from core import http
from core import report as reportlib
from core.console import console, err, info, is_quiet
from core.netutil import human_bitrate, human_bytes, human_duration

DOWNLOAD_SOURCES = [
    ("Cloudflare", "https://speed.cloudflare.com/__down?bytes={bytes}"),
    ("OVH", "https://proof.ovh.net/files/10Mb.dat"),
]

UPLOAD_URL = "https://speed.cloudflare.com/__up"

LATENCY_URL = "https://speed.cloudflare.com/__down?bytes=1000"


def measure_latency(samples: int = 5, timeout: float = 10) -> dict:
    """Average latency to the speed endpoint, in milliseconds."""
    times: list[float] = []
    for _ in range(max(1, samples)):
        started = time.time()
        try:
            http.get(LATENCY_URL, timeout=timeout)
        except Exception:
            continue
        times.append((time.time() - started) * 1000)

    if not times:
        return {"latency_ms": None, "jitter_ms": None}

    jitter = None
    if len(times) > 1:
        jitter = round(
            sum(abs(b - a) for a, b in zip(times, times[1:])) / (len(times) - 1), 2
        )
    return {
        "latency_ms": round(sum(times) / len(times), 2),
        "jitter_ms": jitter,
    }


def measure_download(size_mb: float = 10, timeout: float = 60,
                     show_progress: bool = True) -> dict:
    """Stream ``size_mb`` megabytes and compute throughput."""
    size_bytes = int(size_mb * 1024 * 1024)
    last_error = None

    for name, template in DOWNLOAD_SOURCES:
        url = template.format(bytes=size_bytes) if "{bytes}" in template else template
        try:
            started = time.time()
            response = http.get(url, timeout=timeout, stream=True, verify=False)
            if response.status_code >= 400:
                last_error = f"{name}: HTTP {response.status_code}"
                continue

            total = int(response.headers.get("content-length", 0) or 0)
            downloaded = 0
            milestone = time.time()

            tracker = None
            task = None
            progress = None
            if show_progress and not is_quiet():
                progress = Progress()
                progress.start()
                task = progress.add_task(f"[green]Downloading via {name}...", total=total or None)
                tracker = progress

            try:
                for chunk in response.iter_content(64 * 1024):
                    if not chunk:
                        continue
                    downloaded += len(chunk)
                    if tracker and total:
                        tracker.update(task, completed=downloaded)
            finally:
                if progress:
                    progress.stop()

            elapsed = time.time() - started
            if downloaded == 0 or elapsed <= 0:
                last_error = f"{name}: no data received"
                continue

            # Discard the slow start-up tail: real-world tests warm up first.
            return {
                "source": name,
                "bytes": downloaded,
                "seconds": round(elapsed, 2),
                "mbps": round((downloaded * 8) / elapsed / 1_000_000, 2),
                "size_human": human_bytes(downloaded),
                "time_human": human_duration(elapsed),
            }
        except Exception as exc:
            last_error = f"{name}: {exc}"
            continue

    return {"error": last_error or "all download sources failed"}


def measure_upload(size_kb: int = 2048, timeout: float = 60) -> dict:
    """POST random bytes and compute throughput."""
    payload = os.urandom(size_kb * 1024)
    try:
        started = time.time()
        response = http.session().post(
            UPLOAD_URL, data=payload, timeout=timeout, verify=False
        )
        elapsed = time.time() - started
        if response.status_code >= 400:
            return {"error": f"HTTP {response.status_code}"}
        return {
            "bytes": len(payload),
            "seconds": round(elapsed, 2),
            "mbps": round((len(payload) * 8) / max(elapsed, 1e-6) / 1_000_000, 2),
            "size_human": human_bytes(len(payload)),
        }
    except Exception as exc:
        return {"error": str(exc)}


def speed_test(size_mb: float = 10, upload: bool = False, timeout: float = 60) -> dict:
    """Full speed test, returned as a report dict."""
    report = reportlib.new_report("speed_test", "internet", size_mb=size_mb)
    info(f"Running speed test ({size_mb} MB download)...")

    latency = measure_latency()
    report["meta"]["latency_ms"] = latency["latency_ms"]
    report["meta"]["jitter_ms"] = latency["jitter_ms"]

    download = measure_download(size_mb, timeout=timeout)
    if download.get("error"):
        reportlib.add_error(report, download["error"])

    for key, value in download.items():
        if key != "error":
            reportlib.add_finding(report, metric=f"download_{key}", value=value)

    upload_result = None
    if upload:
        info("Measuring upload...")
        upload_result = measure_upload()
        if upload_result.get("error"):
            reportlib.add_error(report, f"upload: {upload_result['error']}")
        for key, value in upload_result.items():
            if key != "error":
                reportlib.add_finding(report, metric=f"upload_{key}", value=value)

    reportlib.finish(
        report,
        reachable=not download.get("error"),
        download_mbps=download.get("mbps"),
        upload_mbps=(upload_result or {}).get("mbps"),
        latency_ms=latency["latency_ms"],
        jitter_ms=latency["jitter_ms"],
        source=download.get("source"),
    )
    return _present(report)


def _present(report: dict) -> dict:
    if is_quiet():
        return report
    summary = report.get("summary", {})
    table = Table(title="Internet Speed Test", header_style="bold cyan")
    table.add_column("METRIC", style="cyan")
    table.add_column("VALUE", style="green")
    table.add_row("Latency", "n/a" if summary.get("latency_ms") is None
                  else f"{summary['latency_ms']} ms")
    table.add_row("Jitter", "n/a" if summary.get("jitter_ms") is None
                  else f"{summary['jitter_ms']} ms")
    table.add_row("Download", human_bitrate(summary.get("download_mbps")))
    if summary.get("upload_mbps") is not None:
        table.add_row("Upload", human_bitrate(summary["upload_mbps"]))
    table.add_row("Source", str(summary.get("source") or "n/a"))
    console.print(table)

    for error in report.get("errors", []):
        err(error)
    return report
