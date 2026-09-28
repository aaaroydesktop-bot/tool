"""
Report output.

All rendering lives in :mod:`core.report`; this module keeps the historical
``save_report`` helper working while exposing the newer API for callers that
want a specific format.
"""

from __future__ import annotations

from core.report import (  # noqa: F401  (re-exported)
    DEFAULT_DIR,
    FORMATS,
    add_error,
    add_finding,
    finish,
    latest,
    load,
    new_report,
    render,
    slug,
    write,
)

__all__ = [
    "DEFAULT_DIR", "FORMATS", "add_error", "add_finding", "finish", "latest",
    "load", "new_report", "render", "save_report", "write",
]


def save_report(data: dict, filename: str = "reports/report.json") -> str:
    """Write ``data`` to ``filename``; format follows the file extension."""
    fmt = filename.rsplit(".", 1)[-1].lower() if "." in filename else "json"
    if fmt not in FORMATS:
        fmt = "json"
    return write(data, fmt=fmt, path=filename)
