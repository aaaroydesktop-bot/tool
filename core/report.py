"""
Report building and rendering.

A *report* is a plain dict, so it can be dumped as JSON and re-read later.  The
renderers are generic: they build columns from the finding keys actually
present, so any module can add new findings without touching this file.
"""

from __future__ import annotations

import csv
import datetime
import html
import io
import json
import os
import re

from . import EDITION, TOOL_NAME, __version__

DEFAULT_DIR = "reports"
FORMATS = ("json", "md", "html", "csv", "txt")

_SLUG_RE = re.compile(r"[^A-Za-z0-9._-]+")


# --------------------------------------------------------------------------
# BUILDING
# --------------------------------------------------------------------------


def new_report(kind: str, target: str, **meta) -> dict:
    """Start a report.  ``kind`` is a short label such as ``port_scan``."""
    return {
        "tool": TOOL_NAME,
        "version": __version__,
        "edition": EDITION,
        "kind": kind,
        "target": target,
        "started": datetime.datetime.now().isoformat(timespec="seconds"),
        "duration": None,
        "summary": {},
        "findings": [],
        "errors": [],
        "meta": dict(meta),
    }


def add_finding(report: dict, **finding) -> dict:
    report["findings"].append(dict(finding))
    return report["findings"][-1]


def add_error(report: dict, message) -> None:
    report["errors"].append(str(message))


def finish(report: dict, duration: float | None = None, **summary) -> dict:
    if duration is not None:
        report["duration"] = round(float(duration), 3)
    report["summary"].update(summary)
    report["finished"] = datetime.datetime.now().isoformat(timespec="seconds")
    return report


# --------------------------------------------------------------------------
# RENDERING
# --------------------------------------------------------------------------


def _columns(findings: list[dict]) -> list[str]:
    columns: list[str] = []
    for finding in findings:
        for key in finding:
            if key not in columns:
                columns.append(key)
    return columns


def render_json(report: dict) -> str:
    return json.dumps(report, indent=2, default=str)


def render_csv(report: dict) -> str:
    buffer = io.StringIO()
    columns = _columns(report.get("findings") or [])
    writer = csv.DictWriter(buffer, fieldnames=columns or ["result"], extrasaction="ignore")
    writer.writeheader()
    for finding in report.get("findings") or []:
        writer.writerow({key: finding.get(key, "") for key in columns})
    return buffer.getvalue()


def render_markdown(report: dict) -> str:
    lines = [
        f"# {TOOL_NAME} report - `{report.get('kind')}`",
        "",
        f"- **Target:** `{report.get('target')}`",
        f"- **Started:** {report.get('started')}",
        f"- **Duration:** {report.get('duration', 'n/a')} s",
        f"- **Version:** {report.get('version')}",
        "",
    ]

    if report.get("summary"):
        lines += ["## Summary", "", "| Key | Value |", "| --- | --- |"]
        for key, value in report["summary"].items():
            lines.append(f"| {key} | {value} |")
        lines.append("")

    if report.get("meta"):
        lines += ["## Context", "", "| Key | Value |", "| --- | --- |"]
        for key, value in report["meta"].items():
            lines.append(f"| {key} | {value} |")
        lines.append("")

    findings = report.get("findings") or []
    columns = _columns(findings)
    if columns:
        lines += ["## Findings", "", "| " + " | ".join(columns) + " |"]
        lines.append("| " + " | ".join("---" for _ in columns) + " |")
        for finding in findings:
            row = [str(finding.get(column, "")) for column in columns]
            lines.append("| " + " | ".join(row) + " |")
        lines.append("")

    if report.get("errors"):
        lines += ["## Errors", ""]
        lines += [f"- {error}" for error in report["errors"]]
        lines.append("")

    return "\n".join(lines)


def render_html(report: dict) -> str:
    findings = report.get("findings") or []
    columns = _columns(findings)

    def table(rows: list[dict], cols: list[str]) -> str:
        if not cols:
            return "<p class='muted'>Nothing to show.</p>"
        head = "".join(f"<th>{html.escape(str(c))}</th>" for c in cols)
        body = []
        for row in rows:
            cells = "".join(
                f"<td>{html.escape(str(row.get(c, '')))}</td>" for c in cols
            )
            body.append(f"<tr>{cells}</tr>")
        return (
            f"<table><thead><tr>{head}</tr></thead>"
            f"<tbody>{''.join(body)}</tbody></table>"
        )

    summary_rows = [{"key": k, "value": v} for k, v in report.get("summary", {}).items()]
    meta_rows = [{"key": k, "value": v} for k, v in report.get("meta", {}).items()]

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{TOOL_NAME} - {html.escape(str(report.get('kind')))}</title>
<style>
 :root {{ color-scheme: dark; }}
 body {{ background:#0b0f14; color:#c9d6e2; font:15px/1.5 ui-monospace,Menlo,Consolas,monospace; margin:0; padding:24px; }}
 h1,h2 {{ color:#22d3ee; }}
 h1 {{ font-size:20px; margin:0 0 4px; }}
 .sub {{ color:#7b8a9b; margin-bottom:20px; }}
 table {{ border-collapse:collapse; width:100%; margin:8px 0 20px; }}
 th,td {{ border:1px solid #1e2a36; padding:6px 10px; text-align:left; }}
 th {{ background:#111a23; color:#7dd3fc; }}
 tr:nth-child(even) td {{ background:#0e141b; }}
 code {{ color:#fbbf24; }}
 .muted {{ color:#7b8a9b; }}
 .err {{ color:#f87171; }}
</style>
</head>
<body>
<h1>{TOOL_NAME} - {html.escape(str(report.get('kind')))}</h1>
<div class="sub">
  target <code>{html.escape(str(report.get('target')))}</code> &middot;
  {html.escape(str(report.get('started')))} &middot;
  {html.escape(str(report.get('duration', 'n/a')))}s &middot;
  v{html.escape(str(report.get('version')))}
</div>
<h2>Summary</h2>
{table(summary_rows, ['key', 'value'])}
<h2>Context</h2>
{table(meta_rows, ['key', 'value'])}
<h2>Findings ({len(findings)})</h2>
{table(findings, columns)}
<h2>Errors</h2>
{'<p class="err">' + '<br>'.join(html.escape(str(e)) for e in report.get('errors', [])) + '</p>' if report.get('errors') else '<p class="muted">None.</p>'}
</body>
</html>
"""


def render_txt(report: dict) -> str:
    """Plain text with uniform ``key=value`` lines, so it stays greppable."""
    lines = [
        f"{TOOL_NAME} | {report.get('kind')} | target={report.get('target')}",
        f"started={report.get('started')} duration={report.get('duration', 'n/a')}s",
    ]
    for key, value in {**report.get("summary", {}), **report.get("meta", {})}.items():
        lines.append(f"{key}={value}")
    findings = report.get("findings") or []
    columns = _columns(findings)
    if columns:
        lines.append("")
        for finding in findings:
            lines.append(
                " | ".join(f"{column}={finding.get(column, '')}" for column in columns)
            )
    if report.get("errors"):
        lines.append("")
        lines += [f"error: {error}" for error in report["errors"]]
    return "\n".join(lines)


_RENDERERS = {
    "json": render_json,
    "md": render_markdown,
    "markdown": render_markdown,
    "html": render_html,
    "csv": render_csv,
    "txt": render_txt,
    "text": render_txt,
}


def render(report: dict, fmt: str = "json") -> str:
    try:
        renderer = _RENDERERS[fmt.lower().lstrip(".")]
    except KeyError:
        raise ValueError(f"unsupported format: {fmt!r} (try: {', '.join(FORMATS)})")
    return renderer(report)


# --------------------------------------------------------------------------
# WRITING
# --------------------------------------------------------------------------


def slug(value: str, fallback: str = "scan") -> str:
    cleaned = _SLUG_RE.sub("_", str(value or "")).strip("._-")
    return cleaned[:60] or fallback


def default_path(report: dict, fmt: str, directory: str = DEFAULT_DIR) -> str:
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    name = f"{slug(report.get('kind'))}_{slug(report.get('target'))}_{stamp}.{fmt}"
    return os.path.join(directory, name)


def write(report: dict, fmt: str = "json", path: str | None = None,
          directory: str = DEFAULT_DIR) -> str:
    """Write ``report`` to disk and return the absolute path written."""
    fmt = fmt.lower().lstrip(".")
    target_path = path or default_path(report, fmt, directory)
    parent = os.path.dirname(os.path.abspath(target_path))
    os.makedirs(parent, exist_ok=True)
    # newline="" keeps line endings exactly as rendered: it stops Windows from
    # turning the csv module's CRLF into CRCRLF.
    with open(target_path, "w", encoding="utf-8", newline="") as handle:
        handle.write(render(report, fmt))
    return os.path.abspath(target_path)


def latest(directory: str = DEFAULT_DIR, limit: int = 10) -> list[str]:
    """Most recent report files, newest first."""
    if not os.path.isdir(directory):
        return []
    files = [
        os.path.join(directory, name)
        for name in os.listdir(directory)
        if os.path.isfile(os.path.join(directory, name))
    ]
    files.sort(key=os.path.getmtime, reverse=True)
    return files[:limit]


def load(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)
