"""
Scan history stored in SQLite.

The schema is migrated in place: older databases gain the new columns without
losing rows.
"""

from __future__ import annotations

import contextlib
import datetime
import json
import os
import sqlite3

from rich.table import Table

from core.console import console, err, is_quiet, warn

DB_DIR = "database"
DB_PATH = os.path.join(DB_DIR, "toolkit.db")

_COLUMNS = {
    "action": "TEXT",
    "target": "TEXT",
    "time": "TEXT",
    "summary": "TEXT",
    "result_json": "TEXT",
    "status": "TEXT",
}


@contextlib.contextmanager
def _connect():
    """Yield a connection that commits on success and always closes."""
    os.makedirs(DB_DIR, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def init_db() -> None:
    """Create the table and back-fill any missing columns."""
    with _connect() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT,
                target TEXT,
                time TEXT,
                summary TEXT,
                result_json TEXT,
                status TEXT
            )
            """
        )
        existing = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(history)").fetchall()
        }
        for column, kind in _COLUMNS.items():
            if column not in existing:
                connection.execute(f"ALTER TABLE history ADD COLUMN {column} {kind}")
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_history_time ON history(time DESC)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_history_action ON history(action)"
        )


def save_history(action: str, target: str, report: dict | None = None,
                 status: str = "ok") -> int:
    """Record an action.  ``report`` is stored as JSON when supplied."""
    try:
        init_db()
        payload = json.dumps(report, default=str) if report else None
        summary = None
        if report and report.get("summary"):
            summary = json.dumps(report["summary"], default=str)
        with _connect() as connection:
            cursor = connection.execute(
                "INSERT INTO history(action, target, time, summary, result_json, status)"
                " VALUES (?,?,?,?,?,?)",
                (
                    action,
                    target,
                    datetime.datetime.now().isoformat(timespec="seconds"),
                    summary,
                    payload,
                    status,
                ),
            )
            return int(cursor.lastrowid)
    except sqlite3.Error as exc:
        err(f"could not write history: {exc}")
        return 0


def records(limit: int = 20, action: str | None = None) -> list[dict]:
    """Most recent entries, newest first."""
    try:
        init_db()
        query = "SELECT id, action, target, time, status, summary FROM history"
        params: list = []
        if action:
            query += " WHERE action = ?"
            params.append(action)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with _connect() as connection:
            return [dict(row) for row in connection.execute(query, params).fetchall()]
    except sqlite3.Error as exc:
        err(f"could not read history: {exc}")
        return []


def load_result(entry_id: int) -> dict | None:
    """Re-read the full stored report for an entry."""
    try:
        init_db()
        with _connect() as connection:
            row = connection.execute(
                "SELECT result_json FROM history WHERE id = ?", (entry_id,)
            ).fetchone()
    except sqlite3.Error:
        return None
    if not row or not row["result_json"]:
        return None
    try:
        return json.loads(row["result_json"])
    except ValueError:
        return None


def stats() -> dict:
    """Counts per action, for the doctor/dashboard view."""
    try:
        init_db()
        with _connect() as connection:
            rows = connection.execute(
                "SELECT action, COUNT(*) AS n FROM history GROUP BY action ORDER BY n DESC"
            ).fetchall()
            total = connection.execute("SELECT COUNT(*) AS n FROM history").fetchone()["n"]
            earliest = connection.execute("SELECT MIN(time) AS t FROM history").fetchone()["t"]
    except sqlite3.Error as exc:
        err(f"could not read stats: {exc}")
        return {}
    return {
        "total": total,
        "first_scan": earliest,
        "by_action": {row["action"]: row["n"] for row in rows},
    }


def clear() -> int:
    """Delete everything.  Returns the number of rows removed."""
    try:
        init_db()
        with _connect() as connection:
            count = connection.execute("SELECT COUNT(*) AS n FROM history").fetchone()["n"]
            connection.execute("DELETE FROM history")
            return int(count)
    except sqlite3.Error as exc:
        err(f"could not clear history: {exc}")
        return 0


def show_history(limit: int = 20) -> list[dict]:
    """Print the history table; returns the rows for programmatic use."""
    rows = records(limit)
    if is_quiet():
        return rows
    if not rows:
        warn("History is empty.")
        return rows

    table = Table(title=f"Scan History (last {len(rows)})", header_style="bold cyan")
    table.add_column("ID", style="dim", justify="right")
    table.add_column("WHEN", style="cyan")
    table.add_column("ACTION", style="green")
    table.add_column("TARGET", style="yellow")
    table.add_column("SUMMARY", style="white", overflow="fold")
    for row in rows:
        table.add_row(
            str(row["id"]), row["time"] or "", row["action"] or "",
            row["target"] or "", row["summary"] or "",
        )
    console.print(table)
    return rows
