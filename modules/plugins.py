"""
Plugin system.

A plugin is any ``*.py`` file under ``plugins/`` that defines ``run()``.  The
module docstring becomes its description, and ``register()`` may return extra
metadata, so ``netscan plugins`` can list capabilities without guessing.
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import sys
import traceback

from rich.table import Table

from core import report as reportlib
from core.console import console, err, info, is_quiet, ok, warn

PLUGIN_DIR = "plugins"
PACKAGE = "plugins"


def _paths() -> list[str]:
    if not os.path.isdir(PLUGIN_DIR):
        return []
    return sorted(
        os.path.join(PLUGIN_DIR, name)
        for name in os.listdir(PLUGIN_DIR)
        if name.endswith(".py") and not name.startswith("_")
    )


def discover() -> list[dict]:
    """List plugin files with the metadata we can read statically."""
    found: list[dict] = []
    for path in _paths():
        name = os.path.basename(path)[:-3]
        description = ""
        has_run = False
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                source = handle.read()
            has_run = "def run(" in source
            parts = source.split('"""')
            if len(parts) >= 3:
                description = parts[1].strip().splitlines()[0][:100]
        except OSError:
            pass
        found.append({
            "name": name,
            "path": path,
            "description": description,
            "runnable": has_run,
            "size": os.path.getsize(path) if os.path.exists(path) else 0,
        })
    return found


def _import(name: str):
    """Import a plugin by file path so it also works outside the package."""
    try:
        return importlib.import_module(f"{PACKAGE}.{name}")
    except ImportError:
        path = os.path.join(PLUGIN_DIR, f"{name}.py")
        spec = importlib.util.spec_from_file_location(f"_netscan_plugin_{name}", path)
        if not spec or not spec.loader:
            raise ImportError(f"cannot load plugin {name}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module


def run(name: str, **kwargs) -> dict:
    """Execute a single plugin and capture what it returned."""
    report = reportlib.new_report("plugin", name)
    try:
        module = _import(name)
    except Exception as exc:
        reportlib.add_error(report, f"import failed: {exc}")
        reportlib.finish(report, ran=False)
        return report

    entry = getattr(module, "run", None)
    if not callable(entry):
        reportlib.add_error(report, "plugin has no run() function")
        reportlib.finish(report, ran=False)
        return report

    info(f"Running plugin '{name}'...")
    try:
        result = entry(**kwargs) if kwargs else entry()
        if result is not None:
            reportlib.add_finding(report, name=name, result=str(result)[:500])
    except TypeError:
        try:
            result = entry()
            if result is not None:
                reportlib.add_finding(report, name=name, result=str(result)[:500])
        except Exception as exc:
            reportlib.add_error(report, f"{type(exc).__name__}: {exc}")
            report["meta"]["traceback"] = traceback.format_exc()[-800:]
    except Exception as exc:
        reportlib.add_error(report, f"{type(exc).__name__}: {exc}")
        report["meta"]["traceback"] = traceback.format_exc()[-800:]

    reportlib.finish(report, ran=not report["errors"])
    return report


def run_all() -> list[dict]:
    return [run(plugin["name"]) for plugin in discover() if plugin["runnable"]]


def load_plugins(execute: bool = True) -> list[dict]:
    """Menu entry point: list plugins, then optionally run them all."""
    plugins = discover()

    if not is_quiet():
        table = Table(title=f"Plugins ({len(plugins)})", header_style="bold cyan")
        table.add_column("NAME", style="cyan")
        table.add_column("RUNNABLE", style="green")
        table.add_column("DESCRIPTION", overflow="fold")
        for plugin in plugins:
            table.add_row(
                plugin["name"],
                "yes" if plugin["runnable"] else "no",
                plugin["description"],
            )
        console.print(table)

    if not plugins:
        warn(f"No plugins found in {PLUGIN_DIR}/.")
        return []

    if not execute:
        return plugins

    from core.utils import ask

    if ask("Run all runnable plugins? (y/N)", default="n").strip().lower().startswith("y"):
        results = run_all()
        for result in results:
            if result["errors"]:
                err(f"{result['target']}: {'; '.join(result['errors'])}")
            else:
                ok(f"{result['target']} completed")
        return results

    return plugins
