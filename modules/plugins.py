import os
import importlib

from rich.console import Console

console = Console()

def load_plugins():
    plugin_dir = "plugins"

    for file in os.listdir(plugin_dir):

        if file.endswith(".py"):

            name = file[:-3]

            module = importlib.import_module(
                f"plugins.{name}"
            )

            if hasattr(module, "run"):
                console.print(
                    f"[green]Loaded:[/green] {name}"
                )

                module.run()