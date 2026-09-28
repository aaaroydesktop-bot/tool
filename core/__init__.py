"""NetScan core package: console, environment detection, helpers, reporting."""

TOOL_NAME = "NetScan"

#: Machine-readable version. This is what reports and JSON carry, so tooling can
#: compare it safely (no spaces, no edition names).
__version__ = "5.0"

#: Human-facing edition, shown in the banner, ``--version`` and the README.
EDITION = "Pro"

#: What users actually see: "5.0 Pro".
VERSION_LABEL = f"{__version__} {EDITION}"
