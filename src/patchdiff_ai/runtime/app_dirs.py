"""Per-user app data directory.

All generated artifacts (Chroma DB, reports, logs, _temp, windows_sxs,
config.json) live under one root so the tool behaves identically
regardless of which CWD the user invoked it from. Resolution order:

1. ``$PATCHDIFF_AI_HOME`` — escape hatch for tests / CI / sandbox runs.
2. ``%APPDATA%/patchdiff-ai`` on Windows.
3. ``~/.local/share/patchdiff-ai`` everywhere else (XDG-style fallback).

Returns the resolved Path. Does **not** mkdir — callers do that
explicitly so the path is still safe to compute when no I/O is wanted
(e.g. printing the resolved location in `--help`).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

APP_NAME = "patchdiff-ai"

ENV_VAR = "PATCHDIFF_AI_HOME"


def app_data_root() -> Path:
    override = os.environ.get(ENV_VAR)
    if override:
        return Path(override).expanduser()
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / APP_NAME
        return Path.home() / "AppData" / "Roaming" / APP_NAME
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg) / APP_NAME
    return Path.home() / ".local" / "share" / APP_NAME


def config_json_path() -> Path:
    """Canonical location of `config.json` (does not check for existence)."""
    return app_data_root() / "config.json"
