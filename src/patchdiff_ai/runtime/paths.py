"""Project-root-relative paths for bundled resources.

`Path(__file__).parents[N]` math is brittle when the same chain is repeated
in multiple modules — they drift apart silently when files move. Every
project-root-relative location lives here.
"""

from __future__ import annotations

from pathlib import Path

# `runtime/paths.py` is at <root>/src/patchdiff_ai/runtime/paths.py — three
# parents up = src/, four = <root>.
PROJECT_ROOT = Path(__file__).resolve().parents[3]

# Bundled BinDiff binary + IDA plugin DLLs (binexport12_ida64.dll,
# bindiff8_ida64.dll, bindiff.exe). Wired into the BINDIFF_PATH env at
# `AppContext.build()` so python-bindiff finds the binary; copied into IDA's
# plugins dir by `patchdiff-ai install ida-plugins`.
BUNDLED_BINDIFF_DIR = PROJECT_ROOT / "resources" / "bindiff_ida_9.3"
