"""Paths for bundled resources.

`Path(__file__).parents[N]` math is brittle when the same chain is repeated
in multiple modules — they drift apart silently when files move. Every
bundled-resource location lives here.

Two layouts are supported:

* **Wheel install** (`pip install patchdiff-ai` / `pip install git+...`):
  hatchling's `force-include` projects `resources/bindiff_ida_9.3/` into
  `<package>/_resources/bindiff_ida_9.3/` so the DLLs travel with the
  wheel.
* **Editable install** (`pip install -e .`) and direct source-tree runs:
  no projection happens; the package points back at the original
  `<repo>/resources/bindiff_ida_9.3/`.

`_resolve_bundled_bindiff_dir()` checks both at import time. The
`PROJECT_ROOT` constant only makes sense in the source-tree layout and is
kept for that case; callers should treat it as "may not exist" under
wheel installs.
"""

from __future__ import annotations

from pathlib import Path

# `runtime/paths.py` lives at <package>/runtime/paths.py.
_PACKAGE_ROOT = Path(__file__).resolve().parent.parent

# Best-effort source-tree root: <repo>/src/patchdiff_ai/runtime/paths.py
# → parents[3] = <repo>. Under a wheel install this path points
# somewhere inside site-packages and means nothing; callers must not
# assume it exists.
PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _resolve_bundled_bindiff_dir() -> Path:
    """Locate `bindiff_ida_9.3/` for both wheel and source-tree installs.

    Wheel layout (`force-include` in `pyproject.toml`) wins when present;
    otherwise fall back to the dev layout under the repo's `resources/`.
    Returns a path that may not exist (caller checks `is_dir()`) — this
    function does not validate, only resolves.
    """
    inside_pkg = _PACKAGE_ROOT / "_resources" / "bindiff_ida_9.3"
    if inside_pkg.is_dir():
        return inside_pkg
    return PROJECT_ROOT / "resources" / "bindiff_ida_9.3"


def _resolve_bundled_update_compression() -> Path:
    """Locate ``UpdateCompression.dll`` for both wheel and source-tree installs.

    Same wheel/source dual-layout logic as the BinDiff resolver — picks
    the projected copy under ``<package>/_resources/`` when present,
    otherwise the dev tree under ``<repo>/resources/``. Returns a path
    that may not exist; the runtime falls back to KB-bundled
    ``UpdateCompression.dll`` copies at delta-apply time anyway.
    """
    inside_pkg = _PACKAGE_ROOT / "_resources" / "UpdateCompression.dll"
    if inside_pkg.is_file():
        return inside_pkg
    return PROJECT_ROOT / "resources" / "UpdateCompression.dll"


# Bundled BinDiff binary + IDA plugin DLLs (binexport12_ida64.dll,
# bindiff8_ida64.dll, bindiff.exe). Wired into the BINDIFF_PATH env at
# `AppContext.build()` so python-bindiff finds the binary; copied into IDA's
# plugins dir by `patchdiff-ai install ida-plugins`.
BUNDLED_BINDIFF_DIR = _resolve_bundled_bindiff_dir()

# Bundled `UpdateCompression.dll`. Default ``settings.tools.update_compression_dll``
# resolves to this; per-KB copies extracted from `DesktopDeployment.cab` are
# loaded on top at runtime, latest-wins.
BUNDLED_UPDATE_COMPRESSION_DLL = _resolve_bundled_update_compression()
