from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, Field


@dataclass(frozen=True)
class IdaInstall:
    """A discovered IDA Pro install. `executable` is the headless binary
    (idat.exe on 9.3+, idat64.exe on 8.x / 9.0)."""

    root: Path
    version: tuple[int, int]
    executable: Path
    has_idalib: bool

    @property
    def plugins_dir(self) -> Path:
        return self.root / "plugins"

    @property
    def idalib_python_dir(self) -> Path | None:
        d = self.root / "idalib" / "python"
        return d if d.is_dir() else None


_IDA_DIR_RE = re.compile(r"^IDA(?:\s+(?:Pro|Professional))?\s+(\d+)\.(\d+)$", re.IGNORECASE)


def _resolve_executable(root: Path, version: tuple[int, int]) -> Path | None:
    # 9.3+ ships only `idat.exe` (32/64 split removed); 8.x / 9.0 ships
    # `idat64.exe`. Newer naming first so a stale alternate doesn't win.
    candidates = ["idat.exe", "idat64.exe"] if version >= (9, 3) else ["idat64.exe", "idat.exe"]
    for name in candidates:
        exe = root / name
        if exe.is_file():
            return exe
    return None


def _scan_program_files() -> list[IdaInstall]:
    """Discover IDA installs under common Windows locations."""
    roots: list[Path] = []
    for env in ("ProgramFiles", "ProgramFiles(x86)"):
        base = os.environ.get(env)
        if base:
            roots.append(Path(base))
    if not roots:
        roots.append(Path(r"C:\Program Files"))

    found: dict[Path, IdaInstall] = {}
    for base in roots:
        if not base.is_dir():
            continue
        for child in base.iterdir():
            if not child.is_dir():
                continue
            m = _IDA_DIR_RE.match(child.name)
            if not m:
                continue
            version = (int(m.group(1)), int(m.group(2)))
            exe = _resolve_executable(child, version)
            if exe is None:
                continue
            install = IdaInstall(
                root=child,
                version=version,
                executable=exe,
                has_idalib=(child / "idalib" / "python").is_dir(),
            )
            # Same-install duplicates from multiple ProgramFiles roots:
            # last write wins (paths are equal).
            found[child.resolve()] = install
    return list(found.values())


def _try_idalib_install() -> IdaInstall | None:
    """Derive an install from the activated `idapro` Python wrapper.

    `py-activate-idalib.py` records the IDA path; we read it back from
    the bundled config (path varies by wheel layout).
    """
    try:
        import idapro  # type: ignore[import-not-found]
    except Exception:
        return None
    pkg_dir = Path(idapro.__file__).resolve().parent
    candidates = [
        pkg_dir / "ida_install_dir.txt",
        pkg_dir / "config" / "ida_install_dir.txt",
    ]
    ida_root: Path | None = None
    for c in candidates:
        if c.is_file():
            try:
                ida_root = Path(c.read_text(encoding="utf-8").strip())
                break
            except OSError:
                continue
    # Fallback to env vars also set by py-activate-idalib.py.
    if ida_root is None:
        for env in ("IDADIR", "IDA_DIR", "IDA_INSTALL_DIR"):
            v = os.environ.get(env)
            if v:
                ida_root = Path(v)
                break
    if ida_root is None or not ida_root.is_dir():
        return None
    m = _IDA_DIR_RE.match(ida_root.name)
    if not m:
        # Default: idalib first shipped in 9.0.
        version = (9, 0)
    else:
        version = (int(m.group(1)), int(m.group(2)))
    exe = _resolve_executable(ida_root, version)
    if exe is None:
        return None
    return IdaInstall(
        root=ida_root,
        version=version,
        executable=exe,
        has_idalib=True,
    )


def discover_ida_installs() -> list[IdaInstall]:
    """Return all discovered IDA installs sorted newest-first."""
    by_root: dict[Path, IdaInstall] = {}
    for inst in _scan_program_files():
        by_root[inst.root.resolve()] = inst
    idalib_inst = _try_idalib_install()
    if idalib_inst is not None:
        # Upgrade has_idalib on a path the directory scan already found
        # — that scan can't tell whether `idapro` is wired up.
        key = idalib_inst.root.resolve()
        existing = by_root.get(key)
        if existing is not None and not existing.has_idalib:
            by_root[key] = IdaInstall(
                root=existing.root,
                version=existing.version,
                executable=existing.executable,
                has_idalib=True,
            )
        else:
            by_root.setdefault(key, idalib_inst)
    return sorted(by_root.values(), key=lambda i: i.version, reverse=True)


def select_ida_install(installs: list[IdaInstall]) -> IdaInstall | None:
    """Pick the newest install. Among same-version, prefer one with idalib."""
    if not installs:
        return None
    return sorted(installs, key=lambda i: (i.version, i.has_idalib), reverse=True)[0]


class ToolPaths(BaseModel):
    """External-tool paths. Override via env (TOOLS__<NAME>=...)."""

    seven_zip: Path = Field(default=Path("C:/Program Files/7-Zip/7z.exe"))
    # None → resolved at AppContext build via `discover_ida_installs()`
    # (newest wins). Explicit `TOOLS__IDA=...` still wins.
    ida: Path | None = Field(default=None)
    update_compression_dll: Path = Field(
        default=Path(__file__).resolve().parents[1] / "tools" / "_native" / "UpdateCompression.dll"
    )

    process_timeout_seconds: float = 60 * 30
    """Default subprocess timeout for IDA / BinDiff / 7-Zip jobs."""

    def exists(self, *, ida_exe: Path | None = None) -> dict[str, bool]:
        # Pass the resolved `ida_exe` since `self.ida` is None when the
        # user lets discovery pick it.
        ida = ida_exe or self.ida
        return {
            "seven_zip": self.seven_zip.is_file(),
            "ida": ida is not None and ida.is_file(),
            "update_compression_dll": self.update_compression_dll.is_file(),
            "ida_binexport_plugin": _ida_plugin_present(ida, "binexport"),
            "ida_bindiff_plugin": _ida_plugin_present(ida, "bindiff"),
        }


def _ida_plugin_present(ida_exe: Path | None, prefix: str) -> bool:
    # IDA loads `*_ida64.dll`; plugin version suffixes vary
    # (binexport12, bindiff8, …) so we glob.
    if ida_exe is None:
        return False
    plugins = ida_exe.parent / "plugins"
    if not plugins.is_dir():
        return False
    return any(plugins.glob(f"{prefix}*_ida64.dll"))
