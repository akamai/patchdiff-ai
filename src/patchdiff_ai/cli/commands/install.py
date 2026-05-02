"""`patchdiff-ai install <subject>` — bootstrap external IDA assets.

Two subjects:

* `idalib` — locates the bundled `idapro-*-py3-none-any.whl` inside the
  resolved IDA install's `idalib/python/` folder and pip-installs it into
  the current environment. Then runs `py-activate-idalib.py` so the package
  knows where its IDA Pro is. Without this, the new MCP-backed RE agent and
  the chat MCP tools fall back to the legacy subprocess path.

* `ida-plugins` — copies the bundled BinDiff / BinExport DLLs from
  `resources/bindiff_ida_9.3/` into the resolved IDA install's `plugins/`
  folder. Idempotent: same-content copies are skipped.

Both default to acting on the *newest* discovered IDA install. Pass
`--ida-root <path>` to target a specific one.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from hashlib import sha256
from pathlib import Path

import typer

from patchdiff_ai.config.tools import (
    IdaInstall,
    discover_ida_installs,
    select_ida_install,
)
from patchdiff_ai.runtime.paths import BUNDLED_BINDIFF_DIR

app = typer.Typer(no_args_is_help=True)


_PLUGIN_FILES = ("bindiff8_ida64.dll", "binexport12_ida64.dll")


def _resolve_target(ida_root: Path | None) -> IdaInstall:
    if ida_root is not None:
        for inst in discover_ida_installs():
            if inst.root.resolve() == ida_root.resolve():
                return inst
        raise typer.BadParameter(
            f"{ida_root} is not a recognised IDA install (no idat.exe / idat64.exe found)."
        )
    inst = select_ida_install(discover_ida_installs())
    if inst is None:
        raise typer.BadParameter(
            "No IDA install found. Pass --ida-root or set TOOLS__IDA in .env."
        )
    return inst


@app.command("idalib")
def install_idalib(
    ida_root: Path = typer.Option(
        None,
        "--ida-root",
        help="Target IDA install root. Defaults to the newest discovered install.",
    ),
) -> None:
    """Install `idapro` (idalib's Python wrapper) from the IDA install's bundled wheel."""
    inst = _resolve_target(ida_root)
    if not inst.has_idalib:
        raise typer.BadParameter(
            f"{inst.root} doesn't ship idalib (need IDA 9.0+). Use --ida-root to pick a 9.x install."
        )
    py_dir = inst.idalib_python_dir
    assert py_dir is not None  # has_idalib gates this

    # Prefer the bundled wheel when present (9.3+ layout); fall back to
    # editable-installing the source tree (9.0 setup.py layout).
    wheels = sorted(py_dir.glob("idapro-*-py3-none-any.whl"))
    if wheels:
        target = str(wheels[-1])
        typer.echo(f"[*] Installing {wheels[-1].name} from {py_dir}")
    elif (py_dir / "setup.py").is_file():
        target = str(py_dir)
        typer.echo(f"[*] Installing idalib (setup.py) from {py_dir}")
    else:
        raise typer.BadParameter(
            f"No idapro wheel or setup.py found under {py_dir}."
        )

    # `pip install` into the current interpreter. Using `python -m pip` so we
    # honour whatever venv the user is running under.
    rc = subprocess.run(
        [sys.executable, "-m", "pip", "install", "--upgrade", target],
        check=False,
    ).returncode
    if rc != 0:
        raise typer.Exit(rc)

    # Run the activation script so `idapro` knows where its IDA install is.
    activate = py_dir / "py-activate-idalib.py"
    if activate.is_file():
        typer.echo(f"[*] Activating idalib against {inst.root}")
        rc = subprocess.run(
            [sys.executable, str(activate), "-d", str(inst.root)],
            check=False,
        ).returncode
        if rc != 0:
            typer.echo(
                f"[!] py-activate-idalib.py exited with rc={rc}; idalib may not be wired up."
            )
            raise typer.Exit(rc)

    typer.echo("[+] idalib install complete.")


@app.command("ida-plugins")
def install_ida_plugins(
    ida_root: Path = typer.Option(
        None,
        "--ida-root",
        help="Target IDA install root. Defaults to the newest discovered install.",
    ),
) -> None:
    """Copy bundled BinDiff/BinExport DLLs into IDA's plugins folder (idempotent)."""
    inst = _resolve_target(ida_root)
    if not BUNDLED_BINDIFF_DIR.is_dir():
        raise typer.BadParameter(
            f"Bundled plugin folder missing: {BUNDLED_BINDIFF_DIR}"
        )
    plugins_dir = inst.plugins_dir
    plugins_dir.mkdir(parents=True, exist_ok=True)
    typer.echo(f"[*] Target: {plugins_dir}")

    copied: list[str] = []
    skipped: list[str] = []
    for name in _PLUGIN_FILES:
        src = BUNDLED_BINDIFF_DIR / name
        if not src.is_file():
            typer.echo(f"  ! source missing: {src}")
            continue
        dst = plugins_dir / name
        if dst.is_file() and _hash(src) == _hash(dst):
            skipped.append(name)
            continue
        shutil.copy2(src, dst)
        copied.append(name)

    for name in copied:
        typer.echo(f"  + {name}")
    for name in skipped:
        typer.echo(f"  = {name} (already up-to-date)")
    typer.echo("[+] ida-plugins install complete.")


def _hash(path: Path) -> str:
    h = sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()
