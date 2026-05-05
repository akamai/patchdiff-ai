"""`patchdiff-ai install` — bootstrap external assets.

Three modes:

* `patchdiff-ai install` (no subcommand) — aggregate: runs every
  registered `PlatformProvider.install()`, then suggests `idalib` /
  `ida-plugins` if those tools are missing.
* `patchdiff-ai install idalib` — locate the bundled
  `idapro-*-py3-none-any.whl` inside the resolved IDA install's
  `idalib/python/` and pip-install it. Then run `py-activate-idalib.py`.
* `patchdiff-ai install ida-plugins` — copy bundled BinDiff / BinExport
  DLLs from `resources/bindiff_ida_9.3/` into the resolved IDA install's
  `plugins/` folder. Idempotent.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from hashlib import sha256
from pathlib import Path

import click

from patchdiff_ai.config.tools import (
    IdaInstall,
    discover_ida_installs,
    select_ida_install,
)
from patchdiff_ai.platforms import providers
from patchdiff_ai.runtime.paths import BUNDLED_BINDIFF_DIR


_PLUGIN_FILES = ("bindiff8_ida64.dll", "binexport12_ida64.dll")
# Version the bundled plugin DLLs were built against. Copying them into a
# different IDA's `plugins/` won't load (BinExport pins the SDK ABI per IDA
# minor version), so we refuse and tell the user instead of silently
# installing a non-functional plugin.
BUNDLED_PLUGIN_IDA_VERSION = (9, 3)


def is_admin() -> bool:
    """Best-effort check for elevated privileges on Windows.

    Returns True on non-Windows (irrelevant there) and on any failure to
    query the OS — the worst case is a missing warning, never a false
    abort. Writing into `C:\\Program Files\\IDA *` requires elevation, so
    callers use this to print a hint before letting `shutil.copy2` or
    `pip install` fail with a permission error.
    """
    if sys.platform != "win32":
        return True
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return True


def _resolve_target(ida_root: Path | None) -> IdaInstall:
    if ida_root is not None:
        for inst in discover_ida_installs():
            if inst.root.resolve() == ida_root.resolve():
                return inst
        raise click.BadParameter(
            f"{ida_root} is not a recognised IDA install (no idat.exe / idat64.exe found)."
        )
    inst = select_ida_install(discover_ida_installs())
    if inst is None:
        raise click.BadParameter(
            "No IDA install found. Pass --ida-root, set tools.ida in config.json, "
            "or set TOOLS__IDA env var."
        )
    return inst


@click.group(
    "install",
    help="Install prerequisites for every registered platform (or a specific component).",
    invoke_without_command=True,
)
@click.pass_context
def install_group(ctx: click.Context) -> None:
    """No subcommand → aggregate over every registered provider."""
    if ctx.invoked_subcommand is not None:
        return
    failures: list[str] = []
    for provider in providers():
        click.echo(f"\n--- {provider.name} ---")
        try:
            provider.install()
        except Exception as exc:
            click.echo(f"[!] {provider.name} install failed: {exc}")
            failures.append(provider.name)
    if failures:
        raise click.exceptions.Exit(code=1)
    click.echo("\n[+] platform installs complete (run `patchdiff-ai install idalib` / "
               "`install ida-plugins` if you also need IDA assets)")


def do_install_idalib(inst: IdaInstall) -> None:
    """Install `idapro` from `<ida_root>/idalib/python/` and run the activator.

    Caller is responsible for picking `inst` (typically the newest 9.0+
    install). Raises `click.BadParameter` if `inst` doesn't ship idalib
    or `click.exceptions.Exit` if pip / the activator return non-zero.
    """
    if not inst.has_idalib:
        raise click.BadParameter(
            f"{inst.root} doesn't ship idalib (need IDA 9.0+). "
            "Use --ida-root to pick a 9.x install."
        )
    py_dir = inst.idalib_python_dir
    assert py_dir is not None  # has_idalib gates this

    wheels = sorted(py_dir.glob("idapro-*-py3-none-any.whl"))
    if wheels:
        target = str(wheels[-1])
        click.echo(f"[*] Installing {wheels[-1].name} from {py_dir}")
    elif (py_dir / "setup.py").is_file():
        target = str(py_dir)
        click.echo(f"[*] Installing idalib (setup.py) from {py_dir}")
    else:
        raise click.BadParameter(f"No idapro wheel or setup.py found under {py_dir}.")

    rc = subprocess.run(
        [sys.executable, "-m", "pip", "install", "--upgrade", target],
        check=False,
    ).returncode
    if rc != 0:
        raise click.exceptions.Exit(code=rc)

    activate = py_dir / "py-activate-idalib.py"
    if activate.is_file():
        click.echo(f"[*] Activating idalib against {inst.root}")
        rc = subprocess.run(
            [sys.executable, str(activate), "-d", str(inst.root)],
            check=False,
        ).returncode
        if rc != 0:
            click.echo(
                f"[!] py-activate-idalib.py exited with rc={rc}; idalib may not be wired up."
            )
            raise click.exceptions.Exit(code=rc)

    click.echo("[+] idalib install complete.")


def do_install_ida_plugins(inst: IdaInstall) -> None:
    """Copy bundled BinDiff/BinExport DLLs into `inst`'s `plugins/` folder.

    Only safe for IDA 9.3 — the bundled DLLs in
    `resources/bindiff_ida_9.3/` link against that minor version's SDK.
    Caller checks `inst.version == BUNDLED_PLUGIN_IDA_VERSION` and skips
    otherwise. Idempotent: skips files whose contents already match.
    """
    if not BUNDLED_BINDIFF_DIR.is_dir():
        raise click.BadParameter(f"Bundled plugin folder missing: {BUNDLED_BINDIFF_DIR}")
    plugins_dir = inst.plugins_dir
    plugins_dir.mkdir(parents=True, exist_ok=True)
    click.echo(f"[*] Target: {plugins_dir}")

    copied: list[str] = []
    skipped: list[str] = []
    for name in _PLUGIN_FILES:
        src = BUNDLED_BINDIFF_DIR / name
        if not src.is_file():
            click.echo(f"  ! source missing: {src}")
            continue
        dst = plugins_dir / name
        if dst.is_file() and _hash(src) == _hash(dst):
            skipped.append(name)
            continue
        shutil.copy2(src, dst)
        copied.append(name)

    for name in copied:
        click.echo(f"  + {name}")
    for name in skipped:
        click.echo(f"  = {name} (already up-to-date)")
    click.echo("[+] ida-plugins install complete.")


@install_group.command("idalib", help="Install `idapro` (idalib's Python wrapper) from IDA's bundled wheel.")
@click.option(
    "--ida-root",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=None,
    help="Target IDA install root. Defaults to the newest discovered install.",
)
def install_idalib(ida_root: Path | None) -> None:
    inst = _resolve_target(ida_root)
    do_install_idalib(inst)


@install_group.command("ida-plugins", help="Copy bundled BinDiff/BinExport DLLs into IDA's plugins folder.")
@click.option(
    "--ida-root",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=None,
    help="Target IDA install root. Defaults to the newest discovered install.",
)
def install_ida_plugins(ida_root: Path | None) -> None:
    inst = _resolve_target(ida_root)
    do_install_ida_plugins(inst)


def _hash(path: Path) -> str:
    h = sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()
