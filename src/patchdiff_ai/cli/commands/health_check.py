"""`patchdiff-ai health-check` — validate environment + every registered platform.

Two layers:
  1. Core checks (env, Azure creds, IDA / 7-Zip paths, model catalog) —
     these don't depend on which platform is running.
  2. Per-provider checks — each registered `PlatformProvider`'s
     `health_check()` runs (e.g. Windows: MSRC reachability, WinSxS
     archives present).
"""

from __future__ import annotations

import asyncio
import os

import click

from patchdiff_ai.config.settings import get_settings
from patchdiff_ai.config.tools import discover_ida_installs, select_ida_install
from patchdiff_ai.platforms import providers
from patchdiff_ai.runtime.app_context import AppContext


@click.command("health-check", help="Validate environment, tools, and every registered platform.")
def health_check_command() -> None:
    settings = get_settings()
    settings.paths.ensure()
    ctx = AppContext.build(settings)

    click.echo("== Settings ==")
    click.echo(f"db_dir          = {settings.paths.db_dir}")
    click.echo(f"reports_dir     = {settings.paths.reports_dir}")
    click.echo(f"7z              = {settings.tools.seven_zip}")
    click.echo(f"ida (resolved)  = {ctx.tools.ida.executable}")
    click.echo(f"updatecomp dll  = {settings.tools.update_compression_dll}")
    click.echo(f"BINDIFF_PATH    = {os.environ.get('BINDIFF_PATH', '<unset>')}")

    click.echo("\n== IDA installs discovered ==")
    installs = discover_ida_installs()
    selected = select_ida_install(installs)
    if not installs:
        click.echo("  (none — set TOOLS__IDA explicitly or install IDA Pro)")
    for inst in installs:
        marker = "*" if selected and inst.root == selected.root else " "
        idalib_tag = "idalib" if inst.has_idalib else "no-idalib"
        ver = ".".join(str(x) for x in inst.version)
        click.echo(
            f"  {marker} {ver:8}  {idalib_tag:10}  {inst.executable.name:14}  {inst.root}"
        )

    click.echo("\n== Tool availability ==")
    avail = settings.tools.exists(ida_exe=ctx.tools.ida.executable)
    for k, v in avail.items():
        click.echo(f"  {k:24} = {'OK' if v else 'MISSING'}")
    if not avail.get("ida_binexport_plugin", True):
        click.echo(
            "  ! BinExport plugin missing — run `patchdiff-ai install ida-plugins` "
            "to copy the bundled DLLs into IDA's plugins folder."
        )
    if not avail.get("ida_bindiff_plugin", True):
        click.echo(
            "  ! BinDiff IDA plugin missing — run `patchdiff-ai install ida-plugins` "
            "to copy the bundled DLLs into IDA's plugins folder."
        )

    click.echo("\n== MCP / idalib readiness ==")
    try:
        import idapro  # noqa: F401  # type: ignore[import-not-found]

        idalib_ok = True
    except ImportError:
        idalib_ok = False
    click.echo(f"  idapro (idalib)      = {'OK' if idalib_ok else 'MISSING — run `patchdiff-ai install idalib`'}")
    try:
        import ida_pro_mcp  # noqa: F401  # type: ignore[import-not-found]

        mcp_pkg_ok = True
    except ImportError:
        mcp_pkg_ok = False
    click.echo(f"  ida_pro_mcp package  = {'OK' if mcp_pkg_ok else 'MISSING — install via `pip install -e .`'}")
    click.echo(
        f"  RE agent strategy    = "
        f"{'idalib (preferred)' if ctx.tools.idalib is not None else 'subprocess (legacy)'}"
    )
    click.echo(
        f"  Chat IDA tools       = "
        f"{'available' if ctx.tools.ida_chat is not None else 'unavailable (no idalib)'}"
    )

    click.echo("\n== Available models ==")
    for spec in ctx.registry.list_available():
        click.echo(f"  {spec.name:32} -> {spec.provider.value} ({spec.deployment})")

    async def smoke() -> None:
        from patchdiff_ai.tools.process import run

        try:
            res = await run(
                [str(settings.tools.seven_zip)],
                timeout=10,
                check=False,
            )
            status = "OK" if res.returncode == 0 else f"rc={res.returncode}"
            click.echo(f"  7-Zip launch         = {status}")
        except Exception as exc:
            click.echo(f"  7-Zip launch         = FAILED ({exc})")

    click.echo("\n== Tool smoke ==")
    asyncio.run(smoke())

    failures: list[str] = []
    for provider in providers():
        click.echo(f"\n== Platform: {provider.name} ==")
        try:
            ok = provider.health_check()
        except Exception as exc:
            click.echo(f"  ERROR: {exc}")
            ok = False
        if not ok:
            failures.append(provider.name)

    ctx.close()

    if failures:
        click.echo(f"\n[!] Provider health-check failed: {failures}")
        raise click.exceptions.Exit(code=1)
    click.echo("\n[+] health-check complete")
