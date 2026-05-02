"""`patchdiff-ai health-check` — validate environment and external tools."""

from __future__ import annotations

import asyncio
import os

import typer

from patchdiff_ai.config.settings import get_settings
from patchdiff_ai.config.tools import discover_ida_installs, select_ida_install
from patchdiff_ai.runtime.app_context import AppContext

app = typer.Typer()


@app.callback(invoke_without_command=True)
def health_check_command() -> None:
    """Validate `.env`, print model catalog, smoke-test 7-Zip / IDA."""
    settings = get_settings()
    settings.paths.ensure()
    ctx = AppContext.build(settings)

    typer.echo("== Settings ==")
    typer.echo(f"db_dir          = {settings.paths.db_dir}")
    typer.echo(f"reports_dir     = {settings.paths.reports_dir}")
    typer.echo(f"7z              = {settings.tools.seven_zip}")
    typer.echo(f"ida (resolved)  = {ctx.tools.ida.executable}")
    typer.echo(f"updatecomp dll  = {settings.tools.update_compression_dll}")
    typer.echo(f"BINDIFF_PATH    = {os.environ.get('BINDIFF_PATH', '<unset>')}")

    typer.echo("\n== IDA installs discovered ==")
    installs = discover_ida_installs()
    selected = select_ida_install(installs)
    if not installs:
        typer.echo("  (none — set TOOLS__IDA explicitly or install IDA Pro)")
    for inst in installs:
        marker = "*" if selected and inst.root == selected.root else " "
        idalib_tag = "idalib" if inst.has_idalib else "no-idalib"
        ver = ".".join(str(x) for x in inst.version)
        typer.echo(
            f"  {marker} {ver:8}  {idalib_tag:10}  {inst.executable.name:14}  {inst.root}"
        )

    typer.echo("\n== Tool availability ==")
    avail = settings.tools.exists(ida_exe=ctx.tools.ida.executable)
    for k, v in avail.items():
        typer.echo(f"  {k:24} = {'OK' if v else 'MISSING'}")
    if not avail.get("ida_binexport_plugin", True):
        typer.echo(
            "  ! BinExport plugin missing — run `patchdiff-ai install ida-plugins` "
            "to copy the bundled DLLs into IDA's plugins folder."
        )
    if not avail.get("ida_bindiff_plugin", True):
        typer.echo(
            "  ! BinDiff IDA plugin missing — run `patchdiff-ai install ida-plugins` "
            "to copy the bundled DLLs into IDA's plugins folder."
        )

    typer.echo("\n== MCP / idalib readiness ==")
    try:
        import idapro  # noqa: F401  # type: ignore[import-not-found]

        idalib_ok = True
    except ImportError:
        idalib_ok = False
    typer.echo(f"  idapro (idalib)      = {'OK' if idalib_ok else 'MISSING — run `patchdiff-ai install idalib`'}")
    try:
        import ida_pro_mcp  # noqa: F401  # type: ignore[import-not-found]

        mcp_pkg_ok = True
    except ImportError:
        mcp_pkg_ok = False
    typer.echo(f"  ida_pro_mcp package  = {'OK' if mcp_pkg_ok else 'MISSING — install via `pip install -e .`'}")
    typer.echo(
        f"  RE agent strategy    = "
        f"{'idalib (preferred)' if ctx.tools.idalib is not None else 'subprocess (legacy)'}"
    )
    typer.echo(
        f"  Chat IDA tools       = "
        f"{'available' if ctx.tools.ida_chat is not None else 'unavailable (no idalib)'}"
    )

    typer.echo("\n== Available models ==")
    for spec in ctx.registry.list_available():
        typer.echo(f"  {spec.name:32} -> {spec.provider.value} ({spec.deployment})")

    async def smoke() -> None:
        # Launch 7-Zip with no args to confirm the binary is actually runnable
        # (file existence is already covered by `tools.exists()` above). Bare
        # `7z` prints help to stdout and exits in milliseconds. Pointing it at
        # a real path here would either fail noisily on a non-archive or, if
        # the path is a directory, make 7-Zip recursively scan it for ages.
        from patchdiff_ai.tools.process import run

        try:
            res = await run(
                [str(settings.tools.seven_zip)],
                timeout=10,
                check=False,
            )
            status = "OK" if res.returncode == 0 else f"rc={res.returncode}"
            typer.echo(f"  7-Zip launch         = {status}")
        except Exception as exc:
            typer.echo(f"  7-Zip launch         = FAILED ({exc})")

    typer.echo("\n== Tool smoke ==")
    asyncio.run(smoke())
    ctx.close()
    typer.echo("\n[+] health-check complete")
