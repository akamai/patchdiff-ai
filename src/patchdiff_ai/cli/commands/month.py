"""`patchdiff-ai month <YYYY-MMM>` — Patch Tuesday batch run."""

from __future__ import annotations

import typer

from patchdiff_ai.cli.validators import month_value, platform_ids
from patchdiff_ai.config.settings import get_settings
from patchdiff_ai.observability.progress import make_reporter
from patchdiff_ai.runtime.app_context import AppContext
from patchdiff_ai.runtime.cancel import run_cancellable
from patchdiff_ai.runtime.orchestrator import run_cve

app = typer.Typer()


@app.callback(invoke_without_command=True)
def month_command(
    month: str = typer.Argument(..., callback=month_value, metavar="YYYY-MMM"),
    platform_name: str = typer.Option(
        "", "--platform-name", help="MSRC product-name filter (e.g. 'Windows 11 …')."
    ),
    platforms_csv: str = typer.Option("", "--platform-ids"),
    eval_mode: bool = typer.Option(False, "--eval"),
    platform_plugin: str = typer.Option(
        "",
        "--platform",
        help="Platform plugin override (e.g. windows). Default: auto-detect per CVE.",
    ),
) -> None:
    """Generate reports for every CVE in the named Patch Tuesday."""
    from patchdiff_ai.patches.platform_filter import (
        collect_cves,
        download_cvrf,
        pick_ids,
    )

    pids = platform_ids(platforms_csv)

    settings = get_settings()
    settings.paths.ensure()
    ctx = AppContext.build(settings)

    cvrf = download_cvrf(month)
    targets, names = pick_ids(cvrf, platform_name or None, pids)
    if not targets:
        raise typer.Exit("No matching ProductIDs")

    cve_rows = collect_cves(cvrf, targets)
    if not cve_rows:
        raise typer.Exit("No CVEs found")

    typer.echo(f"[*] Selected {names}: {len(cve_rows)} CVEs")

    async def _run() -> None:
        for row in cve_rows:
            await run_cve(
                ctx,
                row["CVE"],
                interactive=False,
                evaluate=eval_mode,
                platform_name=platform_plugin or None,
            )

    try:
        with make_reporter() as progress:
            ctx.progress = progress
            run_cancellable(_run())
    finally:
        ctx.close()
