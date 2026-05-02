"""`patchdiff-ai cve <CVE>` — single-CVE end-to-end run."""

from __future__ import annotations

import typer

from patchdiff_ai.cli.validators import cve_value, platform_ids
from patchdiff_ai.config.settings import get_settings
from patchdiff_ai.observability.progress import make_reporter
from patchdiff_ai.runtime.app_context import AppContext
from patchdiff_ai.runtime.cancel import run_cancellable
from patchdiff_ai.runtime.orchestrator import run_cve

app = typer.Typer(help="Run analysis for a single CVE.")


@app.callback(invoke_without_command=True)
def cve_command(
    cve_id: str = typer.Argument(..., callback=cve_value, metavar="CVE-YYYY-NNNNN"),
    eval_mode: bool = typer.Option(False, "--eval", help="Generate reports across multiple models."),
    interactive: bool = typer.Option(False, "--interrupt", help="Allow interactive refinement."),
    chat: bool = typer.Option(False, "--chat", help="Drop into an interactive chat after the run completes."),
    chat_permissive: bool = typer.Option(
        False,
        "--chat-permissive",
        help="Like --chat but the ReAct agent runs tools without asking for y/N approval.",
    ),
    platform_name: str = typer.Option(
        "",
        "--platform",
        help="Override the platform plugin (e.g. windows). Default: auto-detect.",
    ),
    platform: str = typer.Option(
        "", "--platform-ids", help="Comma-separated MSRC product IDs."
    ),
) -> None:
    """Generate an RCA report for a single CVE."""
    settings = get_settings()
    settings.paths.ensure()
    ctx = AppContext.build(settings)

    pids = platform_ids(platform)
    selected_platform = None
    if pids:
        from patchdiff_ai.patches.platform_filter import get_platforms_by_ids

        platforms = get_platforms_by_ids(pids)
        if platforms:
            selected_platform = next(iter(platforms))

    try:
        with make_reporter() as progress:
            ctx.progress = progress
            # Share the live reporter with the idalib pool so each worker
            # call surfaces a Rich spinner instead of log-line heartbeats.
            if ctx.tools.idalib is not None:
                ctx.tools.idalib.attach_progress(progress)
            final_state = run_cancellable(
                run_cve(
                    ctx,
                    cve_id,
                    interactive=interactive,
                    evaluate=eval_mode,
                    platform=selected_platform,
                    platform_name=platform_name or None,
                )
            )
        # `--chat-permissive` implies `--chat`.
        if chat or chat_permissive:
            from patchdiff_ai.cli.chat import run_chat

            run_chat(
                ctx, cve_id, state=final_state,
                interactive=interactive, permissive=chat_permissive,
            )
    finally:
        ctx.close()
