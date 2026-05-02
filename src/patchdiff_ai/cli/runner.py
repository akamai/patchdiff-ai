"""Shared CVE-run dispatch.

Both the root `cve` command (after NVD auto-detect) and each provider's
`cve` sub-command (after explicit resolve) call into `run_single_cve`.
This is where AppContext is built, the progress reporter is mounted,
and `run_cve(...)` is invoked. Keeps the actual orchestrator entry point
in one place so the CLI surface stays declarative.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import click

from patchdiff_ai.config.settings import get_settings
from patchdiff_ai.observability.progress import make_reporter
from patchdiff_ai.runtime.app_context import AppContext
from patchdiff_ai.runtime.cancel import run_cancellable
from patchdiff_ai.runtime.orchestrator import run_cve

if TYPE_CHECKING:
    from patchdiff_ai.platforms.base import Platform


def run_single_cve(
    ctx: click.Context,
    *,
    cve_id: str,
    platform: "Platform",
    eval_mode: bool = False,
    interactive: bool = False,
    chat: bool = False,
    chat_permissive: bool = False,
) -> None:
    """Build AppContext, run the pipeline, optionally drop into chat.

    `platform` is already resolved by the caller (provider.resolve(...) or
    provider.matches_nvd(...)) — there is no platform-name lookup here.
    """
    settings = get_settings()
    settings.paths.ensure()
    app_ctx = AppContext.build(settings)

    try:
        with make_reporter() as progress:
            app_ctx.progress = progress
            if app_ctx.tools.idalib is not None:
                app_ctx.tools.idalib.attach_progress(progress)
            final_state = run_cancellable(
                run_cve(
                    app_ctx,
                    cve_id,
                    platform=platform,
                    interactive=interactive,
                    evaluate=eval_mode,
                )
            )
        if chat or chat_permissive:
            from patchdiff_ai.cli.chat import run_chat

            run_chat(
                app_ctx,
                cve_id,
                state=final_state,
                interactive=interactive,
                permissive=chat_permissive,
            )
    finally:
        app_ctx.close()
