"""Shared CVE-run dispatch.

Both the root `cve` command (after NVD auto-detect) and each provider's
`cve` sub-command (after explicit resolve) call into `run_single_cve`.
Batch commands (e.g. `windows month`) call `run_batch_cves` so AppContext
+ progress reporter + IdalibPool are built once, not once per CVE.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Iterable

import click

from patchdiff_ai.config.settings import get_settings
from patchdiff_ai.observability.progress import make_reporter
from patchdiff_ai.runtime.app_context import AppContext
from patchdiff_ai.runtime.cancel import run_cancellable
from patchdiff_ai.runtime.orchestrator import run_cve

if TYPE_CHECKING:
    from patchdiff_ai.platforms.base import Platform


async def _run_one_cve_in_ctx(
    app_ctx: AppContext,
    *,
    cve_id: str,
    platform: "Platform",
    eval_mode: bool,
    interactive: bool,
    keep_idalib_alive: bool = False,
) -> dict:
    """Run a single CVE inside an already-built AppContext.

    Lower-level than `run_single_cve`: no AppContext build, no progress
    reporter spin-up, no chat launch — caller owns those. Exists so a
    batch caller can hold one AppContext open across many CVEs.

    `keep_idalib_alive` is forwarded to `run_cve`; batch callers set
    True so the pool stays up across CVEs.
    """
    return await run_cve(
        app_ctx,
        cve_id,
        platform=platform,
        interactive=interactive,
        evaluate=eval_mode,
        keep_idalib_alive=keep_idalib_alive,
    )


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
    provider.matches_native(...)) — there is no platform-name lookup here.
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
                _run_one_cve_in_ctx(
                    app_ctx,
                    cve_id=cve_id,
                    platform=platform,
                    eval_mode=eval_mode,
                    interactive=interactive,
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


def run_batch_cves(
    ctx: click.Context,
    *,
    cves: Iterable[tuple[str, "Platform"]],
    eval_mode: bool = False,
) -> None:
    """Run many CVEs back-to-back inside a single AppContext.

    `cves` is an iterable of `(cve_id, platform)` pairs — the caller does
    its own per-CVE platform resolution (e.g. `provider.matches_native`)
    before calling this. Skips chat / interrupt by design — batch runs
    should be unattended.

    Ctrl-C cancels the *whole* batch; nothing about the partial work
    completed before the cancel is rolled back (cached reports stay in
    Chroma).
    """
    cves = list(cves)
    settings = get_settings()
    settings.paths.ensure()
    app_ctx = AppContext.build(settings)

    async def _run_all() -> None:
        try:
            for cve_id, platform in cves:
                await _run_one_cve_in_ctx(
                    app_ctx,
                    cve_id=cve_id,
                    platform=platform,
                    eval_mode=eval_mode,
                    interactive=False,
                    keep_idalib_alive=True,
                )
        finally:
            # Single aclose at the end of the batch — must happen
            # inside this coroutine (still own the event loop the
            # idalib worker IO threads attached to).
            if app_ctx.tools.idalib is not None:
                try:
                    await app_ctx.tools.idalib.aclose()
                except Exception as exc:
                    import structlog
                    structlog.get_logger(__name__).warning(
                        "idalib_aclose_error", error=str(exc)
                    )

    try:
        with make_reporter() as progress:
            app_ctx.progress = progress
            if app_ctx.tools.idalib is not None:
                app_ctx.tools.idalib.attach_progress(progress)
            run_cancellable(_run_all())
    finally:
        app_ctx.close()
