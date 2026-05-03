"""Orchestrator: drives the pipeline graph and resumes interrupts."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

import structlog
from langgraph.types import Command

from patchdiff_ai.graphs.interrupts import RefinementPickRequest, RefinementRequest
from patchdiff_ai.observability.metrics import bind_cost_tracker
from patchdiff_ai.observability.trace import bind_cve
from patchdiff_ai.runtime.app_context import AppContext
from patchdiff_ai.runtime.interactive import CliInteractor
from patchdiff_ai.runtime.timer import bind_phase_tracker

if TYPE_CHECKING:
    from patchdiff_ai.platforms.base import Platform

log = structlog.get_logger(__name__)


async def run_cve(
    ctx: AppContext,
    cve: str,
    *,
    platform: "Platform",
    interactive: bool = False,
    evaluate: bool = False,
    force: bool = False,
    keep_idalib_alive: bool = False,
    interactor: CliInteractor | None = None,
) -> dict[str, Any]:
    """Run the pipeline graph for a single CVE end-to-end.

    `platform` is the resolved concrete `Platform` (from the CLI's
    NVD auto-detect or `--platform <name>` / `<provider> cve --platform-id`
    overrides). The orchestrator does not look up a platform — that
    responsibility moved up to the CLI in M1.

    `force=True` bypasses the CVE_INFO cached-report short-circuit so
    a reanalyze actually re-runs (orthogonal to `evaluate`, which fans
    the analysis across every eval model).

    `keep_idalib_alive=True` skips this run's idalib pool teardown so a
    batch caller (`cli.runner.run_batch_cves`) can reuse the same pool
    across many CVEs in one event loop. The batch caller is responsible
    for awaiting `ctx.tools.idalib.aclose()` once at the end.
    """
    from patchdiff_ai.graphs.pipeline.graph import build_pipeline_graph
    from patchdiff_ai.graphs.pipeline.state import PipelineState

    # Pass the reporter so the interactor can pause Live around input() —
    # else Rich's bars redraw over the prompt and typed chars vanish.
    interactor = interactor or CliInteractor(enabled=interactive, progress=ctx.progress)

    from patchdiff_ai.observability.metrics import LLMMetricsHandler

    run_id = uuid.uuid4().hex[:12]
    config: dict[str, Any] = {
        "configurable": {
            "thread_id": run_id,
            "cve": cve,
            "evaluate": evaluate,
            "force": force,
            "interrupt": interactive,
            "thresholds": ctx.settings.thresholds.model_dump(),
        },
        "callbacks": [LLMMetricsHandler()],
    }

    import time as _time
    run_t0 = _time.perf_counter()
    with bind_cve(cve, run_id), bind_phase_tracker() as phases, bind_cost_tracker() as cost:
        log.info("cve_run_start", evaluate=evaluate, interactive=interactive)
        log.trace(
            "cve_run_enter",
            run_id=run_id,
            thread_id=run_id,
            interactive=interactive,
            evaluate=evaluate,
            force=force,
            platform=platform.name,
        )
        ctx.platform = platform
        log.info("platform_selected", name=platform.name)
        # Checkpointer only when an interrupt() can fire. The gather_info
        # node parks live polars DataFrames in state and the JSON serdes
        # choke on them — skipping the checkpointer avoids that.
        graph = build_pipeline_graph(ctx, with_checkpointer=interactive)

        initial = PipelineState()
        initial.cve_details.cve = cve

        state: dict[str, Any] | None = None
        try:
            feed: Any = initial
            iter_num = 0
            while True:
                iter_num += 1
                log.trace(
                    "pipeline_feed_iteration",
                    iter_num=iter_num,
                    feed_kind=type(feed).__name__,
                )
                state = await graph.ainvoke(feed, config=config)
                if "__interrupt__" not in state:
                    break
                interrupts = state["__interrupt__"]
                if not interrupts:
                    break
                req_obj = interrupts[0].value
                log.trace(
                    "pipeline_interrupt_received",
                    iter_num=iter_num,
                    request_type=type(req_obj).__name__,
                )
                if isinstance(req_obj, RefinementRequest):
                    feed = Command(resume=interactor.handle(req_obj))
                elif isinstance(req_obj, RefinementPickRequest):
                    feed = Command(resume=interactor.handle_pick(req_obj))
                else:
                    log.warning("unknown_interrupt", value=str(req_obj)[:200])
                    break
        finally:
            # Tear down idalib while we still own the event loop its
            # worker IO threads attached to. `AppContext.close()` is sync
            # and runs after `asyncio.run` returns — too late to unwind
            # `loop.run_in_executor` futures cleanly.
            #
            # `keep_idalib_alive=True` defers the teardown to the batch
            # caller so the same pool can serve many CVEs in one loop.
            if not keep_idalib_alive and ctx.tools.idalib is not None:
                try:
                    await ctx.tools.idalib.aclose()
                except Exception as exc:
                    # Pool teardown shouldn't mask a real run error.
                    log.warning("idalib_aclose_error", error=str(exc))

        report_count = len(state.get("reports", []) or []) if state else 0
        log.info(
            "run_perf_summary",
            elapsed_s=round(_time.perf_counter() - run_t0, 2),
            phases=phases.summary(),
            cost_usd_total=cost.total_cost_usd,
            llm_calls=cost.total_calls,
            cost_by_model=cost.summary(),
        )
        log.info(
            "cve_run_complete",
            reports=report_count,
            cost_usd_total=cost.total_cost_usd,
        )
        return state or {}
