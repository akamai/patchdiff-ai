"""Pipeline nodes: cve_info_node, gather_node, finalize_node.

The platform-specific work (advisory fetch, package gather) is delegated to
`ctx.platform`; these nodes only do the platform-agnostic plumbing
(cache short-circuit, summary logging).
"""

from __future__ import annotations

from typing import Any

import structlog
from langchain_core.runnables import RunnableConfig

from patchdiff_ai.graphs.pipeline.routing import Stage
from patchdiff_ai.graphs.pipeline.state import PipelineState
from patchdiff_ai.observability.metrics import get_cost_tracker
from patchdiff_ai.runtime.app_context import AppContext

log = structlog.get_logger(__name__)


def make_cve_info_node(ctx: AppContext):
    async def cve_info(state: PipelineState, config: RunnableConfig) -> dict[str, Any]:
        # Platform must be set on ctx before the graph runs (orchestrator
        # does this). Defensive check so misuse fails fast and loud.
        if ctx.platform is None:
            raise RuntimeError(
                "ctx.platform is not set; orchestrator must call select_platform "
                "before invoking the pipeline graph"
            )

        # Platform-specific advisory + KB selection. Returns the `stage`,
        # `os`, `KB`, `cve_details` slice of the state-update dict.
        update = await ctx.platform.enrich_cve(state, ctx)

        # Cache short-circuit (platform-agnostic). Honors the legacy rule:
        # any cached report wins unless --eval or chat-driven reanalyze
        # (force=True) explicitly re-runs the pipeline.
        stores = ctx.open_vector_stores()
        evaluate = config.get("configurable", {}).get("evaluate", False)
        force = config.get("configurable", {}).get("force", False)
        cached_reports = stores.reports.get(where={"cve": state.cve_details.cve})
        cached_count = len(cached_reports.get("ids") or [])
        log.info("cached_report_count", n=cached_count, force=force)

        if cached_count > 0 and not evaluate and not force:
            from patchdiff_ai.schemas.analysis import Artifact
            from patchdiff_ai.schemas.cve import CveDetails
            from patchdiff_ai.schemas.patch_store import PatchStoreEntry
            from patchdiff_ai.schemas.report import Report

            reports = []
            ids = cached_reports.get("ids") or []
            for i in range(len(ids)):
                doc = cached_reports["documents"][i]
                meta = cached_reports["metadatas"][i] or {}
                reports.append(
                    Report(
                        cve_details=CveDetails(cve=meta.get("cve", "")),
                        artifact=Artifact(
                            primary_file=PatchStoreEntry(
                                name=meta.get("file", ""),
                                kb=meta.get("kb", ""),
                                uid=meta.get("patch_store_uid", ""),
                            )
                        ),
                        content=doc,
                        confidence=float(meta.get("confidence") or 0.0),
                        model=meta.get("model_name", ""),
                    )
                )
            update["reports"] = reports

        return update

    return cve_info


def make_gather_node(ctx: AppContext):
    """Thin pipeline-stage wrapper around `ctx.platform.gather_packages`.

    The actual download/extract/index work lives on the platform plugin
    (Windows = the existing gather subgraph, Linux/Android = whatever they
    use). The pipeline graph only knows "do the gather stage now."
    """

    async def gather(state: PipelineState) -> dict[str, Any]:
        if ctx.platform is None:
            raise RuntimeError("ctx.platform is not set when GATHER node ran")
        try:
            return await ctx.platform.gather_packages(state, ctx)
        finally:
            # Past this point the pipeline (PI/RE/VR) adds no Progress tasks
            # and the PI agent prompts the user via interrupt(). Keeping the
            # Rich Live region alive would clobber the input cursor on every
            # refresh; stop it now so refinement runs on a clean tty.
            ctx.progress.stop_live()

    return gather


def make_finalize_node(ctx: AppContext):
    async def finalize(state: PipelineState) -> dict[str, Any]:
        threshold = ctx.settings.thresholds.candidates
        candidates = state.candidates.results if state.candidates else []
        top_relevancy = max((c.relevancy for c in candidates), default=0.0)
        passing = sum(1 for c in candidates if c.relevancy > threshold)

        if len(state.reports) > 0:
            outcome = "ok"
        elif len(candidates) == 0:
            outcome = "no_candidates"
        elif passing == 0:
            outcome = "no_candidates_above_threshold"
        elif len(state.artifacts) == 0:
            outcome = "all_re_runs_dropped"
        else:
            outcome = "reports_failed"

        cost = get_cost_tracker()
        log.info(
            "cve_run_summary",
            cve=state.cve_details.cve,
            outcome=outcome,
            candidates_total=len(candidates),
            candidates_above_threshold=passing,
            relevancy_threshold=threshold,
            top_relevancy=top_relevancy,
            artifacts_dispatched=len(state.artifacts),
            reports_produced=len(state.reports),
            cost_usd_total=cost.total_cost_usd if cost is not None else None,
            llm_calls=cost.total_calls if cost is not None else None,
        )
        return {"stage": Stage.COMPLETE}

    return finalize
