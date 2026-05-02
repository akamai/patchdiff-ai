"""Pipeline state machine. Replaces the 140-line `node[-2]` router."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

import polars as pl
import structlog
from langgraph.constants import END, Send

from patchdiff_ai.persistence.patch_store import (
    get_patch_store_df,
    resource_lock,
    safe_serialize,
)
from patchdiff_ai.schemas.patch_store import PatchStoreEntry

if TYPE_CHECKING:
    from patchdiff_ai.graphs.pipeline.state import PipelineState
    from patchdiff_ai.runtime.app_context import AppContext

log = structlog.get_logger(__name__)


class Stage(str, Enum):
    START = "start"
    CVE_INFO_DONE = "cve_info_done"
    GATHER_DONE = "gather_done"
    INTERNALS_DONE = "internals_done"
    RE_DONE = "re_done"
    VR_DONE = "vr_done"
    COMPLETE = "complete"


class PipelineNodeNames:
    CVE_INFO = "Get CVE information"
    GATHER = "Gather Information"
    PI_AGENT = "Platform Internals Agent"
    RE_AGENT = "Reverse Engineering Agent"
    VR_AGENT = "Vulnerability Research Agent"
    FINALIZE = "Finalize"


class PipelineRouter:
    """One method per source stage. Pure functions of state + ctx."""

    def __init__(self, ctx: "AppContext") -> None:
        self.ctx = ctx

    def from_cve_info(self, state):
        next_node = (
            PipelineNodeNames.FINALIZE if state.reports else PipelineNodeNames.GATHER
        )
        log.trace(
            "pipeline_route_cve_info",
            cached_reports=len(state.reports),
            next=next_node,
        )
        return next_node

    def from_gather(self, state):
        return PipelineNodeNames.PI_AGENT

    async def from_internals(self, state):
        """Fan out: each subject -> a Send to the RE subgraph.

        Async because `_patch_candidates` extracts WinSxS baselines from
        the platform's `.7z` archive (subprocess await) before applying
        deltas — see `WindowsVersionedPlatform.extract_baselines`.
        """
        if not state.candidates.results:
            log.warning("no_candidates")
            log.trace(
                "pipeline_route_internals",
                candidates_total=0,
                re_sends=0,
                next=PipelineNodeNames.FINALIZE,
            )
            return PipelineNodeNames.FINALIZE

        targets = await self._compute_re_targets(state)
        log.trace(
            "pipeline_route_internals",
            candidates_total=len(state.candidates.results),
            threshold=self.ctx.settings.thresholds.candidates,
            re_sends=len(targets) if targets else 0,
            next=("RE_AGENT" if targets else PipelineNodeNames.FINALIZE),
        )
        if not targets:
            return PipelineNodeNames.FINALIZE
        return targets

    def from_re(self, state):
        from patchdiff_ai.graphs.vulnerability_research.state import (
            VulnerabilityResearchState,
        )

        if not state.artifacts:
            log.trace("pipeline_route_re", artifacts=0, vr_sends=0, next=PipelineNodeNames.FINALIZE)
            return PipelineNodeNames.FINALIZE
        sends = [
            Send(
                PipelineNodeNames.VR_AGENT,
                VulnerabilityResearchState(
                    artifact=art, cve_details=state.cve_details
                ).model_dump(),
            )
            for art in state.artifacts
        ]
        log.trace(
            "pipeline_route_re",
            artifacts=len(state.artifacts),
            vr_sends=len(sends),
            next="VR_AGENT",
        )
        return sends

    def from_vr(self, state):
        return PipelineNodeNames.FINALIZE

    def from_finalize(self, state):
        return END

    # internals

    async def _compute_re_targets(self, state):
        from patchdiff_ai.graphs.reverse_engineering.state import ReverseEngineeringState

        thresholds = self.ctx.settings.thresholds
        ranked_df = pl.DataFrame(
            [
                {
                    "name": c.name,
                    "package": c.package,
                    "similarity": c.similarity,
                    "relevancy": c.relevancy,
                }
                for c in state.candidates.results
            ]
        )

        subjects = await self._patch_candidates(state, ranked_df)
        if subjects is None:
            return None

        subjects = subjects.filter(pl.col("relevancy") > thresholds.candidates)
        if subjects.is_empty():
            top_relevancy = float(ranked_df["relevancy"].max() or 0.0)
            log.warning(
                "candidates_below_threshold",
                threshold=thresholds.candidates,
                top_relevancy=top_relevancy,
                total_candidates=ranked_df.height,
            )
            return None
        patch_store_index = self.ctx.settings.paths.patch_store_index
        patch_store_df = get_patch_store_df(patch_store_index)
        platform_id = self.ctx.platform.name

        sends = []
        for row in subjects.iter_rows(named=True):
            patched = patch_store_df.filter(
                (pl.col("platform") == platform_id)
                & (pl.col("name") == row["name"])
                & (pl.col("package") == row["package"])
                & (pl.col("arch") == row["arch"])
                & pl.col("kb").is_in((state.KB.current, state.KB.previous, state.KB.base))
            )
            selected = list(patched.iter_rows(named=True))
            if len(selected) < 2:
                continue
            primary = next((s for s in selected if s["kb"] == state.KB.current), None)
            if primary is None:
                continue
            secondary = next(
                (s for s in selected if s["kb"] == state.KB.previous), None
            ) or next((s for s in selected if s["kb"] == state.KB.base), None)
            if secondary is None:
                continue

            sends.append(
                Send(
                    PipelineNodeNames.RE_AGENT,
                    ReverseEngineeringState(
                        primary_file=PatchStoreEntry.from_row(primary),
                        secondary_file=PatchStoreEntry.from_row(secondary),
                    ).model_dump(),
                )
            )
        return sends or None

    async def _patch_candidates(self, state, ranked_df: pl.DataFrame):
        from patchdiff_ai.graphs.pipeline.routing_helpers import (
            build_subjects_df,
        )  # local import to avoid cycle
        from patchdiff_ai.patches.delta_apply import patch_entry

        subjects = build_subjects_df(state, ranked_df)
        if subjects is None or subjects.is_empty():
            return None

        patch_store_index = self.ctx.settings.paths.patch_store_index
        # NB: we synchronously serialize once after applying patches; the lock here
        # is best-effort against parallel CVE runs sharing one patch_store_df.
        patch_store_df = get_patch_store_df(patch_store_index)

        # Compute the minimal set of baselines actually needed:
        #   - filter subjects to those whose base-KB output isn't already
        #     in patch_store (the durable cache),
        #   - then join filtered_base_df against just those subjects to
        #     pick the matching reverse-delta rows.
        # If every base-KB output is cached, `needed_rows` is empty and
        # `extract_baselines` short-circuits without spawning 7z.
        from patchdiff_ai.patches.delta_apply import store_path

        filtered_base_df = state.filtered_dataframes.base
        ps_dir = self.ctx.settings.paths.patch_store_dir
        base_kb = state.KB.base
        platform_id = self.ctx.platform.name

        def _base_missing(row: dict) -> bool:
            return not (store_path(ps_dir, platform_id, row) / base_kb / row["name"]).exists()

        uncached = [s for s in subjects.iter_rows(named=True) if _base_missing(s)]
        if not uncached or filtered_base_df.is_empty():
            needed_rows: list[dict] = []
            if not uncached and not subjects.is_empty():
                log.info(
                    "winsxs_archive_skip",
                    reason="all base-KB outputs already in patch_store",
                    subjects=len(subjects),
                )
        else:
            needed = filtered_base_df.join(
                pl.DataFrame(uncached).select("name", "package", "arch", "pubkey"),
                on=["name", "package", "arch", "pubkey"],
                how="semi",
            )
            needed_rows = needed.to_dicts()

        async with self.ctx.platform.extract_baselines(needed_rows) as tmp:
            # Inside the with-block, rewrite filtered_base_df["path"] to
            # the absolute extracted location. patch_entry reads `path`
            # from the joined row exactly as before — the rewrite is
            # transparent to it.
            rewritten = filtered_base_df
            if needed_rows:
                rewritten = filtered_base_df.with_columns(
                    pl.col("path").map_elements(
                        lambda p: str((tmp / p).resolve()),
                        return_dtype=pl.Utf8,
                    )
                )

            results = []
            for row in subjects.iter_rows(named=True):
                try:
                    base, curr, prev = patch_entry(
                        self.ctx.tools.delta,
                        self.ctx.settings.paths.patch_store_dir,
                        row,
                        platform_id=platform_id,
                        base_kb=state.KB.base,
                        curr_kb=state.KB.current,
                        prev_kb=state.KB.previous,
                        prev_df=state.dataframes.previous,
                        filtered_base_df=rewritten,
                    )
                    patched = [x for x in [base, curr, prev] if x]
                    if patched:
                        results.append(pl.DataFrame([p.to_row() for p in patched]))
                except Exception as exc:
                    log.warning(
                        "patch_entry_failed",
                        error=str(exc),
                        name=row.get("name"),
                        package=row.get("package"),
                        arch=row.get("arch"),
                    )

        if results:
            patch_store_df = pl.concat(
                [patch_store_df, *results], how="vertical_relaxed"
            )
            try:
                safe_serialize(patch_store_df, patch_store_index)
            except Exception as exc:
                log.warning("patch_store_serialize_failed", error=str(exc))

        return subjects
