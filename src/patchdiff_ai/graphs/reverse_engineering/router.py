"""RE router — picks a backend per candidate via `Platform.classify_candidate`.

Replaces the M2-era single-implementation `build_re_graph` as the
RE_AGENT entry. Every Send from the pipeline router (one per ranked
candidate) lands here; the conditional entry point asks the active
platform plugin which backend to use, then forwards the
`ReverseEngineeringState` straight into that backend's compiled
StateGraph.

Adding a new backend is additive:
  1. Create `<kind>_graph.py` with `build_<kind>_re_graph(ctx)`.
  2. Add an `RECategory.<KIND>` enum value in `platforms/base.py`.
  3. Register it in `_BACKENDS` below.
  4. Update `Platform.classify_candidate` (or `default_classify`) to
     return the new value for the relevant candidates.
"""

from __future__ import annotations

import structlog
from langgraph.graph import END, StateGraph

from patchdiff_ai.graphs.reverse_engineering.binary_graph import build_binary_re_graph
from patchdiff_ai.graphs.reverse_engineering.source_graph import build_source_re_graph
from patchdiff_ai.graphs.reverse_engineering.state import ReverseEngineeringState
from patchdiff_ai.platforms.base import RECategory, default_classify
from patchdiff_ai.runtime.app_context import AppContext
from patchdiff_ai.schemas.candidate import Candidate

log = structlog.get_logger(__name__)


def build_re_router_graph(ctx: AppContext):
    """Build the per-Send router. Replaces the legacy `build_re_graph`."""
    backends: dict[str, object] = {
        RECategory.BINARY.value: build_binary_re_graph(ctx),
        RECategory.SOURCE.value: build_source_re_graph(ctx),
    }

    def _classify(state: ReverseEngineeringState) -> str:
        # Build a thin Candidate from the patch_store entry so the
        # plugin's `classify_candidate` (and `default_classify`) sees a
        # consistent shape — even though only `name` is read today.
        candidate = Candidate(
            name=state.primary_file.name,
            package=state.primary_file.package,
        )
        if ctx.platform is not None:
            try:
                category = ctx.platform.classify_candidate(candidate)
            except Exception as exc:
                log.warning(
                    "classify_candidate_error",
                    platform=ctx.platform.name,
                    name=candidate.name,
                    error=str(exc),
                    fallback="binary",
                )
                category = RECategory.BINARY
        else:
            category = default_classify(candidate)

        log.debug(
            "re_routed",
            file=candidate.name,
            category=category.value,
        )
        return category.value

    builder = StateGraph(ReverseEngineeringState)
    for key, subgraph in backends.items():
        builder.add_node(key, subgraph)
        builder.add_edge(key, END)
    builder.set_conditional_entry_point(_classify, list(backends.keys()))
    return builder.compile()
