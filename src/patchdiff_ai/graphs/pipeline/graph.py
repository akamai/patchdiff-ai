"""Build the pipeline StateGraph."""

from __future__ import annotations

import pickle
from typing import Any

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph

from patchdiff_ai.graphs.pipeline.nodes import (
    make_cve_info_node,
    make_finalize_node,
    make_gather_node,
)
from patchdiff_ai.graphs.pipeline.routing import (
    PipelineNodeNames,
    PipelineRouter,
    Stage,
)
from patchdiff_ai.graphs.pipeline.state import PipelineState
from patchdiff_ai.graphs.platform_internals.graph import build_pi_graph
from patchdiff_ai.graphs.reverse_engineering.graph import build_re_graph
from patchdiff_ai.graphs.vulnerability_research.graph import build_vr_graph
from patchdiff_ai.runtime.app_context import AppContext


class _PickleSerde:
    """In-process pickle serde for MemorySaver.

    The default `JsonPlusSerializer` (ormsgpack) chokes on `PatchSources`
    fields holding `polars.DataFrame` / `Path`. The checkpointer is
    in-process only, so pickle round-trips them fine.
    """

    def dumps(self, obj: Any) -> bytes:
        return pickle.dumps(obj)

    def loads(self, data: bytes) -> Any:
        return pickle.loads(data)

    def dumps_typed(self, obj: Any) -> tuple[str, bytes]:
        return "pickle", pickle.dumps(obj)

    def loads_typed(self, data: tuple[str, bytes]) -> Any:
        return pickle.loads(data[1])


def build_pipeline_graph(
    ctx: AppContext,
    *,
    with_checkpointer: bool = False,
    gather_node: Any = None,
):
    """Build the pipeline StateGraph.

    `with_checkpointer=True` (interactive runs only) compiles with a
    MemorySaver — required for `Command(resume=...)` after `interrupt()`.
    `gather_node` lets the docs renderer inject a compiled gather
    subgraph for `xray=True`.
    """
    router = PipelineRouter(ctx)

    builder = StateGraph(PipelineState)
    builder.add_node(PipelineNodeNames.CVE_INFO, make_cve_info_node(ctx))
    # Thin delegator to `ctx.platform.gather_packages`.
    builder.add_node(
        PipelineNodeNames.GATHER,
        gather_node if gather_node is not None else make_gather_node(ctx),
    )
    builder.add_node(PipelineNodeNames.PI_AGENT, build_pi_graph(ctx))
    # Picks idalib vs legacy via `ctx.tools.idalib`.
    builder.add_node(PipelineNodeNames.RE_AGENT, build_re_graph(ctx))
    builder.add_node(PipelineNodeNames.VR_AGENT, build_vr_graph(ctx))
    builder.add_node(PipelineNodeNames.FINALIZE, make_finalize_node(ctx))

    builder.set_entry_point(PipelineNodeNames.CVE_INFO)
    builder.add_conditional_edges(
        PipelineNodeNames.CVE_INFO,
        router.from_cve_info,
        [PipelineNodeNames.GATHER, PipelineNodeNames.FINALIZE],
    )

    # gather -> platform-internals
    builder.add_edge(PipelineNodeNames.GATHER, PipelineNodeNames.PI_AGENT)

    # platform-internals -> Send(re_agent, ...) | finalize
    builder.add_conditional_edges(
        PipelineNodeNames.PI_AGENT,
        router.from_internals,
        [PipelineNodeNames.RE_AGENT, PipelineNodeNames.FINALIZE],
    )

    # re -> Send(vr_agent, ...) | finalize
    builder.add_conditional_edges(
        PipelineNodeNames.RE_AGENT,
        router.from_re,
        [PipelineNodeNames.VR_AGENT, PipelineNodeNames.FINALIZE],
    )

    builder.add_edge(PipelineNodeNames.VR_AGENT, PipelineNodeNames.FINALIZE)
    builder.add_edge(PipelineNodeNames.FINALIZE, END)

    # MemorySaver is required for `Command(resume=...)` after
    # `interrupt(...)`. Skipped non-interactively so per-step
    # serialisation (and the polars DataFrame round-trip) stays off.
    if with_checkpointer:
        return builder.compile(checkpointer=MemorySaver(serde=_PickleSerde()))
    return builder.compile()
