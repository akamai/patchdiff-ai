from __future__ import annotations

from langgraph.graph import END, StateGraph

from patchdiff_ai.graphs.platform_internals.nodes import PiNodes, make_nodes
from patchdiff_ai.graphs.platform_internals.state import PlatformInternalsState
from patchdiff_ai.runtime.app_context import AppContext


def build_pi_graph(ctx: AppContext):
    collect, rank, user_refinement, refinement_router = make_nodes(ctx)

    builder = StateGraph(PlatformInternalsState)
    builder.add_node(PiNodes.COLLECT, collect)
    builder.add_node(PiNodes.RANK, rank)
    builder.add_node(PiNodes.USER_REFINEMENT, user_refinement)

    builder.set_entry_point(PiNodes.COLLECT)
    builder.add_edge(PiNodes.COLLECT, PiNodes.RANK)
    builder.add_conditional_edges(
        PiNodes.RANK, refinement_router, [PiNodes.USER_REFINEMENT, END]
    )
    builder.add_edge(PiNodes.USER_REFINEMENT, END)

    return builder.compile()
