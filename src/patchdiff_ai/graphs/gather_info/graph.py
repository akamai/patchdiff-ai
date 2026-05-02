from __future__ import annotations

from langgraph.graph import END, StateGraph

from patchdiff_ai.graphs.gather_info.nodes import GatherNodes, make_nodes
from patchdiff_ai.graphs.gather_info.state import GatherInfoState
from patchdiff_ai.runtime.app_context import AppContext


def build_gather_graph(ctx: AppContext):
    download, index, add_file_info, add_file_info_if_needed, update_vector_store = make_nodes(ctx)

    builder = StateGraph(GatherInfoState)
    builder.add_node(GatherNodes.DOWNLOAD, download)
    builder.add_node(GatherNodes.INDEX, index)
    builder.add_node(GatherNodes.ADD_FILE_INFO, add_file_info)
    builder.add_node(GatherNodes.UPDATE_VS, update_vector_store)

    builder.set_entry_point(GatherNodes.DOWNLOAD)
    builder.add_edge(GatherNodes.DOWNLOAD, GatherNodes.INDEX)
    builder.add_conditional_edges(
        GatherNodes.INDEX,
        add_file_info_if_needed,
        [GatherNodes.ADD_FILE_INFO, GatherNodes.UPDATE_VS],
    )
    builder.add_edge(GatherNodes.ADD_FILE_INFO, GatherNodes.UPDATE_VS)
    builder.add_edge(GatherNodes.UPDATE_VS, END)

    return builder.compile()
