"""Tiny generic StateGraph factory used by ad-hoc subgraphs."""

from __future__ import annotations

from typing import Any, Sequence

from langgraph.graph import END, StateGraph


def build_state_graph(
    name: str,
    schema: type,
    nodes: dict[str, Any],
    edges: Sequence[tuple[str, str]],
    entry_point: str,
    finish_points: Sequence[str] | None = None,
):
    builder = StateGraph(schema)
    for node_name, fn in nodes.items():
        builder.add_node(node_name, fn)
    for src, dst in edges:
        builder.add_edge(src, dst)
    builder.set_entry_point(entry_point)
    for fp in finish_points or []:
        builder.add_edge(fp, END)
    return builder.compile()
