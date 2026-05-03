"""Binary RE backend (PE / ELF / Mach-O via IDA + BinDiff).

One of N backends the M3 RE router (`router.py`) dispatches to. Picks
between two `make_nodes` implementations at build time:

  * idalib-backed (preferred) — drives idalib directly via `IdalibPool`.
    Selected when `ctx.tools.idalib is not None`.
  * idat-subprocess (legacy fallback) — spawns `idat.exe -A -S<script>`
    per pair. Selected when idalib isn't activated (IDA 8.x setups).

The two flows produce identical artefact shapes (`<binary>.BinExport`,
`<primary>.<secondary_kb>.BinDiff`, `__funcs__/<ea>.c`) so VR is
agnostic.
"""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from patchdiff_ai.graphs.reverse_engineering.state import ReverseEngineeringState
from patchdiff_ai.runtime.app_context import AppContext


class BinaryReNodes:
    ANALYZE = "Analyze binaries"
    DIFF_AND_DECOMPILE = "Diff and decompile"


def build_binary_re_graph(ctx: AppContext):
    """Build the binary RE subgraph for the configured IDA install."""
    if ctx.tools.idalib is not None:
        from patchdiff_ai.graphs.reverse_engineering.nodes_idalib import make_nodes
    else:
        from patchdiff_ai.graphs.reverse_engineering.nodes import make_nodes

    analyze, diff_and_decompile = make_nodes(ctx)

    builder = StateGraph(ReverseEngineeringState)
    builder.add_node(BinaryReNodes.ANALYZE, analyze)
    # Diff + decompile is one node so the live BinDiff (sqlite3-backed,
    # not pickleable) never crosses a checkpoint boundary.
    builder.add_node(BinaryReNodes.DIFF_AND_DECOMPILE, diff_and_decompile)

    builder.set_entry_point(BinaryReNodes.ANALYZE)
    builder.add_edge(BinaryReNodes.ANALYZE, BinaryReNodes.DIFF_AND_DECOMPILE)
    builder.add_edge(BinaryReNodes.DIFF_AND_DECOMPILE, END)

    return builder.compile()
