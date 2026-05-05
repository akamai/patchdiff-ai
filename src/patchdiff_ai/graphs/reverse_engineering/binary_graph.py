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
from langgraph.types import RetryPolicy

from patchdiff_ai.graphs.reverse_engineering.state import ReverseEngineeringState
from patchdiff_ai.runtime.app_context import AppContext
from patchdiff_ai.tools.idalib_pool import IdalibBinaryBusy


class BinaryReNodes:
    ANALYZE = "Analyze binaries"
    DIFF_AND_DECOMPILE = "Diff and decompile"


# When the IDB sidecars are held by another live IDA process, the pool
# raises `IdalibBinaryBusy`. LangGraph's retry policy yields the task
# back to the scheduler — other CVEs run during the backoff window, and
# this one re-runs once the holder releases. 10 attempts × up to 30s ≈
# 5 min worst case before the CVE actually fails.
_BUSY_RETRY = RetryPolicy(
    initial_interval=2.0,
    backoff_factor=2.0,
    max_interval=30.0,
    max_attempts=10,
    retry_on=IdalibBinaryBusy,
)


def build_binary_re_graph(ctx: AppContext):
    """Build the binary RE subgraph for the configured IDA install."""
    if ctx.tools.idalib is not None:
        from patchdiff_ai.graphs.reverse_engineering.nodes_idalib import make_nodes
    else:
        from patchdiff_ai.graphs.reverse_engineering.nodes import make_nodes

    analyze, diff_and_decompile = make_nodes(ctx)

    builder = StateGraph(ReverseEngineeringState)
    builder.add_node(BinaryReNodes.ANALYZE, analyze, retry_policy=_BUSY_RETRY)
    # Diff + decompile is one node so the live BinDiff (sqlite3-backed,
    # not pickleable) never crosses a checkpoint boundary.
    builder.add_node(
        BinaryReNodes.DIFF_AND_DECOMPILE,
        diff_and_decompile,
        retry_policy=_BUSY_RETRY,
    )

    builder.set_entry_point(BinaryReNodes.ANALYZE)
    builder.add_edge(BinaryReNodes.ANALYZE, BinaryReNodes.DIFF_AND_DECOMPILE)
    builder.add_edge(BinaryReNodes.DIFF_AND_DECOMPILE, END)

    return builder.compile()
