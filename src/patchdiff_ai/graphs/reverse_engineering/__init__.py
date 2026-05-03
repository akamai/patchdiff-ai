"""RE subgraph package.

The pipeline-facing entry is `build_re_router_graph` (the router that
classifies each Send and dispatches to a backend). Backends live in
`binary_graph.py` (IDA + BinDiff) and `source_graph.py` (text udiff).
"""

from patchdiff_ai.graphs.reverse_engineering.binary_graph import build_binary_re_graph
from patchdiff_ai.graphs.reverse_engineering.router import build_re_router_graph
from patchdiff_ai.graphs.reverse_engineering.source_graph import build_source_re_graph
from patchdiff_ai.graphs.reverse_engineering.state import ReverseEngineeringState

__all__ = [
    "ReverseEngineeringState",
    "build_re_router_graph",
    "build_binary_re_graph",
    "build_source_re_graph",
]
