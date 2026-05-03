"""Source RE backend — text udiff for non-binary candidates.

One of N backends the M3 RE router dispatches to. Selected when
`Platform.classify_candidate` returns `RECategory.SOURCE` (e.g. C
sources from a Linux distro source-package diff, Python files, kernel
patches).

What it does:
  * Reads `state.primary_file.path` (post-patch source) and
    `state.secondary_file.path` (pre-patch source) directly off disk.
  * Treats the whole file as one "function" (M3 starting point —
    language-aware splitting via tree-sitter / regex is left as a
    follow-up; the schema and VR support multiple FunctionMatchRefs
    per Artifact already).
  * Writes `<artifact_dir>/__funcs__/<identifier>.txt` for both sides
    so VR's diff-reading code path stays uniform across backends.
  * Emits one `Artifact` with one `FunctionMatchRef(identifier=...,
    extension="txt")` whose hex-address fields stay 0 (not meaningful
    here — VR's `primary_key` / `secondary_key` falls back to
    `identifier`).

Topology: single node `DIFF_SOURCES → END`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import structlog
from langgraph.graph import END, StateGraph

from patchdiff_ai.graphs.reverse_engineering.state import ReverseEngineeringState
from patchdiff_ai.runtime.app_context import AppContext
from patchdiff_ai.schemas.analysis import Artifact, FunctionMatchRef

log = structlog.get_logger(__name__)


class SourceReNodes:
    DIFF_SOURCES = "Diff source files"


def make_source_nodes(ctx: AppContext):
    async def diff_sources(state: ReverseEngineeringState) -> dict[str, Any]:
        primary_path = Path(state.primary_file.path)
        secondary_path = Path(state.secondary_file.path)

        if not primary_path.is_file() or not secondary_path.is_file():
            log.warning(
                "source_re_missing_file",
                primary=str(primary_path),
                secondary=str(secondary_path),
                primary_exists=primary_path.is_file(),
                secondary_exists=secondary_path.is_file(),
            )
            return {"artifacts": []}

        # Identifier = the source filename without extension (`tcp_ipv4.c`
        # → `tcp_ipv4`). Stable across pre/post pair so VR's lookup
        # finds both sides of the diff.
        identifier = primary_path.stem

        # Mirror the binary backend's on-disk layout: VR reads
        # `<artifact.primary_file.path>.parent / "__funcs__" / "<key>.<ext>"`.
        primary_dir = primary_path.parent / "__funcs__"
        secondary_dir = secondary_path.parent / "__funcs__"
        primary_dir.mkdir(parents=True, exist_ok=True)
        secondary_dir.mkdir(parents=True, exist_ok=True)

        try:
            primary_text = primary_path.read_text(encoding="utf-8", errors="replace")
            secondary_text = secondary_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            log.warning("source_re_read_failed", error=str(exc))
            return {"artifacts": []}

        # If pre and post are identical there's nothing to feed VR.
        if primary_text == secondary_text:
            log.info("source_re_no_change", file=primary_path.name)
            return {"artifacts": []}

        (primary_dir / f"{identifier}.txt").write_text(primary_text, encoding="utf-8")
        (secondary_dir / f"{identifier}.txt").write_text(secondary_text, encoding="utf-8")

        match = FunctionMatchRef(
            name1=primary_path.name,
            name2=secondary_path.name,
            identifier=identifier,
            extension="txt",
            # address1 / address2 / similarity / confidence stay at 0
            # — the binary-only metrics. VR's `primary_key` /
            # `secondary_key` ignores them when `identifier` is set.
        )

        artifact = Artifact(
            primary_file=state.primary_file,
            secondary_file=state.secondary_file,
            changed=[match],
        )
        log.info(
            "source_re_artifact_emitted",
            file=primary_path.name,
            identifier=identifier,
        )
        return {"artifacts": [artifact]}

    return diff_sources


def build_source_re_graph(ctx: AppContext):
    """Build the source RE subgraph (single-node text-diff backend)."""
    diff_sources = make_source_nodes(ctx)

    builder = StateGraph(ReverseEngineeringState)
    builder.add_node(SourceReNodes.DIFF_SOURCES, diff_sources)
    builder.set_entry_point(SourceReNodes.DIFF_SOURCES)
    builder.add_edge(SourceReNodes.DIFF_SOURCES, END)
    return builder.compile()
