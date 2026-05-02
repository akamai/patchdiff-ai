"""bindiff_* — read-only queries over the per-pair `.BinDiff` SQLite the pipeline produced.

Path convention: `{primary_path}.{secondary_kb}.BinDiff`. Goes deeper
than `list_changed_functions`: matches at similarity == 1.0,
unmatched functions on either side, basic-block-level matches, and
overall similarity stats. All read from disk — no new BinDiff runs.
"""

from __future__ import annotations

from typing import Any

from patchdiff_ai.tools.bindiff_query import BindiffQueryService

from ..catalogue import ToolCatalogue
from ..constants import _NO_ARTIFACTS_HINT


def register(cat: ToolCatalogue, artifacts: list[Any]) -> None:
    """Register every `bindiff_*` tool against `cat`."""

    bindiff_q = BindiffQueryService(artifacts)

    def _no_artifacts_envelope() -> dict[str, Any]:
        return {"kind": "error", "error": _NO_ARTIFACTS_HINT}

    def _bindiff_call(fn, /, **kwargs) -> Any:
        if not artifacts:
            return _no_artifacts_envelope()
        try:
            return fn(**kwargs)
        except (FileNotFoundError, ValueError) as exc:
            return {"kind": "error", "error": str(exc)}

    def bindiff_list_pairs() -> Any:
        if not artifacts:
            return _no_artifacts_envelope()
        return bindiff_q.list_pairs()

    cat.register_native(
        "bindiff_list_pairs",
        "List every binary pair this chat has BinDiff data for. Each row "
        "carries `file` (the primary binary name — the key for every other "
        "bindiff_* tool), `primary_kb` / `secondary_kb`, the `bindiff_path` "
        "on disk, and `exists` (the SQLite is reachable). Call before "
        "asking about matches if you're not sure which file is available.",
        {"type": "object", "properties": {}, "required": []},
        bindiff_list_pairs,
        tags=["reverse engineering", "binary"],
    )

    def bindiff_stats(file: str) -> Any:
        return _bindiff_call(bindiff_q.stats, file=file)

    cat.register_native(
        "bindiff_stats",
        "Per-pair similarity / match statistics for one binary: matched / "
        "unmatched function counts on each side, basic-block match count, "
        "the overall similarity + confidence numbers BinDiff stores in the "
        "metadata table, and similarity / confidence histogram buckets. "
        "Use as a sanity check before walking individual function matches.",
        {
            "type": "object",
            "properties": {
                "file": {
                    "type": "string",
                    "description": "Primary binary filename, e.g. 'shell32.dll'. See bindiff_list_pairs.",
                },
            },
            "required": ["file"],
        },
        bindiff_stats,
        tags=["reverse engineering", "binary"],
    )

    def bindiff_function_matches(
        file: str,
        min_similarity: float = 0.0,
        max_similarity: float = 1.0,
        min_confidence: float = 0.0,
        name_contains: str = "",
        address: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> Any:
        return _bindiff_call(
            bindiff_q.function_matches,
            file=file,
            min_similarity=min_similarity,
            max_similarity=max_similarity,
            min_confidence=min_confidence,
            name_contains=name_contains,
            address=address,
            limit=limit,
            offset=offset,
        )

    cat.register_native(
        "bindiff_function_matches",
        "Filtered, paginated view of every matched function in one pair. "
        "Goes BEYOND `list_changed_functions`: also returns matches at "
        "similarity == 1.0 (unchanged) when you don't constrain the range. "
        "Filter knobs: `min_similarity` / `max_similarity` (default full "
        "range), `min_confidence`, `name_contains` (substring against "
        "name1 OR name2, case-insensitive), `address` (hex; matches "
        "address1 OR address2). Returns {file, data, total, next_offset}; "
        "`data` rows have address1/2, name1/2, similarity, confidence. "
        "Sorted by ascending similarity then address.",
        {
            "type": "object",
            "properties": {
                "file": {"type": "string", "description": "Primary binary filename."},
                "min_similarity": {"type": "number", "default": 0.0},
                "max_similarity": {"type": "number", "default": 1.0},
                "min_confidence": {"type": "number", "default": 0.0},
                "name_contains": {"type": "string", "default": ""},
                "address": {
                    "type": "string",
                    "description": "Hex address (with or without 0x); matches either side.",
                    "default": "",
                },
                "limit": {"type": "integer", "default": 100},
                "offset": {"type": "integer", "default": 0},
            },
            "required": ["file"],
        },
        bindiff_function_matches,
        tags=["reverse engineering", "binary"],
    )

    def bindiff_unmatched(
        file: str,
        side: str = "both",
        limit: int = 100,
        offset: int = 0,
    ) -> Any:
        return _bindiff_call(
            bindiff_q.unmatched,
            file=file,
            side=side,
            limit=limit,
            offset=offset,
        )

    cat.register_native(
        "bindiff_unmatched",
        "List functions present in one program but not matched in the "
        "other — the BinDiff dropouts. `side` is 'primary' (post-patch "
        "additions), 'secondary' (pre-patch removals), or 'both' "
        "(default). Heavier than other bindiff_* tools because it loads "
        "the per-side BinExport on first call (cached for the chat "
        "session). Returns {file, side, data: [{address, name, side}], "
        "total, next_offset}.",
        {
            "type": "object",
            "properties": {
                "file": {"type": "string", "description": "Primary binary filename."},
                "side": {
                    "type": "string",
                    "enum": ["primary", "secondary", "both"],
                    "default": "both",
                },
                "limit": {"type": "integer", "default": 100},
                "offset": {"type": "integer", "default": 0},
            },
            "required": ["file"],
        },
        bindiff_unmatched,
        tags=["reverse engineering", "binary"],
    )

    def bindiff_basic_blocks(file: str, function_address: str) -> Any:
        return _bindiff_call(
            bindiff_q.basic_blocks,
            file=file,
            function_address=function_address,
        )

    cat.register_native(
        "bindiff_basic_blocks",
        "Basic-block matches inside one function pair. `function_address` "
        "is the primary-side hex address (use `bindiff_function_matches` "
        "or `list_changed_functions` to find one). Loads the BinExport "
        "for both sides on first call (cached). Returns {file, function: "
        "{address1/2, name1/2, similarity, confidence}, data: [{address1, "
        "address2, algorithm}], total} — pair this with show_diff to "
        "correlate matched BBs against the source-level diff.",
        {
            "type": "object",
            "properties": {
                "file": {"type": "string", "description": "Primary binary filename."},
                "function_address": {
                    "type": "string",
                    "description": "Hex address (with or without 0x) of the function in primary.",
                },
            },
            "required": ["file", "function_address"],
        },
        bindiff_basic_blocks,
        tags=["reverse engineering", "binary"],
    )
