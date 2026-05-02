"""Preview + on-demand body fetch.

Mirrors upstream's `_truncate_value` + `_output_cache` pattern
(ida_pro_mcp/rpc.py): preview inline, cache the full body, fetch
chunks via `read_result`.
"""

from __future__ import annotations

from typing import Any


_PREVIEW_ITEMS = 10
_PREVIEW_STR_LEN = 1000
_PREVIEW_DEPTH = 5
# Larger cap for top-level text returns so 3-5 KB listings inline
# whole; nested strings inside structured returns still trim at
# `_PREVIEW_STR_LEN`.
_TOP_LEVEL_STR_LEN = 6000
_RESULT_STORE_MAX = 8
# Per-`read_result` slice cap so one chunk can't blow the context budget.
_READ_RESULT_MAX_LENGTH = 8000


def _preview_value(value: Any, depth: int = 0) -> Any:
    """JSON-serialisable preview of `value` with bulky parts trimmed.

    - strings > `_PREVIEW_STR_LEN` → head + `"... [N chars total]"`
    - lists  > `_PREVIEW_ITEMS`    → head + `"[+M items more]"`
    - dicts                         → recurse, capped at `_PREVIEW_DEPTH`
    - tuples / sets                 → list rules
    """
    if depth >= _PREVIEW_DEPTH:
        return f"[truncated at depth {_PREVIEW_DEPTH}]"
    if isinstance(value, str):
        if len(value) <= _PREVIEW_STR_LEN:
            return value
        return value[:_PREVIEW_STR_LEN] + f"... [{len(value)} chars total]"
    if isinstance(value, dict):
        return {k: _preview_value(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        items = list(value)
        previewed = [_preview_value(v, depth + 1) for v in items[:_PREVIEW_ITEMS]]
        if len(items) > _PREVIEW_ITEMS:
            previewed.append(f"[+{len(items) - _PREVIEW_ITEMS} items more]")
        return previewed
    if isinstance(value, set):
        return _preview_value(list(value), depth)
    return value


class _PreviewResultStore:
    """FIFO cache of full tool-result bodies, capped at `_RESULT_STORE_MAX`."""

    def __init__(self, capacity: int = _RESULT_STORE_MAX) -> None:
        self._capacity = capacity
        self._store: dict[str, str] = {}

    def put(self, body: str) -> str:
        import uuid as _uuid

        result_id = _uuid.uuid4().hex[:12]
        self._store[result_id] = body
        # dict preserves insertion order → pop first = oldest.
        while len(self._store) > self._capacity:
            oldest = next(iter(self._store))
            del self._store[oldest]
        return result_id

    def get(self, result_id: str) -> str | None:
        return self._store.get(result_id)

    def __contains__(self, result_id: str) -> bool:
        return result_id in self._store
