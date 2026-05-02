"""`read_result` — chunk reader for the per-session preview cache."""

from __future__ import annotations

from typing import Any

from ..catalogue import ToolCatalogue
from ..preview import _READ_RESULT_MAX_LENGTH


def register(cat: ToolCatalogue) -> None:
    """Register `read_result` against `cat`."""

    def read_result(result_id: str, offset: int = 0, length: int = 4000) -> Any:
        """Read a chunk of a previously cached tool result body."""
        body = cat.get_result(result_id)
        if body is None:
            return {
                "kind": "error",
                "error": (
                    f"Result {result_id!r} is not in the cache (evicted, "
                    "expired, or never stored). Re-run the original tool "
                    "to get a fresh result_id."
                ),
            }
        # Negative offset / length → 0; length clamped to the per-call cap.
        offset = max(0, int(offset))
        length = max(0, min(int(length), _READ_RESULT_MAX_LENGTH))
        chunk = body[offset : offset + length]
        end = offset + len(chunk)
        eof = end >= len(body)
        return {
            "kind": "chunk",
            "result_id": result_id,
            "offset": offset,
            "length": len(chunk),
            "next_offset": None if eof else end,
            "total_bytes": len(body),
            "eof": eof,
            "chunk": chunk,
        }

    cat.register_native(
        "read_result",
        "Read a chunk of a cached tool result body. Use the `result_id` "
        "from a previous call's `summary.result_id`; pass `offset` (0 to "
        "start) and `length` (default 4000, max "
        f"{_READ_RESULT_MAX_LENGTH}). Returns "
        "{result_id, offset, length, next_offset, total_bytes, eof, "
        "chunk}; resume reading by passing `next_offset` until `eof` is "
        "true. Most questions are answerable from the preview alone — "
        "only call this when you specifically need body content the "
        "preview doesn't show.",
        {
            "type": "object",
            "properties": {
                "result_id": {"type": "string"},
                "offset": {"type": "integer", "default": 0},
                "length": {"type": "integer", "default": 4000},
            },
            "required": ["result_id"],
        },
        read_result,
    )
