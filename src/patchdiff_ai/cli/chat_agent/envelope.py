"""Result envelope: uniform `{summary, result}` shape for every tool call.

Upstream ida-pro-mcp tools return diverse shapes (lists, `Page[T]`,
`{cursor, more, total, truncated, limit_reason}`). `_extract_summary`
maps each known shape onto common keys so the agent only sees one.
"""

from __future__ import annotations

import json
from typing import Any


def _stringify(value: Any) -> str:
    try:
        return json.dumps(value, default=str)
    except Exception:
        return str(value)


def _extract_summary(name: str, result: Any) -> dict[str, Any]:
    """Build a uniform summary dict from a tool's raw return.

    Keys (all optional except `kind`):
      kind         — list | object | text | empty | error
      count        — items in this response
      total        — total available when upstream reports it
      next_offset  — pagination cursor; null = done
      more         — fallback when cursor isn't numeric
      truncated    — upstream itself truncated
      limit_reason — short reason for `truncated`
    """
    if result is None:
        return {"kind": "empty", "count": 0}

    if isinstance(result, str):
        return {"kind": "text", "count": 1, "chars": len(result)}

    if isinstance(result, list):
        return _summarize_list(result)

    if isinstance(result, dict):
        return _summarize_dict(result)

    # Bool / int / float / TypedDict-as-mapping fallback.
    return {"kind": "object", "count": 1}


def _summarize_list(result: list[Any]) -> dict[str, Any]:
    """Summarize a list-shaped return.

    Recognised per-entry shapes:
      Page[T]                — list_funcs, func_query, entity_query, …
      {xrefs|callees, more}  — xrefs_to, callees
      {matches, n, cursor}   — find_bytes, find
      {blocks, total_blocks} — basic_blocks
      {nodes, edges}         — callgraph
    Plain lists of records fall through to count-only.
    """
    summary: dict[str, Any] = {"kind": "list"}
    if not result:
        summary["count"] = 0
        return summary

    if all(isinstance(p, dict) for p in result):
        # Page[T] / FunctionQueryPage / EntityQueryPage / …
        if any("data" in p and isinstance(p.get("data"), list) for p in result):
            count = sum(len(p["data"]) for p in result if isinstance(p.get("data"), list))
            next_offsets = [p.get("next_offset") for p in result if p.get("next_offset") is not None]
            totals = [p.get("total") for p in result if isinstance(p.get("total"), int)]
            summary.update({
                "count": count,
                "pages": len(result),
            })
            if next_offsets:
                summary["next_offset"] = next_offsets[0]
            if totals:
                summary["total"] = sum(totals)
            return summary

        # `{xrefs|callees, more}` per target.
        for key in ("xrefs", "callees"):
            if any(key in p for p in result):
                items = sum(
                    len(p[key]) for p in result
                    if isinstance(p.get(key), list)
                )
                more = any(bool(p.get("more")) for p in result)
                summary.update({"count": items, "targets": len(result), "more": more})
                return summary

        # `{matches, n|count, cursor}` per target.
        if any("matches" in p and isinstance(p.get("matches"), list) for p in result):
            count = sum(
                len(p["matches"]) for p in result
                if isinstance(p.get("matches"), list)
            )
            cursors = [p.get("cursor") for p in result if isinstance(p.get("cursor"), dict)]
            summary["count"] = count
            summary["targets"] = len(result)
            next_off = _cursor_next(cursors[0]) if cursors else None
            if next_off is not None:
                summary["next_offset"] = next_off
            return summary

        # `{blocks, count, total_blocks}` per target (basic_blocks).
        if any("blocks" in p for p in result):
            count = sum(
                len(p.get("blocks") or []) for p in result
            )
            totals = [p.get("total_blocks") for p in result if isinstance(p.get("total_blocks"), int)]
            summary["count"] = count
            summary["targets"] = len(result)
            if totals:
                summary["total"] = sum(totals)
            return summary

        # `{nodes, edges, truncated}` per root (callgraph).
        if any("nodes" in p and "edges" in p for p in result):
            nodes = sum(
                len(p.get("nodes") or []) for p in result
            )
            edges = sum(
                len(p.get("edges") or []) for p in result
            )
            truncated = any(bool(p.get("truncated")) for p in result)
            limit_reasons = [p.get("limit_reason") for p in result if p.get("limit_reason")]
            summary.update({
                "count": nodes,
                "edges": edges,
                "roots": len(result),
                "truncated": truncated,
            })
            if limit_reasons:
                summary["limit_reason"] = limit_reasons[0]
            return summary

    summary["count"] = len(result)
    return summary


def _summarize_dict(result: dict[str, Any]) -> dict[str, Any]:
    """Summarize a dict-shaped return.

    Probes known fields in priority order; falls back to `kind=object, count=1`.
    """
    summary: dict[str, Any] = {"kind": "object"}

    # Single-page Page[T]: `{data, next_offset}`.
    if isinstance(result.get("data"), list):
        summary["kind"] = "list"
        summary["count"] = len(result["data"])
        if isinstance(result.get("total"), int):
            summary["total"] = result["total"]
        if result.get("next_offset") is not None:
            summary["next_offset"] = result["next_offset"]
        return summary

    # find_regex / search_text: `{n, matches|hits, cursor}`.
    for items_key in ("matches", "hits"):
        if isinstance(result.get(items_key), list):
            summary["kind"] = "list"
            summary["count"] = result.get("n") or result.get("count") or len(result[items_key])
            cursor_next = _cursor_next(result.get("cursor"))
            if cursor_next is not None:
                summary["next_offset"] = cursor_next
            return summary

    # disasm: `{asm, instruction_count, total_instructions, cursor}`.
    if "instruction_count" in result:
        summary["kind"] = "list"
        summary["count"] = result.get("instruction_count")
        if isinstance(result.get("total_instructions"), int):
            summary["total"] = result["total_instructions"]
        cursor_next = _cursor_next(result.get("cursor"))
        if cursor_next is not None:
            summary["next_offset"] = cursor_next
        return summary

    # insn_query: `{count, cursor, scanned, truncated}`.
    if "cursor" in result and "count" in result:
        summary["kind"] = "list"
        summary["count"] = result.get("count")
        cursor_next = _cursor_next(result.get("cursor"))
        if cursor_next is not None:
            summary["next_offset"] = cursor_next
        if result.get("truncated"):
            summary["truncated"] = True
        return summary

    # Single-object with optional error (idalib_open, idalib_current, …).
    if "error" in result and result["error"]:
        summary["kind"] = "error"
        summary["error"] = str(result["error"])[:200]
        return summary

    summary["count"] = 1
    return summary


def _cursor_next(cursor: Any) -> int | None:
    """Extract the int next_offset from `{"next": int}` or `{"done": True}`."""
    if not isinstance(cursor, dict):
        return None
    nxt = cursor.get("next")
    if isinstance(nxt, int):
        return nxt
    return None


def _build_hint(summary: dict[str, Any]) -> str:
    """One-line follow-up guidance derived from the summary."""
    if summary.get("kind") == "error":
        return ""
    if summary.get("preview_truncated"):
        rid = summary.get("result_id")
        if rid:
            return (
                f"Body was {summary.get('bytes_total')} chars; preview "
                f"shows scalar metadata + first 10 items per list / 1000 "
                f"chars per string. Use "
                f'read_result("{rid}", offset=0, length=4000) only if '
                f"you need body content the preview doesn't show."
            )
        return (
            f"Body was {summary.get('bytes_total')} chars; preview "
            f"shows the trimmed structure."
        )
    if summary.get("next_offset") is not None:
        total = summary.get("total")
        count = summary.get("count")
        if isinstance(total, int) and isinstance(count, int):
            return (
                f"{count} of {total} items shown; pass "
                f"offset={summary['next_offset']} to fetch the next page."
            )
        return f"More results available; pass offset={summary['next_offset']}."
    if summary.get("more"):
        return "More results available; raise the per-target `limit` to see them."
    if summary.get("truncated"):
        reason = summary.get("limit_reason") or "upstream limit reached"
        return f"Upstream truncated ({reason}); raise its limit args if you need more."
    return ""


def _format_envelope(summary: dict[str, Any], body_text: str | None) -> str:
    """JSON-encode `{summary, result}`, splicing pre-encoded bodies verbatim.

    `body_text` is already JSON for structured tools or a plain string
    for text tools; splicing avoids double-encoding. `None` body → error
    or empty.
    """
    summary_json = json.dumps(summary, default=str)
    if body_text is None:
        return '{"summary":' + summary_json + ',"result":null}'
    if not body_text:
        return '{"summary":' + summary_json + ',"result":""}'
    if _looks_like_json(body_text):
        return '{"summary":' + summary_json + ',"result":' + body_text + '}'
    # Plain text → quote so the envelope stays valid JSON.
    return (
        '{"summary":' + summary_json
        + ',"result":' + json.dumps(body_text) + '}'
    )


def _looks_like_json(text: str) -> bool:
    """Heuristic: does the string start with a JSON structural token?

    A false negative just quotes the body as a string — still valid envelope.
    """
    if not text:
        return False
    head = text.lstrip()[:1]
    return head in ("{", "[", '"', "t", "f", "n") or head.isdigit() or head == "-"
