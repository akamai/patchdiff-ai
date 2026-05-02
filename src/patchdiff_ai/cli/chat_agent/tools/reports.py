"""`read_report`, `search_reports`, and the `show_report` passthrough display.

Thin shims over `ChromaQueryService` for the most common shapes; the
generic surface is `chroma_query` in `chroma.py`.
"""

from __future__ import annotations

from typing import Any

from patchdiff_ai.runtime.app_context import AppContext
from patchdiff_ai.tools.chroma_query import ChromaQueryService

from ..catalogue import ToolCatalogue


def register(cat: ToolCatalogue, ctx: AppContext, cve: str, chroma: ChromaQueryService) -> None:
    """Register `read_report`, `search_reports`, and `show_report` against `cat`."""

    def _read_report(model_name: str = "") -> dict[str, Any]:
        where: dict[str, Any] = (
            {"$and": [{"cve": cve}, {"model_name": model_name}]} if model_name
            else {"cve": cve}
        )
        return chroma.query("reports", where=where, include_documents=True)

    cat.register_native(
        "read_report",
        "Shortcut for `chroma_query(\"reports\", where={\"cve\": <current>}, "
        "include_documents=True)` — fetches RCA report(s) for THIS CVE into "
        "your context. For any cross-CVE / by-file / by-confidence / "
        "body-text query, use `chroma_query` directly (this shortcut can "
        "only filter by `model_name`).",
        {
            "type": "object",
            "properties": {"model_name": {"type": "string", "default": ""}},
            "required": [],
        },
        _read_report,
    )

    def _search_reports(query: str) -> dict[str, Any]:
        return chroma.query("reports", query=query, k=5, include_documents=True)

    cat.register_native(
        "search_reports",
        "Shortcut for `chroma_query(\"reports\", query=<q>, k=5, "
        "include_documents=True)` — semantic search across every cached "
        "CVE. Use `chroma_query` when you need to combine semantic search "
        "with metadata filters (e.g. only LPE reports, only shell32.dll, "
        "only the last week).",
        {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
        _search_reports,
    )

    def _load_report_for_display(model_name: str = "") -> str:
        result = _read_report(model_name)
        if result.get("kind") == "error":
            return f"[!] {result.get('error', 'query error')}"
        rows = result.get("data") or []
        if not rows:
            return f"No reports found for {cve}" + (
                f" with model_name={model_name!r}" if model_name else ""
            )
        out: list[str] = []
        for row in rows:
            meta = row.get("metadata") or {}
            out.append(f"## Report ({meta.get('model_name', '?')}) for {cve}")
            out.append(row.get("document", ""))
            out.append("")
        return "\n".join(out)

    cat.register_native(
        "show_report",
        "DISPLAY ONLY — print the cached RCA report(s) for the current CVE "
        "to the user's terminal verbatim. Use ONLY when the user explicitly "
        "wants to read the report themselves (e.g. 'show', 'print', "
        "'display'). The report body is NOT returned to you — you cannot "
        "summarise, quote, or analyse from it. For analysis intent use "
        "`read_report` (this CVE) or `chroma_query` (any filter).",
        {
            "type": "object",
            "properties": {"model_name": {"type": "string", "default": ""}},
            "required": [],
        },
        _load_report_for_display,
        passthrough=True,
    )
