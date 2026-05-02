"""Generic Chroma surface — `list_collections` + `chroma_query`."""

from __future__ import annotations

from typing import Any

from patchdiff_ai.tools.chroma_query import ChromaQueryService

from ..catalogue import ToolCatalogue


_CHROMA_QUERY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "collection": {
            "type": "string",
            "description": "One of reports | file_info | func_logic. Use list_collections to discover.",
        },
        "where": {
            "type": "object",
            "description": (
                "Chroma metadata filter. Operators: $eq (implicit; "
                "{field: value} == {field: {$eq: value}}), $ne, $in, "
                "$nin, $and, $or, $gt, $gte, $lt, $lte. Example: "
                "{\"$and\": [{\"cve\": \"CVE-...\"}, {\"confidence\": "
                "{\"$gte\": 0.7}}]}."
            ),
            "default": None,
        },
        "where_document": {
            "type": "object",
            "description": (
                "Body-text filter. Operators: $contains, $not_contains. "
                "Example: {\"$contains\": \"use-after-free\"}."
            ),
            "default": None,
        },
        "query": {
            "type": "string",
            "description": (
                "Non-empty → semantic search; `where` and "
                "`where_document` apply as filters. Empty → metadata "
                "filter only."
            ),
            "default": "",
        },
        "k": {
            "type": "integer",
            "description": "Top-k for semantic mode.",
            "default": 5,
        },
        "limit": {
            "type": "integer",
            "description": "Row cap for filter mode.",
            "default": 50,
        },
        "offset": {
            "type": "integer",
            "description": "Pagination offset for filter mode.",
            "default": 0,
        },
        "ids": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Exact-id lookup; takes precedence over query/where.",
            "default": None,
        },
        "include_documents": {
            "type": "boolean",
            "description": (
                "False (default) → metadata-only rows; cheap, ideal for "
                "listing/filtering. True → include the full document body."
            ),
            "default": False,
        },
    },
    "required": ["collection"],
}


def register(cat: ToolCatalogue, chroma: ChromaQueryService) -> None:
    """Register `list_collections` and `chroma_query` against `cat`."""

    def list_collections() -> list[dict[str, Any]]:
        """Schemas + live counts for the three Chroma collections."""
        return chroma.info()

    cat.register_native(
        "list_collections",
        "Schema catalogue for the three Chroma collections reachable from "
        "chroma_query (reports, file_info, func_logic). Each entry: name, "
        "description, live document count, metadata fields with dtypes + "
        "descriptions, and the source file where the schema is defined. "
        "Call this before constructing a non-trivial `chroma_query` "
        "`where` clause if you're not sure which fields exist.",
        {"type": "object", "properties": {}, "required": []},
        list_collections,
        tags=["search", "vector-store", "schema"],
    )

    def chroma_query(
        collection: str,
        where: dict[str, Any] | None = None,
        where_document: dict[str, Any] | None = None,
        query: str = "",
        k: int = 5,
        limit: int = 50,
        offset: int = 0,
        ids: list[str] | None = None,
        include_documents: bool = False,
    ) -> dict[str, Any]:
        return chroma.query(
            collection,
            where=where,
            where_document=where_document,
            query=query,
            k=k,
            limit=limit,
            offset=offset,
            ids=ids,
            include_documents=include_documents,
        )

    cat.register_native(
        "chroma_query",
        "Generic read-only query over the three Chroma collections. Three "
        "modes — exact ids, semantic search (when `query` is non-empty), or "
        "metadata filter (default). Returns {collection, mode, n, data: "
        "[{id, metadata, [document], [distance]}]}. DEFAULT IS METADATA-"
        "ONLY: pass include_documents=True only when you need body text. "
        "Prefer this over read_report / search_reports whenever you need "
        "to filter, list, or cross-reference reports — they only handle "
        "the bare {cve: <current>} / pure-semantic cases.",
        _CHROMA_QUERY_SCHEMA,
        chroma_query,
        tags=["search", "vector-store"],
    )
