"""Read-only generic gateway over the three Chroma collections.

Mirrors `DataframeRegistry` ([tools/dataframe_query.py]): one `query()`
covers all access paths (exact ids, semantic, metadata filter), plus
`info()` for static-schema-plus-live-count discovery.

Schemas are hardcoded next to the collection names, sourced from the
three write sites:
  - reports     → graphs/vulnerability_research/nodes.py (in `generate`)
  - file_info   → graphs/gather_info/nodes.py:247
  - func_logic  → graphs/vulnerability_research/nodes.py
                  (in `_persist_func_logic`, called from `indexing`)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:
    from patchdiff_ai.persistence.vector_store import VectorStores


# Supported Chroma operators, surfaced in the malformed-where hint and
# the tool description.
_WHERE_OPS = "$eq, $ne, $in, $nin, $and, $or, $gt, $gte, $lt, $lte"
_WHERE_DOC_OPS = "$contains, $not_contains"


class ChromaQueryService:
    """Read-only gateway over the three Chroma collections."""

    _SCHEMAS: ClassVar[dict[str, dict[str, Any]]] = {
        "reports": {
            "attr": "reports",
            "description": "One row per (CVE × file × model × retry) RCA report.",
            "metadata_fields": [
                ("cve", "str", "e.g. 'CVE-2024-12345'"),
                ("kb", "str", "Microsoft KB number"),
                ("file", "str", "Source binary, e.g. 'shell32.dll'"),
                ("patch_store_uid", "str", "Stable patch_store row id"),
                ("confidence", "float", "0.0-1.0; report self-confidence"),
                ("change_count", "int", "Number of changed functions"),
                ("date", "float", "Unix epoch seconds"),
                ("model_name", "str", "Generating model"),
                ("cvss", "float", "MSRC base CVSS"),
            ],
            "schema_source": "graphs/vulnerability_research/nodes.py:279",
        },
        "file_info": {
            "attr": "file_info",
            "description": "One row per Windows binary; lowercased name+package+description.",
            "metadata_fields": [
                ("name", "str", "Lowercased filename"),
                ("package", "str", "Lowercased KB / package"),
                ("description", "str", "Lowercased free-text summary"),
            ],
            "schema_source": "graphs/gather_info/nodes.py:247",
        },
        "func_logic": {
            "attr": "func_logic",
            "description": (
                "One row per (CVE × file × function × patch wave) — embeds "
                "the unified diff between pre/post-patch decompilation. Use "
                "for semantic search across past patches: 'find functions "
                "whose patch shape resembles X'."
            ),
            "metadata_fields": [
                ("cve", "str", "e.g. 'CVE-2024-12345'"),
                ("file", "str", "Source binary, e.g. 'shell32.dll'"),
                ("address", "str", "Hex function address (post-patch), e.g. '1801A3F80'"),
                ("name", "str", "Function name (post-patch)"),
                ("kb", "str", "Current Microsoft KB"),
                ("previous_kb", "str", "Previous Microsoft KB (the version that was patched)"),
                ("patch_store_uid", "str", "Stable patch_store row id; joins with reports"),
                ("similarity", "float", "BinDiff similarity 0.0-1.0"),
                ("confidence", "float", "BinDiff confidence 0.0-1.0"),
            ],
            "schema_source": "graphs/vulnerability_research/nodes.py:_persist_func_logic",
        },
    }

    def __init__(self, stores: "VectorStores") -> None:
        self._stores = stores

    def names(self) -> list[str]:
        return list(self._SCHEMAS)

    def info(self) -> list[dict[str, Any]]:
        """Static schemas + live document counts."""
        out: list[dict[str, Any]] = []
        for name, schema in self._SCHEMAS.items():
            handle = getattr(self._stores, schema["attr"])
            try:
                # `_collection.count()` is the cheap path; private hop
                # but stable across chromadb 1.5.x.
                docs = int(handle._collection.count())
            except Exception:
                docs = 0
            out.append({
                "name": name,
                "description": schema["description"],
                "docs": docs,
                "metadata_fields": [
                    {"name": fn, "dtype": dt, "description": desc}
                    for fn, dt, desc in schema["metadata_fields"]
                ],
                "schema_source": schema["schema_source"],
            })
        return out

    def query(
        self,
        collection: str,
        *,
        where: dict[str, Any] | None = None,
        where_document: dict[str, Any] | None = None,
        query: str = "",
        k: int = 5,
        limit: int = 50,
        offset: int = 0,
        ids: list[str] | None = None,
        include_documents: bool = False,
    ) -> dict[str, Any]:
        """Three-mode dispatch:
          1. ids set         → handle.get(ids=ids, include=...)
          2. query non-empty → similarity_search_with_score(...)
          3. otherwise       → handle.get(where=..., where_document=..., limit, offset, include=...)
        """
        schema = self._SCHEMAS.get(collection)
        if schema is None:
            return {
                "kind": "error",
                "error": (
                    f"Unknown collection {collection!r}. Available: "
                    f"{list(self._SCHEMAS)}. Use list_collections() for schemas."
                ),
            }
        handle = getattr(self._stores, schema["attr"])

        include = ["metadatas"]
        if include_documents:
            include.append("documents")

        try:
            if ids:
                return self._mode_get_by_ids(collection, handle, ids, include)
            if query:
                return self._mode_semantic(
                    collection, handle, query, k, where, where_document, include_documents
                )
            return self._mode_filter(
                collection, handle, where, where_document, limit, offset, include
            )
        except Exception as exc:
            return self._wrap_error(collection, exc)

    @staticmethod
    def _mode_get_by_ids(
        collection: str,
        handle: Any,
        ids: list[str],
        include: list[str],
    ) -> dict[str, Any]:
        got = handle.get(ids=list(ids), include=include)
        rows = _flatten_get(got)
        return {
            "collection": collection,
            "mode": "get_by_ids",
            "n": len(rows),
            "data": rows,
        }

    @staticmethod
    def _mode_semantic(
        collection: str,
        handle: Any,
        query: str,
        k: int,
        where: dict[str, Any] | None,
        where_document: dict[str, Any] | None,
        include_documents: bool,
    ) -> dict[str, Any]:
        kwargs: dict[str, Any] = {"k": max(1, int(k))}
        if where:
            kwargs["filter"] = where
        if where_document:
            kwargs["where_document"] = where_document
        results = handle.similarity_search_with_score(query, **kwargs)
        rows: list[dict[str, Any]] = []
        for doc, score in results:
            row: dict[str, Any] = {
                "id": getattr(doc, "id", None) or doc.metadata.get("id"),
                "metadata": dict(doc.metadata or {}),
                "distance": float(score),
            }
            if include_documents:
                row["document"] = doc.page_content
            rows.append(row)
        return {
            "collection": collection,
            "mode": "semantic",
            "n": len(rows),
            "data": rows,
        }

    @staticmethod
    def _mode_filter(
        collection: str,
        handle: Any,
        where: dict[str, Any] | None,
        where_document: dict[str, Any] | None,
        limit: int,
        offset: int,
        include: list[str],
    ) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "limit": max(1, int(limit)),
            "offset": max(0, int(offset)),
            "include": include,
        }
        if where:
            kwargs["where"] = where
        if where_document:
            kwargs["where_document"] = where_document
        got = handle.get(**kwargs)
        rows = _flatten_get(got)
        return {
            "collection": collection,
            "mode": "filter",
            "n": len(rows),
            "data": rows,
        }

    @staticmethod
    def _wrap_error(collection: str, exc: Exception) -> dict[str, Any]:
        # `_wrap_error` is reached only for runtime query failures, so
        # the hint is always relevant.
        hint = (
            f"supported `where` operators: {_WHERE_OPS}; "
            f"for body text use where_document with {_WHERE_DOC_OPS}."
        )
        return {
            "kind": "error",
            "collection": collection,
            "error": f"{type(exc).__name__}: {exc}; {hint}",
        }


def _flatten_get(got: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert Chroma's column-oriented `.get()` return into row dicts."""
    ids = got.get("ids") or []
    metadatas = got.get("metadatas") or [None] * len(ids)
    documents = got.get("documents")  # may be None when not requested
    rows: list[dict[str, Any]] = []
    for i, rid in enumerate(ids):
        row: dict[str, Any] = {
            "id": rid,
            "metadata": dict(metadatas[i] or {}),
        }
        if documents is not None and i < len(documents):
            row["document"] = documents[i]
        rows.append(row)
    return rows


def build_chroma_query_service(stores: "VectorStores") -> ChromaQueryService:
    """Default service over the three known collections."""
    return ChromaQueryService(stores)
