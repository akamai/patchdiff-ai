"""DataFrame tools — `list_dataframes`, `query_dataframe`, `show_dataframe_query`.

Generic SQL surface over the persisted DataFrames (patch_store, winsxs).
One tool + one query language instead of a new bespoke filter tool per
question.
"""

from __future__ import annotations

from typing import Any

from patchdiff_ai.runtime.app_context import AppContext
from patchdiff_ai.tools.dataframe_query import build_dataframe_registry

from ..catalogue import ToolCatalogue
from ..envelope import _stringify


_QUERY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "name": {
            "type": "string",
            "description": "Primary DataFrame name (see list_dataframes).",
        },
        "sql": {
            "type": "string",
            "description": "polars SQL. Blank → SELECT * LIMIT <limit>.",
            "default": "",
        },
        "limit": {
            "type": "integer",
            "description": "Default-mode row cap; ignored when sql is non-empty.",
            "default": 200,
        },
    },
    "required": ["name"],
}


def register(cat: ToolCatalogue, ctx: AppContext) -> None:
    """Register the dataframe tool trio against `cat`."""

    df_registry = build_dataframe_registry(ctx)

    def list_dataframes() -> list[dict[str, Any]]:
        """Catalogue of polars DataFrames available for query_dataframe."""
        return df_registry.info()

    cat.register_native(
        "list_dataframes",
        "List the polars DataFrames available for SQL queries via "
        "query_dataframe. Returns each table's name, on-disk path, row "
        "count, and column schema (name + dtype).",
        {"type": "object", "properties": {}, "required": []},
        list_dataframes,
        tags=["data", "schema"],
    )

    def query_dataframe(
        name: str, sql: str = "", limit: int = 200
    ) -> dict[str, Any]:
        """Run polars SQL against a registered DataFrame."""
        return df_registry.query(name, sql, limit)

    def _render_query_dataframe(raw: dict[str, Any]) -> str:
        """Render a query result as a wide polars table with a header line."""
        if not isinstance(raw, dict):
            return _stringify(raw)
        if raw.get("kind") == "error":
            return f"[!] {raw.get('error', 'query error')}"
        import polars as pl
        sql = raw.get("sql", "")
        data = raw.get("data") or []
        columns = raw.get("columns") or []
        header = f"sql: {sql}\nrows: {len(data)} × {len(columns)} cols\n"
        if not data:
            return header + "(no rows)"
        df = pl.DataFrame(data)
        if columns:
            # Match the executed projection order.
            existing = [c for c in columns if c in df.columns]
            if existing:
                df = df.select(existing)
        with pl.Config(tbl_width_chars=200, fmt_str_lengths=80, tbl_rows=-1):
            return header + str(df)

    cat.register_native(
        "query_dataframe",
        "Run a polars SQL query against a registered DataFrame and RETURN "
        "the rows TO YOU so you can inspect, filter, or reason about them. "
        "`name` is the primary table (use list_dataframes() to discover); "
        "all registered tables are reachable in one SQLContext so JOINs "
        "work. If `sql` is blank, runs `SELECT * FROM <name> LIMIT <limit>` "
        "as a convenience sample. polars SQL is read-only. Use this when "
        "you need to look at the data — for any 'find', 'count', 'check', "
        "'summarise', 'compare' style request. For pure 'show me / print "
        "the table' display requests, use `show_dataframe_query` instead "
        "(saves tokens). Returns {sql, columns, data} where `data` is a "
        "list of row dicts.",
        _QUERY_SCHEMA,
        query_dataframe,
        tags=["data", "sql"],
    )

    cat.register_native(
        "show_dataframe_query",
        "DISPLAY ONLY — run a polars SQL query and print the result table "
        "to the user's terminal verbatim. Same arguments as "
        "`query_dataframe`. Use ONLY when the user explicitly wants to see "
        "the rows themselves (e.g. 'show', 'print', 'list the table'). "
        "The rows are NOT returned to you — you cannot read individual "
        "values. You still see the row × column count in the summary so "
        "you can suggest follow-up queries. For any request that needs "
        "you to read or reason over the data, use `query_dataframe`.",
        _QUERY_SCHEMA,
        query_dataframe,
        tags=["data", "sql", "display"],
        passthrough=True,
        display=_render_query_dataframe,
    )
