"""Polars-SQL gateway over the project's on-disk DataFrames.

The pipeline persists a small number of polars DataFrames to disk:

  - `db/.patch_store_df` : master index of every binary across CVE runs
                           (PatchStoreEntry rows: name, path, kb, arch,
                           package, pubkey, version, hash, ms_id, uid).
  - `db/winsxs.bin`      : Windows side-by-side store index.

Higher-level callers (chat agent, debug subcommands, future MCP server)
expose these to LLMs / users via polars SQL. polars SQL is read-only by
construction — no Python eval, no DDL touches the underlying file. All
registered tables share one `SQLContext` per query so cross-table JOINs
work transparently. DataFrames deserialize lazily on first reference and
stay cached for the registry's lifetime.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

import polars as pl

if TYPE_CHECKING:
    from patchdiff_ai.runtime.app_context import AppContext


class DataframeRegistry:
    """Lazy-loading registry of on-disk polars DataFrames keyed by name.

    `specs` is `{name: path}`; entries whose file does not exist are
    silently dropped at construction so an empty `db/` doesn't make the
    catalogue blow up. `query()` registers every materialized DF into
    one `SQLContext` so cross-table JOINs work transparently.
    """

    def __init__(self, specs: dict[str, Path]) -> None:
        self._specs = {n: p for n, p in specs.items() if p.exists()}
        self._cache: dict[str, pl.DataFrame] = {}

    def names(self) -> list[str]:
        return list(self._specs)

    def info(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for name, path in self._specs.items():
            df = self._load(name)
            out.append({
                "name": name,
                "path": str(path),
                "n_rows": df.height,
                "n_columns": df.width,
                "columns": [
                    {"name": c, "dtype": str(df.schema[c])} for c in df.columns
                ],
            })
        return out

    def _load(self, name: str) -> pl.DataFrame:
        if name in self._cache:
            return self._cache[name]
        path = self._specs[name]
        df = pl.DataFrame.deserialize(path)
        self._cache[name] = df
        return df

    def query(self, name: str, sql: str, limit: int) -> dict[str, Any]:
        if name not in self._specs:
            return {
                "kind": "error",
                "error": (
                    f"Unknown dataframe {name!r}. Available: "
                    f"{sorted(self._specs)}. Use list_dataframes() to "
                    "see schemas."
                ),
            }
        # Materialize every registered DF into a single SQLContext so
        # callers can write JOINs across tables in one query without
        # having to declare them up front. Cached after first load.
        registered = {n: self._load(n) for n in self._specs}
        ctx = pl.SQLContext(registered, eager=True)
        # Default-mode: no SQL → sample the named table at `limit` rows.
        # When SQL is provided we trust it verbatim — the caller's
        # explicit LIMIT (if any) wins, and `limit` is ignored.
        sql = (sql or "").strip()
        if not sql:
            sql = f'SELECT * FROM "{name}" LIMIT {max(1, int(limit))}'
        result = ctx.execute(sql)
        # eager=True returns DataFrame, but be defensive in case a
        # future polars release flips the default.
        if isinstance(result, pl.LazyFrame):
            result = result.collect()
        # Return shape uses `data` (not `rows`) so the chat envelope's
        # Page[T] summarizer picks it up and reports kind=list, count=N.
        # Columns + sql ride alongside as metadata.
        return {
            "sql": sql,
            "columns": result.columns,
            "data": result.to_dicts(),
        }


def build_dataframe_registry(ctx: "AppContext") -> DataframeRegistry:
    """Default registry: on-disk DataFrames the pipeline persists.

    Includes the active platform's WinSxS DataFrame when one was
    selected for this run (chat starts after `run_cve` resolves a
    platform); otherwise just the patch_store index.
    """
    paths = ctx.settings.paths
    specs: dict[str, "Path"] = {
        "patch_store": paths.patch_store_index,
    }
    platform = getattr(ctx, "platform", None)
    if platform is not None:
        archive = getattr(platform, "_archive", None)
        if archive is not None and getattr(archive, "dataframe_path", None) is not None:
            specs["winsxs"] = archive.dataframe_path
    return DataframeRegistry(specs)
