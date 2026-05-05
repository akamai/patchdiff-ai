"""Gather-info nodes: download/extract KBs, index files, embed file descriptions."""

from __future__ import annotations

import asyncio
import json
import uuid
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any

import polars as pl
import structlog
from langchain_core.documents import Document
from langchain_core.messages import SystemMessage
from langchain_core.prompts import ChatPromptTemplate, HumanMessagePromptTemplate
from langgraph.constants import Send
from pydantic import BaseModel, Field, ValidationError

from patchdiff_ai.platforms.windows.gather_info.state import GatherInfoState
from patchdiff_ai.llm.catalog import ModelPurpose
from patchdiff_ai.llm.retry import resilient
from patchdiff_ai.patches.extractor import extract_kb, extraction_marker, load_delta_dlls
from patchdiff_ai.patches.files_collection import (
    file_desc,
    filter_executables,
    get_report,
    get_update_dataframe,
)
from patchdiff_ai.patches.kb_downloader import download_kb
from patchdiff_ai.prompts.registry import PromptId, PromptRegistry
from patchdiff_ai.runtime.app_context import AppContext
from patchdiff_ai.runtime.timer import Timer

log = structlog.get_logger(__name__)

# Files described per LLM call. ~15 keeps the structured-output response
# well under any provider's output cap (15 × 80 tokens ≈ 1.2k completion)
# while cutting request count by an order of magnitude vs. the legacy
# one-call-per-file fan-out.
BATCH_SIZE = 15

# Per-`name` asyncio locks coalesce concurrent description requests for
# the same file across batch CVE runs. The first batch holding the lock
# pays the LLM call; later batches block on the lock, re-check the store
# after release, and short-circuit. Coalescing is per-file even though
# the LLM call is per-batch — different batches may overlap on names in
# multi-CVE runs that share KB content.
_file_info_locks: dict[str, asyncio.Lock] = {}
_file_info_locks_guard = asyncio.Lock()


async def _file_info_lock_for(name: str) -> asyncio.Lock:
    async with _file_info_locks_guard:
        lock = _file_info_locks.get(name)
        if lock is None:
            lock = asyncio.Lock()
            _file_info_locks[name] = lock
        return lock


class GatherNodes:
    DOWNLOAD = "Download & extract updates"
    INDEX = "Indexing"
    ADD_FILE_INFO = "Add to file info store"
    UPDATE_VS = "Update vectorstore"


class _FileDesc(BaseModel):
    name: str
    description: str = Field(description="One paragraph, max ~80 tokens.")


class _FileDescBatch(BaseModel):
    files: list[_FileDesc]


def _build_desc_prompt() -> ChatPromptTemplate:
    system = PromptRegistry.default().get(PromptId.WINDOWS_FILE_DESC)
    return ChatPromptTemplate(
        input_variables=["files"],
        messages=[
            SystemMessage(system),
            HumanMessagePromptTemplate.from_template("{files}"),
        ],
    )


def make_nodes(ctx: AppContext):
    desc_prompt = _build_desc_prompt()
    semaphore = asyncio.Semaphore(ctx.settings.concurrency.file_info_semaphore)

    async def download(state: GatherInfoState) -> dict[str, Any]:
        log.info(
            "download_kbs",
            current=state.KB.current,
            previous=state.KB.previous,
        )

        async with Timer("download_kbs"):
            curr_t = asyncio.create_task(
                download_kb(ctx, state.KB.current, state.os.name, ctx.settings.paths.temp_dir, False)
            )
            prev_t = asyncio.create_task(
                download_kb(ctx, state.KB.previous, state.os.name, ctx.settings.paths.temp_dir, False)
            )
            curr, prev = await asyncio.gather(curr_t, prev_t)
        # Either the .msu is on disk, or a prior run already committed
        # the extraction (in which case the .msu was deleted to save
        # space). Both states are valid for proceeding to extract_kb.
        for kb in (curr, prev):
            if not (kb.exists() or extraction_marker(kb).exists()):
                raise RuntimeError("KB download failed")

        async with Timer("extract_kbs"):
            await asyncio.gather(extract_kb(ctx, prev), extract_kb(ctx, curr))
        load_delta_dlls(ctx.tools.delta, [prev, curr])

        return {
            "extracted": state.extracted.model_copy(
                update={
                    "previous": prev.parent / f"extracted_{prev.name}",
                    "current": curr.parent / f"extracted_{curr.name}",
                }
            )
        }

    async def index(state: GatherInfoState) -> dict[str, Any]:
        # The WinSxS DataFrame now comes from the platform plugin's
        # bundled archive (`resources/windows_sxs/<id>.<slug>.bin`),
        # not from the host's `C:\Windows\WinSxS`. Loaded eagerly from
        # disk; the actual binaries get extracted lazily later in
        # `_patch_candidates` via `platform.extract_baselines`.
        winsxs_df = ctx.platform.get_winsxs_df()
        log.info("winsxs_indexed", rows=len(winsxs_df), platform=ctx.platform.name)

        arch = state.os.arch
        prev_report = get_report(state.extracted.previous / "report.txt", arch)
        curr_report = get_report(state.extracted.current / "report.txt", arch)

        prev_handle = ctx.progress.index_task(state.KB.previous)
        try:
            prev_df = await get_update_dataframe(
                state.KB.previous,
                prev_report,
                cache=state.extracted.previous / "report.cache",
                progress=prev_handle,
            )
        finally:
            prev_handle.complete()

        curr_handle = ctx.progress.index_task(state.KB.current)
        try:
            curr_df = await get_update_dataframe(
                state.KB.current,
                curr_report,
                cache=state.extracted.current / "report.cache",
                progress=curr_handle,
            )
        finally:
            curr_handle.complete()

        winsxs_df = winsxs_df.filter(filter_executables) if not winsxs_df.is_empty() else winsxs_df

        # Per-component dedupe: pick the row that delta_apply will treat
        # as "the baseline".
        #
        # Two valid baseline shapes:
        #   * `delta_type == "r"` — updated WinSxS, reverse-delta chain
        #     reaches RTM. Microsoft only writes a complete chain on the
        #     LATEST version's `r/` file; intermediate versions carry
        #     one-step deltas that recursive_apply can't unwind. Pick the
        #     highest-version r-row per component so `winsxs_patch.item(0,
        #     ...)` in delta_apply is deterministic.
        #   * `delta_type is null` — vanilla / never-CU'd WinSxS. The
        #     materialized `<component>/<file>` IS the baseline (RTM); no
        #     r-delta exists and `_apply_forward` succeeds via its
        #     "direct" path with `r_delta_bytes=None`.
        #
        # When both shapes exist for the same `(name, package, arch,
        # pubkey)` (mixed/partially-updated dump), prefer the r-row — it
        # carries the rollback chain. The `_is_flat` priority column +
        # `unique(keep="first")` enforces that.
        r_patch = (
            winsxs_df.filter(
                pl.col("arch").eq(arch)
                & (pl.col("delta_type").eq("r") | pl.col("delta_type").is_null())
            )
            .with_columns(pl.col("delta_type").is_null().alias("_is_flat"))
            .sort(["_is_flat", "version"], descending=[False, True])
            .unique(subset=["name", "package", "arch", "pubkey"], keep="first")
            .drop("_is_flat")
            if not winsxs_df.is_empty() else winsxs_df
        )

        curr_relevant = (
            curr_df.filter(
                pl.col("arch").eq(arch)
                & ~pl.col("hash").is_in(prev_df["hash"])
            ).join(
                r_patch.select("package", "pubkey", "arch").unique(),
                on=["package", "pubkey", "arch"],
                how="semi",
            )
            if not (curr_df.is_empty() or r_patch.is_empty())
            else curr_df.clear()
        )

        prev_relevant = (
            prev_df.filter(
                pl.col("arch").eq(arch)
                & ~pl.col("hash").is_in(curr_df["hash"])
            ).join(
                r_patch.select("package", "pubkey", "arch").unique(),
                on=["package", "pubkey", "arch"],
                how="semi",
            )
            if not (prev_df.is_empty() or r_patch.is_empty())
            else prev_df.clear()
        )

        relevant_r_patch = (
            r_patch.join(
                curr_relevant.select(["package", "pubkey", "arch"]).unique(),
                on=["package", "pubkey", "arch"],
                how="semi",
            )
            if not r_patch.is_empty()
            else r_patch
        )

        return {
            "dataframes": state.dataframes.model_copy(
                update={"previous": prev_df, "current": curr_df, "base": winsxs_df}
            ),
            "filtered_dataframes": state.filtered_dataframes.model_copy(
                update={
                    "previous": prev_relevant.filter(
                        pl.col("name").str.to_lowercase().is_in(
                            relevant_r_patch.get_column("name").str.to_lowercase()
                        )
                    )
                    if not relevant_r_patch.is_empty()
                    else prev_relevant,
                    "current": curr_relevant.filter(
                        pl.col("name").str.to_lowercase().is_in(
                            relevant_r_patch.get_column("name").str.to_lowercase()
                        )
                    )
                    if not relevant_r_patch.is_empty()
                    else curr_relevant,
                    "base": relevant_r_patch,
                }
            ),
        }

    async def add_file_info(batch: list[tuple[str, str, str]]) -> dict[str, Any]:
        """Describe a batch of files in one structured-output LLM call.

        `batch` is a list of `(base_path_str, name, package)` tuples.
        Path is serialized as a string because LangGraph's `Send` payload
        must be JSON-serializable for checkpoint/replay parity.
        """
        if not batch:
            return {}
        stores = ctx.open_vector_stores()

        names = [name for _, name, _ in batch]

        # Acquire per-name locks in sorted order to avoid deadlocks when
        # two batches in flight share names. Coalesces duplicate LLM
        # spend across multi-CVE runs that share KB content.
        async with AsyncExitStack() as stack:
            await stack.enter_async_context(semaphore)
            for name in sorted(set(names)):
                lock = await _file_info_lock_for(name)
                await stack.enter_async_context(lock)

            # Bulk dedup once we hold all locks. A concurrent batch may
            # have just persisted some of these names while we were
            # blocked on the lock; recheck after acquiring.
            existing = stores.file_info.get(where={"name": {"$in": names}})
            already: set[str] = {
                md["name"]
                for md in (existing.get("metadatas") or [])
                if md.get("name")
            }
            pending = [(p, n, pkg) for p, n, pkg in batch if n not in already]
            if not pending:
                return {}

            # Build per-file inputs — read PE FileDescription synchronously,
            # cheap relative to the LLM call.
            items: list[dict[str, str]] = []
            desc_by_name: dict[str, str] = {}
            for path_str, name, package in pending:
                base = Path(path_str)
                desc = (file_desc(base) if base.exists() else None) or "_"
                desc_by_name[name] = desc
                items.append({"filename": name, "package": package, "description": desc})

            # Lower temperature for embedding-input stability — same input
            # across runs should yield near-identical descriptions, otherwise
            # cross-batch style drift muddies the vector index. `model_copy`
            # returns a fresh instance so the registry-cached model is not
            # mutated.
            model = ctx.registry.for_purpose(ModelPurpose.GATHER_INFO).model.model_copy(
                update={"temperature": 0.2}
            )
            chain = resilient(desc_prompt | model.with_structured_output(_FileDescBatch))

            try:
                result: _FileDescBatch = await chain.ainvoke(
                    {"files": json.dumps({"files": items})}
                )
            except (ValidationError, ValueError) as exc:
                # Best-effort: drop the whole batch on a structured-output
                # parse failure. Names re-emit on the next run via the
                # routing dedup at `add_file_info_if_needed`.
                log.warning(
                    "add_file_info_batch_failed",
                    error=str(exc)[:200],
                    names=names,
                )
                return {}

            # Map LLM output back to inputs by name. Anything the model
            # silently dropped will get a fresh attempt next run.
            by_name: dict[str, str] = {fd.name.lower(): fd.description for fd in result.files}
            docs: list[Document] = []
            ids: list[str] = []
            for path_str, name, package in pending:
                content = by_name.get(name.lower())
                if not content:
                    continue
                docs.append(
                    Document(
                        page_content=content,
                        metadata={
                            "name": name.lower(),
                            # `package` recorded for traceability; not
                            # part of the dedup key.
                            "package": package.lower(),
                            "description": desc_by_name[name].lower(),
                        },
                    )
                )
                ids.append(str(uuid.uuid4()))

            if docs:
                await stores.file_info.aadd_documents(documents=docs, ids=ids)
            log.info(
                "add_file_info_batch",
                requested=len(pending),
                persisted=len(docs),
                skipped_existing=len(batch) - len(pending),
            )
            return {}

    def add_file_info_if_needed(state: GatherInfoState):
        stores = ctx.open_vector_stores()

        base_df = state.filtered_dataframes.base
        if base_df is None or base_df.is_empty():
            return GatherNodes.UPDATE_VS

        # Dedup key is `name` only: descriptions are filename-driven and
        # the LLM output isn't differentiated by `package`. Coalescing
        # cuts duplicate LLM spend across batch CVEs that share files.
        update_set: set[str] = {
            row["name"]
            for row in base_df.unique(subset=["name"]).iter_rows(named=True)
        }

        existing = stores.file_info.get()
        exists_set: set[str] = {
            md["name"] for md in (existing.get("metadatas") or []) if md.get("name")
        }

        update_set -= exists_set
        if not update_set:
            return GatherNodes.UPDATE_VS

        pending: list[tuple[str, str, str]] = []
        for row in base_df.unique(subset=["name"]).iter_rows(named=True):
            if row["name"] not in update_set:
                continue
            # r-row path is `<component>/r/<file>`; the materialized
            # binary lives two levels up next to r/. Flat row path IS
            # the materialized binary (vanilla WinSxS, no r/f/n).
            row_path = Path(row["path"])
            if row.get("delta_type") == "r":
                base_path = row_path.parents[1] / row["name"]
            else:
                base_path = row_path
            pending.append((str(base_path), row["name"], row["package"]))

        sends = [
            Send(GatherNodes.ADD_FILE_INFO, pending[i:i + BATCH_SIZE])
            for i in range(0, len(pending), BATCH_SIZE)
        ]
        return sends or GatherNodes.UPDATE_VS

    async def update_vector_store(state: GatherInfoState) -> dict[str, Any]:
        # Placeholder; the file_info store is updated incrementally above.
        return {}

    return download, index, add_file_info, add_file_info_if_needed, update_vector_store
