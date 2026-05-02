"""Gather-info nodes: download/extract KBs, index files, embed file descriptions."""

from __future__ import annotations

import asyncio
import threading
import uuid
from pathlib import Path
from typing import Any

import polars as pl
import structlog
from langchain_core.documents import Document
from langchain_core.prompts import ChatPromptTemplate, HumanMessagePromptTemplate
from langchain_core.messages import SystemMessage
from langgraph.constants import Send
from openai import RateLimitError
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
    wait_random,
)

from patchdiff_ai.graphs.gather_info.state import GatherInfoState
from patchdiff_ai.llm.catalog import ModelPurpose
from patchdiff_ai.patches.extractor import extract_kb, extraction_marker, load_delta_dlls
from patchdiff_ai.patches.files_collection import (
    file_desc,
    filter_executables,
    get_report,
    get_update_dataframe,
)
from patchdiff_ai.patches.kb_downloader import download_kb
from patchdiff_ai.runtime.app_context import AppContext
from patchdiff_ai.runtime.timer import Timer

log = structlog.get_logger(__name__)

# Global mutex used by `add_file_info` workers; reentrant so a single graph
# execution doesn't deadlock against itself.
_file_info_mutex = threading.RLock()


class GatherNodes:
    DOWNLOAD = "Download & extract updates"
    INDEX = "Indexing"
    ADD_FILE_INFO = "Add to file info store"
    UPDATE_VS = "Update vectorstore"


def _build_desc_prompt() -> ChatPromptTemplate:
    return ChatPromptTemplate(
        input_variables=["filename", "package", "description"],
        messages=[
            SystemMessage("You are a senior Windows-internals analyst"),
            HumanMessagePromptTemplate.from_template(
                "Write a maximum of 80 token unformatted paragraph about the Windows executable "
                "{filename} package: {package} description: {description}. Include only "
                "technical details about its purpose in the system. Keep it short, consistent, "
                "and strictly one paragraph. Do not repeat facts. Omit headings, bullets, and "
                "conjunctions; the output is for embedding context."
            ),
        ],
    )


def make_nodes(ctx: AppContext):
    desc_prompt = _build_desc_prompt()
    semaphore = asyncio.Semaphore(ctx.settings.concurrency.file_info_semaphore)

    def _log_rate_limit_retry(retry_state) -> None:
        sleep_s = getattr(retry_state.next_action, "sleep", None)
        log.warning(
            "llm_rate_limited",
            attempt=retry_state.attempt_number,
            sleep_s=round(sleep_s, 1) if sleep_s is not None else None,
        )

    @retry(
        stop=stop_after_attempt(20),
        wait=wait_exponential(multiplier=5, min=5, max=120) + wait_random(0, 10),
        retry=retry_if_exception_type(RateLimitError),
        before_sleep=_log_rate_limit_retry,
        reraise=True,
    )
    async def _invoke_desc(chain, name: str, package: str, description: str):
        return await chain.ainvoke(
            {"filename": name, "package": package, "description": description}
        )

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

        # Multi-version dedupe: a bundled WinSxS archive can carry several
        # patch levels of the same component (e.g. 26100.1 / .712 / .1591).
        # Microsoft only writes a complete reverse-delta chain (back to
        # RTM) on the LATEST version's `r/` file; intermediate versions
        # carry one-step deltas that recursive_apply can't unwind to the
        # MSU's expected source. Pick the highest version per component
        # so `winsxs_patch.item(0, ...)` in delta_apply is deterministic
        # and points at the row whose r-delta reaches RTM.
        r_patch = (
            winsxs_df.filter(pl.col("arch").eq(arch) & pl.col("delta_type").eq("r"))
            .sort("version", descending=True)
            .unique(subset=["name", "package", "arch", "pubkey"], keep="first")
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

    async def add_file_info(args: tuple[Path, str, str]) -> dict[str, Any]:
        base, name, package = args
        stores = ctx.open_vector_stores()

        with _file_info_mutex:
            async with semaphore:
                res = stores.file_info.get(
                    where={"$and": [{"name": name}, {"package": package}]}
                )
                if res.get("ids"):
                    return {}

                desc = (file_desc(base) if base.exists() else None) or "_"
                model = ctx.registry.for_purpose(ModelPurpose.GATHER_INFO).model
                chain = desc_prompt | model
                result = await _invoke_desc(chain, name, package, desc)

                doc = Document(
                    page_content=getattr(result, "content", "") or "",
                    metadata={
                        "name": name.lower(),
                        "package": package.lower(),
                        "description": desc.lower(),
                    },
                )
                await stores.file_info.aadd_documents(documents=[doc], ids=[str(uuid.uuid4())])
                return {}

    def add_file_info_if_needed(state: GatherInfoState):
        stores = ctx.open_vector_stores()
        update_set: set[tuple[str, str]] = set()
        exists_set: set[tuple[str, str]] = set()

        base_df = state.filtered_dataframes.base
        if base_df is None or base_df.is_empty():
            return GatherNodes.UPDATE_VS

        for row in base_df.unique(subset=["name", "package"]).iter_rows(named=True):
            update_set.add((row["name"], row["package"]))

        existing = stores.file_info.get()
        for metadata in existing.get("metadatas") or []:
            exists_set.add((metadata["name"], metadata["package"]))

        update_set = update_set - exists_set
        if not update_set:
            return GatherNodes.UPDATE_VS

        sends = []
        for row in base_df.unique(subset=["name", "package"]).iter_rows(named=True):
            if (row["name"], row["package"]) in update_set:
                base_path = Path(row["path"]).parents[1] / row["name"]
                sends.append(
                    Send(GatherNodes.ADD_FILE_INFO, (base_path, row["name"], row["package"]))
                )
        return sends or GatherNodes.UPDATE_VS

    async def update_vector_store(state: GatherInfoState) -> dict[str, Any]:
        # Placeholder; the file_info store is updated incrementally above.
        return {}

    return download, index, add_file_info, add_file_info_if_needed, update_vector_store
