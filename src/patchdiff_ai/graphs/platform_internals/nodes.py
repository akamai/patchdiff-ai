"""Platform-internals nodes: collect candidates, rank, optionally interrupt for user refinement."""

from __future__ import annotations

import json
from typing import Any

import polars as pl
import structlog
from langchain_core.documents import Document
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.runnables import RunnableConfig
from langchain_openai.chat_models.base import OpenAIRefusalError
from langgraph.types import interrupt
from pydantic import BaseModel, Field, ValidationError

from patchdiff_ai.graphs.interrupts import (
    RefinementPickCandidate,
    RefinementPickRequest,
    RefinementPickResponse,
    RefinementRequest,
    RefinementResponse,
)
from patchdiff_ai.graphs.platform_internals.state import PlatformInternalsState
from patchdiff_ai.llm.catalog import ModelPurpose
from patchdiff_ai.llm.retry import resilient
from patchdiff_ai.observability.logging import write_raw_to_file
from patchdiff_ai.prompts.registry import PromptId
from patchdiff_ai.runtime.app_context import AppContext
from patchdiff_ai.schemas.candidate import Candidates, RankedCandidate
from patchdiff_ai.schemas.patch_store import PatchSources

log = structlog.get_logger(__name__)


class _Query(BaseModel):
    query: str = Field(..., description="Query for similarity search")


class _FileScore(BaseModel):
    file: str = Field(..., description="Filename including extension")
    score: float = Field(..., ge=0.0, le=10.0)


class _FileScoreList(BaseModel):
    files: list[_FileScore]


class PiNodes:
    COLLECT = "Collect relevant files"
    RANK = "Rank relevancy"
    USER_REFINEMENT = "User refinement"


def _candidate_from_doc(doc: Document, sim: float, relevancy: float = 0.0) -> RankedCandidate:
    return RankedCandidate(
        name=doc.metadata.get("name", ""),
        package=doc.metadata.get("package", ""),
        page_content=doc.page_content,
        metadata=doc.metadata,
        similarity=float(sim),
        relevancy=float(relevancy),
    )


def make_nodes(ctx: AppContext):
    # Prompts and the advisory-metadata projection both come from the
    # active platform plugin. Resolved lazily inside each node so we read
    # `ctx.platform` (set during CVE_INFO) at call time, not at graph-build
    # time. Falls back to the Windows defaults if no plugin is set yet —
    # only the build-time tests hit that path.
    def _prompts():
        if ctx.platform is not None:
            collect_id, rank_id = ctx.platform.candidate_prompts()
        else:
            collect_id, rank_id = PromptId.PI_COLLECT, PromptId.PI_RANK
        collect_str = ctx.prompts.get(collect_id) if ctx.prompts else ""
        rank_str = ctx.prompts.get(rank_id) if ctx.prompts else ""
        return (
            ChatPromptTemplate(
                [
                    SystemMessage(collect_str),
                    MessagesPlaceholder("json_metadata"),
                ]
            ),
            ChatPromptTemplate.from_template(rank_str),
        )

    def _candidate_metadata(state):
        if ctx.platform is not None:
            return ctx.platform.candidate_metadata(state.cve_details)
        # Legacy fallback: inline Windows projection.
        return {
            k: v
            for k, v in state.cve_details.msrc_report.model_dump().items()
            if k != "products"
        }

    async def collect(state: PlatformInternalsState) -> dict[str, Any]:
        log.info("pi_collect", cve=state.cve_details.cve)
        stores = ctx.open_vector_stores()
        llm = ctx.registry.for_purpose(ModelPurpose.PLATFORM_INTERNALS).model

        collect_prompt, _ = _prompts()
        query_chain = resilient(collect_prompt | llm.with_structured_output(_Query))
        meta_dict = _candidate_metadata(state)
        result: _Query = await query_chain.ainvoke(
            {"json_metadata": [HumanMessage(json.dumps(meta_dict))]}
        )
        log.trace("pi_collect_query", query=result.query[:200])

        docs = await stores.file_info.asimilarity_search_with_score(result.query, k=10)
        log.info("pi_candidates", count=len(docs), query=result.query)
        if docs:
            sims = [round(s, 4) for _, s in docs]
            log.trace(
                "pi_collect_results",
                docs_returned=len(docs),
                similarity_top=sims[0],
                similarity_min=sims[-1],
            )
        return {"docs": docs, "query": result.query}

    async def rank(state: PlatformInternalsState) -> dict[str, Any]:
        if not state.docs:
            return {"candidates": Candidates(query=state.query)}

        llm = ctx.registry.for_purpose(ModelPurpose.DEFAULT).model
        _, rank_prompt = _prompts()
        chain = resilient(rank_prompt | llm.with_structured_output(_FileScoreList))

        files_text = "\n\n".join(
            f"name: {d.metadata.get('name', '')}\n{d.page_content}" for d, _ in state.docs
        )
        meta_dict = _candidate_metadata(state)
        try:
            result: _FileScoreList = await chain.ainvoke(
                {"query": state.query, "metadata": json.dumps(meta_dict), "files": files_text}
            )
        except OpenAIRefusalError as exc:
            # Reasoning models (o4-mini) sometimes emit schema-prefixed output
            # like " _FileScoreList\n{...}" that Azure's strict-output check
            # routes into the `refusal` channel even though the JSON is valid.
            # Try to recover by stripping the prefix and parsing the rest.
            payload = str(exc).strip()
            prefix = _FileScoreList.__name__
            if payload.startswith(prefix):
                payload = payload[len(prefix):].lstrip(" :\n")
            try:
                result = _FileScoreList.model_validate_json(payload)
                log.warning("rank_refusal_recovered", chars=len(payload))
            except (ValidationError, ValueError) as parse_exc:
                log.warning(
                    "rank_refusal_unparseable",
                    error=str(parse_exc)[:200],
                    payload=payload[:500],
                )
                # Fall back to similarity-only ranking — every doc gets 0.0.
                result = _FileScoreList(files=[])

        score_map = {fs.file: fs.score for fs in result.files}
        ranked = []
        for doc, sim in state.docs:
            name = doc.metadata.get("name")
            relevancy = score_map.get(name, 0.0)
            log.trace(
                "pi_rank_candidate",
                file=name,
                vector_sim=round(sim, 4),
                llm_score=relevancy,
            )
            ranked.append(_candidate_from_doc(doc, sim, relevancy=relevancy))
        ranked.sort(key=lambda c: c.relevancy, reverse=True)

        if ranked:
            log.info("pi_rank_complete", n=len(ranked), top=ranked[0].name)
            rows = [
                {
                    "name": c.name,
                    "package": c.package,
                    "similarity": round(c.similarity, 4),
                    "relevancy": c.relevancy,
                }
                for c in ranked
            ]
            log.debug("pi_ranked_candidates", rows=rows)
            # Render the table to terminal (Rich-safe) and append raw to the
            # log file (bypassing JSON to avoid escaped Unicode). Printed
            # unconditionally — `rank` runs once per pipeline so there's no
            # duplication, and the user wants to see the ranking before
            # refinement (matching the old reference at info level).
            with pl.Config(tbl_width_chars=200, fmt_str_lengths=60, tbl_rows=-1):
                table_text = str(pl.DataFrame(rows))
            ctx.progress.print(table_text)
            write_raw_to_file(table_text)

        return {"candidates": Candidates(query=state.query, results=ranked)}

    def _changed_names(filtered: PatchSources) -> list[str]:
        names: set[str] = set()
        for df in (filtered.current, filtered.previous):
            if isinstance(df, pl.DataFrame) and "name" in df.columns:
                names.update(n for n in df.get_column("name").to_list() if n)
        return sorted(names)

    def _docs_by_name(stores, names: list[str]) -> list[tuple[Document, float]]:
        if not names:
            return []
        res = stores.file_info.get(where={"name": {"$in": names}})
        if not res or not res.get("documents"):
            return []
        return [
            (
                Document(page_content=res["documents"][i], metadata=res["metadatas"][i]),
                0.5,
            )
            for i in range(len(res["documents"]))
        ]

    async def _run_search(opt, stores, filtered: PatchSources) -> list[tuple[Document, float]]:
        changed = _changed_names(filtered)
        if not changed:
            log.warning("pi_refine_no_changed_files")
            return []

        if opt.name == "__filename__":
            pattern = opt.payload.get("pattern", "").strip().lower()
            if not pattern:
                return []
            matches = [n for n in changed if pattern in n.lower()][:10]
            return _docs_by_name(stores, matches)

        if opt.name == "__semantic__":
            query = opt.payload.get("query", "")
            if not query:
                return []
            # Vector-search wider than 10 then filter to changed files; the
            # store carries every WinSxS file, but refinement should only
            # surface candidates that actually changed in this KB.
            results = await stores.file_info.asimilarity_search_with_score(query, k=50)
            changed_set = set(changed)
            filtered_results = [
                (doc, sim)
                for doc, sim in results
                if doc.metadata.get("name") in changed_set
            ][:10]
            return filtered_results

        return []

    async def user_refinement(state: PlatformInternalsState, config: RunnableConfig) -> dict[str, Any]:
        if not config.get("configurable", {}).get("interrupt", False):
            return {}

        stores = ctx.open_vector_stores()
        user_docs = list(state.user_docs)

        # Two-phase loop per iteration: ask kind+query, run search inside the
        # graph (vector store lives here), then interrupt again so the CLI can
        # render the numbered list and let the user pick which entries to add.
        # Mirrors the old reference's `Select (e.g., 1,3,5 or 'all')` UX.
        while True:
            req = RefinementRequest(cve=state.cve_details.cve)
            response: RefinementResponse = interrupt(req)
            if response.skip or not response.selected:
                break

            search_results = await _run_search(
                response.selected[0], stores, state.filtered_dataframes
            )
            if not search_results:
                continue

            pick_req = RefinementPickRequest(
                cve=state.cve_details.cve,
                candidates=[
                    RefinementPickCandidate(
                        name=doc.metadata.get("name", ""),
                        score=float(sim),
                    )
                    for doc, sim in search_results
                ],
            )
            picks: RefinementPickResponse = interrupt(pick_req)
            for idx in picks.indices:
                if not (0 <= idx < len(search_results)):
                    continue
                doc, sim = search_results[idx]
                if not any(
                    d.metadata.get("name") == doc.metadata.get("name") for d, _ in user_docs
                ):
                    user_docs.append((doc, sim))

        existing = list(state.candidates.results)
        for doc, sim in user_docs:
            existing.append(_candidate_from_doc(doc, sim, relevancy=10.0))
        existing.sort(key=lambda c: c.relevancy, reverse=True)
        return {
            "user_docs": user_docs,
            "candidates": Candidates(query=state.query, results=existing),
        }

    def refinement_router(state: PlatformInternalsState, config: RunnableConfig) -> str:
        if config.get("configurable", {}).get("interrupt", False):
            return PiNodes.USER_REFINEMENT
        return "__end__"

    return collect, rank, user_refinement, refinement_router
