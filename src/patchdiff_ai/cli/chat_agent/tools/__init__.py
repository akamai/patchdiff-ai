"""Tool registrations for the chat agent.

`register_all` is the single orchestrator: it builds the shared
services (vector stores, ChromaQueryService) once, then asks each
domain module to register its tools against the passed-in
`ToolCatalogue`. The always-on artifact-bound `@tool` factories are
re-exported via `always_on_tools` for the agent build.
"""

from __future__ import annotations

from typing import Any

from patchdiff_ai.runtime.app_context import AppContext
from patchdiff_ai.tools.chroma_query import ChromaQueryService

from ..catalogue import ToolCatalogue
from . import bindiff, chroma, dataframes, ida, patch_store, python_exec, reports, result_cache
from .artifacts import always_on_tools


__all__ = ["register_all", "always_on_tools"]


async def register_all(
    cat: ToolCatalogue,
    ctx: AppContext,
    cve: str,
    artifacts: list[Any],
) -> None:
    """Register every dispatchable tool against `cat`.

    Mutating REPL commands (`reanalyze`, `change assistant`, `exit`, …)
    live in `chat.py`'s switch — never the catalogue — so the agent
    can't trigger destructive actions to "fix" tool noise.
    """
    stores = ctx.open_vector_stores()
    chroma_svc = ChromaQueryService(stores)

    reports.register(cat, ctx, cve, chroma_svc)
    chroma.register(cat, chroma_svc)
    patch_store.register(cat, ctx)
    dataframes.register(cat, ctx)
    bindiff.register(cat, artifacts)
    result_cache.register(cat)
    python_exec.register(cat)
    await ida.register(cat, ctx)
