"""IDA chat catalogue — bulk-register the ida-pro-mcp tools through one async dispatcher."""

from __future__ import annotations

from typing import Any

import structlog

from patchdiff_ai.runtime.app_context import AppContext

from ..catalogue import ToolCatalogue


log = structlog.get_logger(__name__)


async def register(cat: ToolCatalogue, ctx: AppContext) -> None:
    """Fetch the IDA catalogue (worker spawns lazily) and bulk-register it.

    No-op if `ctx.tools.ida_chat` is not configured. Catalogue-fetch
    failures are logged and swallowed so the rest of the chat tools
    remain usable.
    """
    if ctx.tools.ida_chat is None:
        return
    try:
        ida_entries = await ctx.tools.ida_chat.get_catalogue()
    except Exception as exc:
        log.warning("ida_chat_catalogue_failed", error=str(exc))
        ida_entries = []
    if not ida_entries:
        return
    ida_chat = ctx.tools.ida_chat

    async def ida_dispatcher(name: str, args: dict[str, Any]) -> str:
        return await ida_chat.call_tool(name, args)

    cat.register_ida(ida_entries, ida_dispatcher)
