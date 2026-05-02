"""ReAct chat agent for free-form REPL turns.

Tool surface is a hybrid catalogue: a fixed set of always-on tools plus
three meta-tools (`list_tools`, `describe_tool`, `call_tool`) that proxy
the full ~80-tool ida-pro-mcp catalogue through one registry, keeping
prompt schemas small. Tool calls pause via `interrupt_before=["tools"]`
so the REPL can prompt y/N before each invocation.
"""

from __future__ import annotations

import json
from typing import Any

import structlog
from langchain_core.tools import tool
from langchain.agents import create_agent
from langgraph.checkpoint.memory import MemorySaver

from patchdiff_ai.llm.registry import ModelEntry
from patchdiff_ai.prompts.registry import PromptId
from patchdiff_ai.runtime.app_context import AppContext

from .catalogue import ToolCatalogue
from .tools import always_on_tools, register_all


log = structlog.get_logger(__name__)


def _load_system_prompt(ctx: AppContext, cve: str) -> str:
    """Load the chat system prompt with `{cve}` substituted.

    `str.replace` (not `.format`) so the markdown can carry literal
    JSON snippets without `{{ }}` escaping.
    """
    if ctx.prompts is None:
        raise RuntimeError("AppContext.prompts is not configured")
    return ctx.prompts.get(PromptId.CHAT_SYSTEM).replace("{cve}", cve)


def _make_agent_tools(catalogue: ToolCatalogue, artifacts: list[Any]):
    """Build the always-on tools + meta-tools, closing over `catalogue`."""

    @tool
    def list_tools(tag: str = "", name_filter: str = "") -> str:
        """Discover catalogue tools.

        With no args: returns a tag overview — each tag with its tool
        count and the first few tool names. Tools carrying multiple
        tags appear under each.

        With `tag="X"`: returns every tool tagged X, one per line, with
        the first line of each description.

        With `name_filter="..."`: substring search across all tags on
        tool name + description (combine with `tag` to AND-filter).

        After picking a tool, call `describe_tool(name)` for its
        argument schema, then `call_tool(name, {...})` to invoke.
        """
        if not tag and not name_filter:
            tags = catalogue.list_tags()
            if not tags:
                return "Catalogue is empty."
            lines = []
            for t in sorted(tags):
                names = tags[t]
                sample = ", ".join(names[:6])
                more = f", … (+{len(names) - 6} more)" if len(names) > 6 else ""
                lines.append(f"{t:22} ({len(names):>3}): {sample}{more}")
            lines.append("")
            lines.append(
                "Drill in with list_tools(tag=\"<name>\") for full "
                "listings, or list_tools(name_filter=\"...\") for substring "
                "search across all tags."
            )
            return "\n".join(lines)

        entries = catalogue.list(name_filter=name_filter, tag=tag)
        if not entries:
            ctx_bits = []
            if tag:
                ctx_bits.append(f"tag={tag!r}")
            if name_filter:
                ctx_bits.append(f"name_filter={name_filter!r}")
            return f"No tools match {' + '.join(ctx_bits)}."
        lines = []
        for e in entries:
            tag_str = ", ".join(e["tags"]) if e["tags"] else "general"
            desc_first = e["description"].splitlines()[0] if e["description"] else ""
            lines.append(f"{e['name']:32} [{tag_str}]  {desc_first}")
        return "\n".join(lines)

    @tool
    def describe_tool(name: str) -> str:
        """Return the JSON args schema and full description for one catalogue tool."""
        info = catalogue.describe(name)
        if info is None:
            return f"Unknown tool: {name!r}. Use list_tools() to discover available tools."
        return json.dumps(info, indent=2, default=str)

    @tool
    async def call_tool(name: str, tool_args: dict[str, Any] | None = None) -> str:
        """Invoke a catalogue tool with kwargs (`{}` for no-arg tools).

        The parameter is `tool_args` (not `args`) because LangChain rewrites
        a field literally named `args` to `v__args` in the derived schema,
        which then fails to bind.
        """
        return await catalogue.dispatch(name, tool_args or {})

    return [
        *always_on_tools(artifacts),
        list_tools,
        describe_tool,
        call_tool,
    ]


async def build_chat_agent(
    ctx: AppContext,
    cve: str,
    state: dict[str, Any] | None,
    model_entry: ModelEntry,
    *,
    permissive: bool = False,
):
    """Compile a ReAct agent that pauses before each tool call for y/N approval.

    Async so the first build can warm the IDA chat worker — the
    ~5-10 s `idapro` + `ida_pro_mcp` bootstrap cost is paid here, not
    on the first user turn.
    """
    artifacts = list((state or {}).get("artifacts", []) or [])
    catalogue = ToolCatalogue()
    await register_all(catalogue, ctx, cve, artifacts)
    log.info(
        "chat_agent_built",
        cve=cve,
        catalogue_size=len(catalogue.list()),
        ida_chat=ctx.tools.ida_chat is not None,
    )
    tools = _make_agent_tools(catalogue, artifacts)
    kwargs: dict[str, Any] = dict(
        tools=tools,
        system_prompt=_load_system_prompt(ctx, cve),
        checkpointer=MemorySaver(),
    )
    if not permissive:
        kwargs["interrupt_before"] = ["tools"]
    return create_agent(model_entry.model, **kwargs)
