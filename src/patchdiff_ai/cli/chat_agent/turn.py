"""Drive one user turn against the chat agent, gating tool calls on y/N approval."""

from __future__ import annotations

from typing import Any

import structlog
from langchain_core.messages import HumanMessage, ToolMessage
from langgraph.errors import GraphRecursionError
from langgraph.types import Command

from patchdiff_ai.observability.metrics import LLMMetricsHandler, bind_cost_tracker

from .approval import _ask_approval, _ask_increase_recursion_limit


log = structlog.get_logger(__name__)


_RECURSION_LIMIT_ABORTED = (
    "[!] Recursion limit reached and not extended; this turn was aborted."
)


async def _safe_ainvoke(agent, invoke_input: Any, config: dict[str, Any]):
    """`agent.ainvoke` with a y/N prompt to bump `recursion_limit` on overflow.

    On `GraphRecursionError`, the LangGraph checkpoint already holds
    everything up to the last completed node, so the retry resumes
    with `None` regardless of the original input.

    Returns `(state, config)` on success — `config` may carry an
    extended limit. Returns `(None, config)` if the user declined to
    extend, signalling the caller to abort the turn cleanly.
    """
    current_input = invoke_input
    while True:
        try:
            state = await agent.ainvoke(current_input, config=config)
            return state, config
        except GraphRecursionError:
            current_limit = config.get("recursion_limit", 30)
            new_limit = _ask_increase_recursion_limit(current_limit)
            if new_limit is None:
                return None, config
            config = {**config, "recursion_limit": new_limit}
            current_input = None


async def run_turn(agent, user_input: str, thread_id: str) -> str:
    """Drive one user turn, gating each tool call on y/N approval.

    `bind_cost_tracker` aggregates costs across the multi-step
    think→tool→…→answer cycle so we log one summary per turn.
    """
    with bind_cost_tracker() as cost:
        config: dict[str, Any] = {
            "configurable": {"thread_id": thread_id},
            "callbacks": [LLMMetricsHandler()],
            "recursion_limit": 30,
        }
        state, config = await _safe_ainvoke(
            agent, {"messages": [HumanMessage(content=user_input)]}, config
        )
        if state is None:
            return _RECURSION_LIMIT_ABORTED

        try:
            while True:
                messages = state.get("messages") or []
                if not messages:
                    return "(no response)"
                last = messages[-1]
                pending_calls = list(getattr(last, "tool_calls", None) or [])
                if not pending_calls:
                    content = getattr(last, "content", "")
                    return content if isinstance(content, str) else str(content)

                approvals = _ask_approval(pending_calls)
                if all(approvals.values()):
                    state, config = await _safe_ainvoke(agent, None, config)
                else:
                    # Any decline → cancel ALL pending calls; mixing executed
                    # and declined within one round leaves the agent with an
                    # inconsistent view.
                    cancellations = [
                        ToolMessage(
                            content="User declined this tool call.",
                            tool_call_id=call["id"],
                        )
                        for call in pending_calls
                    ]
                    state, config = await _safe_ainvoke(
                        agent, Command(update={"messages": cancellations}), config
                    )
                if state is None:
                    return _RECURSION_LIMIT_ABORTED
        finally:
            log.info(
                "chat_turn_cost",
                cost_usd_total=cost.total_cost_usd,
                llm_calls=cost.total_calls,
                total_tokens=cost.total_tokens,
                cost_by_model=cost.summary(),
            )
