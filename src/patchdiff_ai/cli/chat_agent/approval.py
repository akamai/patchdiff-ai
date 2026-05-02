"""y/N approval prompt for pending tool calls."""

from __future__ import annotations

from typing import Any

import structlog


log = structlog.get_logger(__name__)


def _format_call(call: dict[str, Any]) -> str:
    args = call.get("args") or {}
    args_repr = ", ".join(f"{k}={v!r}" for k, v in args.items())
    return f"{call.get('name')}({args_repr})"


def _ask_approval(pending_calls: list[dict[str, Any]]) -> dict[str, bool]:
    """Prompt the user once per pending tool call. Returns id -> approved."""
    approvals: dict[str, bool] = {}
    for call in pending_calls:
        log.trace(
            "tool_approval_prompted",
            call_id=call.get("id"),
            tool=call.get("name"),
        )
        print("\n[?] Assistant wants to call:")
        print(f"    {_format_call(call)}")
        try:
            ans = input("    Allow? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = ""
        approved = ans.startswith("y")
        approvals[call["id"]] = approved
        log.trace(
            "tool_approval_result",
            call_id=call.get("id"),
            tool=call.get("name"),
            approved=approved,
        )
    return approvals


def _ask_increase_recursion_limit(current: int, increment: int = 30) -> int | None:
    """Prompt to bump the LangGraph recursion limit when an agent turn hits it.

    Returns the new limit (current + increment) on `y`, or `None` if the
    user declines or hits EOF/Ctrl-C — letting the caller exit the turn
    gracefully instead of raising.
    """
    print(f"\n[!] Recursion limit of {current} reached without a stop condition.")
    try:
        ans = input(
            f"    Increase by {increment} (→ {current + increment}) and continue? [y/N] "
        ).strip().lower()
    except (EOFError, KeyboardInterrupt):
        ans = ""
    approved = ans.startswith("y")
    log.info(
        "recursion_limit_prompted",
        current=current,
        proposed=current + increment,
        approved=approved,
    )
    return current + increment if approved else None
