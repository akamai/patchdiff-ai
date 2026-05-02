"""Post-run REPL.

Hardcoded commands (`reports`, `reanalyze`, `change assistant`, …) match
against `AssistantCommand` and dispatch directly. Free-form input goes
to the ReAct agent in `chat_agent.py`, gated by y/N approval prompts.
Lives in the CLI process — never inside the graph.
"""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path
from typing import Any

import structlog
from rich.console import Console
from rich.markdown import Markdown

from patchdiff_ai.cli.chat_agent import build_chat_agent, run_turn
from patchdiff_ai.cli.commands.cached import _save_reports
from patchdiff_ai.graphs.interrupts import AssistantCommand
from patchdiff_ai.llm.catalog import ModelPurpose
from patchdiff_ai.observability.progress import make_reporter
from patchdiff_ai.runtime.app_context import AppContext
from patchdiff_ai.runtime.orchestrator import run_cve

log = structlog.get_logger(__name__)

_console = Console()

HELP_TEXT = """
Available commands:
  exit                  - exit the program
  help                  - show this help message
  reports               - show the generated reports
  save reports          - save reports to files
  delete all reports    - delete all cached reports for this CVE
  reanalyze             - reanalyze the current CVE
  change assistant      - change the assistant model
"""


async def post_run_repl(
    ctx: AppContext,
    cve: str,
    state: dict[str, Any] | None = None,
    *,
    interactive: bool = False,
    permissive: bool = False,
) -> None:
    """Drop the user into a chat after a CVE run completes.

    `state` is the final `PipelineState` dict; tools use it to inspect
    artifacts. After `reanalyze`, the agent is rebuilt against the new
    state so closed-over artifacts don't go stale.

    `interactive` mirrors `--interrupt` and is forwarded into chat-
    driven reruns. `permissive` skips the y/N tool-approval gate.
    """
    # Tear down `ida_chat` while we still own the loop its worker IO
    # threads attached to: leaving the executor alive across
    # `asyncio.run`'s loop close GCs futures against a dead
    # ProactorEventLoop on Windows (werfault). Sibling pattern to the
    # idalib-pool aclose in `orchestrator.run_cve`'s finally.
    try:
        stores = ctx.open_vector_stores()
        assistant_entry = ctx.registry.for_purpose(ModelPurpose.DEFAULT)
        # `interactive` and `permissive` are captured by the agent closure so its
        # `reanalyze` tool and tool-approval gating stay consistent across rebuilds.
        agent = await build_chat_agent(
            ctx, cve, state, assistant_entry,
            permissive=permissive,
        )
        thread_id = uuid.uuid4().hex[:12]

        while True:
            try:
                _console.print()
                _console.rule(
                    f"[bold green]You[/] [dim]({assistant_entry.spec.name})[/]",
                    style="green",
                )
                user_input = _console.input("[bold green]»[/] ").strip()
                _console.rule(style="green")
            except (EOFError, KeyboardInterrupt):
                return
            if not user_input:
                continue

            match user_input.lower():
                case AssistantCommand.EXIT.value:
                    return
                case AssistantCommand.HELP.value:
                    print(HELP_TEXT)
                    continue
                case AssistantCommand.REPORTS.value:
                    _print_reports(stores, cve)
                    continue
                case AssistantCommand.SAVE_REPORTS.value:
                    docs = stores.reports.get(where={"cve": cve})
                    if docs.get("ids"):
                        _save_reports(docs, Path.cwd())
                        print(f"[+] Saved reports to {Path.cwd()}")
                    else:
                        print(f"[-] No reports found for {cve}")
                    continue
                case AssistantCommand.DELETE_ALL_REPORTS.value:
                    if input("Are you sure? [y/N] ").lower().startswith("y"):
                        docs = stores.reports.get(where={"cve": cve})
                        if docs.get("ids"):
                            stores.reports.delete(ids=docs["ids"])
                            print(f"[+] Deleted reports for {cve}")
                    continue
                case AssistantCommand.REANALYZE.value:
                    model = _pick_model(ctx, "researcher")
                    if model:
                        # `force=True` bypasses CVE_INFO's cached-report
                        # short-circuit. The picked model is applied by
                        # overriding the RESEARCHER purpose for the run
                        # — `_analyze_with` reads it via `for_purpose`.
                        # `make_reporter()` re-enters because the outer
                        # reporter was stopped by cve.py before chat started.
                        print("[*] Reanalyzing — running the full pipeline. This can take a few minutes…")
                        prev_researcher = ctx.registry._purpose_overrides.get(
                            ModelPurpose.RESEARCHER
                        )
                        ctx.registry._purpose_overrides[ModelPurpose.RESEARCHER] = (
                            model.spec.name
                        )
                        try:
                            with make_reporter() as progress:
                                ctx.progress = progress
                                if ctx.tools.idalib is not None:
                                    ctx.tools.idalib.attach_progress(progress)
                                new_state = await run_cve(
                                    ctx,
                                    cve,
                                    interactive=interactive,
                                    evaluate=False,
                                    force=True,
                                )
                        finally:
                            ctx.registry._purpose_overrides[ModelPurpose.RESEARCHER] = (
                                prev_researcher
                            )
                        print("[+] Reanalyze complete.")
                        agent = await build_chat_agent(
                            ctx, cve, new_state, assistant_entry,
                            permissive=permissive,
                        )
                        thread_id = uuid.uuid4().hex[:12]
                    continue
                case AssistantCommand.CHANGE_ASSISTANT.value:
                    pick = _pick_model(ctx, "assistant")
                    if pick:
                        assistant_entry = pick
                        agent = await build_chat_agent(
                            ctx, cve, state, assistant_entry,
                            permissive=permissive,
                        )
                        thread_id = uuid.uuid4().hex[:12]
                        print(f"Using {assistant_entry.spec.name}")
                    continue

            try:
                response = await run_turn(agent, user_input, thread_id)
            except Exception as exc:
                print(f"[!] Agent turn failed: {exc}")
                log.warning(
                    "agent_turn_failed",
                    error_type=type(exc).__name__,
                    error=str(exc),
                    exc_info=True,
                )
                continue
            _console.print(Markdown(response))
    finally:
        try:
            await ctx.tools.ida_chat.aclose()
        except Exception as exc:
            log.warning("ida_chat_aclose_error", error=str(exc))


def _print_reports(stores, cve: str) -> None:
    docs = stores.reports.get(where={"cve": cve})
    ids = docs.get("ids") or []
    for i in range(len(ids)):
        meta = docs["metadatas"][i] or {}
        print(f"[+] Report ({meta.get('model_name')}) for {cve}:")
        _console.print(Markdown(docs["documents"][i]))
        print()


def _pick_model(ctx: AppContext, label: str):
    available = ctx.registry.list_chat_models()
    if not available:
        print("No chat models available")
        return None
    print(f"\nAvailable {label} models:")
    for i, spec in enumerate(available, start=1):
        print(f"  {i}. {spec.name}")
    try:
        choice = input(f"Select {label} model (1-{len(available)}): ").strip()
        idx = int(choice) - 1
        if 0 <= idx < len(available):
            return ctx.registry.get(available[idx].name)
    except (ValueError, KeyboardInterrupt, EOFError):
        return None
    return None


def run_chat(
    ctx: AppContext,
    cve: str,
    state: dict[str, Any] | None = None,
    *,
    interactive: bool = False,
    permissive: bool = False,
) -> None:
    """Sync entrypoint for the post-run REPL."""
    # Mirror run_cancellable's crash-logging contract: chat-driven
    # reanalyze bypasses it, so without this the traceback would only
    # land in the truncated Rich panel.
    from patchdiff_ai.observability.logging import write_traceback_to_file

    try:
        asyncio.run(
            post_run_repl(
                ctx, cve, state=state,
                interactive=interactive, permissive=permissive,
            )
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as exc:
        log.error(
            "chat_crashed",
            error_type=type(exc).__name__,
            error=str(exc)[:500],
        )
        write_traceback_to_file(exc, tag="chat_crashed")
        raise
