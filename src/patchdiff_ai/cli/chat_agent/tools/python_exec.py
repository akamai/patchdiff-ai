"""Sandboxed Python-execution chat tool.

Per-session persistent namespace closed over by `register`. Always
prompts the user with the code rendered as Markdown before running —
including in permissive mode — so the human sees the exact source
before each invocation. In-process exec; not a security boundary
(the chat already reads project files freely). The point is namespace
isolation, crash containment, and a visible approval gate.
"""

from __future__ import annotations

import contextlib
import io
import traceback
from typing import Any

import structlog
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.text import Text

from ..catalogue import ToolCatalogue


log = structlog.get_logger(__name__)

_console = Console()

_SNAPSHOT_MAX_LINES = 20


def _render_snapshot(stdout: str, stderr: str) -> None:
    """Print a tinted-background snapshot of stdout/stderr (≤20 lines).

    Uses `rich.text.Text` (not markup) so brackets in user output
    aren't reinterpreted. The full body is still returned to the
    assistant via the tool envelope; the snapshot is for the human
    in the terminal.
    """
    if not stdout and not stderr:
        return

    out_lines = stdout.splitlines() if stdout else []
    err_lines = stderr.splitlines() if stderr else []
    total = len(out_lines) + len(err_lines)

    text = Text()
    remaining = _SNAPSHOT_MAX_LINES

    if out_lines and remaining > 0:
        take = min(len(out_lines), remaining)
        text.append("\n".join(out_lines[:take]))
        remaining -= take

    if err_lines and remaining > 0:
        if out_lines:
            text.append("\n-- stderr --\n", style="bold red")
        take = min(len(err_lines), remaining)
        text.append("\n".join(err_lines[:take]), style="red")
        remaining -= take

    if total > _SNAPSHOT_MAX_LINES:
        text.append(
            f"\n... ({total - _SNAPSHOT_MAX_LINES} more line(s); "
            "full content returned to assistant)",
            style="dim italic",
        )

    _console.print(
        Panel(
            text,
            title="[dim]python_exec output[/dim]",
            title_align="left",
            border_style="grey50",
            style="on grey15",
            expand=False,
            padding=(0, 1),
        )
    )


def register(cat: ToolCatalogue) -> None:
    """Register `python_exec` with a closure-scoped persistent namespace.

    The namespace lives for the lifetime of the catalogue, which is
    rebuilt by `build_chat_agent` on session start, `reanalyze`, and
    `change assistant`. No teardown needed — GC reclaims it when the
    closure goes out of scope.
    """
    namespace: dict[str, Any] = {}

    def python_exec(code: str) -> dict[str, Any]:
        _console.print(Markdown(f"```python\n{code}\n```"))
        try:
            answer = _console.input(
                "[bold yellow]Execute this Python?[/] \\[y/N] "
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        if not answer.startswith("y"):
            log.info("python_exec_denied", code_chars=len(code))
            return {"kind": "denied", "error": "User declined execution"}

        keys_before = {k for k in namespace if not k.startswith("__")}
        buf_out, buf_err = io.StringIO(), io.StringIO()

        try:
            code_obj = compile(code, "<chat python_exec>", "exec")
        except SyntaxError as exc:
            log.warning("python_exec_syntax_error", error=str(exc))
            return {
                "kind": "error",
                "error": f"SyntaxError: {exc}",
                "traceback": traceback.format_exc(),
            }

        try:
            with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
                exec(code_obj, namespace)
        except SystemExit as exc:
            # sys.exit() inside a snippet must not kill the chat process.
            log.warning("python_exec_system_exit", code_arg=exc.code)
            _render_snapshot(buf_out.getvalue(), buf_err.getvalue())
            return {
                "kind": "error",
                "error": (
                    f"SystemExit suppressed (code={exc.code!r}). "
                    "sys.exit() is intercepted to keep the chat alive."
                ),
                "stdout": buf_out.getvalue(),
                "stderr": buf_err.getvalue(),
            }
        except KeyboardInterrupt:
            log.info("python_exec_interrupted")
            _render_snapshot(buf_out.getvalue(), buf_err.getvalue())
            return {
                "kind": "interrupted",
                "error": "Execution interrupted",
                "stdout": buf_out.getvalue(),
                "stderr": buf_err.getvalue(),
            }
        except Exception as exc:
            log.warning(
                "python_exec_failed",
                error_type=type(exc).__name__,
                error=str(exc),
            )
            _render_snapshot(buf_out.getvalue(), buf_err.getvalue())
            return {
                "kind": "error",
                "error": f"{type(exc).__name__}: {exc}",
                "traceback": traceback.format_exc(),
                "stdout": buf_out.getvalue(),
                "stderr": buf_err.getvalue(),
            }

        keys_after = {k for k in namespace if not k.startswith("__")}
        new_bindings = sorted(keys_after - keys_before)
        log.info(
            "python_exec_ok",
            stdout_bytes=len(buf_out.getvalue()),
            stderr_bytes=len(buf_err.getvalue()),
            new_bindings=new_bindings,
        )
        _render_snapshot(buf_out.getvalue(), buf_err.getvalue())
        return {
            "kind": "success",
            "stdout": buf_out.getvalue(),
            "stderr": buf_err.getvalue(),
            "namespace_keys": sorted(keys_after),
            "new_bindings": new_bindings,
        }

    cat.register_native(
        name="python_exec",
        description=(
            "Execute Python code in a per-chat-session persistent namespace. "
            "ALWAYS prompts the user with the code rendered as markdown "
            "before executing — even in permissive mode — so keep snippets "
            "small and focused. The namespace persists across calls in this "
            "chat session (reset by `reanalyze` / `change assistant`). Use "
            "print(...) to surface results; the tool does NOT return last-"
            "expression repr. Response includes `namespace_keys` (all "
            "bindings) and `new_bindings` (created by this call). Runs "
            "in-process — not a security sandbox."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "description": (
                        "Python source. Multi-line OK. Use print() for "
                        "output. Imports persist across calls."
                    ),
                },
            },
            "required": ["code"],
        },
        callable_=python_exec,
        tags=["scripting", "python"],
    )
