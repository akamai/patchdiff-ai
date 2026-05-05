"""`patchdiff-ai` entry point.

Tiny adapter: runs the env-strip / tracing-disable bootstrap (which has
to happen before any LangChain/LangGraph import), then dispatches to
the Click root in `cli.root`.
"""

from __future__ import annotations

import os
import sys


def _bootstrap() -> None:
    """Force-disable LangSmith / LangChain tracing before LangGraph imports.

    LangChain reads `LANGCHAIN_TRACING_V2` (legacy) and `LANGSMITH_TRACING`
    (newer) at import time to wire up the LangSmith callback. Pin both
    to `false` and strip any inherited API key / endpoint so a stray env
    var on the host machine cannot accidentally ship traces or anonymous
    data out. All observability stays local (structlog → log file).
    """
    os.environ["LANGCHAIN_TRACING_V2"] = "false"
    os.environ["LANGSMITH_TRACING"] = "false"
    for var in (
        "LANGCHAIN_API_KEY",
        "LANGSMITH_API_KEY",
        "LANGCHAIN_ENDPOINT",
        "LANGSMITH_ENDPOINT",
        "LANGCHAIN_PROJECT",
        "LANGSMITH_PROJECT",
    ):
        os.environ.pop(var, None)


def _silence_rich_shutdown_noise() -> None:
    """Suppress `rich.file_proxy.FileProxy.flush` ImportError at teardown.

    Python 3.14 finalises the import system earlier than 3.13. Buffered
    `rich` Consoles flushed during GC then call `rich_cast`, which lazy-
    imports `rich.text.Text` and raises `ImportError: sys.meta_path is
    None`. The default unraisable hook prints a noisy traceback for
    output we couldn't have rendered anyway. Drop the buffer silently
    when (and only when) the import system is already gone.
    """
    try:
        from rich import file_proxy
    except ImportError:
        return
    proxy_cls = getattr(file_proxy, "FileProxy", None)
    if proxy_cls is None:
        return
    original = proxy_cls.flush

    def _safe_flush(self):
        try:
            original(self)
        except ImportError:
            if sys.meta_path is None:
                return
            raise

    proxy_cls.flush = _safe_flush


def main() -> None:
    """Entry point for `patchdiff-ai` (and `python -m patchdiff_ai`)."""
    _bootstrap()
    _silence_rich_shutdown_noise()
    from patchdiff_ai.cli.root import build_root
    from patchdiff_ai.observability.metrics import bind_cost_tracker

    cli = build_root()
    # Session-level cost aggregator. Each per-CVE `bind_cost_tracker`
    # (inside `runtime.orchestrator.run_cve`) folds its totals into this
    # one on scope-exit, so single, batch (`windows month`), and chat
    # runs all converge to a single `session_cost_summary` event below.
    with bind_cost_tracker() as session_cost:
        try:
            cli(standalone_mode=True)
        except (KeyboardInterrupt, EOFError):
            sys.exit(130)
        finally:
            if session_cost.total_calls > 0:
                import structlog
                structlog.get_logger("patchdiff_ai.cli").info(
                    "session_cost_summary",
                    cost_usd_total=session_cost.total_cost_usd,
                    llm_calls=session_cost.total_calls,
                    total_tokens=session_cost.total_tokens,
                    cost_by_model=session_cost.summary(),
                )


if __name__ == "__main__":
    main()
