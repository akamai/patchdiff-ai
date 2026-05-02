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


def main() -> None:
    """Entry point for `patchdiff-ai` (and `python -m patchdiff_ai`)."""
    _bootstrap()
    from patchdiff_ai.cli.root import build_root

    cli = build_root()
    try:
        cli(standalone_mode=True)
    except (KeyboardInterrupt, EOFError):
        sys.exit(130)


if __name__ == "__main__":
    main()
