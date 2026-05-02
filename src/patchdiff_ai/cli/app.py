"""`patchdiff-ai` CLI root.

Owns all interactivity. Builds AppContext once, then dispatches to subcommands.
"""

from __future__ import annotations

import os
import sys

import typer

from patchdiff_ai.config.settings import get_settings
from patchdiff_ai.observability.logging import configure_logging

cli = typer.Typer(
    name="patchdiff-ai",
    help="Generate a single CVE report or a Patch Tuesday batch report.",
    no_args_is_help=True,
)


@cli.callback()
def _root(
    log_level: str = typer.Option(
        None,
        "--log-level",
        "-L",
        help="Verbosity: trace, debug, info, warning, error. "
        "At trace/debug, full crash tracebacks are written to the log file.",
        case_sensitive=False,
    ),
) -> None:
    """Configure logging for every subcommand. Runs before any command body."""
    settings = get_settings()
    effective_level = log_level if log_level is not None else settings.log_level
    configure_logging(
        level=effective_level,
        logs_dir=settings.paths.logs_dir,
    )


def _bootstrap() -> None:
    """Force-disable LangSmith / LangChain tracing before LangGraph imports.

    LangChain reads `LANGCHAIN_TRACING_V2` (legacy) and `LANGSMITH_TRACING`
    (newer) at import time to wire up the LangSmith callback. We pin both to
    `false` and strip any inherited API key / endpoint so a stray env var on
    the host machine cannot accidentally ship traces or anonymous data out.
    All observability stays local (structlog → log file).
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


# Subcommand registration is done lazily inside the _bootstrap-aware wrapper
# so importing langgraph happens after we've pinned tracing off.
def _register_commands() -> None:
    from patchdiff_ai.cli.commands import cached, cve, health_check, install, month

    cli.add_typer(health_check.app, name="health-check", help="Validate environment and tools.")
    cli.add_typer(cve.app, name="cve", help="Run analysis on a single CVE.")
    cli.add_typer(month.app, name="month", help="Run analysis for a Patch Tuesday batch.")
    cli.add_typer(cached.app, name="cached", help="Print or save cached reports.")
    cli.add_typer(install.app, name="install", help="Install idalib / IDA plugins from bundled assets.")


def main() -> None:  # entrypoint for `python -m patchdiff_ai`
    _bootstrap()
    _register_commands()
    try:
        cli()
    except (KeyboardInterrupt, EOFError):
        sys.exit(130)


if __name__ == "__main__":
    main()
