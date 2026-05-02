"""Click root for `patchdiff-ai`.

Mounts:
  * Generic core commands: `cve`, `health-check`, `install`.
  * One sub-group per registered platform provider (`windows`, ...).
  * The legacy typer-based `cached` command via the typer→Click bridge.

The root callback configures structlog before any subcommand body runs,
preserving the same ordering the legacy typer root had (env-strip
already happened in `app._bootstrap()` before this module was imported).
"""

from __future__ import annotations

import click

from patchdiff_ai.config.settings import get_settings
from patchdiff_ai.observability.logging import configure_logging
from patchdiff_ai.platforms import providers


@click.group(
    name="patchdiff-ai",
    help="patchdiff-ai — security-update RCA across platforms.",
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.option(
    "-L",
    "--log-level",
    default=None,
    help="Verbosity: trace, debug, info, warning, error. "
    "At trace/debug, full crash tracebacks are written to the log file.",
)
@click.pass_context
def root(ctx: click.Context, log_level: str | None) -> None:
    settings = get_settings()
    effective_level = log_level if log_level is not None else settings.log_level
    configure_logging(level=effective_level, logs_dir=settings.paths.logs_dir)
    ctx.ensure_object(dict)
    ctx.obj["log_level"] = effective_level


def build_root() -> click.Group:
    """Wire commands + provider sub-groups onto the root group."""
    # Lazy imports so the module-level `import click` cost stays low and
    # so command modules only execute when their commands are dispatched.
    from patchdiff_ai.cli.commands.cve import cve_command
    from patchdiff_ai.cli.commands.health_check import health_check_command
    from patchdiff_ai.cli.commands.install import install_group

    root.add_command(cve_command)
    root.add_command(health_check_command)
    root.add_command(install_group)

    # Mount each registered provider's Click group.
    for provider in providers():
        root.add_command(provider.cli_group())

    # `cached` stays on typer for now; mount via the typer→Click bridge.
    from typer.main import get_command

    from patchdiff_ai.cli.commands import cached as cached_module

    root.add_command(get_command(cached_module.app), name="cached")

    return root
