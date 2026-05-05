"""Click root for `patchdiff-ai`.

Mounts:
  * Generic core commands: `cve`, `health-check`, `install`, `cached`.
  * One sub-group per registered platform provider (`windows`, ...).

The root callback configures structlog before any subcommand body runs;
env-strip already happened in `app._bootstrap()` before this module was
imported.
"""

from __future__ import annotations

import click

from patchdiff_ai.config.settings import get_settings
from patchdiff_ai.observability.logging import configure_logging
from patchdiff_ai.platforms import providers


@click.group(
    name="patchdiff-ai",
    help="patchdiff-ai — security-update RCA across platforms.\n\n"
         "Bare `patchdiff-ai` (or `patchdiff-ai --chat[-permissive]`) drops "
         "into the REPL with no CVE bound — useful for browsing cached "
         "reports, querying Chroma, or driving the IDA tools directly.",
    context_settings={"help_option_names": ["-h", "--help"]},
    invoke_without_command=True,
)
@click.option(
    "-L",
    "--log-level",
    default=None,
    help="Verbosity: trace, debug, info, warning, error. "
    "At trace/debug, full crash tracebacks are written to the log file.",
)
@click.option(
    "--chat",
    "chat_flag",
    is_flag=True,
    default=False,
    help="Force-enter the REPL with no CVE bound (also the default when "
         "no subcommand is given). Ignored when a subcommand is invoked.",
)
@click.option(
    "--chat-permissive",
    "chat_permissive_flag",
    is_flag=True,
    default=False,
    help="Like --chat but skips the y/N tool-approval gate. "
         "Ignored when a subcommand is invoked.",
)
@click.pass_context
def root(
    ctx: click.Context,
    log_level: str | None,
    chat_flag: bool,
    chat_permissive_flag: bool,
) -> None:
    settings = get_settings()
    effective_level = log_level if log_level is not None else settings.log_level
    configure_logging(level=effective_level, logs_dir=settings.paths.logs_dir)
    ctx.ensure_object(dict)
    ctx.obj["log_level"] = effective_level

    # Bare invocation → CVE-less chat. The flags are accepted purely as
    # explicit/documented forms; they have no effect when paired with a
    # subcommand (each subcommand owns its own chat options).
    if ctx.invoked_subcommand is None:
        from patchdiff_ai.cli.runner import run_chat_only

        run_chat_only(permissive=chat_permissive_flag)


def build_root() -> click.Group:
    """Wire commands + provider sub-groups onto the root group."""
    # Lazy imports so the module-level `import click` cost stays low and
    # so command modules only execute when their commands are dispatched.
    from patchdiff_ai.cli.commands.cve import cve_command
    from patchdiff_ai.cli.commands.health_check import health_check_command
    from patchdiff_ai.cli.commands.init import init_command
    from patchdiff_ai.cli.commands.install import install_group

    root.add_command(init_command)
    root.add_command(cve_command)
    root.add_command(health_check_command)
    root.add_command(install_group)

    # Mount each registered provider's Click group.
    for provider in providers():
        root.add_command(provider.cli_group())

    from patchdiff_ai.cli.commands.cached import cached_command

    root.add_command(cached_command)

    return root
