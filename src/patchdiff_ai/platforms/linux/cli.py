"""Click sub-group mounted as `patchdiff-ai linux ...` (skeleton).

Three commands: `cve`, `health-check`, `install`. The `cve` subcommand
takes `--distro` / `--release` to pick a concrete `LinuxDistroPlatform`
before forwarding to the shared runner.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import click

from patchdiff_ai.cli.options import cve_options

if TYPE_CHECKING:
    from patchdiff_ai.platforms.linux.provider import LinuxProvider


def build_linux_group(provider: "LinuxProvider") -> click.Group:
    grp = click.Group(name=provider.name, help="Linux distro advisory operations (skeleton).")

    @grp.command("health-check", help="Validate Linux-side prerequisites.")
    def _hc() -> None:
        ok = provider.health_check()
        if not ok:
            raise click.ClickException("Linux health-check reported failures.")

    @grp.command("install", help="Install Linux-side prerequisites.")
    def _install() -> None:
        provider.install()

    @grp.command("cve", help="Run RCA on a single CVE through the Linux path.")
    @click.argument("cve_id", metavar="CVE-YYYY-NNNNN")
    @click.option(
        "--distro",
        type=click.Choice(
            sorted({d.distro for d in provider.distros}),
            case_sensitive=False,
        ),
        default=None,
        help="Force a specific Linux distribution.",
    )
    @click.option(
        "--release",
        default=None,
        help="Force a specific release/version (e.g. 24.04).",
    )
    @cve_options
    @click.pass_context
    def _cve(
        ctx: click.Context,
        cve_id: str,
        distro: str | None,
        release: str | None,
        eval_mode: bool,
        interrupt: bool,
        chat: bool,
        chat_permissive: bool,
    ) -> None:
        from patchdiff_ai.cli.runner import run_single_cve

        platform = provider.resolve(distro=distro, release=release)
        run_single_cve(
            ctx,
            cve_id=cve_id,
            platform=platform,
            eval_mode=eval_mode,
            interactive=interrupt,
            chat=chat,
            chat_permissive=chat_permissive,
        )

    return grp
