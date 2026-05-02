"""Click sub-group mounted as `patchdiff-ai windows ...`.

Owns four commands:

* `cve <CVE-ID> [--platform-id N]` — single-CVE run forced through
  the Windows path (skips NVD auto-detect).
* `health-check` — run `WindowsProvider.health_check()`.
* `install` — run `WindowsProvider.install()`.
* `month <YYYY-MMM> [--platform-id N]` — Patch Tuesday batch run.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import click

from patchdiff_ai.cli.options import cve_options
from patchdiff_ai.platforms.windows.cycle import (
    collect_cves,
    download_cvrf,
    normalize_month,
    pick_ids,
)

if TYPE_CHECKING:
    from patchdiff_ai.platforms.windows.provider import WindowsProvider


def build_windows_group(provider: "WindowsProvider") -> click.Group:
    grp = click.Group(name=provider.name, help="Windows (MSRC) operations.")

    @grp.command("health-check", help="Validate Windows-side prerequisites.")
    def _hc() -> None:
        ok = provider.health_check()
        if not ok:
            raise click.ClickException("Windows health-check reported failures.")

    @grp.command("install", help="Install Windows-side prerequisites.")
    def _install() -> None:
        provider.install()

    @grp.command("cve", help="Run RCA on a single CVE through the Windows path.")
    @click.argument("cve_id", metavar="CVE-YYYY-NNNNN")
    @click.option(
        "--platform-id",
        type=int,
        default=None,
        help="Force a specific MSRC product ID (Windows release).",
    )
    @cve_options
    @click.pass_context
    def _cve(
        ctx: click.Context,
        cve_id: str,
        platform_id: int | None,
        eval_mode: bool,
        interrupt: bool,
        chat: bool,
        chat_permissive: bool,
    ) -> None:
        from patchdiff_ai.cli.runner import run_single_cve

        platform = provider.resolve(platform_id=platform_id)
        run_single_cve(
            ctx,
            cve_id=cve_id,
            platform=platform,
            eval_mode=eval_mode,
            interactive=interrupt,
            chat=chat,
            chat_permissive=chat_permissive,
        )

    @grp.command("month", help="Run analysis for an entire Patch Tuesday cycle.")
    @click.argument("cycle_id", metavar="YYYY-MMM")
    @click.option(
        "--platform-id",
        type=int,
        default=None,
        help="Force a specific MSRC product ID. Default: every Windows release "
             "configured in platforms.json.",
    )
    @click.option(
        "--platform-name",
        default="",
        help="MSRC product-name filter (e.g. 'Windows 11 Version 24H2').",
    )
    @click.option(
        "--eval",
        "eval_mode",
        is_flag=True,
        help="Generate reports across multiple models.",
    )
    @click.pass_context
    def _month(
        ctx: click.Context,
        cycle_id: str,
        platform_id: int | None,
        platform_name: str,
        eval_mode: bool,
    ) -> None:
        try:
            month = normalize_month(cycle_id)
        except ValueError as exc:
            raise click.BadParameter(str(exc))

        from patchdiff_ai.cli.runner import run_single_cve

        cvrf = download_cvrf(month)
        ids: set[str] = {str(platform_id)} if platform_id is not None else set()
        targets, names = pick_ids(cvrf, platform_name or None, ids)
        if not targets:
            raise click.ClickException("No matching ProductIDs")

        cve_rows = collect_cves(cvrf, targets)
        if not cve_rows:
            raise click.ClickException("No CVEs found")

        click.echo(f"[*] Selected {names}: {len(cve_rows)} CVEs")

        # Resolve the Windows version once if --platform-id was given;
        # else pick the newest manifest entry per CVE.
        platform = provider.resolve(platform_id=platform_id)
        for row in cve_rows:
            run_single_cve(
                ctx,
                cve_id=row["CVE"],
                platform=platform,
                eval_mode=eval_mode,
                interactive=False,
                chat=False,
                chat_permissive=False,
            )

    return grp
