"""Click sub-group mounted as `patchdiff-ai windows ...`.

Owns the platform-specific commands:

* `cve <CVE-ID> [--platform-id N]` — single-CVE run forced through
  the Windows path (skips NVD auto-detect).
* `health-check` — run `WindowsProvider.health_check()`.
* `index <winsxs_path> ...` — index a WinSxS dump into a platform entry.
* `install` — run `WindowsProvider.install()`.
* `month <YYYY-MMM> [--platform-id N]` — Patch Tuesday batch run.
* `month-stats <YYYY-MMM>` — aggregate cached-report stats for a cycle.
* `recover-cache` — rebuild stale `report.cache` files under the temp dir.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import click
import structlog

from patchdiff_ai.cli.options import cve_options
from patchdiff_ai.platforms.windows.cycle import (
    collect_cves,
    download_cvrf,
    normalize_month,
    pick_ids,
)
from patchdiff_ai.platforms.windows.index import index_command
from patchdiff_ai.platforms.windows.month_stats import month_stats_command
from patchdiff_ai.platforms.windows.recover_cache import recover_cache_command

if TYPE_CHECKING:
    from patchdiff_ai.platforms.base import Platform
    from patchdiff_ai.platforms.windows.provider import WindowsProvider

log = structlog.get_logger(__name__)


_NATIVE_RESOLVE_CONCURRENCY = 10


def build_windows_group(provider: "WindowsProvider") -> click.Group:
    grp = click.Group(name=provider.name, help="Windows (MSRC) operations.")
    grp.add_command(index_command)
    grp.add_command(month_stats_command)
    grp.add_command(recover_cache_command)

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
        help="Force a specific MSRC product ID. Filters the cycle's CVE list "
             "to those affecting that product AND runs every selected CVE "
             "against that Windows release. Default: include CVEs affecting "
             "any product in this cycle and pick the right Windows release "
             "per CVE via MSRC.",
    )
    @click.option(
        "--platform-name",
        default="",
        help="MSRC product-name filter (e.g. 'Windows 11 Version 24H2'). "
             "Filter-only — does not force a Windows version. Combine with "
             "--platform-id if you also want to force one.",
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
        # Cheap validation first — fail fast before the CVRF download.
        try:
            month = normalize_month(cycle_id)
        except ValueError as exc:
            raise click.BadParameter(str(exc))

        from patchdiff_ai.cli.runner import run_batch_cves

        cvrf = download_cvrf(month)

        # Default product-ID filter when no flags given: every MSRC product
        # this provider's configured versions know about. Without this the
        # cycle returns zero CVEs because the legacy `pick_ids(set(), None)`
        # contract was "filter by nothing → return nothing".
        if platform_id is not None:
            ids: set[str] = {str(platform_id)}
        elif platform_name:
            ids = set()  # pick_ids resolves the name → ids itself
        else:
            ids = {
                str(pid)
                for v in provider.versions
                for pid in v.spec.msrc_product_ids
            }

        targets, names = pick_ids(cvrf, platform_name or None, ids)
        if not targets:
            raise click.ClickException("No matching ProductIDs")

        cve_rows = collect_cves(cvrf, targets)
        if not cve_rows:
            raise click.ClickException("No CVEs found")

        click.echo(f"[*] Selected {names}: {len(cve_rows)} CVEs")

        # Per-CVE platform resolution.
        # --platform-id given → force that version for every CVE.
        # --platform-id absent → ask MSRC per CVE (matches_native) and
        # fall back to the newest manifest entry for any CVE MSRC misses.
        if platform_id is not None:
            forced = provider.resolve(platform_id=platform_id)
            cves: list[tuple[str, "Platform"]] = [(row["CVE"], forced) for row in cve_rows]
        else:
            cves = asyncio.run(
                _resolve_per_cve(provider, [row["CVE"] for row in cve_rows])
            )

        run_batch_cves(ctx, cves=cves, eval_mode=eval_mode)

    return grp


async def _resolve_per_cve(
    provider: "WindowsProvider", cve_ids: list[str]
) -> list[tuple[str, "Platform"]]:
    """Resolve each CVE's Windows version via MSRC, in parallel up to
    `_NATIVE_RESOLVE_CONCURRENCY`. CVEs MSRC can't claim fall back to
    `provider.resolve()` (newest manifest entry) and a warning log."""
    sem = asyncio.Semaphore(_NATIVE_RESOLVE_CONCURRENCY)

    async def _one(cve_id: str) -> "Platform":
        async with sem:
            try:
                plat = await provider.matches_native(cve_id)
            except Exception as exc:
                log.warning("month_native_match_error", cve=cve_id, error=str(exc))
                plat = None
        if plat is None:
            log.warning(
                "month_native_match_fallback",
                cve=cve_id,
                hint="MSRC didn't claim this CVE for any configured Windows version. "
                     "Falling back to newest. Pass --platform-id to force.",
            )
            plat = provider.resolve()
        return plat

    plats = await asyncio.gather(*[_one(c) for c in cve_ids])
    return list(zip(cve_ids, plats))
