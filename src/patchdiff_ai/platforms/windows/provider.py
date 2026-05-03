"""`WindowsProvider` — group-level plugin for the Windows side of the CLI.

Owns the catalog of `WindowsVersionedPlatform` instances loaded from
`resources/windows_sxs/platforms.json`. Resolves a CVE to a concrete
`Platform` either by NVD CPE match or by `--platform-id` override.
"""

from __future__ import annotations

import asyncio
import os
import re
from functools import cached_property
from pathlib import Path
from typing import Any

import click
import structlog

from patchdiff_ai.config.settings import get_settings
from patchdiff_ai.platforms.base import Platform, PlatformProvider
from patchdiff_ai.platforms.winsxs_archive import (
    PlatformsManifest,
    WinsxsArchive,
    staleness_warning,
)
from patchdiff_ai.platforms.windows.versioned import WindowsVersionedPlatform

log = structlog.get_logger(__name__)

# Microsoft's NVD CPE prefixes are like:
#   cpe:2.3:o:microsoft:windows_11_24h2:...
#   cpe:2.3:o:microsoft:windows_server_2025:...
# Matching against `:o:microsoft:` gives both Windows client + server.
_MS_NVD_PREFIX = re.compile(r"cpe:2\.3:o:microsoft:windows", re.IGNORECASE)


class WindowsProvider(PlatformProvider):
    """The `windows` group: aggregates all bundled WinSxS-backed versions."""

    name = "windows"

    def __init__(self) -> None:
        self._versions: tuple[WindowsVersionedPlatform, ...] | None = None
        # Memoised MSRC report per CVE id; shared with each version's
        # `_msrc_cache` so `enrich_cve` reuses it instead of re-fetching.
        self._msrc_cache: dict[str, Any] = {}

    # ----- catalog loading --------------------------------------------------

    @cached_property
    def versions(self) -> tuple[WindowsVersionedPlatform, ...]:
        """Build the per-version platform list from `platforms.json`. Cached
        for the lifetime of the provider instance."""
        settings = get_settings()
        manifest_path = settings.paths.platforms_manifest
        archive_dir = settings.paths.windows_sxs_dir
        seven_zip_path = settings.tools.seven_zip
        if seven_zip_path is None:
            raise RuntimeError(
                "tools.seven_zip is not configured; can't extract WinSxS archives. "
                "Set TOOLS__SEVEN_ZIP in your env."
            )

        from patchdiff_ai.tools.seven_zip import SevenZipTool
        seven_zip = SevenZipTool(Path(seven_zip_path))

        manifest = PlatformsManifest.load(manifest_path)
        if not manifest.platforms:
            log.warning(
                "no_platforms_configured",
                manifest=str(manifest_path),
                hint="Run `python resources/index_winsxs.py <winsxs_dir> "
                     "--product-id <id> --slug <slug>` to add one.",
            )
            return ()

        warning = staleness_warning(manifest)
        if warning is not None:
            log.warning("platforms_manifest_stale", message=warning)

        versions: list[WindowsVersionedPlatform] = []
        for spec in manifest.platforms:
            archive = WinsxsArchive(spec, archive_dir, seven_zip)
            versions.append(WindowsVersionedPlatform(spec, archive))
        log.info(
            "windows_versions_loaded",
            count=len(versions),
            ids=[v.name for v in versions],
        )
        return tuple(versions)

    # ----- PlatformProvider protocol ----------------------------------------

    async def matches_native(self, cve_id: str) -> Platform | None:
        """Primary auto-detect via MSRC.

        Fetches the CVE's SUG report once (memoised) and returns the
        first configured version whose `msrc_product_ids` are listed
        among the report's affected products. Hands the cached MSRC
        payload to that version so `enrich_cve` reuses it.
        """
        if not cve_id.upper().startswith("CVE-"):
            return None
        try:
            metadata = await asyncio.to_thread(self._fetch_msrc, cve_id)
        except Exception as exc:
            log.debug("windows_msrc_fetch_failed", cve=cve_id, error=str(exc))
            return None

        affected: set[int] = set()
        for p in metadata.products:
            pid = p.get("productId")
            if pid is None:
                continue
            try:
                affected.add(int(pid))
            except (TypeError, ValueError):
                continue
        if not affected:
            return None

        for v in self.versions:
            wanted = set(int(x) for x in v.spec.msrc_product_ids)
            if affected & wanted:
                # Share the cache so v.enrich_cve doesn't refetch.
                v._msrc_cache[cve_id] = metadata
                log.info(
                    "windows_msrc_match",
                    cve=cve_id,
                    matched_version=v.name,
                    matched_pids=sorted(affected & wanted),
                )
                return v
        return None

    def matches_nvd(self, cpes: list[str]) -> Platform | None:
        """NVD CPE fallback. Strict: returns the version whose CPE
        fragment appears in any criterion, or None.

        The orchestrator only calls this if every provider's
        `matches_native` returned None, so we don't need a "pick the
        newest" softer fallback here — that decision moves to the
        caller of `resolve_for_cve`.
        """
        if not any(_MS_NVD_PREFIX.search(c) for c in cpes):
            return None

        for v in self.versions:
            fragment = self._cpe_fragment_for(v.spec.slug)
            if any(fragment in c.lower() for c in cpes):
                log.info(
                    "windows_nvd_match",
                    cve_cpes=len(cpes),
                    matched_version=v.name,
                    fragment=fragment,
                )
                return v
        log.debug(
            "windows_nvd_no_version_match",
            cpes=cpes[:5],
            hint="CVE looks like Windows but no configured slug matched.",
        )
        return None

    def resolve(self, **overrides: Any) -> Platform:
        """Pick a concrete Windows `Platform` from CLI overrides.

        Accepts `platform_id: int | None` (MSRC product ID). Unknown
        kwargs raise. Empty / None means "newest version in the
        manifest".
        """
        platform_id = overrides.pop("platform_id", None)
        if overrides:
            raise TypeError(f"WindowsProvider.resolve: unexpected kwargs {sorted(overrides)}")

        if not self.versions:
            raise RuntimeError(
                "no Windows versions configured. Run "
                "`python resources/index_winsxs.py` to add one."
            )

        if platform_id is None:
            return self.versions[0]

        for v in self.versions:
            if int(platform_id) in set(v.spec.msrc_product_ids):
                return v
            if int(platform_id) == int(v.spec.primary_product_id):
                return v
        ids = sorted({pid for v in self.versions for pid in v.spec.msrc_product_ids})
        raise click.BadParameter(
            f"--platform-id={platform_id} is not in any configured Windows version. "
            f"Known IDs: {ids}"
        )

    def health_check(self) -> bool:
        """Provider-specific checks: manifest present, archives + dataframes
        on disk, MSRC CVRF API reachable."""
        ok = True
        click.echo(f"  versions configured        = {len(self.versions)}")
        for v in self.versions:
            archive_ok = v._archive.archive_path.exists()
            df_ok = v._archive.dataframe_path.exists()
            tag = "OK" if (archive_ok and df_ok) else f"archive={archive_ok} df={df_ok}"
            click.echo(f"  {v.name:24} = {tag}")
            if not (archive_ok and df_ok):
                ok = False

        try:
            import requests
            res = requests.get(
                "https://api.msrc.microsoft.com/cvrf/2025-Apr",
                headers={"Accept": "application/json"},
                timeout=10,
            )
            click.echo(f"  MSRC CVRF reachability     = {'OK' if res.status_code == 200 else f'rc={res.status_code}'}")
            if res.status_code != 200:
                ok = False
        except Exception as exc:
            click.echo(f"  MSRC CVRF reachability     = FAILED ({exc})")
            ok = False

        bindiff_path = os.environ.get("BINDIFF_PATH", "")
        click.echo(f"  BINDIFF_PATH               = {bindiff_path or '<unset>'}")
        return ok

    def install(self) -> None:
        """Install Windows-side prerequisites: idalib + IDA 9.3 plugins.

        Driven from this provider so `patchdiff-ai install` (no
        subcommand) does the right thing on Windows in one call. Steps:

        1. Warn if not running elevated. The `plugins/` copy and the
           `pip install` against `idalib/python/` both target paths
           under `C:\\Program Files\\` and will fail without admin.
        2. If any discovered IDA install ships idalib (>= 9.0), run the
           `idalib` install against the newest such install. Skips
           cleanly when no idalib-capable install exists.
        3. If an IDA 9.3 install is present, copy the bundled
           BinDiff / BinExport DLLs from `resources/bindiff_ida_9.3/`
           into its `plugins/` folder. The bundled DLLs are pinned to
           IDA 9.3's SDK ABI; copying them into 8.x or 9.0 would just
           produce a non-loadable plugin, so we refuse and tell the
           user to install IDA 9.3.

        WinSxS archives still need to be built locally
        (`resources/index_winsxs.py`) — too large to bundle.
        """
        from patchdiff_ai.cli.commands.install import (
            BUNDLED_PLUGIN_IDA_VERSION,
            do_install_ida_plugins,
            do_install_idalib,
            is_admin,
        )
        from patchdiff_ai.config.tools import discover_ida_installs

        if not is_admin():
            click.echo(
                "  [!] Not running as administrator. Writing into "
                "`C:\\Program Files\\IDA *` (idalib wheel install + plugin "
                "copy) likely needs elevation. Re-run this command from an "
                "elevated PowerShell / Command Prompt if the steps below "
                "fail with a permission error."
            )

        installs = discover_ida_installs()
        if not installs:
            click.echo(
                "  [!] No IDA install discovered under Program Files. "
                "Skipping IDA-side steps."
            )
        else:
            ida_versions = ", ".join(f"{i.version[0]}.{i.version[1]}" for i in installs)
            click.echo(f"  IDA installs discovered: {ida_versions}")

            # ---- idalib (any 9.0+ install that ships it) ------------------
            idalib_capable = [i for i in installs if i.has_idalib]
            if idalib_capable:
                # `discover_ida_installs` already sorts newest-first.
                target = idalib_capable[0]
                click.echo(
                    f"\n  --- idalib (target: IDA {target.version[0]}."
                    f"{target.version[1]} at {target.root}) ---"
                )
                try:
                    do_install_idalib(target)
                except click.exceptions.Exit as exc:
                    click.echo(f"  [!] idalib install exited with rc={exc.exit_code}")
                except click.BadParameter as exc:
                    click.echo(f"  [!] idalib install skipped: {exc}")
            else:
                click.echo(
                    "  [!] No idalib-capable IDA install (need 9.0+). "
                    "Skipping idalib step."
                )

            # ---- IDA 9.3 plugins (bundled DLLs are 9.3-only) --------------
            wanted = BUNDLED_PLUGIN_IDA_VERSION
            ida_93 = next((i for i in installs if i.version == wanted), None)
            click.echo(f"\n  --- ida-plugins (target: IDA {wanted[0]}.{wanted[1]}) ---")
            if ida_93 is None:
                click.echo(
                    f"  [!] No IDA {wanted[0]}.{wanted[1]} install found. "
                    "The bundled BinDiff / BinExport DLLs in "
                    "`resources/bindiff_ida_9.3/` are pinned to IDA 9.3's "
                    "SDK ABI and won't load into other minors — skipping."
                )
            else:
                click.echo(f"  Target install: {ida_93.root}")
                try:
                    do_install_ida_plugins(ida_93)
                except click.exceptions.Exit as exc:
                    click.echo(f"  [!] ida-plugins install exited with rc={exc.exit_code}")
                except click.BadParameter as exc:
                    click.echo(f"  [!] ida-plugins install skipped: {exc}")

        # WinSxS archives are too large to bundle and must be built locally.
        click.echo(
            "\n  WinSxS archives must be built locally — "
            "see resources/index_winsxs.py for how to add a Windows version."
        )

    def cli_group(self) -> click.Group:
        """Mounted as `patchdiff-ai windows ...`. Defined in `cli.py` to
        keep the CLI definitions out of the provider's hot path."""
        from patchdiff_ai.platforms.windows.cli import build_windows_group
        return build_windows_group(self)

    # ----- helpers ----------------------------------------------------------

    def _fetch_msrc(self, cve_id: str):
        """Memoised MSRC report fetch shared across versions."""
        from patchdiff_ai.patches.cve_enrichment import report
        if cve_id not in self._msrc_cache:
            self._msrc_cache[cve_id] = report(cve_id)
        return self._msrc_cache[cve_id]

    @staticmethod
    def _cpe_fragment_for(slug: str) -> str:
        """Map a manifest slug ("win11_24h2") to the lowercase fragment
        NVD uses inside CPE criteria ("windows_11_24h2")."""
        s = slug.lower()
        if s.startswith("win"):
            s = "windows_" + s[3:].lstrip("_")
        return s
