"""Platform plugin registry — driven by `resources/windows_sxs/platforms.json`.

Each entry in the manifest becomes one `WindowsVersionedPlatform`
instance backed by its `.7z` + `.bin` sibling. Adding a new Windows
release means: run `python resources/index_winsxs.py` for it (which
appends to the manifest), drop in the produced files. No code edits.

The legacy monolithic `WindowsPlatform` is gone — there is no
host-WinSxS reading path any more.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import structlog

from patchdiff_ai.config.settings import get_settings
from patchdiff_ai.platforms.base import (
    Platform,
    UnknownPlatform,
    UnsupportedPlatform,
)
from patchdiff_ai.platforms.winsxs_archive import (
    PlatformsManifest,
    WinsxsArchive,
    staleness_warning,
)
from patchdiff_ai.platforms.windows_versioned import WindowsVersionedPlatform

log = structlog.get_logger(__name__)


@lru_cache(maxsize=1)
def _build_registry() -> tuple[Platform, ...]:
    """Load `platforms.json` and instantiate one plugin per entry.

    Cached process-wide. The cache is keyed on no inputs (the manifest
    path comes from settings, which is itself cached). Tests that need
    to reset can call `_build_registry.cache_clear()`.
    """
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

    plugins: list[Platform] = []
    for spec in manifest.platforms:
        archive = WinsxsArchive(spec, archive_dir, seven_zip)
        plugins.append(WindowsVersionedPlatform(spec, archive))
    log.info(
        "platforms_loaded",
        count=len(plugins),
        names=[p.name for p in plugins],
    )
    return tuple(plugins)


def select_platform(cve_id: str, override: str | None = None) -> Platform:
    """Pick a platform plugin by name (override) or auto-detect via `matches()`.

    Auto-detect hits MSRC once (cheap; cached on the plugin) to confirm a
    productId match. The first plugin to claim the CVE wins; ties are
    broken by manifest order.

    Raises:
        `UnknownPlatform` — override doesn't resolve.
        `UnsupportedPlatform` — no plugin claims the CVE.
    """
    plugins = _build_registry()
    if not plugins:
        raise UnsupportedPlatform(
            "no platforms configured. Run `python resources/index_winsxs.py` "
            "to bundle a Windows version."
        )

    if override:
        target = override.lower()
        for p in plugins:
            if p.name.lower() == target:
                return p
        raise UnknownPlatform(
            f"unknown platform {override!r}; registered: {[p.name for p in plugins]}"
        )
    matched = [p for p in plugins if p.matches(cve_id)]
    if not matched:
        raise UnsupportedPlatform(
            f"no platform plugin claims {cve_id!r}. Configured platforms: "
            f"{[p.name for p in plugins]}. The CVE may affect a Windows "
            "release we haven't bundled yet — run "
            "`python resources/index_winsxs.py` for the missing version, "
            "or use `--platform <name>` to force one."
        )
    if len(matched) > 1:
        log.warning(
            "multiple_platforms_match",
            cve=cve_id,
            matched=[p.name for p in matched],
            picked=matched[0].name,
            hint="pass `--platform <name>` to force a specific one",
        )
    return matched[0]


__all__ = [
    "Platform",
    "UnknownPlatform",
    "UnsupportedPlatform",
    "WindowsVersionedPlatform",
    "select_platform",
]
