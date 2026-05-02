"""Platform plugin registry — provider-level.

Each `PlatformProvider` contributes one Click sub-group (`windows`,
`linux`, ...). CVE→provider resolution is two-phase:

  1. **Native, parallel.** Every provider's `matches_native(cve_id)`
     runs concurrently against its own advisory source (Windows: MSRC
     SUG, Linux: distro tracker). The first provider to claim the CVE
     wins; ties pick by registration order.
  2. **NVD fallback.** Only if every native check missed do we hit
     NVD's CPE data and ask each provider's `matches_nvd(cpes)` in
     order.

Today: just `WindowsProvider`. Adding a second provider is a one-line
append + an entry in this module.
"""

from __future__ import annotations

import asyncio
from functools import lru_cache

import structlog

from patchdiff_ai.platforms.base import (
    Platform,
    PlatformProvider,
    UnknownPlatform,
    UnsupportedPlatform,
)
from patchdiff_ai.platforms.linux import LinuxDistroPlatform, LinuxProvider
from patchdiff_ai.platforms.windows import WindowsProvider, WindowsVersionedPlatform

log = structlog.get_logger(__name__)


@lru_cache(maxsize=1)
def providers() -> tuple[PlatformProvider, ...]:
    """All registered providers, process-wide cached."""
    return (WindowsProvider(), LinuxProvider())


def provider_by_name(name: str) -> PlatformProvider:
    """Lookup a provider by `--platform <name>`."""
    target = name.lower()
    for p in providers():
        if p.name.lower() == target:
            return p
    raise UnknownPlatform(
        f"unknown platform {name!r}; registered: {[p.name for p in providers()]}"
    )


async def _native_round(cve_id: str) -> tuple[PlatformProvider, Platform] | None:
    """Run every provider's `matches_native` in parallel; return the first
    `(provider, platform)` that claims the CVE, or None if all missed.

    Exceptions from individual providers are downgraded to misses with
    a debug log — one provider's network blip shouldn't sink the whole
    auto-detect.
    """
    plugins = providers()
    tasks = [asyncio.create_task(p.matches_native(cve_id)) for p in plugins]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    matched: list[tuple[PlatformProvider, Platform]] = []
    for p, result in zip(plugins, results):
        if isinstance(result, BaseException):
            log.debug("matches_native_error", provider=p.name, error=str(result))
            continue
        if result is None:
            continue
        matched.append((p, result))

    if not matched:
        return None
    if len(matched) > 1:
        names = [p.name for p, _ in matched]
        log.warning(
            "multiple_providers_native_match",
            cve=cve_id,
            matched=names,
            picked=names[0],
            hint="pass --platform <name> to force one",
        )
    return matched[0]


def _nvd_round(cve_id: str) -> tuple[PlatformProvider, Platform] | None:
    """Sync NVD fallback. Hits NVD's CPE list, then asks each provider's
    `matches_nvd` in registration order. Returns the first claim or None
    (also None if NVD has no data for this CVE)."""
    from patchdiff_ai.platforms.nvd import cpes_for

    cpes = cpes_for(cve_id)
    if not cpes:
        return None

    for p in providers():
        platform = p.matches_nvd(cpes)
        if platform is not None:
            log.info("nvd_fallback_match", cve=cve_id, provider=p.name,
                     platform=platform.name)
            return p, platform
    return None


def resolve_for_cve(
    cve_id: str,
    *,
    platform_override: str | None = None,
) -> tuple[PlatformProvider, Platform]:
    """Resolve `cve_id` to `(provider, concrete Platform)`.

    Order of operations:
      0. If `--platform <name>` is given, look up that provider; ask it
         to pick the right version (native first, then NVD, then
         provider-default).
      1. Otherwise: run every provider's `matches_native` in parallel.
         First non-None wins.
      2. If all native checks miss: query NVD once, ask each provider's
         `matches_nvd`. First non-None wins.
      3. Nothing claimed it: `UnsupportedPlatform`.
    """
    if platform_override:
        provider = provider_by_name(platform_override)
        try:
            plat = asyncio.run(provider.matches_native(cve_id))
        except RuntimeError:
            # Edge case: an outer event loop is already running. Fall
            # back to skipping the async native call here; NVD round
            # below will still get a chance.
            plat = None
        if plat is not None:
            return provider, plat
        nvd_result = _nvd_round(cve_id)
        if nvd_result is not None and nvd_result[0] is provider:
            return nvd_result
        # Last resort: provider-chosen default version.
        log.info(
            "platform_override_default_version",
            cve=cve_id,
            provider=provider.name,
            hint="MSRC and NVD both missed; falling back to provider's default version.",
        )
        return provider, provider.resolve()

    native = asyncio.run(_native_round(cve_id))
    if native is not None:
        return native

    log.info("native_match_missed_falling_back_to_nvd", cve=cve_id)
    nvd_result = _nvd_round(cve_id)
    if nvd_result is not None:
        return nvd_result

    raise UnsupportedPlatform(
        f"no provider claims {cve_id!r} (native + NVD both missed). "
        f"Registered: {[p.name for p in providers()]}. "
        f"Pass --platform <name> to force one."
    )


def select_provider(cve_id: str, *, override: str | None = None) -> PlatformProvider:
    """Convenience wrapper: just the provider, discarding the chosen Platform."""
    provider, _ = resolve_for_cve(cve_id, platform_override=override)
    return provider


__all__ = [
    "Platform",
    "PlatformProvider",
    "UnknownPlatform",
    "UnsupportedPlatform",
    "WindowsProvider",
    "WindowsVersionedPlatform",
    "LinuxProvider",
    "LinuxDistroPlatform",
    "providers",
    "provider_by_name",
    "select_provider",
    "resolve_for_cve",
]
