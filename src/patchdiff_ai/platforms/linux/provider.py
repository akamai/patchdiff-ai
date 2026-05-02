"""`LinuxProvider` — group-level Linux plugin (skeleton).

Today: `ubuntu_24.04` and `debian_12` are pre-declared so `--platform-id`
/ `--distro` resolution and `matches_nvd` have something to chew on.
The actual advisory fetch (`matches_native`) and pipeline-facing
methods on `LinuxDistroPlatform` raise `NotImplementedError`.

Use this as the template for new providers — see
`platforms/add_platform.md`.
"""

from __future__ import annotations

import re
from functools import cached_property
from typing import Any

import click
import structlog

from patchdiff_ai.platforms.base import Platform, PlatformProvider
from patchdiff_ai.platforms.linux.distro import LinuxDistroPlatform

log = structlog.get_logger(__name__)

# NVD CPEs for the major distros: cpe:2.3:o:canonical:ubuntu:24.04:...
# and cpe:2.3:o:debian:debian_linux:12:... (or :debian:... for older
# entries).
_LINUX_NVD_PREFIX = re.compile(
    r"cpe:2\.3:o:(canonical:ubuntu|debian:debian)",
    re.IGNORECASE,
)


class LinuxProvider(PlatformProvider):
    """The `linux` group. Skeleton — see module docstring."""

    name = "linux"

    @cached_property
    def distros(self) -> tuple[LinuxDistroPlatform, ...]:
        # Hard-coded for the skeleton. A real impl would discover the
        # supported (distro, release) set from a manifest file the same
        # way `platforms/windows/provider.py` reads platforms.json.
        return (
            LinuxDistroPlatform("ubuntu", "24.04"),
            LinuxDistroPlatform("ubuntu", "22.04"),
            LinuxDistroPlatform("debian", "12"),
        )

    # ----- PlatformProvider protocol ----------------------------------------

    async def matches_native(self, cve_id: str) -> Platform | None:
        """Stub. A real impl would query the Ubuntu USN / Debian DSA
        trackers in parallel and return the first distro/release that
        lists the CVE as affected."""
        log.debug("linux_matches_native_skeleton", cve=cve_id)
        return None

    def matches_nvd(self, cpes: list[str]) -> Platform | None:
        """Pick a distro by NVD CPE prefix. If the CPE contains an
        `ubuntu` or `debian` token plus a version that matches one of
        our pre-declared distros, return it."""
        if not any(_LINUX_NVD_PREFIX.search(c) for c in cpes):
            return None
        for v in self.distros:
            tok = f":{v.distro}:".lower()
            ver_tok = f":{v.release}:".lower()
            for c in cpes:
                cl = c.lower()
                if tok in cl and ver_tok in cl:
                    log.info(
                        "linux_nvd_match",
                        cve_cpes=len(cpes),
                        matched=v.name,
                    )
                    return v
        return None

    def resolve(self, **overrides: Any) -> Platform:
        """Pick a `LinuxDistroPlatform` by `distro` and/or `release`.

        Both kwargs are optional. With nothing provided, returns the
        newest distro the provider knows about (manifest-order proxy).
        """
        distro = overrides.pop("distro", None)
        release = overrides.pop("release", None)
        if overrides:
            raise TypeError(f"LinuxProvider.resolve: unexpected kwargs {sorted(overrides)}")

        candidates = self.distros
        if distro:
            candidates = tuple(c for c in candidates if c.distro == distro.lower())
        if release:
            candidates = tuple(c for c in candidates if c.release == release)

        if not candidates:
            raise click.BadParameter(
                f"no linux distro matches distro={distro!r} release={release!r}. "
                f"Known: {[d.name for d in self.distros]}"
            )
        return candidates[0]

    def health_check(self) -> bool:
        click.echo("  linux provider             = skeleton (no advisory wiring)")
        click.echo(f"  pre-declared distros       = {len(self.distros)}")
        for d in self.distros:
            click.echo(f"  {d.name:24} = stub")
        return True

    def install(self) -> None:
        click.echo("  linux install is a no-op (skeleton).")
        click.echo("  -> wire apt source-package caches / debdiff binaries here.")

    def cli_group(self) -> click.Group:
        from patchdiff_ai.platforms.linux.cli import build_linux_group
        return build_linux_group(self)
