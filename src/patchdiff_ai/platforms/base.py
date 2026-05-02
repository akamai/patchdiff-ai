"""Platform plugin protocols.

Two layers:

* `Platform` — per-version concrete plugin (e.g. one Windows release/SKU).
  Owns advisory fetch (`enrich_cve`), package gather (`gather_packages`),
  and candidate-ranking inputs (`candidate_prompts`, `candidate_metadata`).
  RE / VR / FINALIZE stay shared.

* `PlatformProvider` — group-level CLI-facing plugin (e.g. "windows" /
  "linux"). Contributes one Click sub-group, owns NVD-driven CVE→Platform
  resolution, and aggregates health-check / install for everything in
  the provider's scope.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    import click

    from patchdiff_ai.graphs.pipeline.state import PipelineState
    from patchdiff_ai.prompts.registry import PromptId
    from patchdiff_ai.runtime.app_context import AppContext
    from patchdiff_ai.schemas.cve import CveDetails


class UnknownPlatform(KeyError):
    """A `--platform` override was given but no provider has that name."""


class UnsupportedPlatform(LookupError):
    """No registered provider claims this CVE (NVD lookup found no match)."""


class Platform(Protocol):
    """Plug-in for one concrete platform version (e.g. one Windows SKU)."""

    name: str

    async def enrich_cve(
        self, state: "PipelineState", ctx: "AppContext"
    ) -> dict[str, Any]:
        """CVE_INFO stage: advisory data + package selection.

        Returns a state-update dict (`stage`, `os`, `KB`, `cve_details`).
        """
        ...

    async def gather_packages(
        self, state: "PipelineState", ctx: "AppContext"
    ) -> dict[str, Any]:
        """GATHER stage: download + extract pre/post-patch packages.

        Returns a state-update dict with `extracted` / `dataframes` /
        `filtered_dataframes` populated.
        """
        ...

    def candidate_prompts(self) -> tuple["PromptId", "PromptId"]:
        """Return `(collect_prompt_id, rank_prompt_id)` for PI ranking."""
        ...

    def candidate_metadata(self, cve: "CveDetails") -> dict[str, Any]:
        """Project advisory data into a JSON-able dict for ranking prompts."""
        ...


class PlatformProvider(Protocol):
    """Group-level plugin: one Click sub-group, N concrete `Platform`s."""

    name: str

    def cli_group(self) -> "click.Group":
        """Return the Click group mounted as `patchdiff-ai <name> ...`.

        Owns the provider's `cve`, `health-check`, `install`, plus any
        provider-specific commands (Windows: `month`).
        """
        ...

    def health_check(self) -> bool:
        """Validate provider-specific prerequisites. Core env/tool checks
        live in `cli/commands/health_check.py`. Returns True if the
        provider is usable."""
        ...

    def install(self) -> None:
        """Install provider-specific prerequisites (e.g. download a
        WinSxS bundle, prime an apt source-package cache)."""
        ...

    async def matches_native(self, cve_id: str) -> "Platform | None":
        """Primary auto-detect: ask this provider's *native* advisory source
        whether it claims the CVE.

        Windows: hits MSRC's SUG report, picks the version whose
        `msrc_product_ids` are listed as affected. Linux (future): hits
        the distro security tracker / USN list.

        Runs in parallel with every other provider's `matches_native`
        — implementations should `await asyncio.to_thread(...)` for any
        sync HTTP / network calls. Return None on miss; raise only on
        unexpected errors (the runner downgrades exceptions to misses).
        """
        ...

    def matches_nvd(self, cpes: list[str]) -> "Platform | None":
        """NVD CPE *fallback*. Called only if every provider's
        `matches_native` returned None.

        Match against the flattened `cpeMatch.criteria` list NVD ships
        for the CVE; pick the version whose CPE fragment appears in any
        criterion. Return None if this provider doesn't claim any of
        the CPEs.
        """
        ...

    def resolve(self, **overrides: Any) -> "Platform":
        """Pick a concrete `Platform` from CLI overrides.

        Provider-specific kwargs are interpreted by the provider; unknown
        kwargs raise. Windows: `platform_id: int`. Linux (future):
        `distro: str`, `release: str`.
        """
        ...
