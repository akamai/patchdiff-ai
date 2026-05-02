"""Platform plugin protocol.

The pipeline is platform-agnostic; plugins customise three seams:
advisory fetch (CVE_INFO), package gather (GATHER), and the
candidate-ranking prompts + metadata (PI). RE / VR / FINALIZE stay shared.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from patchdiff_ai.graphs.pipeline.state import PipelineState
    from patchdiff_ai.prompts.registry import PromptId
    from patchdiff_ai.runtime.app_context import AppContext
    from patchdiff_ai.schemas.cve import CveDetails


class UnknownPlatform(KeyError):
    """A `--platform` override was given but no plugin in the registry has that name."""


class UnsupportedPlatform(LookupError):
    """No registered plugin's `matches()` returned True for this CVE."""


class Platform(Protocol):
    """Plug-in for platform-specific advisory + package + ranking inputs."""

    name: str

    def matches(self, cve_id: str) -> bool:
        """Cheap, sync, no-network heuristic for auto-detect.

        Runs for every registered plugin on every run; network probing
        belongs in `enrich_cve`.
        """
        ...

    async def enrich_cve(
        self, state: "PipelineState", ctx: "AppContext"
    ) -> dict[str, Any]:
        """CVE_INFO stage: advisory data + package selection.

        Returns a state-update dict (`stage`, `os`, `KB`, `cve_details`).
        The cache short-circuit runs on top of this dict in the pipeline node.
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
        """Return `(collect_prompt_id, rank_prompt_id)` for PI ranking.

        Different platforms have different binary vocabularies (DLL vs
        .so vs .dex) so the prompts swap; the ranking algorithm doesn't.
        """
        ...

    def candidate_metadata(self, cve: "CveDetails") -> dict[str, Any]:
        """Project advisory data into a JSON-able dict for ranking prompts.

        Windows: `cve.msrc_report.model_dump(exclude={'products'})`.
        """
        ...
