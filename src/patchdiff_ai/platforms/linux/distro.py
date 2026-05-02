"""`LinuxDistroPlatform` — per-(distro, release) `Platform` skeleton.

Mirrors `WindowsVersionedPlatform`: one instance per distro/release the
project supports (e.g. `ubuntu_24.04`, `debian_12`). Real implementations
would download source `.deb` / `.rpm` pairs, run debdiff/rpmdiff to find
changed source files, and produce `Artifact`s the source-RE backend
(M3) understands.

Skeleton: every pipeline-facing method raises `NotImplementedError`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from patchdiff_ai.platforms.base import Platform
from patchdiff_ai.prompts.registry import PromptId

if TYPE_CHECKING:
    from patchdiff_ai.graphs.pipeline.state import PipelineState
    from patchdiff_ai.runtime.app_context import AppContext
    from patchdiff_ai.schemas.cve import CveDetails


class LinuxDistroPlatform(Platform):
    """One Linux distro/release, e.g. `ubuntu_24.04`. Skeleton."""

    def __init__(self, distro: str, release: str) -> None:
        self.distro = distro
        self.release = release
        self.name = f"{distro}_{release}"

    async def enrich_cve(
        self, state: "PipelineState", ctx: "AppContext"
    ) -> dict[str, Any]:
        raise NotImplementedError(
            f"LinuxDistroPlatform({self.name!r}).enrich_cve is a skeleton. "
            "Wire it to the distro's security tracker (Ubuntu USN / Debian DSA) "
            "and return the same state-update dict shape Windows returns."
        )

    async def gather_packages(
        self, state: "PipelineState", ctx: "AppContext"
    ) -> dict[str, Any]:
        raise NotImplementedError(
            f"LinuxDistroPlatform({self.name!r}).gather_packages is a skeleton. "
            "Wire it to apt-get source / rpm source caches and return "
            "`{extracted, dataframes, filtered_dataframes}`."
        )

    def candidate_prompts(self) -> tuple[PromptId, PromptId]:
        # Reuse the Windows prompts for the skeleton; real impl should
        # ship distro-specific prompts (`linux.collect`, `linux.rank`).
        return PromptId.PI_COLLECT, PromptId.PI_RANK

    def candidate_metadata(self, cve: "CveDetails") -> dict[str, Any]:
        raise NotImplementedError(
            f"LinuxDistroPlatform({self.name!r}).candidate_metadata is a skeleton."
        )
