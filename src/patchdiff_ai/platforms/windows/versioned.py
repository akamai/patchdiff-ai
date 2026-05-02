"""Per-Windows-version `Platform` plugin, parameterised by `PlatformSpec`.

Every Windows release/SKU we ship a WinSxS archive for becomes one
instance, loaded from `resources/windows_sxs/platforms.json`. The
provider (`platforms.windows.provider`) owns the catalog and resolves a
CVE / `--platform-id` to one of these instances per run.

Pipeline-facing seams (`enrich_cve`, `gather_packages`,
`candidate_prompts`, `candidate_metadata`) are unchanged from the
legacy monolithic `WindowsPlatform`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, AsyncContextManager
from pathlib import Path

import polars as pl
import structlog

from patchdiff_ai.platforms.base import Platform
from patchdiff_ai.platforms.winsxs_archive import PlatformSpec, WinsxsArchive
from patchdiff_ai.prompts.registry import PromptId

if TYPE_CHECKING:
    from patchdiff_ai.graphs.pipeline.state import PipelineState
    from patchdiff_ai.runtime.app_context import AppContext
    from patchdiff_ai.schemas.cve import CveDetails

log = structlog.get_logger(__name__)


class WindowsVersionedPlatform(Platform):
    """One Windows release/SKU, backed by a bundled WinSxS archive."""

    def __init__(self, spec: PlatformSpec, archive: WinsxsArchive) -> None:
        self.spec = spec
        self.name = spec.id
        self._archive = archive
        # The compiled gather subgraph is built lazily on first use so we
        # don't pay the cost on cache-short-circuited runs.
        self._gather_graph: Any = None
        # Memoised MSRC report per CVE id.
        self._msrc_cache: dict[str, Any] = {}

    # ----- Platform protocol ------------------------------------------------

    async def enrich_cve(
        self, state: "PipelineState", ctx: "AppContext"
    ) -> dict[str, Any]:
        from patchdiff_ai.graphs.pipeline.routing import Stage
        from patchdiff_ai.patches.os_detection import processor_arch_tokens
        from patchdiff_ai.runtime.timer import Timer

        async with Timer("cve_enrichment"):
            metadata = self._fetch_msrc(state.cve_details.cve)

        wanted = set(self.spec.msrc_product_ids)
        product = next(
            (p for p in metadata.products if p.get("productId") == self.spec.primary_product_id),
            None,
        ) or next(
            (p for p in metadata.products if p.get("productId") in wanted),
            None,
        )
        if not product:
            raise RuntimeError(
                f"Platform {self.name!r}: no MSRC product matched "
                f"product_ids={sorted(wanted)} for {state.cve_details.cve}"
            )

        name = product.get("product") or self.spec.slug
        pid = product.get("productId") or self.spec.primary_product_id
        arch = processor_arch_tokens(
            {0: ("x86",), 5: ("arm",), 9: ("amd64",), 12: ("arm64",)}
        )[0]
        log.info("os_detected", name=name, id=pid, arch=arch, platform=self.name)

        articles = [
            a
            for a in (product.get("articles") or [])
            if a.get("article") and a.get("supercedence")
        ]
        if not articles:
            raise RuntimeError(
                f"No two consecutive KBs found for {state.cve_details.cve} "
                f"on platform {self.name!r}"
            )
        article = next(
            (a for a in articles if a.get("type") == "security update"),
            articles[0],
        )

        return {
            "stage": Stage.CVE_INFO_DONE,
            "os": state.os.model_copy(update={"name": name, "id": pid, "arch": arch}),
            "KB": state.KB.model_copy(
                update={
                    "base": product.get("baseVersion"),
                    "current": "KB" + str(article.get("article")),
                    "previous": "KB" + str(article.get("supercedence")),
                }
            ),
            "cve_details": state.cve_details.model_copy(
                update={
                    "description": metadata.description,
                    "msrc_report": metadata,
                }
            ),
        }

    async def gather_packages(
        self, state: "PipelineState", ctx: "AppContext"
    ) -> dict[str, Any]:
        if self._gather_graph is None:
            from patchdiff_ai.graphs.gather_info.graph import build_gather_graph
            self._gather_graph = build_gather_graph(ctx)
        result = await self._gather_graph.ainvoke(state.model_dump())
        return {
            k: result[k]
            for k in ("extracted", "dataframes", "filtered_dataframes")
            if k in result
        }

    def candidate_prompts(self) -> tuple[PromptId, PromptId]:
        return PromptId.PI_COLLECT, PromptId.PI_RANK

    def candidate_metadata(self, cve: "CveDetails") -> dict[str, Any]:
        return {
            k: v
            for k, v in cve.msrc_report.model_dump().items()
            if k != "products"
        }

    # ----- Archive access (consumed by gather_info / delta_apply) -----------

    def get_winsxs_df(self) -> pl.DataFrame:
        return self._archive.get_dataframe()

    def extract_baselines(self, rows: list[dict]) -> AsyncContextManager[Path]:
        return self._archive.extract_baselines(rows)

    # ----- Internal helpers --------------------------------------------------

    def _fetch_msrc(self, cve_id: str):
        from patchdiff_ai.patches.cve_enrichment import report
        if cve_id not in self._msrc_cache:
            self._msrc_cache[cve_id] = report(cve_id)
        return self._msrc_cache[cve_id]
