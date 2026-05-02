"""Per-Windows-version platform plugin, parameterised by `PlatformSpec`.

Replaces the monolithic `WindowsPlatform` (which read baselines off the
host's `C:\\Windows\\WinSxS`). Every concrete Windows release/SKU the
project ships an archive for becomes one instance of this class, loaded
from `resources/windows_sxs/platforms.json` at startup.

The pipeline-facing seams (`enrich_cve`, `gather_packages`,
`candidate_prompts`, `candidate_metadata`) are unchanged from the legacy
`WindowsPlatform`. The two new things:

  * `matches(cve)` is no longer "any CVE-…": each instance only claims
    a CVE when MSRC's affected products include this archive's
    `msrc_product_ids`.
  * `get_winsxs_df()` and `extract_baselines(rows)` come from the
    archive helper, not the host filesystem.
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
        # Cache the MSRC report fetch within a single run — `matches` and
        # `enrich_cve` both pull it. Keyed by CVE id; one entry expected.
        self._msrc_cache: dict[str, Any] = {}

    # ----- Platform protocol ------------------------------------------------

    def matches(self, cve_id: str) -> bool:
        """True if MSRC lists any of this platform's product IDs as affected.

        This *does* hit the network on auto-detect, but the result is
        memoised so subsequent calls (e.g. `enrich_cve`) reuse it. Only
        a well-formed CVE id is checked; everything else returns False.
        """
        if not cve_id.upper().startswith("CVE-"):
            return False
        try:
            metadata = self._fetch_msrc(cve_id)
        except Exception as exc:
            # Network / API failure: don't claim the CVE. select_platform
            # will try the next plugin or raise UnsupportedPlatform.
            log.debug("matches_msrc_fetch_failed",
                      platform=self.name, cve=cve_id, error=str(exc))
            return False
        wanted = set(self.spec.msrc_product_ids)
        return any(p.get("productId") in wanted for p in metadata.products)

    async def enrich_cve(
        self, state: "PipelineState", ctx: "AppContext"
    ) -> dict[str, Any]:
        from patchdiff_ai.graphs.pipeline.routing import Stage
        from patchdiff_ai.patches.os_detection import processor_arch_tokens
        from patchdiff_ai.runtime.timer import Timer

        async with Timer("cve_enrichment"):
            metadata = self._fetch_msrc(state.cve_details.cve)

        wanted = set(self.spec.msrc_product_ids)
        # Prefer the primary product id; fall back to the first matching
        # product in the MSRC report.
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

        # Use the resolved product's name + id as the os identity. Arch
        # comes from the host (used for filtering the WinSxS DataFrame),
        # NOT from the archive — the archive can carry multiple arches.
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
        """Return the DataFrame indexing this archive's contents. Loaded
        lazily and cached for the life of the plugin instance."""
        return self._archive.get_dataframe()

    def extract_baselines(self, rows: list[dict]) -> AsyncContextManager[Path]:
        """Async context manager yielding a tmp dir with extracted baselines.

        Caller pattern:

            async with platform.extract_baselines(rows) as tmp:
                for row in rows:
                    real = tmp / row["path"]
                    ...

        The tmp dir is auto-deleted on context exit. The `db/patch_store/`
        cache is the durable store — one extraction per `(file, base_kb)`
        per project lifetime, then the patch_store check at
        `delta_apply.py:48` skips the entire path on re-runs.
        """
        return self._archive.extract_baselines(rows)

    # ----- Internal helpers --------------------------------------------------

    def _fetch_msrc(self, cve_id: str):
        """Memoised MSRC report fetch. Local import to keep `cve_enrichment`
        out of the import path for plugins that never touch MSRC."""
        from patchdiff_ai.patches.cve_enrichment import report
        if cve_id not in self._msrc_cache:
            self._msrc_cache[cve_id] = report(cve_id)
        return self._msrc_cache[cve_id]
