"""On-demand WinSxS archive helper.

Used by `WindowsVersionedPlatform` to materialise baseline binaries from
a per-platform `.7z` archive for the duration of a single `delta_apply`
batch, then throw them away.

The durable cache is `db/patch_store/`, which already holds every
patched binary the pipeline produces. So 7z is paid only the first time
a `(file, base_kb)` combination is touched; on every subsequent run the
existing presence check in `delta_apply` (the `(base_kb_path /
entry["name"]).exists()` short-circuit) skips the entire extract+apply
path, and `extract_baselines` is never called for that entry.
"""

from __future__ import annotations

import json
import tempfile
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import AsyncIterator, Iterable

import polars as pl
import structlog

from patchdiff_ai.tools.seven_zip import SevenZipTool

log = structlog.get_logger(__name__)


@dataclass(frozen=True)
class PlatformSpec:
    """One entry from `<data_root>/windows_sxs/platforms.json`."""

    id: str
    primary_product_id: int
    slug: str
    archive: str           # filename or dirname (relative to the manifest's dir)
    dataframe: str         # filename (relative to the manifest's dir)
    msrc_product_ids: tuple[int, ...]
    msrc_product_name_pattern: str
    # "archive" -> .7z file, extracted on demand into a tempdir.
    # "directory" -> folder with executables already on disk; no extraction.
    type: str = "archive"

    @classmethod
    def from_dict(cls, d: dict) -> "PlatformSpec":
        return cls(
            id=d["id"],
            primary_product_id=int(d["primary_product_id"]),
            slug=d["slug"],
            archive=d["archive"],
            dataframe=d["dataframe"],
            msrc_product_ids=tuple(int(x) for x in d.get("msrc_product_ids", [])),
            msrc_product_name_pattern=d.get("msrc_product_name_pattern", ""),
            type=d.get("type", "archive"),
        )


@dataclass(frozen=True)
class PlatformsManifest:
    """In-memory view of `platforms.json`."""

    generated_at: str  # ISO date or ""
    msrc_month: str    # MSRC month tag or ""
    platforms: tuple[PlatformSpec, ...]
    source_path: Path  # where it was read from

    @classmethod
    def load(cls, path: Path) -> "PlatformsManifest":
        if not path.exists():
            return cls(generated_at="", msrc_month="", platforms=(), source_path=path)
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            generated_at=data.get("_generated_at", ""),
            msrc_month=data.get("_msrc_month", ""),
            platforms=tuple(
                PlatformSpec.from_dict(p) for p in data.get("platforms", [])
            ),
            source_path=path,
        )

    def is_stale(self, max_age_days: int = 30) -> bool:
        """Return True if the manifest is older than `max_age_days`. Empty
        timestamp counts as stale (forces a refresh on first ever run)."""
        if not self.generated_at:
            return True
        try:
            then = date.fromisoformat(self.generated_at)
        except ValueError:
            return True
        return (date.today() - then).days > max_age_days


def _archive_paths_for(spec: PlatformSpec, row: dict) -> tuple[str, str]:
    """For one DataFrame row, return the two archive-relative paths
    needed by `delta_apply`:

      1. the row's own `path` (the reverse-delta file at
         `<component>/r/<filename>`)
      2. the corresponding non-delta baseline at
         `<component>/<filename>` — recreated from `parents[1] / name`
         exactly like the legacy on-host code did.
    """
    rel = row["path"].replace("\\", "/")
    reverse_path = Path(rel)
    base_path = reverse_path.parents[1] / row["name"]
    return rel, str(base_path).replace("\\", "/")


class WinsxsArchive:
    """Lazy wrapper around one per-platform .7z + DataFrame pair."""

    def __init__(self, spec: PlatformSpec, archive_dir: Path, seven_zip: SevenZipTool) -> None:
        self.spec = spec
        self.archive_path = archive_dir / spec.archive
        self.dataframe_path = archive_dir / spec.dataframe
        self._seven_zip = seven_zip
        self._df: pl.DataFrame | None = None

    def get_dataframe(self) -> pl.DataFrame:
        """Load and cache the DataFrame index. Raises FileNotFoundError if
        the indexer hasn't been run yet for this platform."""
        if self._df is None:
            if not self.dataframe_path.exists():
                raise FileNotFoundError(
                    f"DataFrame missing for platform {self.spec.id!r}: "
                    f"{self.dataframe_path}. Run "
                    f"`patchdiff-ai index <winsxs_dir> "
                    f"--product-ids {self.spec.primary_product_id} "
                    f"--slug {self.spec.slug}` to build it."
                )
            self._df = pl.DataFrame.deserialize(self.dataframe_path)
        return self._df

    @asynccontextmanager
    async def extract_baselines(
        self, rows: Iterable[dict]
    ) -> AsyncIterator[Path]:
        """Extract the listed rows' baseline binaries to a `tempfile.
        TemporaryDirectory` and yield its Path. Auto-deletes on exit.

        For each row we extract two files (reverse delta + non-delta
        baseline) — together they're what `delta_apply` needs to
        reconstruct the base KB binary. The returned tmp dir mirrors
        the archive layout, so callers can rebuild absolute paths via
        `tmp / row["path"]`.

        When the platform is backed by a directory (``spec.type ==
        "directory"``), the files are already on disk — yield the
        directory path directly without any extraction.
        """
        rows = list(rows)

        # --- directory mode: files already on disk --------------------------
        if self.spec.type == "directory":
            if not self.archive_path.is_dir():
                raise FileNotFoundError(
                    f"Directory missing for platform {self.spec.id!r}: "
                    f"{self.archive_path}. Run the indexer to produce it."
                )
            log.info(
                "winsxs_directory_yield",
                platform=self.spec.id,
                files=len(rows),
                directory=str(self.archive_path),
            )
            yield self.archive_path
            return

        # --- archive mode: extract from .7z ---------------------------------
        if not rows:
            with tempfile.TemporaryDirectory(prefix=f"winsxs_{self.spec.id}_") as tmp:
                yield Path(tmp)
            return

        if not self.archive_path.exists():
            raise FileNotFoundError(
                f"Archive missing for platform {self.spec.id!r}: "
                f"{self.archive_path}. Run the indexer to produce it."
            )

        # Dedupe — multiple subjects often share package/component dirs.
        wanted: set[str] = set()
        for row in rows:
            for p in _archive_paths_for(self.spec, row):
                wanted.add(p)

        with tempfile.TemporaryDirectory(prefix=f"winsxs_{self.spec.id}_") as tmp:
            tmp_path = Path(tmp)
            t0 = time.perf_counter()
            log.info(
                "winsxs_archive_extract_start",
                platform=self.spec.id,
                files=len(wanted),
                archive=str(self.archive_path),
            )
            res = await self._seven_zip.extract_by_list(
                self.archive_path, sorted(wanted), tmp_path, flat=False
            )
            elapsed = round(time.perf_counter() - t0, 2)
            if res.returncode != 0:
                raise RuntimeError(
                    f"7z extraction failed (rc={res.returncode}) for "
                    f"{self.archive_path}"
                )
            log.info(
                "winsxs_archive_extracted",
                platform=self.spec.id,
                files=len(wanted),
                elapsed_s=elapsed,
                tmp=str(tmp_path),
            )
            yield tmp_path
        log.debug("winsxs_archive_temp_cleaned", platform=self.spec.id)


def staleness_warning(manifest: PlatformsManifest) -> str | None:
    """One-line WARN message if the manifest is older than 30 days, else None."""
    if not manifest.is_stale():
        return None
    if not manifest.generated_at:
        return (
            "platforms.json has no _generated_at; run "
            "`patchdiff-ai refresh-platforms` to populate MSRC product IDs."
        )
    return (
        f"platforms.json _generated_at={manifest.generated_at} is older than "
        f"30 days; run `patchdiff-ai refresh-platforms` to refresh MSRC "
        f"product IDs against the current month."
    )
