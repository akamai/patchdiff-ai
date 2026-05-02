"""KB extractor: nests 7-Zip + PSF, leaves a `report.txt` next to the output."""

from __future__ import annotations

import asyncio
import re
import shutil
import time
from pathlib import Path
from typing import Iterable

import structlog

from patchdiff_ai.observability.progress import ProgressHandle
from patchdiff_ai.runtime.app_context import AppContext
from patchdiff_ai.runtime.errors import DiskFullError, free_bytes_for
from patchdiff_ai.tools.delta import DeltaApi
from patchdiff_ai.tools.psf import PsfArchive
from patchdiff_ai.tools.seven_zip import SevenZipTool

log = structlog.get_logger(__name__)

EXECUTABLE_EXTENSIONS = (".exe", ".dll", ".ocx", ".sys", ".com", ".scr", ".cpl")

_DISK_FULL_RE = re.compile(
    r"(not enough space|no space left|disk(?:\s+is)?\s+full|output device is full)",
    re.IGNORECASE,
)


def extraction_marker(msu_path: Path) -> Path:
    """Path whose existence proves extraction is committed for this `.msu`.

    Once present, the source `.msu` is redundant: re-runs hit the
    extraction cache through this same file (see `extract_kb`), and
    indexing reads only from the extracted dir. Single source of truth
    for the `extracted_<msu_name>/report.txt` naming so the downloader
    and extractor can't drift.
    """
    return msu_path.parent / f"extracted_{msu_path.name}" / "report.txt"


class _KBExtractor:
    """Async KB extractor. Builds an `extracted_<archive>` directory tree."""

    def __init__(
        self,
        *,
        seven_zip: SevenZipTool,
        delta: DeltaApi,
        progress: ProgressHandle,
        n_workers: int = 5,
    ) -> None:
        self.seven_zip = seven_zip
        self.delta = delta
        self.progress = progress
        self.dest: Path = Path()
        self.archives: asyncio.Queue[Path] = asyncio.Queue()
        self.extracted: list[Path] = []
        self.fatal_error: BaseException | None = None
        self.workers = [
            asyncio.create_task(self._worker()) for _ in range(n_workers)
        ]

    async def submit(self, archive: Path, dest: Path) -> None:
        self.dest = dest
        self.progress.add_total(1)
        await self.archives.put(archive)

    async def join(self) -> None:
        await self.archives.join()
        for w in self.workers:
            w.cancel()
        await asyncio.gather(*self.workers, return_exceptions=True)

    async def _worker(self) -> None:
        while True:
            try:
                archive = await self.archives.get()
            except asyncio.CancelledError:
                return
            try:
                if self.fatal_error is None:
                    await self._extract(archive)
            except DiskFullError as exc:
                # Stop the pool; let queued items drain via task_done.
                if self.fatal_error is None:
                    self.fatal_error = exc
                    log.error(
                        "extract_aborted_disk_full",
                        archive=str(archive),
                        path=str(exc.path),
                    )
            except Exception as exc:
                log.warning(
                    "extract_failed", archive=str(archive), error=str(exc)
                )
            finally:
                self.archives.task_done()
                self.progress.advance(1)

    async def _extract(self, archive: Path) -> None:
        ext = archive.suffix.lower()
        if ext == ".psf":
            await self._extract_psf(archive)
            return
        if ext in self.seven_zip.get_supported_ext():
            await self._extract_seven_zip(archive)
            return
        log.error("archive_unsupported", ext=ext)

    async def _extract_psf(self, archive: Path) -> None:
        async with PsfArchive(archive, delta=self.delta) as psf:
            files = await psf.list_filenames()
            executables = [f for f in files if Path(f).suffix.lower() in EXECUTABLE_EXTENSIONS]
            if executables:
                await psf.extract(executables, self.dest / archive.name)
                for e in executables:
                    self.extracted.append(Path(archive.name) / e)

    async def _extract_seven_zip(self, archive: Path) -> None:
        rc, files, stderr = await self.seven_zip.list_files(archive)
        if rc != 0 or not files:
            log.warning("seven_zip_list_failed", archive=str(archive), stderr=stderr[-200:])
            return

        nested_supported = (
            set(self.seven_zip.get_supported_ext()) | {".psf"}
        )
        nested = [f for f in files if Path(f).suffix.lower() in nested_supported]
        executables = [f for f in files if Path(f).suffix.lower() in EXECUTABLE_EXTENSIONS]

        # Extract nested (flat into archives/<archive>/)
        if nested:
            sub_dest = self.dest / "archives" / archive.name
            res = await self.seven_zip.extract_by_list(archive, nested, sub_dest, flat=True)
            self._raise_if_disk_full(res, sub_dest)
            for n in nested:
                p = sub_dest / Path(n).name
                if p.exists():
                    self.extracted.append(Path("archives") / archive.name / Path(n).name)
                    self.progress.add_total(1)
                    await self.archives.put(p)

        if executables:
            exe_dest = self.dest / archive.name
            res = await self.seven_zip.extract_by_list(
                archive, executables, exe_dest, flat=False
            )
            self._raise_if_disk_full(res, exe_dest)
            for e in executables:
                self.extracted.append(Path(archive.name) / e)

    @staticmethod
    def _raise_if_disk_full(result, dest: Path) -> None:
        """7z exits non-zero with a recognisable stderr line on ENOSPC."""
        if result.returncode == 0:
            return
        if _DISK_FULL_RE.search(result.stderr or ""):
            raise DiskFullError(dest, free_bytes=free_bytes_for(dest))


async def extract_kb(ctx: AppContext, kb_path: Path, dest: Path | None = None) -> Path:
    """Extract a KB. Skips if a previous run produced `report.txt`.

    On success the source `.msu` is deleted: extraction is the cache
    key (`report.txt` gates this function on subsequent runs and
    indexing reads only from the extracted dir), so keeping the
    multi-GB archive around buys nothing.
    """
    kb_path = Path(kb_path)
    out = dest or kb_path.parent.absolute() / f"extracted_{kb_path.name}"
    marker = out / "report.txt"

    if marker.exists():
        log.info("kb_extract_existing", out=str(out))
        return out

    start = time.time()
    handle = ctx.progress.extract_task(kb_path.name)
    extractor = _KBExtractor(
        seven_zip=ctx.tools.seven_zip,
        delta=ctx.tools.delta,
        progress=handle,
        n_workers=ctx.settings.concurrency.extractor_workers,
    )
    try:
        await extractor.submit(kb_path, out)
        await extractor.join()
    finally:
        handle.complete()

    if extractor.fatal_error is not None:
        raise extractor.fatal_error

    log.info("kb_extracted", elapsed_s=round(time.time() - start, 2))

    archives_tmp = out / "archives"
    if archives_tmp.exists():
        shutil.rmtree(archives_tmp, ignore_errors=True)

    with marker.open("w", encoding="utf-8") as fh:
        for e in extractor.extracted:
            if e.suffix.lower() in EXECUTABLE_EXTENSIONS:
                fh.write(str(e) + "\n")

    log.info("kb_extracted_report", count=len(extractor.extracted), report=str(marker))

    # `report.txt` is now committed — the .msu is redundant. Capture
    # size first so we can log how much was reclaimed; failure here
    # doesn't invalidate the extraction.
    if kb_path.exists():
        try:
            freed_mb = kb_path.stat().st_size // 1_048_576
            kb_path.unlink()
            log.info("kb_msu_deleted", name=kb_path.name, freed_mb=freed_mb)
        except OSError as exc:
            log.warning("kb_msu_delete_failed", name=kb_path.name, error=str(exc))

    return out


def load_delta_dlls(delta: DeltaApi, kb_paths: Iterable[Path]) -> None:
    """Each KB carries its own UpdateCompression.dll under DesktopDeployment.cab."""
    for kb in kb_paths:
        extracted = kb.parent.resolve() / f"extracted_{kb.name}"
        candidate = extracted / "DesktopDeployment.cab" / "UpdateCompression.dll"
        if candidate.exists():
            delta.load_module(candidate)
