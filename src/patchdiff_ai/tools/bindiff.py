"""BinDiff wrapper. One bounded retry on DB corruption."""

from __future__ import annotations

import asyncio
import sqlite3
import time
from pathlib import Path

import structlog
from bindiff import BinDiff

log = structlog.get_logger(__name__)


class BindiffTool:
    """Generates a `.BinDiff` from two `.BinExport` files."""

    @staticmethod
    async def diff(
        primary_binexport: Path,
        secondary_binexport: Path,
        out_path: Path,
    ) -> BinDiff | None:
        """Run BinDiff. On sqlite corruption, retry once with override=True."""
        primary_size = _stat_size(primary_binexport)
        secondary_size = _stat_size(secondary_binexport)
        log.info(
            "bindiff_start",
            primary=primary_binexport.name,
            secondary=secondary_binexport.name,
            primary_size_b=primary_size,
            secondary_size_b=secondary_size,
        )
        t0 = time.perf_counter()
        try:
            result = await asyncio.to_thread(
                BinDiff.from_binexport_files,
                str(primary_binexport),
                str(secondary_binexport),
                str(out_path),
            )
            log.info(
                "bindiff_done",
                out=out_path.name,
                elapsed_s=round(time.perf_counter() - t0, 2),
                retried=False,
            )
            return result
        except sqlite3.DatabaseError:
            log.warning("bindiff_db_corrupted", out=str(out_path))
            try:
                result = await asyncio.to_thread(
                    BinDiff.from_binexport_files,
                    str(primary_binexport),
                    str(secondary_binexport),
                    str(out_path),
                    override=True,
                )
                log.info(
                    "bindiff_done",
                    out=out_path.name,
                    elapsed_s=round(time.perf_counter() - t0, 2),
                    retried=True,
                )
                return result
            except sqlite3.DatabaseError as exc:
                log.error(
                    "bindiff_db_corrupted_after_retry",
                    error=str(exc),
                    elapsed_s=round(time.perf_counter() - t0, 2),
                )
                return None


def _stat_size(p: Path) -> int:
    try:
        return p.stat().st_size
    except OSError:
        return -1
