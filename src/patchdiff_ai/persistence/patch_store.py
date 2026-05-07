"""Polars patch-store I/O — atomic writes + per-key async locks.

Ports:
- `safe_serialize` from common.py (atomic write-temp + fsync + rename)
- `resource_lock` weak-ref Lock table — converted to asyncio.Lock to avoid
  thread/async mixing.
"""

from __future__ import annotations

import os
import shutil
import weakref
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Hashable

import polars as pl
import structlog

from patchdiff_ai.schemas.patch_store import PatchStoreEntry

log = structlog.get_logger(__name__)


def safe_serialize(df: pl.DataFrame, path: Path, format: str = "binary") -> None:
    """Atomically serialize a DataFrame: write tmp → fsync → rename."""
    path = Path(path)
    temp_path = path.with_suffix(path.suffix + ".tmp")

    try:
        path.parent.mkdir(parents=True, exist_ok=True)

        try:
            usage = shutil.disk_usage(path.parent)
            if usage.free / (1024 ** 3) < 0.1:
                log.warning("low_disk_space", available_gb=usage.free / (1024 ** 3))
        except Exception:
            pass

        df.serialize(temp_path, format=format)

        try:
            fd = os.open(temp_path, os.O_RDWR)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        except (OSError, AttributeError):
            log.debug("fsync_failed_continuing")

        os.replace(temp_path, path)
        log.debug("serialized", path=str(path), bytes=path.stat().st_size)

    except Exception:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except Exception:
                pass
        raise


def get_patch_store_df(path: Path) -> pl.DataFrame:
    """Load the master patch-store index.

    The ``path`` column is stored relative to ``paths.patch_store_dir``
    (forward-slashed). Callers absolutize at the boundary where rows
    leave the dataframe — see ``graphs/pipeline/routing.py``.
    """
    if path.exists():
        return pl.DataFrame.deserialize(path)
    df = pl.DataFrame([PatchStoreEntry().to_row()])
    return df.clear()


import asyncio  # noqa: E402

_async_lock_table: weakref.WeakValueDictionary[Hashable, asyncio.Lock] = (
    weakref.WeakValueDictionary()
)
_table_guard = asyncio.Lock()


async def _get_async_lock(key: Hashable) -> asyncio.Lock:
    async with _table_guard:
        lock = _async_lock_table.get(key)
        if lock is None:
            lock = asyncio.Lock()
            _async_lock_table[key] = lock
        return lock


@asynccontextmanager
async def resource_lock(key: Hashable):
    """Async equivalent of the legacy `resource_lock(key)` context manager."""
    if key is None:
        yield
        return
    lock = await _get_async_lock(key)
    async with lock:
        yield
