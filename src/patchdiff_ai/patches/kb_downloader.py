"""Async KB downloader. Replaces sync requests-html flow with tenacity retries."""

from __future__ import annotations

import asyncio
import errno
import re
import threading
from pathlib import Path
from typing import TYPE_CHECKING

import requests
import structlog
from requests_html import HTMLSession
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from patchdiff_ai.persistence.patch_store import resource_lock
from patchdiff_ai.runtime.errors import (
    DiskFullError,
    KbCatalogUnavailableError,
    free_bytes_for,
)

if TYPE_CHECKING:
    from patchdiff_ai.observability.progress import ProgressHandle
    from patchdiff_ai.runtime.app_context import AppContext

log = structlog.get_logger(__name__)

SEARCH_URL = "https://www.catalog.update.microsoft.com/Search.aspx?q={}"
DL_URL = "https://catalog.update.microsoft.com/DownloadDialog.aspx"
UID_PAT = re.compile(r"goToDetails\(['\"]([0-9a-f\-]{36})['\"]\)")

# Process-wide bandwidth cap shared by all CVEs in a batch. Lazy-init on
# first use because the configured value is read from `AppContext.settings`
# which isn't available at import time. asyncio.Semaphore (3.10+) is loop-
# agnostic until first __aenter__, so a module-level holder is safe.
_DOWNLOAD_SEM: asyncio.Semaphore | None = None
_DOWNLOAD_SEM_LOCK = asyncio.Lock()


async def _download_semaphore(ctx: "AppContext") -> asyncio.Semaphore:
    global _DOWNLOAD_SEM
    if _DOWNLOAD_SEM is None:
        async with _DOWNLOAD_SEM_LOCK:
            if _DOWNLOAD_SEM is None:
                n = max(1, ctx.settings.concurrency.kb_downloads)
                _DOWNLOAD_SEM = asyncio.Semaphore(n)
                log.info("kb_download_semaphore_init", limit=n)
    return _DOWNLOAD_SEM


class _DownloadCancelled(Exception):
    """Raised inside the streaming thread when the asyncio side cancels."""


def _find_uid(session: HTMLSession, kb: str, product: str) -> str:
    resp = session.get(SEARCH_URL.format(kb), timeout=30)
    target = (
        "microsoft server operating system" if "server" in product.lower() else product.lower()
    )
    target_tokens = set(re.findall(r"[a-z0-9]+", target))
    best_score, best_uid = -1, None
    anchors = resp.html.find("a[onclick^='goToDetails']")
    for a in anchors:
        m = UID_PAT.search(a.attrs.get("onclick", ""))
        if not m:
            continue
        tokens = set(re.findall(r"[a-z0-9]+", a.text.lower()))
        s = len(target_tokens & tokens)
        if s > best_score:
            best_score, best_uid = s, m.group(1)
    if best_uid is None:
        # An empty anchor list means the catalog returned the search
        # page with no result rows at all — distinct from "rows present
        # but none scored a product-name overlap".
        if not anchors:
            raise KbCatalogUnavailableError(
                kb,
                product,
                reason="empty",
                hint=(
                    "Microsoft Update Catalog returned no rows for this KB. "
                    "Drop a downloaded .msu into the KB cache directory to "
                    "bypass the catalog lookup."
                ),
            )
        raise KbCatalogUnavailableError(
            kb,
            product,
            reason="no_match",
            hint=(
                f"{len(anchors)} catalog row(s) matched the KB but none "
                f"matched the product name."
            ),
        )
    return best_uid


def _find_msu(session: HTMLSession, uid: str, kb_num: str, product: str) -> str:
    payload = {"updateIDs": f'[{{"uidInfo":"{uid}","updateID":"{uid}"}}]'}
    html = session.post(DL_URL, data=payload, timeout=30).text
    pat = re.compile(rf"https://[^'\"\s]*kb{kb_num}[^'\"\s]*\.(?:msu|cab)", re.I)
    m = pat.search(html)
    if not m:
        raise KbCatalogUnavailableError(
            f"KB{kb_num}",
            product,
            reason="no_msu",
            hint=(
                "DownloadDialog returned no .msu/.cab URL for the resolved "
                "UID. Drop a downloaded .msu into the KB cache directory "
                "to bypass the download dialog."
            ),
        )
    return m.group(0)


def _stream_to_disk(
    session: HTMLSession,
    url: str,
    dest: Path,
    cancel: threading.Event,
    handle: "ProgressHandle",
) -> None:
    """Stream `url` to `dest`. On cancel, delete the partial file and raise."""
    partial = True
    try:
        with session.get(url, stream=True, timeout=(10, 60)) as r:
            r.raise_for_status()
            total = int(r.headers.get("Content-Length") or 0)
            if total:
                handle.set_total(total)
            with dest.open("wb") as f:
                for chunk in r.iter_content(chunk_size=64 * 1024):
                    if cancel.is_set():
                        raise _DownloadCancelled()
                    if not chunk:
                        continue
                    try:
                        f.write(chunk)
                    except OSError as exc:
                        if exc.errno == errno.ENOSPC:
                            raise DiskFullError(
                                dest, free_bytes=free_bytes_for(dest)
                            ) from exc
                        raise
                    handle.advance(len(chunk))
        partial = False
    finally:
        if partial:
            try:
                dest.unlink(missing_ok=True)
            except OSError:
                pass


async def _grab(
    ctx: "AppContext",
    session: HTMLSession,
    url: str,
    out_dir: Path,
    overwrite: bool,
) -> Path:
    # Local import to avoid an import cycle (extractor pulls in
    # AppContext via type-only imports we don't want here).
    from patchdiff_ai.patches.extractor import extraction_marker

    out_dir.mkdir(parents=True, exist_ok=True)
    name = url.rsplit("/", 1)[1]
    dest = out_dir / name

    async with resource_lock(dest.resolve()):
        # Extraction marker wins over `.msu` presence: post-extraction
        # the .msu is deleted, but the extracted dir (with its report.txt)
        # is the real cache key. Returning `dest` is fine even when the
        # file is gone — `extract_kb` cache-checks the same marker
        # before touching the archive.
        if not overwrite and extraction_marker(dest).exists():
            log.info("kb_extraction_committed", name=name)
            return dest
        if not overwrite and dest.exists():
            log.info("kb_existing", name=name)
            return dest

        handle = ctx.progress.download_task(name)
        cancel = threading.Event()
        loop = asyncio.get_running_loop()

        # Bandwidth cap: gate the actual byte-streaming so a 12-CVE batch
        # spanning many Windows versions doesn't open 12 multi-GB streams
        # at once. Acquired here (inside the per-path lock) so same-KB
        # CVEs never reach this — they short-circuit on the cache check
        # above.
        sem = await _download_semaphore(ctx)
        async with sem:
            log.info("kb_download_start", name=name)
            fut = loop.run_in_executor(
                None, _stream_to_disk, session, url, dest, cancel, handle
            )
            try:
                await fut
            except asyncio.CancelledError:
                cancel.set()
                log.info("kb_download_cancelled", name=name)
                raise
            finally:
                handle.complete()

    log.info("kb_download_done", name=name, mb=dest.stat().st_size // 1_048_576)
    return dest


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=20),
    retry=retry_if_exception_type(requests.RequestException),
)
async def download_kb(
    ctx: "AppContext",
    kb: str,
    product: str,
    out_dir: Path,
    overwrite: bool = False,
) -> Path:
    """Download `kb` (e.g. 'KB5031356') for `product` ('Windows Server 2022').

    Two pre-HTTP shortcuts: an existing `.msu` on disk, or a committed
    extraction whose source `.msu` was deleted post-extract. The latter
    returns a synthetic path (the file isn't there), which is fine —
    its only consumer is `extract_kb`, which short-circuits on the
    extraction marker before ever touching the archive.
    """
    # MSU filenames in MS catalog URLs are lowercase; callers pass `KB...`.
    # Match case-insensitively.
    kb_l = kb.lower()
    existing = [f for f in out_dir.glob("*.msu") if kb_l in f.stem.lower() and f.is_file()]
    if len(existing) == 1:
        log.info("kb_existing", name=existing[0].name)
        return existing[0]
    extracted = [
        d for d in out_dir.glob("extracted_*.msu")
        if kb_l in d.name.lower() and (d / "report.txt").exists()
    ]
    if len(extracted) == 1:
        msu_name = extracted[0].name.removeprefix("extracted_")
        log.info("kb_extraction_committed", name=msu_name)
        return out_dir / msu_name

    kb_num = kb.lower().lstrip("kb")
    session = HTMLSession()
    session.cookies.set("display-culture", "en-US")

    uid = await asyncio.to_thread(_find_uid, session, kb, product)
    url = await asyncio.to_thread(_find_msu, session, uid, kb_num, product)
    return await _grab(ctx, session, url, out_dir, overwrite)
