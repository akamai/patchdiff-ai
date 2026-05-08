"""Domain-specific errors for graceful CLI exits.

Anything in this module is treated as an *expected* failure: the CLI logs a
single concise event and exits non-zero, without dumping a traceback.
"""

from __future__ import annotations

import shutil
from pathlib import Path


class DiskFullError(Exception):
    """A filesystem write failed because the volume is out of space."""

    def __init__(
        self,
        path: Path | str,
        *,
        free_bytes: int | None = None,
    ) -> None:
        self.path = Path(path)
        self.free_bytes = free_bytes
        msg = f"out of disk space writing to {self.path}"
        if free_bytes is not None:
            msg += f" ({free_bytes // (1024 * 1024)} MB free)"
        super().__init__(msg)


class KbCatalogUnavailableError(Exception):
    """The Microsoft Update Catalog can't deliver a KB we asked for.

    Three observable failure modes, surfaced via this single exception:
      * `reason="empty"` — search page returned 200 with zero result
        rows for the KB.
      * `reason="no_match"` — search page had rows, but none matched
        the product name we asked for.
      * `reason="no_msu"` — UID resolved, but DownloadDialog returned
        no .msu/.cab URL.
    """

    def __init__(self, kb: str, product: str, *, reason: str, hint: str = "") -> None:
        self.kb = kb
        self.product = product
        self.reason = reason
        self.hint = hint
        msg = f"{kb} for {product!r}: {reason}"
        if hint:
            msg += f" ({hint})"
        super().__init__(msg)


def free_bytes_for(path: Path | str) -> int | None:
    """Best-effort free-space lookup. Walks up until it finds an existing
    parent (the target file may not exist yet). Returns None on failure.
    """
    p = Path(path)
    while not p.exists() and p.parent != p:
        p = p.parent
    try:
        return shutil.disk_usage(str(p)).free
    except OSError:
        return None
