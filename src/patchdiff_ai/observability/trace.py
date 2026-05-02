"""Per-CVE-run trace context. structlog `merge_contextvars` propagates these."""

from __future__ import annotations

import uuid
from contextlib import contextmanager
from contextvars import ContextVar

import structlog

_run_id: ContextVar[str | None] = ContextVar("run_id", default=None)


def current_run_id() -> str | None:
    return _run_id.get()


@contextmanager
def bind_cve(cve: str, run_id: str | None = None):
    """Attach `cve` and `run_id` to all log records emitted in this scope."""
    rid = run_id or uuid.uuid4().hex[:12]
    token = _run_id.set(rid)
    structlog.contextvars.bind_contextvars(cve=cve, run_id=rid)
    try:
        yield rid
    finally:
        structlog.contextvars.unbind_contextvars("cve", "run_id")
        _run_id.reset(token)
