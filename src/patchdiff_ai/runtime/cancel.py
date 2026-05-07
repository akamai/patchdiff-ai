"""Cancellable async runner for the CLI.

`asyncio.run()` on Windows ProactorEventLoop doesn't always cancel the running
task on Ctrl+C — it can sit waiting on a subprocess pipe until the child
exits. We install a SIGINT handler that explicitly cancels the root task so
the cleanup paths (`process.py` killing 7z, the download thread setting its
cancel event) get a chance to fire.
"""

from __future__ import annotations

import asyncio
import signal
import sys
from typing import Awaitable, TypeVar

import structlog

from patchdiff_ai.observability.logging import write_traceback_to_file
from patchdiff_ai.runtime.errors import DiskFullError, KbCatalogUnavailableError

log = structlog.get_logger(__name__)

T = TypeVar("T")


def run_cancellable(coro: Awaitable[T]) -> T:
    """Run `coro` to completion. Ctrl+C cancels the task and exits 130.

    Unhandled exceptions from the coroutine are routed through structlog
    before propagating, so the per-run log file always shows that a crash
    occurred even at INFO level. The full traceback is emitted as a DEBUG
    event so it lands on disk only when `--log-level debug` (or `trace`)
    is set.
    """
    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        task = loop.create_task(coro)  # type: ignore[arg-type]

        def _on_sigint(_signum: int, _frame: object) -> None:
            loop.call_soon_threadsafe(task.cancel)

        prev_handler = signal.signal(signal.SIGINT, _on_sigint)
        try:
            return loop.run_until_complete(task)
        except asyncio.CancelledError:
            sys.exit(130)
        except KeyboardInterrupt:
            sys.exit(130)
        except SystemExit:
            raise
        except DiskFullError as exc:
            # Expected, environmental — not a bug. No traceback even at TRACE.
            log.error(
                "disk_full",
                path=str(exc.path),
                free_mb=(exc.free_bytes // (1024 * 1024)) if exc.free_bytes else None,
            )
            sys.exit(1)
        except KbCatalogUnavailableError as exc:
            # Catalog can't deliver this KB. Single clean line; the hint
            # carries the recovery suggestion.
            log.error(
                "kb_catalog_unavailable",
                kb=exc.kb,
                product=exc.product,
                reason=exc.reason,
                hint=exc.hint,
            )
            sys.exit(1)
        except BaseException as exc:
            log.error(
                "run_crashed",
                error_type=type(exc).__name__,
                error=str(exc)[:500],
            )
            # Always dump the full traceback to the log file, regardless of
            # level — Rich's terminal panel can truncate, and at INFO the
            # debug event below is filtered out, leaving no on-disk trace.
            write_traceback_to_file(exc, tag="run_crashed")
            log.debug("run_crashed_traceback", exc_info=True)
            raise
        finally:
            signal.signal(signal.SIGINT, prev_handler)
    finally:
        try:
            _cancel_pending(loop)
        finally:
            asyncio.set_event_loop(None)
            loop.close()


def _cancel_pending(loop: asyncio.AbstractEventLoop) -> None:
    pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
    if not pending:
        return
    for t in pending:
        t.cancel()
    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
