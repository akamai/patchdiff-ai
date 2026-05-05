"""IdalibPool — pool of `idapro` worker processes for bulk RE.

`idapro` is process-global (one binary per interpreter) and Hex-Rays
pins the GIL, so processes — not threads — are the only way to
parallelise BinExport / decompile. The parent dispatches via
`multiprocessing.Pipe` with pickled `(op, kwargs)` tuples; no MCP / HTTP
layer in the hot path.

Workers spawn lazily on first `open()` and pin to a binary's path until
`release()`, which closes the IDB *and* terminates the process so the OS
reclaims the 1-2 GB RSS Python won't return otherwise. Every spawned PID
is registered with `_subprocess_lifecycle` so the shared `atexit` cleans
up survivors on Ctrl-C / uncaught exceptions.
"""

from __future__ import annotations

import asyncio
import concurrent.futures as _cf
import multiprocessing as _mp
import time
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Any

import structlog

from patchdiff_ai.config.tools import IdaInstall
from patchdiff_ai.observability.progress import ProgressReporter
from patchdiff_ai.tools._subprocess_lifecycle import register, terminate_proc, unregister

log = structlog.get_logger(__name__)


# Sidecars IDA writes next to an open `.i64`. Their presence at startup
# means a prior run crashed; idalib refuses to reopen until they're gone.
_IDB_LOCK_SUFFIXES = (".id0", ".id1", ".id2", ".nam", ".til", ".lock")


class IdalibUnavailable(RuntimeError):
    """Idalib worker died, timed out, or refused to start."""


class IdalibBinaryBusy(RuntimeError):
    """The IDB sidecars are held by another live IDA process.

    Raised by `_assign` when the cleanup probe cannot remove an existing
    sidecar (typically `.id0` / `.id1`) because another process has the
    file mmap'd. Callers (the RE node) should let this propagate — the
    `RetryPolicy` on the node yields the task back to the LangGraph
    scheduler, and the retry runs after the holder releases.
    """


class _Worker:
    """One spawned subprocess + its parent-side pipe.

    Single-threaded: one in-flight op at a time. Callers hold `self.lock`
    for the round-trip; `start_lock` separately guards the lazy spawn.
    """

    def __init__(self, idx: int) -> None:
        self.idx = idx
        self.proc: _mp.Process | None = None
        self.conn: Connection | None = None
        self.bound_path: Path | None = None
        self.lock: asyncio.Lock = asyncio.Lock()
        self.start_lock: asyncio.Lock = asyncio.Lock()

    @property
    def is_alive(self) -> bool:
        return self.proc is not None and self.proc.is_alive()


class IdalibPool:
    """Pool of `_Worker`s; ops serialised per worker, parallel across workers."""

    # Generous: auto-analysis on a 25 MB DLL can run for minutes.
    DEFAULT_OPEN_TIMEOUT = 600.0
    DEFAULT_OP_TIMEOUT = 600.0

    def __init__(
        self,
        *,
        n_workers: int = 5,
        ida_install: IdaInstall | None = None,
    ) -> None:
        self.n_workers = max(1, n_workers)
        self.ida_install = ida_install
        self._progress: ProgressReporter | None = None
        self.workers: list[_Worker] = [_Worker(idx=i) for i in range(self.n_workers)]
        self._bindings: dict[str, _Worker] = {}
        self._assign_lock: asyncio.Lock = asyncio.Lock()
        # Lazy-init: `__init__` doesn't require a running loop.
        self._worker_freed: asyncio.Event | None = None
        self._next_idx: int = 0
        # Pipe.recv is blocking; lazy thread pool bridges it to asyncio.
        self._io_executor: _cf.ThreadPoolExecutor | None = None
        # spawn (not fork) is required on Windows and gives each worker a
        # clean Python with no inherited state.
        self._mp_ctx = _mp.get_context("spawn")

    def attach_progress(self, reporter: ProgressReporter) -> None:
        """Surface per-call status via a Rich spinner; no-op until called."""
        self._progress = reporter

    # ------------------------------------------------------- core flow

    def _ensure_executor(self) -> _cf.ThreadPoolExecutor:
        if self._io_executor is None:
            self._io_executor = _cf.ThreadPoolExecutor(
                max_workers=self.n_workers,
                thread_name_prefix="idalib-io",
            )
        return self._io_executor

    async def _start_worker(self, w: _Worker) -> None:
        """Lazily spawn the worker; idempotent via `_Worker.start_lock`."""
        if w.is_alive and w.conn is not None:
            return
        async with w.start_lock:
            if w.is_alive and w.conn is not None:
                return
            parent_conn, child_conn = self._mp_ctx.Pipe(duplex=True)
            from patchdiff_ai.tools._idalib_pool_worker import worker_main

            t0 = time.perf_counter()
            log.info("idalib_pool_worker_spawn_start", worker=w.idx)
            proc = self._mp_ctx.Process(
                target=worker_main,
                args=(child_conn,),
                name=f"idalib-worker-{w.idx}",
                daemon=False,
            )
            proc.start()
            # Close our copy of the child end. If we keep it open, the
            # child won't see EOF when we drop our parent end and recv
            # blocks forever.
            child_conn.close()
            w.proc = proc
            w.conn = parent_conn
            register(proc.pid)
            log.info(
                "idalib_pool_worker_spawn_done",
                worker=w.idx,
                pid=proc.pid,
                elapsed_s=round(time.perf_counter() - t0, 2),
            )

    async def _send_recv(
        self,
        w: _Worker,
        op: str,
        kwargs: dict[str, Any],
        *,
        timeout: float,
    ) -> Any:
        """Send `(op, kwargs)` to `w` and await reply. Caller holds `w.lock`."""
        await self._start_worker(w)
        assert w.conn is not None
        loop = asyncio.get_running_loop()
        executor = self._ensure_executor()
        spinner = self._spinner(f"worker {w.idx}: {op} {_short_kwargs(kwargs)}")
        log.info("idalib_pool_op_send", worker=w.idx, op=op)
        log.trace(
            "idalib_pool_op_send_detail",
            worker=w.idx,
            op=op,
            args_keys=sorted(kwargs.keys()) if kwargs else [],
            timeout_s=timeout,
        )
        t0 = time.perf_counter()
        try:
            w.conn.send((op, kwargs))
            try:
                tag, payload = await asyncio.wait_for(
                    loop.run_in_executor(executor, w.conn.recv),
                    timeout=timeout,
                )
            except asyncio.TimeoutError as exc:
                # State is unknown after timeout, and a stale pickled reply
                # could land later and corrupt the next send.
                self._kill_worker(w, reason="timeout")
                raise IdalibUnavailable(
                    f"idalib worker {w.idx} timed out on {op!r} after "
                    f"{timeout:.0f}s"
                ) from exc
            except (EOFError, BrokenPipeError, ConnectionResetError) as exc:
                # Segfault / OOM / IDA crash inside auto-analysis.
                self._kill_worker(w, reason="pipe_closed")
                raise IdalibUnavailable(
                    f"idalib worker {w.idx} died during {op!r}: {exc}"
                ) from exc
        finally:
            if spinner is not None:
                spinner.complete()
        log.info(
            "idalib_pool_op_recv",
            worker=w.idx,
            op=op,
            tag=tag,
            elapsed_s=round(time.perf_counter() - t0, 2),
        )
        if tag == "ok":
            return payload
        first_line = (payload or "").strip().splitlines()[-1] if payload else "<no message>"
        raise RuntimeError(f"idalib worker {w.idx} op={op}: {first_line}")

    def _spinner(self, label: str):
        progress = self._progress
        if progress is None:
            return None
        try:
            return progress.ida_task(label)
        except Exception:
            return None

    def _kill_worker(self, w: _Worker, *, reason: str) -> None:
        """Emergency teardown when worker state can't be trusted."""
        proc = w.proc
        log.warning(
            "idalib_pool_kill",
            worker=w.idx,
            pid=proc.pid if proc else None,
            reason=reason,
        )
        if w.conn is not None:
            try:
                w.conn.close()
            except Exception:
                pass
        w.conn = None
        terminate_proc(proc, timeout=3.0)
        w.proc = None
        # Drop binding so the next assign re-spawns.
        if w.bound_path is not None:
            self._bindings.pop(str(w.bound_path), None)
            w.bound_path = None
        self._notify_worker_freed()

    # ----------------------------------------------------- worker assign

    def _ensure_event(self) -> asyncio.Event:
        if self._worker_freed is None:
            self._worker_freed = asyncio.Event()
        return self._worker_freed

    def _notify_worker_freed(self) -> None:
        ev = self._worker_freed
        if ev is not None:
            ev.set()

    async def _assign(self, binary: Path) -> _Worker:
        """Return the worker that owns `binary`, opening it on first call.

        Round-robin assignment, pinned thereafter (until `release()`).
        When the pool is saturated, **waits** for a free slot instead of
        raising — backpressure stays internal.
        """
        key = str(binary.resolve())
        w = self._bindings.get(key)
        if w is not None:
            log.info("idalib_pool_assign_done", binary=binary.name, worker=w.idx, was_pinned=True)
            return w

        ev = self._ensure_event()
        wait_t0: float | None = None

        # Each iteration tries to claim a free worker; the open-op runs
        # outside the assign lock further down.
        while True:
            async with self._assign_lock:
                w = self._bindings.get(key)
                if w is not None:
                    log.info(
                        "idalib_pool_assign_done",
                        binary=binary.name,
                        worker=w.idx,
                        was_pinned=True,
                    )
                    return w
                for offset in range(self.n_workers):
                    cand = self.workers[(self._next_idx + offset) % self.n_workers]
                    if cand.bound_path is None:
                        w = cand
                        self._next_idx = (self._next_idx + offset + 1) % self.n_workers
                        break
                if w is not None:
                    w.bound_path = binary.resolve()
                    self._bindings[key] = w
                    break

                # Saturated. Clear the event under the lock so we don't
                # miss a notify between our check and our wait.
                ev.clear()
                log.info(
                    "idalib_pool_wait_for_free_worker",
                    binary=binary.name,
                    pool_size=self.n_workers,
                )
                if wait_t0 is None:
                    wait_t0 = time.perf_counter()
            try:
                await asyncio.wait_for(ev.wait(), timeout=1800.0)
            except asyncio.TimeoutError as exc:
                raise IdalibUnavailable(
                    f"Waited 30 minutes for a free idalib worker (pool "
                    f"size: {self.n_workers}). Workers stuck on auto-"
                    f"analysis, or pool under-sized for this workload."
                ) from exc

        wait_s = round(time.perf_counter() - wait_t0, 2) if wait_t0 is not None else 0.0
        log.info(
            "idalib_pool_assign_done",
            binary=binary.name,
            worker=w.idx,
            was_pinned=False,
            wait_s=wait_s,
        )

        # Clear stale lock sidecars from any prior crashed run. If any
        # are held by a live process, yield instead of opening — nuking
        # another IDA's sidecars corrupts its in-flight analysis.
        locked = _clean_idb_sidecars(binary)
        if locked:
            self._bindings.pop(key, None)
            if w.bound_path == binary.resolve():
                w.bound_path = None
            self._notify_worker_freed()
            log.info(
                "idalib_open_busy_yield",
                binary=binary.name,
                sidecar=locked[0].name,
                worker=w.idx,
            )
            raise IdalibBinaryBusy(
                f"{binary.name}: held by another IDA process "
                f"(sidecar locked: {locked[0].name})"
            )

        log.info("idalib_pool_open_start", binary=binary.name, worker=w.idx)
        open_t0 = time.perf_counter()
        async with w.lock:
            for attempt in (1, 2):
                try:
                    await self._send_recv(
                        w, "open",
                        {"path": str(binary.resolve())},
                        timeout=self.DEFAULT_OPEN_TIMEOUT,
                    )
                    break
                except RuntimeError as exc:
                    log.warning(
                        "idalib_pool_open_failed",
                        worker=w.idx,
                        binary=binary.name,
                        attempt=attempt,
                        error=str(exc),
                    )
                    if attempt == 2:
                        self._bindings.pop(key, None)
                        w.bound_path = None
                        self._notify_worker_freed()
                        raise
                    # IDA appends `.i64` to the full filename, so
                    # `with_suffix` would give the wrong path here.
                    idb = binary.with_name(binary.name + ".i64")
                    try:
                        if idb.is_file():
                            idb.unlink()
                    except OSError as unlink_exc:
                        log.warning(
                            "idalib_pool_idb_unlink_failed",
                            path=str(idb),
                            error=str(unlink_exc),
                        )
                    # Same lock-aware cleanup — if a live holder appeared
                    # mid-open, yield rather than corrupting its state.
                    locked = _clean_idb_sidecars(binary)
                    if locked:
                        self._bindings.pop(key, None)
                        w.bound_path = None
                        self._notify_worker_freed()
                        log.info(
                            "idalib_open_busy_yield",
                            binary=binary.name,
                            sidecar=locked[0].name,
                            worker=w.idx,
                            mid_open=True,
                        )
                        raise IdalibBinaryBusy(
                            f"{binary.name}: held by another IDA process "
                            f"(sidecar locked mid-open: {locked[0].name})"
                        ) from exc
        log.info(
            "idalib_pool_open_done",
            binary=binary.name,
            worker=w.idx,
            elapsed_s=round(time.perf_counter() - open_t0, 2),
        )
        return w

    # -------------------------------------------------------- public API

    async def open(self, binary: Path) -> None:
        """Open `binary` in idalib. Idempotent per absolute path."""
        await self._assign(binary)

    async def binexport(
        self,
        binary: Path,
        out: Path,
        *,
        skip_if_exists: bool = True,
    ) -> Path:
        """Run BinExport, persisting the IDB so it's cached for next time.

        `skip_if_exists=True` returns `out` directly when it already
        exists; BinExport is deterministic per IDB.
        """
        if skip_if_exists and out.exists():
            return out
        w = await self._assign(binary)
        log.info("idalib_pool_binexport_start", binary=binary.name, worker=w.idx, out=str(out))
        op_t0 = time.perf_counter()
        async with w.lock:
            await self._send_recv(
                w, "binexport",
                {"out": str(out.resolve())},
                timeout=self.DEFAULT_OP_TIMEOUT,
            )
        log.info(
            "idalib_pool_binexport_done",
            binary=binary.name,
            worker=w.idx,
            elapsed_s=round(time.perf_counter() - op_t0, 2),
        )
        return out

    async def decompile_many(
        self, binary: Path, addrs: list[int]
    ) -> dict[int, str]:
        """Hex-Rays-decompile `addrs` in one round-trip → `{ea: c_source}`.

        Failed addresses (no Hex-Rays unit, malformed CFG) are absent.
        """
        if not addrs:
            return {}
        w = await self._assign(binary)
        log.info(
            "idalib_pool_decompile_start",
            binary=binary.name,
            worker=w.idx,
            n_addrs=len(addrs),
        )
        op_t0 = time.perf_counter()
        async with w.lock:
            result = await self._send_recv(
                w, "decompile_many",
                {"addrs": list(addrs)},
                timeout=self.DEFAULT_OP_TIMEOUT,
            )
        log.info(
            "idalib_pool_decompile_done",
            binary=binary.name,
            worker=w.idx,
            n_addrs=len(addrs),
            n_returned=len(result) if isinstance(result, dict) else 0,
            elapsed_s=round(time.perf_counter() - op_t0, 2),
        )
        if not isinstance(result, dict):
            return {}
        return {int(k): str(v) for k, v in result.items() if isinstance(v, str)}

    async def release(self, binary: Path) -> None:
        """Close the IDB and terminate the worker process.

        Killing the process — not just closing the DB — is the only way
        to return the 1-2 GB of post-auto-analysis RSS to the OS. The
        next bind on this slot lazily respawns.
        """
        key = str(binary.resolve())
        w = self._bindings.get(key)
        if w is None:
            return
        still_bound = sum(1 for x in self.workers if x.bound_path is not None)
        log.info(
            "idalib_pool_release_start",
            binary=binary.name,
            worker=w.idx,
            still_bound=still_bound,
        )
        op_t0 = time.perf_counter()
        if w.is_alive and w.conn is not None:
            async with w.lock:
                try:
                    await self._send_recv(w, "release", {}, timeout=30.0)
                except Exception as exc:
                    log.warning(
                        "idalib_pool_release_op_failed",
                        worker=w.idx,
                        binary=binary.name,
                        error=str(exc),
                    )
                try:
                    w.conn.send(("shutdown", {}))
                except Exception:
                    pass
            await self._await_proc_exit(w, timeout=10.0)
        else:
            self._kill_worker(w, reason="release_after_death")
            log.info(
                "idalib_pool_release_done",
                binary=binary.name,
                worker=w.idx,
                elapsed_s=round(time.perf_counter() - op_t0, 2),
                already_dead=True,
            )
            return
        self._bindings.pop(key, None)
        if w.bound_path == binary.resolve():
            w.bound_path = None
        self._notify_worker_freed()
        log.info(
            "idalib_pool_release_done",
            binary=binary.name,
            worker=w.idx,
            elapsed_s=round(time.perf_counter() - op_t0, 2),
        )

    async def _await_proc_exit(self, w: _Worker, *, timeout: float) -> None:
        """Await exit, terminate after `timeout`, reset the slot for reuse."""
        proc = w.proc
        if proc is None:
            w.conn = None
            return
        try:
            await asyncio.get_running_loop().run_in_executor(
                self._ensure_executor(),
                proc.join,
                timeout,
            )
        except Exception:
            pass
        if proc.is_alive():
            log.warning(
                "idalib_pool_force_terminate",
                worker=w.idx,
                pid=proc.pid,
            )
            terminate_proc(proc, timeout=3.0)
        unregister(proc.pid)
        if w.conn is not None:
            try:
                w.conn.close()
            except Exception:
                pass
        w.proc = None
        w.conn = None

    # ------------------------------------------------------- shutdown

    async def aclose(self) -> None:
        """Graceful shutdown; idempotent."""
        log.info("idalib_pool_aclose_start", n_alive=sum(1 for w in self.workers if w.is_alive))
        for w in self.workers:
            if not w.is_alive or w.conn is None:
                continue
            try:
                # Skip `w.lock`: if a prior op timed out and left it held,
                # we still want shutdown to fire.
                w.conn.send(("shutdown", {}))
            except Exception:
                pass
        for w in self.workers:
            if w.proc is not None:
                await self._await_proc_exit(w, timeout=8.0)
        self._bindings.clear()
        if self._io_executor is not None:
            # wait=False: a stuck recv() thread shouldn't block shutdown.
            self._io_executor.shutdown(wait=False)
            self._io_executor = None
        log.info("idalib_pool_aclose_done")


# ----------------------------------------------------------- helpers


def _clean_idb_sidecars(target: Path) -> list[Path]:
    """Remove stale lock sidecars next to `target`.

    Returns the list of sidecars that exist but could not be unlinked —
    almost always because another live IDA process still has the file
    mmap'd (Windows ERROR_SHARING_VIOLATION). Callers treat a non-empty
    return as "binary is busy elsewhere" and yield instead of force-
    opening; nuking another process's sidecars corrupts that process's
    in-flight analysis.
    """
    locked: list[Path] = []
    for ext in _IDB_LOCK_SUFFIXES:
        sibling = target.with_suffix(target.suffix + ext)
        if sibling.exists():
            try:
                sibling.unlink()
                log.debug("idalib_sidecar_removed", path=str(sibling))
            except OSError as exc:
                log.warning(
                    "idalib_sidecar_unlink_failed",
                    path=str(sibling),
                    error=str(exc),
                )
                locked.append(sibling)
    return locked


def _short_kwargs(kwargs: dict[str, Any]) -> str:
    """Compact one-line description for the spinner."""
    if not kwargs:
        return ""
    for key in ("path", "out"):
        v = kwargs.get(key)
        if v:
            return Path(str(v)).name
    addrs = kwargs.get("addrs")
    if addrs:
        return f"{len(addrs)} addrs"
    for v in kwargs.values():
        s = str(v)
        return s[:40] + ("…" if len(s) > 40 else "")
    return ""
