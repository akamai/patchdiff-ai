"""IdaMcpService — chat-mode idalib driver over `multiprocessing.Pipe`.

One subprocess hosts ida-pro-mcp's `MCP_SERVER.tools.methods` registry
(api_* analysis + idalib_* lifecycle); the parent talks to it with
pickled `(op, kwargs)` round-trips. No HTTP transport, no MCP framing.

The worker pays a ~5-10 s `idapro` + `ida_pro_mcp` import cost on first
call and stays warm for the chat session; `aclose()` (or the shared
atexit handler) kills it.

Class name kept as `IdaMcpService` for import compatibility despite no
longer using the MCP transport.
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

from patchdiff_ai.tools._subprocess_lifecycle import (
    register,
    terminate_proc,
    unregister,
)

log = structlog.get_logger(__name__)


class IdaMcpUnavailable(RuntimeError):
    """Chat worker can't start (idalib / ida_pro_mcp missing) or has died."""


# ------------------------------------------------------------------ worker


class _IdaChatWorker:
    """Chat worker subprocess + parent-side pipe; single in-flight op."""

    # Generous: first call also pays the ~5-10 s idapro bootstrap.
    DEFAULT_CATALOGUE_TIMEOUT = 120.0
    # Aligned with IdalibPool.DEFAULT_OPEN_TIMEOUT — auto-analysis on
    # big DLLs (mshtml, ieframe) can take minutes.
    DEFAULT_OPEN_TIMEOUT = 600.0
    DEFAULT_CALL_TIMEOUT = 300.0

    def __init__(self) -> None:
        self.proc: _mp.Process | None = None
        self.conn: Connection | None = None
        self.lock: asyncio.Lock = asyncio.Lock()
        self.start_lock: asyncio.Lock = asyncio.Lock()
        self._io_executor: _cf.ThreadPoolExecutor | None = None
        # spawn (not fork): required on Windows; gives the worker a
        # clean Python with no inherited parent state.
        self._mp_ctx = _mp.get_context("spawn")

    @property
    def is_alive(self) -> bool:
        return self.proc is not None and self.proc.is_alive()

    def _ensure_executor(self) -> _cf.ThreadPoolExecutor:
        if self._io_executor is None:
            # One thread is enough; `lock` already serialises recvs.
            self._io_executor = _cf.ThreadPoolExecutor(
                max_workers=1,
                thread_name_prefix="idachat-io",
            )
        return self._io_executor

    async def start(self) -> None:
        """Lazily spawn the worker; idempotent via `start_lock`."""
        if self.is_alive and self.conn is not None:
            return
        async with self.start_lock:
            if self.is_alive and self.conn is not None:
                return

            # Surface ImportError synchronously rather than as a
            # worker-side traceback that exits before the first reply.
            try:
                __import__("idapro")
            except ImportError as exc:
                raise IdaMcpUnavailable(
                    "Python package `idapro` is not importable. Run "
                    "`patchdiff-ai install idalib` to install it from the "
                    "IDA 9.x install's bundled wheel."
                ) from exc
            try:
                __import__("ida_pro_mcp.ida_mcp")
            except ImportError as exc:
                raise IdaMcpUnavailable(
                    "Python package `ida_pro_mcp` is not importable. Run "
                    "`pip install -e .` to pull it from GitHub."
                ) from exc

            t0 = time.perf_counter()
            parent_conn, child_conn = self._mp_ctx.Pipe(duplex=True)
            from patchdiff_ai.tools._idalib_chat_worker import worker_main

            log.info("ida_chat_spawn_start")
            proc = self._mp_ctx.Process(
                target=worker_main,
                args=(child_conn,),
                name="idachat-worker",
                daemon=False,
            )
            proc.start()
            # Drop our copy of the child end so the worker sees EOF
            # when we close the parent end.
            child_conn.close()
            self.proc = proc
            self.conn = parent_conn
            register(proc.pid)
            log.info(
                "ida_chat_spawn_done",
                pid=proc.pid,
                elapsed_s=round(time.perf_counter() - t0, 2),
            )

    async def _send_recv(
        self,
        op: str,
        kwargs: dict[str, Any],
        *,
        timeout: float,
    ) -> Any:
        """Send `(op, kwargs)` and await reply; caller holds `lock`."""
        await self.start()
        assert self.conn is not None
        loop = asyncio.get_running_loop()
        executor = self._ensure_executor()
        log.trace(
            "ida_mcp_send",
            op=op,
            args_keys=sorted(kwargs.keys()) if kwargs else [],
            timeout_s=timeout,
        )
        t0 = time.perf_counter()
        try:
            self.conn.send((op, kwargs))
            tag, payload = await asyncio.wait_for(
                loop.run_in_executor(executor, self.conn.recv),
                timeout=timeout,
            )
        except asyncio.TimeoutError as exc:
            self._kill(reason="timeout")
            raise IdaMcpUnavailable(
                f"chat worker timed out on {op!r} after {timeout:.0f}s"
            ) from exc
        except (EOFError, BrokenPipeError, ConnectionResetError) as exc:
            self._kill(reason="pipe_closed")
            raise IdaMcpUnavailable(
                f"chat worker died during {op!r}: {exc}"
            ) from exc
        elapsed_ms = int((time.perf_counter() - t0) * 1000)
        try:
            payload_size = len(payload) if isinstance(payload, (str, bytes)) else len(repr(payload))
        except Exception:
            payload_size = -1
        log.trace(
            "ida_mcp_recv",
            op=op,
            status=tag,
            payload_size=payload_size,
            elapsed_ms=elapsed_ms,
        )
        if tag == "ok":
            return payload
        # Worker replied with a traceback string.
        first_line = (payload or "").strip().splitlines()[-1] if payload else "<no message>"
        raise RuntimeError(f"chat worker op={op}: {first_line}")

    def _kill(self, *, reason: str) -> None:
        """Emergency teardown when worker state can't be trusted."""
        proc = self.proc
        log.warning(
            "ida_chat_worker_kill",
            pid=proc.pid if proc else None,
            reason=reason,
        )
        if self.conn is not None:
            try:
                self.conn.close()
            except Exception:
                pass
        self.conn = None
        if proc is not None:
            terminate_proc(proc, timeout=3.0)
        self.proc = None

    async def get_catalogue(self) -> list[dict[str, Any]]:
        async with self.lock:
            return await self._send_recv(
                "catalogue", {}, timeout=self.DEFAULT_CATALOGUE_TIMEOUT
            )

    async def open(
        self, path: Path | str, *, run_auto_analysis: bool = True
    ) -> dict[str, Any]:
        async with self.lock:
            return await self._send_recv(
                "open",
                {"path": str(Path(path).resolve()), "run_auto_analysis": run_auto_analysis},
                timeout=self.DEFAULT_OPEN_TIMEOUT,
            )

    async def call(self, name: str, args: dict[str, Any]) -> Any:
        async with self.lock:
            return await self._send_recv(
                "call",
                {"name": name, "args": args or {}},
                timeout=self.DEFAULT_CALL_TIMEOUT,
            )

    async def aclose(self) -> None:
        """Graceful shutdown; idempotent."""
        if self.proc is None:
            return
        if self.conn is not None and self.is_alive:
            try:
                # Skip `lock`: if a prior op timed out and left it held,
                # we still want shutdown to fire.
                self.conn.send(("shutdown", {}))
            except Exception:
                pass
        proc = self.proc
        if proc is not None:
            log.info("ida_chat_aclose", pid=proc.pid)
            try:
                await asyncio.get_running_loop().run_in_executor(
                    self._ensure_executor(), proc.join, 5.0
                )
            except Exception:
                pass
            if proc.is_alive():
                terminate_proc(proc, timeout=3.0)
            else:
                unregister(proc.pid)
        if self.conn is not None:
            try:
                self.conn.close()
            except Exception:
                pass
        self.conn = None
        self.proc = None
        if self._io_executor is not None:
            # wait=False: stuck recv() thread shouldn't block shutdown.
            self._io_executor.shutdown(wait=False)
            self._io_executor = None


# ------------------------------------------------------------------ service


class IdaMcpService:
    """Chat-mode idalib service. Lifetime: one chat session."""

    def __init__(self) -> None:
        self._worker = _IdaChatWorker()
        self._catalogue: list[dict[str, Any]] | None = None

    @property
    def is_running(self) -> bool:
        return self._worker.is_alive

    async def get_catalogue(self) -> list[dict[str, Any]]:
        """Return the ida-pro-mcp tool registry, lazy-spawning the worker.

        Each entry: `{"name", "description", "input_schema"}`. Cached.
        """
        if self._catalogue is not None:
            return self._catalogue
        try:
            self._catalogue = await self._worker.get_catalogue()
        except IdaMcpUnavailable:
            raise
        except Exception as exc:
            log.warning("ida_chat_catalogue_failed", error=str(exc))
            self._catalogue = []
        log.info("ida_chat_catalogue_loaded", n_tools=len(self._catalogue))
        return self._catalogue

    async def open(
        self, path: Path | str, *, run_auto_analysis: bool = True
    ) -> dict[str, Any]:
        """Load `path` and bind it as the active session for `call_tool`."""
        log.info("ida_chat_open_start", path=str(path))
        t0 = time.perf_counter()
        try:
            result = await self._worker.open(path, run_auto_analysis=run_auto_analysis)
        except Exception as exc:
            log.warning(
                "ida_chat_open_failed",
                path=str(path),
                error=str(exc),
                elapsed_s=round(time.perf_counter() - t0, 2),
            )
            raise
        log.info(
            "ida_chat_open_done",
            path=str(path),
            session_id=result.get("session_id"),
            elapsed_s=round(time.perf_counter() - t0, 2),
        )
        return result

    async def call_tool(self, name: str, args: dict[str, Any]) -> Any:
        """Dispatch `name(**args)`; returns the raw upstream value.

        Structure is preserved (no JSON encoding here) so the dispatcher
        can extract count / next_offset / total before serialising for
        the LLM. Raises `IdaMcpUnavailable` on worker death,
        `RuntimeError` on tool-side errors.
        """
        log.info("ida_chat_call_start", tool_name=name)
        t0 = time.perf_counter()
        try:
            result = await self._worker.call(name, args)
        except Exception as exc:
            log.warning(
                "ida_chat_call_failed",
                tool_name=name,
                error=str(exc),
                elapsed_s=round(time.perf_counter() - t0, 2),
            )
            raise
        log.info(
            "ida_chat_call_done",
            tool_name=name,
            elapsed_s=round(time.perf_counter() - t0, 2),
        )
        return result

    async def aclose(self) -> None:
        await self._worker.aclose()
