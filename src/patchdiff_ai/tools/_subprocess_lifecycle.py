"""Process-lifecycle helpers shared by `idalib_pool.py` and `ida_mcp.py`.

One PID registry, one atexit handler, one terminate-or-kill helper, and the
two TCP-port helpers used by the MCP wrapper. Both modules `import * from`
this; nothing else in the codebase should touch the registry directly.
"""

from __future__ import annotations

import atexit
import os
import signal as _signal
import socket
import subprocess
import sys
import time
from multiprocessing.process import BaseProcess
from subprocess import Popen
from typing import Union

# Module-level registry of every IDA-related subprocess we've spawned. The
# `atexit` handler at the bottom taskkills any survivor regardless of how
# Python exits — Ctrl-C (sys.exit(130)), uncaught exception, or `os._exit`
# from a finalizer all still run atexit. Owners must `unregister(pid)` on
# clean shutdown so the atexit handler is a no-op on the happy path.
_SPAWNED_PIDS: set[int] = set()


def register(pid: int | None) -> None:
    """Add `pid` to the survivor registry. None is a no-op."""
    if pid is not None:
        _SPAWNED_PIDS.add(pid)


def unregister(pid: int | None) -> None:
    """Remove `pid` from the survivor registry. None is a no-op."""
    if pid is not None:
        _SPAWNED_PIDS.discard(pid)


def _kill_tracked_pids() -> None:
    if not _SPAWNED_PIDS:
        return
    pids = list(_SPAWNED_PIDS)
    _SPAWNED_PIDS.clear()
    for pid in pids:
        try:
            if sys.platform == "win32":
                subprocess.run(
                    ["taskkill", "/F", "/PID", str(pid)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
            else:
                os.kill(pid, _signal.SIGKILL)
        except Exception:
            pass


atexit.register(_kill_tracked_pids)


def pick_free_port(host: str = "127.0.0.1") -> int:
    """Bind to an ephemeral port, close, return the number. Tiny TOCTOU
    window between our close and the server's bind, but negligible in
    practice — a collision shows up as a loud server-startup failure."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, 0))
        return s.getsockname()[1]


def wait_for_port(host: str, port: int, timeout: float) -> bool:
    """Block until `host:port` accepts a TCP connection or `timeout` elapses."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            try:
                s.connect((host, port))
                return True
            except OSError:
                time.sleep(0.2)
    return False


def terminate_proc(
    proc: Union[Popen, BaseProcess, None],
    *,
    timeout: float = 5.0,
) -> None:
    """Best-effort `terminate → wait → kill` dance, swallowing all errors.

    Accepts either `subprocess.Popen` (idalib-mcp wrapper) or
    `multiprocessing.Process` (idalib pool worker). Both expose
    `terminate()` and `kill()` with compatible semantics; only the wait
    method differs (`wait(timeout)` vs `join(timeout)` + `is_alive()`).
    """
    if proc is None:
        return
    try:
        proc.terminate()
    except Exception:
        pass
    try:
        if isinstance(proc, BaseProcess):
            proc.join(timeout)
            still_alive = proc.is_alive()
        else:
            try:
                proc.wait(timeout=timeout)
                still_alive = False
            except subprocess.TimeoutExpired:
                still_alive = True
    except Exception:
        still_alive = True
    if still_alive:
        try:
            proc.kill()
        except Exception:
            pass
        try:
            if isinstance(proc, BaseProcess):
                proc.join(timeout=2)
            else:
                proc.wait(timeout=2)
        except Exception:
            pass
    try:
        unregister(proc.pid)
    except Exception:
        pass
