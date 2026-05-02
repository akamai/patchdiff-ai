"""Single subprocess helper used by every tool wrapper.

Discipline:
  - asyncio.create_subprocess_exec only (no shell=True)
  - mandatory timeout, kill on TimeoutError
  - structured ToolError on non-zero exit
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

import structlog

log = structlog.get_logger("patchdiff_ai.tools")


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: str
    stderr: str


class ToolError(RuntimeError):
    """Tool subprocess exited non-zero or could not be launched."""

    def __init__(self, args: Sequence[str], returncode: int, stderr_tail: str):
        super().__init__(
            f"{args[0] if args else 'tool'} exited {returncode}: {stderr_tail[-512:]}"
        )
        self.args = list(args)
        self.returncode = returncode
        self.stderr_tail = stderr_tail


class ToolTimeout(ToolError):
    """Tool exceeded its timeout and was killed."""

    def __init__(self, args: Sequence[str], timeout: float, stderr_tail: str):
        super().__init__(args, returncode=-1, stderr_tail=stderr_tail)
        self.timeout = timeout


async def run(
    args: Sequence[str | os.PathLike],
    *,
    timeout: float,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    capture: bool = True,
    check: bool = True,
) -> ProcessResult:
    """Run a subprocess with a hard timeout. Always uses argv-style invocation."""
    str_args = [str(a) for a in args]

    stdout = asyncio.subprocess.PIPE if capture else asyncio.subprocess.DEVNULL
    stderr = asyncio.subprocess.PIPE

    log.debug("subprocess_start", argv=str_args, timeout=timeout)
    proc = await asyncio.create_subprocess_exec(
        *str_args,
        stdout=stdout,
        stderr=stderr,
        cwd=str(cwd) if cwd else None,
        env=dict(env) if env is not None else None,
    )

    try:
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        try:
            stdout_b, stderr_b = await proc.communicate()
        except Exception:
            stdout_b, stderr_b = b"", b""
        tail = (stderr_b or b"").decode("utf-8", errors="replace")
        log.warning("subprocess_timeout", argv=str_args, timeout=timeout)
        raise ToolTimeout(str_args, timeout, tail)
    except asyncio.CancelledError:
        # Ctrl+C / task cancellation: don't leave the child running.
        try:
            proc.terminate()
        except ProcessLookupError:
            pass
        try:
            await asyncio.wait_for(proc.wait(), timeout=2)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            try:
                await proc.wait()
            except Exception:
                pass
        log.info("subprocess_cancelled", argv=str_args)
        raise

    out = (stdout_b or b"").decode("utf-8", errors="replace")
    err = (stderr_b or b"").decode("utf-8", errors="replace")
    rc = proc.returncode if proc.returncode is not None else -1

    if check and rc != 0:
        log.warning("subprocess_failed", argv=str_args, returncode=rc, stderr_tail=err[-256:])
        raise ToolError(str_args, rc, err)

    log.debug("subprocess_ok", argv=str_args, returncode=rc)
    return ProcessResult(returncode=rc, stdout=out, stderr=err)
