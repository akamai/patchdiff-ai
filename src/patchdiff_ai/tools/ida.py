"""IDA Pro / idat64 wrapper."""

from __future__ import annotations

import asyncio
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable, Callable

import structlog

from patchdiff_ai.tools.process import ProcessResult

log = structlog.get_logger(__name__)


# Sidecars IDA writes alongside an open `.i64`. Their presence at launch
# means another idat64.exe holds the DB or a prior run crashed.
_IDB_LOCK_SUFFIXES = (".id0", ".id1", ".id2", ".nam", ".til", ".lock")


def _detect_idb_lock(target: Path) -> Path | None:
    """Return the first lock-like sidecar found next to a .i64 target."""
    if target.suffix.lower() != ".i64":
        return None
    base = target.with_suffix("")
    for ext in _IDB_LOCK_SUFFIXES:
        sidecar = base.with_suffix(base.suffix + ext) if base.suffix else base.with_suffix(ext)
        if sidecar.exists():
            return sidecar
    return None


def _tail_log(path: str | None, lines: int = 12) -> str | None:
    """Return the last `lines` lines of an IDA -L log file, or None."""
    if not path:
        return None
    try:
        p = Path(path)
        if not p.exists():
            return None
        text = p.read_text(encoding="utf-8", errors="replace")
        tail = text.splitlines()[-lines:]
        return "\n".join(tail) if tail else None
    except OSError:
        return None


@dataclass
class IdaJob:
    target: Path
    script: Path
    args: list[str] = field(default_factory=list)
    log: str | None = None


class IdaTool:
    """Async batch invoker for `idat64.exe -A -S<script>`."""

    def __init__(self, executable: Path, timeout: float = 60 * 30) -> None:
        self.executable = Path(executable)
        self.timeout = timeout

    def is_valid(self, job: IdaJob) -> bool:
        if not self.executable.is_file():
            log.error("ida_executable_missing", path=str(self.executable))
            return False
        if not job.script.is_file():
            log.error("ida_script_missing", path=str(job.script))
            return False
        if not job.target.exists():
            log.error("ida_target_missing", path=str(job.target))
            return False
        return True

    async def run_script(self, job: IdaJob) -> int:
        """Run a single IDA script. Returns process return code."""
        if not self.is_valid(job):
            return -1

        # IDA's -S takes script path + script args as one space-joined
        # token. `create_subprocess_exec` already runs argv through
        # `list2cmdline` for CreateProcess; adding our own quotes here
        # makes IDA treat the whole `-S"file args"` blob as a filename
        # and pop "could not locate file".
        script_argv: list[str] = [str(job.script), *job.args]
        s_arg = subprocess.list2cmdline(script_argv)

        argv: list[str] = [str(self.executable)]
        if job.log:
            argv.append(f"-L{job.log}")
        argv.append("-A")
        argv.append(f"-S{s_arg}")
        argv.append(str(job.target))

        log.debug("ida_run", argv=argv)

        # A second IDA on a locked DB silently misbehaves and may exit 0.
        # Surface the most likely cause up-front so the failure is clear.
        lock = _detect_idb_lock(job.target)
        if lock is not None:
            log.warning(
                "ida_database_locked",
                target=str(job.target),
                lock=str(lock),
                hint=(
                    "Another idat64.exe holds this database open, or a previous "
                    "run crashed and left lock sidecars. Close other IDA "
                    "instances or delete the *.id0/*.id1/*.id2/*.nam/*.til "
                    "siblings before retrying."
                ),
            )

        # Isolate from the parent's console: IDA flips Windows console
        # mode flags (echo off, mouse-input on, raw mode) and on a crash
        # exit (0xC0000374 is common) doesn't restore them — locking the
        # parent terminal. IDA -A -L<file> writes everything to the log
        # so DEVNULL is fine for all three streams.
        # CREATE_NEW_PROCESS_GROUP detaches IDA from our Ctrl+C broadcast
        # group so a stray Ctrl+C can't reach us via the child.
        creationflags = 0
        if sys.platform == "win32":
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            creationflags=creationflags,
        )
        try:
            await asyncio.wait_for(proc.wait(), timeout=self.timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            log.warning("ida_timeout", target=str(job.target), timeout=self.timeout)
            return -1
        except asyncio.CancelledError:
            # Don't leave a zombie idat64 holding console handles or
            # IDB lock sidecars.
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
            log.info("ida_cancelled", target=str(job.target))
            raise

        rc = proc.returncode if proc.returncode is not None else -1
        if rc != 0:
            log.warning(
                "ida_run_failed",
                target=str(job.target),
                returncode=rc,
                log_file=job.log,
                tail=_tail_log(job.log),
            )
        return rc

    async def batch(
        self,
        jobs: list[IdaJob],
        *,
        condition: Callable[[IdaJob], bool] | None = None,
    ) -> list[int]:
        """Run jobs in parallel, deduping by target path. IDA can't share an idb."""
        results: list[int] = []
        remaining = list(jobs)
        while remaining:
            current: list[IdaJob] = []
            future: list[IdaJob] = []
            seen: set[Path] = set()
            for job in remaining:
                if job.target in seen:
                    future.append(job)
                else:
                    current.append(job)
                    seen.add(job.target)
            picked = [j for j in current if (condition(j) if condition else True)]
            tasks: list[Awaitable[int]] = [self.run_script(j) for j in picked]
            if tasks:
                results.extend(await asyncio.gather(*tasks))
            remaining = future
        return results
