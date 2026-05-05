"""Subprocess wrapper around the `patchdiff-ai` CLI.

Pure asyncio, captures stdout + stderr, and tail-trims stderr on failure
so we can echo the relevant lines back to Slack without flooding the
channel. The bot assumes `patchdiff-ai` resolves on PATH (i.e. the bot
is launched from the same venv where `pip install -e .` was run).
"""

from __future__ import annotations

import asyncio
import os
import shutil
import sys
from dataclasses import dataclass


@dataclass
class CliResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def _resolve_executable() -> list[str]:
    """Return the argv prefix that invokes patchdiff-ai.

    Prefers the console-script on PATH; falls back to `python -m
    patchdiff_ai.cli.app` when the script isn't present (e.g. a
    Windows venv where Scripts/ isn't on PATH for the bot's process).
    """
    exe = shutil.which("patchdiff-ai")
    if exe:
        return [exe]
    return [sys.executable, "-m", "patchdiff_ai.cli.app"]


async def run_patchdiff(*args: str, timeout: float | None = None) -> CliResult:
    """Run `patchdiff-ai <args...>` and capture stdout / stderr.

    Forces UTF-8 on the child's stdio. On Windows, Python falls back to
    cp1252 when stdout is a pipe; the CLI prints non-ASCII glyphs (e.g.
    `→`) on the platform-resolution path, which crashes under
    cp1252. PYTHONIOENCODING + PYTHONUTF8 cover both interpreter
    versions.
    """
    argv = _resolve_executable() + list(args)
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )
    try:
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise

    return CliResult(
        args=argv,
        returncode=proc.returncode if proc.returncode is not None else -1,
        stdout=(stdout_b or b"").decode("utf-8", errors="replace"),
        stderr=(stderr_b or b"").decode("utf-8", errors="replace"),
    )


def tail(text: str, n_lines: int = 50) -> str:
    lines = text.splitlines()
    return "\n".join(lines[-n_lines:])
