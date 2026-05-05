"""In-memory dedup registry for long-running analyze jobs.

A job_id like `cve:CVE-2025-29824` or `month:2025-Apr` represents a
single in-flight `patchdiff-ai` subprocess. The bot rejects a second
slash command for the same job_id while the first is still running.

Process-local. Bot restart loses tracking — documented limitation.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field


@dataclass
class JobInfo:
    job_id: str
    user_id: str
    started_at: float
    task: asyncio.Task | None = None


@dataclass
class JobRegistry:
    _jobs: dict[str, JobInfo] = field(default_factory=dict)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def try_register(self, job_id: str, user_id: str) -> JobInfo | None:
        """Returns None if already running, otherwise the new JobInfo."""
        async with self._lock:
            if job_id in self._jobs:
                return None
            info = JobInfo(job_id=job_id, user_id=user_id, started_at=time.time())
            self._jobs[job_id] = info
            return info

    async def existing(self, job_id: str) -> JobInfo | None:
        async with self._lock:
            return self._jobs.get(job_id)

    async def release(self, job_id: str) -> None:
        async with self._lock:
            self._jobs.pop(job_id, None)
