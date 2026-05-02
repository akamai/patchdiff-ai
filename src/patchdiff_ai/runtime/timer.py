"""Async-safe timer + per-run phase aggregation.

`Timer` blocks emit a `timer` event on exit and (when a `PhaseTracker` is
bound to the current contextvar) push their elapsed time into the tracker.
At the end of a run, `PhaseTracker.summary()` produces a phases breakdown
suitable for `log.info("run_perf_summary", phases=...)`.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from contextvars import ContextVar

import structlog

log = structlog.get_logger("patchdiff_ai.timer")


class PhaseTracker:
    """Accumulates `(phase_name, elapsed_s)` records across one run."""

    def __init__(self) -> None:
        self._totals: dict[str, float] = {}
        self._counts: dict[str, int] = {}

    def add(self, name: str, elapsed_s: float) -> None:
        self._totals[name] = self._totals.get(name, 0.0) + elapsed_s
        self._counts[name] = self._counts.get(name, 0) + 1

    def summary(self) -> list[dict[str, float | int | str]]:
        """List sorted by total descending — slowest phases first."""
        names = sorted(self._totals, key=lambda n: self._totals[n], reverse=True)
        return [
            {
                "name": n,
                "total_s": round(self._totals[n], 3),
                "count": self._counts[n],
                "avg_s": round(self._totals[n] / self._counts[n], 3),
            }
            for n in names
        ]


_phase_tracker: ContextVar[PhaseTracker | None] = ContextVar(
    "phase_tracker", default=None
)


def current_phase_tracker() -> PhaseTracker | None:
    return _phase_tracker.get()


@contextmanager
def bind_phase_tracker(tracker: PhaseTracker | None = None):
    """Install a `PhaseTracker` for the duration of this scope so every
    `Timer` block in nested code feeds into it. Yields the tracker.
    """
    t = tracker or PhaseTracker()
    token = _phase_tracker.set(t)
    try:
        yield t
    finally:
        _phase_tracker.reset(token)


class Timer:
    """Both `with Timer(...)` and `async with Timer(...)` work; emits a
    structlog event AND feeds the active `PhaseTracker` (if any)."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.start = 0.0
        self.elapsed = 0.0

    def __enter__(self) -> "Timer":
        self.start = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.elapsed = time.perf_counter() - self.start
        log.info("timer", name=self.name, elapsed_s=round(self.elapsed, 3))
        tracker = _phase_tracker.get()
        if tracker is not None:
            tracker.add(self.name, self.elapsed)

    async def __aenter__(self) -> "Timer":
        return self.__enter__()

    async def __aexit__(self, exc_type, exc, tb) -> None:
        self.__exit__(exc_type, exc, tb)
