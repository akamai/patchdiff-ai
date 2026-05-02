"""Progress reporting: Rich bars on TTY, no-op otherwise.

`RichProgressReporter` routes structlog through Rich's console so log
lines don't tear the live bars. `NullProgressReporter` is the
non-interactive default.
"""

from __future__ import annotations

import sys
from contextlib import AbstractContextManager, contextmanager
from types import TracebackType
from typing import Iterator, Protocol

from rich.console import Console
from rich.progress import (
    BarColumn,
    DownloadColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)

from patchdiff_ai.observability.logging import set_log_sink


class ProgressHandle(Protocol):
    def advance(self, n: int = 1) -> None: ...
    def add_total(self, n: int) -> None: ...
    def set_total(self, n: int) -> None: ...
    def complete(self) -> None: ...


class _NullHandle:
    def advance(self, n: int = 1) -> None: ...
    def add_total(self, n: int) -> None: ...
    def set_total(self, n: int) -> None: ...
    def complete(self) -> None: ...


class ProgressReporter(Protocol):
    def __enter__(self) -> "ProgressReporter": ...
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None: ...
    def download_task(self, name: str, total_bytes: int = 0) -> ProgressHandle: ...
    def extract_task(self, name: str) -> ProgressHandle: ...
    def index_task(self, name: str) -> ProgressHandle: ...
    def ida_task(self, name: str) -> ProgressHandle: ...
    def print(self, text: str) -> None: ...
    def pause(self) -> AbstractContextManager[None]: ...
    def stop_live(self) -> None: ...


class NullProgressReporter(AbstractContextManager["NullProgressReporter"]):
    def __enter__(self) -> "NullProgressReporter":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: D401
        return None

    def download_task(self, name: str, total_bytes: int = 0) -> ProgressHandle:
        return _NullHandle()

    def extract_task(self, name: str) -> ProgressHandle:
        return _NullHandle()

    def index_task(self, name: str) -> ProgressHandle:
        return _NullHandle()

    def ida_task(self, name: str) -> ProgressHandle:
        return _NullHandle()

    def print(self, text: str) -> None:
        # Polars table glyphs aren't cp1252; UTF-8 fallback for non-TTY
        # stderr so box-drawing chars don't blow up.
        try:
            sys.stderr.write(text + "\n")
            sys.stderr.flush()
        except UnicodeEncodeError:
            sys.stderr.buffer.write((text + "\n").encode("utf-8", errors="replace"))
            sys.stderr.flush()

    @contextmanager
    def pause(self) -> Iterator[None]:
        yield

    def stop_live(self) -> None:
        return None


class _RichHandle:
    """Lazy task handle: `add_task` deferred until first interaction.

    Bars allocated for work that turns out to be a no-op (cache-hit
    indexing) never paint. `complete()` removes orphan bars whose total
    stayed at 0.
    """

    def __init__(self, progress: Progress, description: str, initial_total: int) -> None:
        self._p = progress
        self._desc = description
        self._task_id: int | None = None
        self._total = initial_total

    def _ensure(self) -> int:
        if self._task_id is None:
            self._task_id = self._p.add_task(self._desc, total=self._total or None)
        return self._task_id

    def advance(self, n: int = 1) -> None:
        self._p.advance(self._ensure(), n)

    def add_total(self, n: int) -> None:
        self._total += n
        if self._task_id is not None:
            self._p.update(self._task_id, total=self._total)

    def set_total(self, n: int) -> None:
        self._total = n
        self._p.update(self._ensure(), total=n)

    def complete(self) -> None:
        if self._task_id is None:
            return
        if self._total > 0:
            self._p.update(self._task_id, completed=self._total)
        else:
            self._p.remove_task(self._task_id)


class RichProgressReporter(AbstractContextManager["RichProgressReporter"]):
    """Two `Progress` widgets sharing one `Live` region on stderr."""

    def __init__(self) -> None:
        self._console = Console(file=sys.stderr)
        self._download = Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            DownloadColumn(),
            TransferSpeedColumn(),
            TimeRemainingColumn(),
            console=self._console,
            transient=True,
        )
        self._extract = Progress(
            TextColumn("[bold green]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=self._console,
            transient=True,
        )
        # Separate widget for IDA work: the gather widgets are stopped
        # after gather but RE still wants per-call status. `idalib_open`
        # on a 25 MB DLL is a 2-5 min blackbox → spinner + elapsed only.
        self._ida = Progress(
            SpinnerColumn(),
            TextColumn("[bold yellow]{task.description}"),
            TimeElapsedColumn(),
            console=self._console,
            transient=True,
        )
        self._ida_started = False
        self._restore_log_sink: object = None
        # Set after `stop_live()`: `pause()` becomes a no-op so input
        # prompts don't accidentally restart the bars.
        self._stopped = False

    def __enter__(self) -> "RichProgressReporter":
        self._download.start()
        self._extract.start()
        # Route structlog through the Rich console so log lines and the
        # bars don't tear each other.
        self._restore_log_sink = set_log_sink(self._log_write)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._restore_log_sink is not None:
            set_log_sink(self._restore_log_sink)  # type: ignore[arg-type]
        if self._ida_started:
            self._ida.stop()
            self._ida_started = False
        if not self._stopped:
            self._extract.stop()
            self._download.stop()
            self._stopped = True

    def _log_write(self, data: str) -> int:
        # `console.print` interleaves cleanly with the bar redraw via
        # the Live region. Strip trailing newline — `print` adds one.
        if data.endswith("\n"):
            data = data[:-1]
        if data:
            self._console.print(data, highlight=False, markup=False)
        return len(data)

    def download_task(self, name: str, total_bytes: int = 0) -> ProgressHandle:
        return _RichHandle(self._download, f"Downloading {name}", total_bytes)

    def extract_task(self, name: str) -> ProgressHandle:
        return _RichHandle(self._extract, f"Extracting {name}", 0)

    def index_task(self, name: str) -> ProgressHandle:
        return _RichHandle(self._extract, f"Indexing {name}", 0)

    def ida_task(self, name: str) -> ProgressHandle:
        # Lazy-start: cache-hit short-circuits run no IDA work and
        # shouldn't paint an empty Live region.
        if not self._ida_started:
            self._ida.start()
            self._ida_started = True
        return _RichHandle(self._ida, name, 0)

    def print(self, text: str) -> None:
        self._console.print(text, highlight=False, markup=False)

    @contextmanager
    def pause(self) -> Iterator[None]:
        """Suspend rendering so callers can use stdin/stdout cleanly.

        Rich's Live redraws the bars over the cursor position where
        `input()` is waiting; typed characters get painted over. Stopping
        the Progress widgets restores normal line-input behavior, and we
        restart them on exit. No-op after `stop_live()`.
        """
        if self._stopped:
            yield
            return
        was_started = self._download.live.is_started or self._extract.live.is_started
        if was_started:
            self._extract.stop()
            self._download.stop()
        try:
            yield
        finally:
            if was_started:
                self._download.start()
                self._extract.start()

    def stop_live(self) -> None:
        """Permanently stop the Live region; called once gather completes.

        Later phases add no Progress tasks; a still-active Live would
        redraw completed bars over interactive prompts. `transient=True`
        also clears them so the tty is clean for `interrupt()`.
        """
        if self._stopped:
            return
        self._extract.stop()
        self._download.stop()
        self._stopped = True


def make_reporter() -> ProgressReporter:
    """Rich live bars on TTY, no-op otherwise.

    The active Rich reporter routes structlog through its console so
    log lines and bar redraws don't collide.
    """
    if not sys.stderr.isatty():
        return NullProgressReporter()
    return RichProgressReporter()
