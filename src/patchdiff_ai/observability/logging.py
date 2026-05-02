"""structlog configuration: dual-stream rendering, contextvar merging.

Output is split, not tee'd: the terminal (stderr) gets the colorized
`ConsoleRenderer` for human reading, while the per-run file in `logs_dir`
gets `JSONRenderer` for grep/jq. Both come from the same event_dict —
see `_DualRenderer`.
"""

from __future__ import annotations

import logging
import sys
import time
import uuid
import warnings
from pathlib import Path
from typing import IO, Callable

import structlog


# Custom level below DEBUG. `log.trace(...)` is a no-op above threshold;
# see `_make_trace_aware_bound_logger`.
TRACE = 5
logging.addLevelName(TRACE, "TRACE")


def _resolve_level(name: str) -> int:
    upper = name.upper().strip()
    if upper == "TRACE":
        return TRACE
    return getattr(logging, upper, logging.INFO)


class _PrintLoggerWithTrace(structlog.PrintLogger):
    """`PrintLogger` plus a `.trace()` method.

    structlog's bound logger dispatches via `getattr(self._logger, name)`,
    so the underlying logger needs a `trace` attribute for trace events.
    """

    def trace(self, message: str) -> None:
        self.msg(message)


class _PrintLoggerFactoryWithTrace:
    """`PrintLoggerFactory` variant returning `_PrintLoggerWithTrace`."""

    def __init__(self, file: object) -> None:
        self._file = file

    def __call__(self, *_: object) -> _PrintLoggerWithTrace:
        return _PrintLoggerWithTrace(self._file)  # type: ignore[arg-type]


def _make_trace_aware_bound_logger(min_level: int):
    """Filtering bound logger with a real `.trace()` method.

    Above TRACE: `.trace()` is a no-op (just an attribute lookup).
    At/below TRACE: dispatches via `_proxy_to_logger("trace", …)` so the
    processor chain runs and `add_log_level` fills `level="trace"`.
    """
    base = structlog.make_filtering_bound_logger(max(min_level, logging.DEBUG))

    if min_level > TRACE:
        class _NoTrace(base):  # type: ignore[misc, valid-type]
            def trace(self, *_a: object, **_kw: object) -> None:
                return None
        return _NoTrace

    class _WithTrace(base):  # type: ignore[misc, valid-type]
        def trace(self, event: str | None = None, *args: object, **kw: object):
            return self._proxy_to_logger("trace", event, *args, **kw)
    return _WithTrace


class _DualRenderer:
    """Final processor: JSON to file, Console to stderr.

    structlog renders one string per event. We write the JSON copy
    directly to the file and return the Console rendering for the
    factory's stderr sink. `format_exc_info` runs only on the JSON
    copy: ConsoleRenderer pretty-prints `exc_info` itself, JSONRenderer
    wants it flattened, and sharing it triggers structlog's
    "Remove format_exc_info" warning.
    """

    def __init__(
        self,
        console_renderer: structlog.dev.ConsoleRenderer,
        json_renderer: structlog.processors.JSONRenderer,
        file_stream: IO[str] | None,
    ) -> None:
        self._console = console_renderer
        self._json = json_renderer
        self._file = file_stream
        self._format_exc_info = structlog.processors.format_exc_info

    def __call__(self, logger: object, method_name: str, event_dict: dict) -> str:
        if self._file is not None:
            try:
                ed = self._format_exc_info(logger, method_name, dict(event_dict))
                line = self._json(logger, method_name, ed)
                self._file.write(line + "\n")
                self._file.flush()
            except Exception:
                pass
        return self._console(logger, method_name, event_dict)


class _SwappableSink:
    """Indirection so a live progress display can retarget log output.

    `PrintLoggerFactory` binds the sink once; this wrapper's `write` can
    be retargeted at runtime via `set_log_sink`.
    """

    def __init__(self, target: object) -> None:
        self._target = target

    def write(self, data: str) -> int:
        target = self._target
        if hasattr(target, "write"):
            return target.write(data)  # type: ignore[no-any-return]
        if callable(target):
            return target(data)  # type: ignore[no-any-return]
        return len(data)

    def flush(self) -> None:
        target = self._target
        flush = getattr(target, "flush", None)
        if callable(flush):
            try:
                flush()
            except Exception:
                pass

    def swap(self, target: object) -> object:
        prev = self._target
        self._target = target
        return prev


# Only the stderr half is swappable; the file half stays pinned so the
# durable on-disk trace can't be redirected by a progress display.
_STDERR_SINK: _SwappableSink | None = None
_LOG_FILE_STREAM: IO[str] | None = None


def set_log_sink(target: IO[str] | Callable[[str], int] | object) -> object:
    """Retarget terminal log output; returns the previous target.

    File sink is untouched. No-op (returns None) when not yet configured.
    """
    if _STDERR_SINK is None:
        return None
    return _STDERR_SINK.swap(target)


def write_raw_to_file(text: str) -> None:
    """Append raw multi-line text to the log file, bypassing JSON rendering.

    For polars tables and similar content that doesn't survive JSON
    escaping. No-op when no `logs_dir` was configured.
    """
    if _LOG_FILE_STREAM is None:
        return
    try:
        _LOG_FILE_STREAM.write(text if text.endswith("\n") else text + "\n")
        _LOG_FILE_STREAM.flush()
    except Exception:
        pass


def write_traceback_to_file(exc: BaseException, tag: str = "crash") -> None:
    """Dump a full traceback to the log file regardless of log level.

    Bypasses structlog (which would filter at INFO/WARN) and only hits
    the file sink (Rich already prints the terminal panel). No-op when
    no `logs_dir` was configured.
    """
    if _LOG_FILE_STREAM is None:
        return
    import traceback

    try:
        header = f"\n=== {tag}: {type(exc).__name__}: {exc} ===\n"
        body = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        _LOG_FILE_STREAM.write(header + body + "\n")
        _LOG_FILE_STREAM.flush()
    except Exception:
        pass


def configure_logging(
    level: str = "INFO",
    logs_dir: Path | None = None,
) -> Path | None:
    """One-time logging setup; idempotent.

    stderr → colored Console renderer; file (if `logs_dir`) → line JSON.
    Returns the log-file path or None.
    """
    log_level = _resolve_level(level)

    # Cap chatty third-party loggers at WARNING so DEBUG/TRACE doesn't
    # drown the stream. Each comment names what gets hidden:
    for noisy in (
        "azure",
        "httpx",
        "httpcore",
        "urllib3",
        # openai SDK: per-attempt 429 retry records (multi-line each).
        "openai",
        "openai._base_client",
        # anthropic SDK: full request body (system prompt + tools +
        # messages) plus per-request HTTP records via _base_client.
        "anthropic",
        # chromadb: vestigial `Starting component Posthog` (Posthog
        # class in 1.5.x is a `pass`-bodied no-op — looks like leaked
        # telemetry but isn't).
        "chromadb",
        "chromadb.config",
        # msal (azure-identity transitive): per-token-acquisition
        # records + OAuth `event={…}` JSON dump on every call.
        "msal",
        # asyncio: `Using proactor: IocpProactor` per event loop.
        "asyncio",
    ):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    # `warnings` (different machinery from `logging` — silenced separately).
    # langchain_openai's `with_structured_output(SomeBaseModel)` path
    # writes the parsed BaseModel into an internal slot pydantic types
    # as `None`; pydantic's strict serializer flags it on every call.
    # Harmless, but spams stderr once per LLM call. Filter is narrow:
    # only this exact field's mismatch from pydantic.main.
    warnings.filterwarnings(
        "ignore",
        message=r"Pydantic serializer warnings:[\s\S]*field_name='parsed'",
        category=UserWarning,
        module=r"pydantic\.main",
    )

    timestamper = structlog.processors.TimeStamper(fmt="iso", utc=True)

    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        # `format_exc_info` is NOT shared: it would stringify exc_info
        # before ConsoleRenderer pretty-prints it. `_DualRenderer` runs
        # it only on the JSON copy.
        timestamper,
    ]

    log_file: Path | None = None
    global _STDERR_SINK, _LOG_FILE_STREAM
    _STDERR_SINK = _SwappableSink(sys.stderr)
    _LOG_FILE_STREAM = None

    if logs_dir is not None:
        logs_dir.mkdir(parents=True, exist_ok=True)
        log_file = logs_dir / f"{int(time.time())}.{uuid.uuid4()}.log"
        # line-buffered so tail -f sees output immediately
        _LOG_FILE_STREAM = open(log_file, "a", buffering=1, encoding="utf-8")
        print(f"Logging to {log_file}", file=sys.stderr, flush=True)

    final_renderer = _DualRenderer(
        structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty()),
        structlog.processors.JSONRenderer(),
        _LOG_FILE_STREAM,
    )

    structlog.configure(
        processors=shared_processors + [final_renderer],
        wrapper_class=_make_trace_aware_bound_logger(log_level),
        logger_factory=_PrintLoggerFactoryWithTrace(file=_STDERR_SINK),
        cache_logger_on_first_use=True,
    )

    # Stdlib logging → stderr + file so third-party libs hit disk too.
    root = logging.getLogger()
    root.setLevel(log_level)
    for h in list(root.handlers):
        root.removeHandler(h)
    formatter = logging.Formatter("%(message)s")
    stderr_h = logging.StreamHandler(sys.stderr)
    stderr_h.setFormatter(formatter)
    root.addHandler(stderr_h)
    if log_file is not None:
        file_h = logging.FileHandler(log_file, encoding="utf-8")
        file_h.setFormatter(formatter)
        root.addHandler(file_h)

    return log_file
