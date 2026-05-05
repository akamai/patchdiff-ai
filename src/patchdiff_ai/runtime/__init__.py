"""Runtime layer: AppContext DI bundle, orchestrator, timer."""

from typing import TYPE_CHECKING, Any

# Eager re-exports here would drag the full DI graph (LangChain,
# providers, IDA tooling) into any module that imports a foundation
# helper under `runtime/` — e.g. `runtime.app_dirs.app_data_root`,
# pulled in by `config.paths`. PEP 562 `__getattr__` defers each name
# until it's actually accessed (mirrors `patchdiff_ai/__init__.py`,
# commit fd0cb90).
if TYPE_CHECKING:
    from patchdiff_ai.runtime.app_context import AppContext  # noqa: F401
    from patchdiff_ai.runtime.orchestrator import run_cve  # noqa: F401
    from patchdiff_ai.runtime.timer import Timer  # noqa: F401

__all__ = ["AppContext", "Timer", "run_cve"]


def __getattr__(name: str) -> Any:
    if name == "AppContext":
        from patchdiff_ai.runtime.app_context import AppContext as _v
        return _v
    if name == "run_cve":
        from patchdiff_ai.runtime.orchestrator import run_cve as _v
        return _v
    if name == "Timer":
        from patchdiff_ai.runtime.timer import Timer as _v
        return _v
    raise AttributeError(f"module 'patchdiff_ai.runtime' has no attribute {name!r}")
