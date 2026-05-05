"""PatchDiff-AI: turn a CVE ID into a Windows patch root-cause-analysis report."""

from typing import TYPE_CHECKING, Any

__version__ = "0.1.0"

# `run_cve` is exposed as a top-level attribute, but resolving it eagerly
# would pull the full LangChain / LangGraph / provider-SDK stack into
# every Python process that imports anything from this package — including
# spawned multiprocessing workers (idalib pool, chat) that re-import the
# package solely to unpickle their entry point. PEP 562 __getattr__ defers
# the import until someone actually touches `run_cve`.
if TYPE_CHECKING:
    from patchdiff_ai.runtime.orchestrator import run_cve  # noqa: F401

__all__ = ["__version__", "run_cve"]


def __getattr__(name: str) -> Any:
    if name == "run_cve":
        from patchdiff_ai.runtime.orchestrator import run_cve as _run_cve
        return _run_cve
    raise AttributeError(f"module 'patchdiff_ai' has no attribute {name!r}")
