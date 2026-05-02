"""PatchDiff-AI: turn a CVE ID into a Windows patch root-cause-analysis report."""

__version__ = "0.1.0"

from patchdiff_ai.runtime.orchestrator import run_cve

__all__ = ["__version__", "run_cve"]
