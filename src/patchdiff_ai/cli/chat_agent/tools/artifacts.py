"""Always-on artifact-bound tools (`list_changed_functions`, `show_decompiled`, `show_diff`).

These three tools are wired directly into the agent (not into the
catalogue) because they're the fixed entry points the LLM should
always see — every other tool is reachable via the meta-tools.
"""

from __future__ import annotations

import difflib
from pathlib import Path
from typing import Any

from langchain_core.tools import tool

from ..constants import _NO_ARTIFACTS_HINT


def _addr_match(addr_user: str, addr_int: int) -> bool:
    return addr_user.lstrip("0").upper() == f"{addr_int:X}".lstrip("0")


def _find_match(artifacts: list[Any], function_address: str):
    """Return (artifact, match) for the FunctionMatchRef whose address1 or address2 matches."""
    for art in artifacts:
        for fn in art.changed:
            if _addr_match(function_address, fn.address1) or _addr_match(
                function_address, fn.address2
            ):
                return art, fn
    return None, None


def always_on_tools(artifacts: list[Any]):
    """Build the three always-on `@tool`-decorated functions closed over `artifacts`."""

    @tool
    def list_changed_functions() -> str:
        """List the addresses, names, and similarity scores of every changed function."""
        if not artifacts:
            return _NO_ARTIFACTS_HINT
        lines: list[str] = []
        for art in artifacts:
            lines.append(
                f"## {art.primary_file.name} ({art.primary_file.kb} vs {art.secondary_file.kb})"
            )
            for fn in art.changed:
                lines.append(
                    f"  {fn.address1:X}  {fn.name1!r:<48}  "
                    f"similarity={fn.similarity:.3f} confidence={fn.confidence:.3f}"
                )
        return "\n".join(lines) if lines else "No changed functions found."

    @tool
    def show_decompiled(function_address: str, version: str = "after") -> str:
        """Show the decompiled C for one function. version: 'before' (pre-patch) or 'after' (post-patch)."""
        if version not in ("before", "after"):
            return f"version must be 'before' or 'after', got {version!r}"
        if not artifacts:
            return _NO_ARTIFACTS_HINT
        art, fn = _find_match(artifacts, function_address)
        if fn is None:
            return f"Function {function_address!r} not found in changed list."
        if version == "after":
            src_file = Path(art.primary_file.path).parent / "__funcs__" / f"{fn.address1:X}.c"
        else:
            src_file = Path(art.secondary_file.path).parent / "__funcs__" / f"{fn.address2:X}.c"
        if not src_file.exists():
            return f"Decompiled file not found: {src_file}"
        return src_file.read_text(encoding="utf-8", errors="replace")

    @tool
    def show_diff(function_address: str) -> str:
        """Show a unified diff between the pre-patch and post-patch decompiled C for a function."""
        if not artifacts:
            return _NO_ARTIFACTS_HINT
        art, fn = _find_match(artifacts, function_address)
        if fn is None:
            return f"Function {function_address!r} not found in changed list."
        before = Path(art.secondary_file.path).parent / "__funcs__" / f"{fn.address2:X}.c"
        after = Path(art.primary_file.path).parent / "__funcs__" / f"{fn.address1:X}.c"
        if not before.exists() or not after.exists():
            return f"Missing decompiled files: {before.name} (exists={before.exists()}), {after.name} (exists={after.exists()})"
        a = before.read_text(encoding="utf-8", errors="replace").splitlines()
        b = after.read_text(encoding="utf-8", errors="replace").splitlines()
        diff = list(
            difflib.unified_diff(
                a, b,
                fromfile=f"{fn.name2} ({art.secondary_file.kb})",
                tofile=f"{fn.name1} ({art.primary_file.kb})",
                lineterm="",
            )
        )
        return "\n".join(diff) if diff else "(no textual diff)"

    return [list_changed_functions, show_decompiled, show_diff]
