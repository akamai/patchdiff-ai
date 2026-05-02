"""Shared helpers between the legacy subprocess and idalib-backed RE graphs.

Both graph variants emit identical artefact shapes (`__funcs__/<ea>.c`,
`Artifact` / `FunctionMatchRef`); the helpers that produce them are
intentionally identical. Centralising them here prevents drift.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

import binexport
import structlog

from patchdiff_ai.runtime.app_context import AppContext

log = structlog.get_logger(__name__)


def discover_parents(func, iteration: int = 0) -> Iterator[list[str] | None]:
    """Walk the BinDiff function's caller chain (depth-limited).

    Yields lists of caller names ending at `func.name`. Lives here because the
    only valid caller is the RE node — once we cross into VR via `Send`, the
    raw BinDiff object is gone, so `parents` must be pre-resolved per match.
    """
    if func is None:
        yield None
        return
    if not getattr(func, "parents", None) or iteration > 9:
        yield [func.name]
        return
    for parent in func.parents:
        for prefix in discover_parents(parent, iteration + 1):
            yield (prefix or []) + [func.name]


def hexish(s: str) -> bool:
    """True if `s` parses as a hex integer. Used to filter `<ea>.c` filenames."""
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


async def decompile_set_via_idalib(
    ctx: AppContext,
    program: "binexport.program.ProgramBinExport",
    out_dir: Path,
    addresses: set[int],
) -> None:
    """Hex-Rays-decompile every address in `addresses` for one binary
    via the idalib pool, writing `<ea:X>.c` files into `out_dir`.

    One pipe round-trip handles the whole set — for binaries with hundreds
    of changed functions, the per-call overhead would dominate.

    Caller must have already verified `ctx.tools.idalib is not None`.
    """
    if not addresses:
        return
    if ctx.tools.idalib is None:
        # Defensive — caller should have routed via the legacy graph.
        log.warning("decompile_set_no_idalib", n=len(addresses))
        return
    # `program.path` is the `.BinExport`; stripping the suffix gives the
    # original binary path that's pinned to a worker in `IdalibPool`.
    binary_path = program.path.with_suffix("")
    try:
        codes = await ctx.tools.idalib.decompile_many(
            binary_path, list(addresses)
        )
    except Exception as exc:
        log.warning(
            "idalib_decompile_many_failed",
            binary=binary_path.name,
            n=len(addresses),
            error=str(exc),
        )
        return
    for ea, code in codes.items():
        if code:
            (out_dir / f"{ea:X}.c").write_text(code, encoding="utf-8")
    missing = len(addresses) - len(codes)
    if missing:
        log.info(
            "idalib_decompile_partial",
            binary=binary_path.name,
            n_ok=len(codes),
            n_missing=missing,
        )
