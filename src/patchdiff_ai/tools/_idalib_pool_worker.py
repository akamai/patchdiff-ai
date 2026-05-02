"""Child-process entrypoint for `IdalibPool`.

Receives `(op, kwargs)` on a `multiprocessing.Pipe`, replies with
`("ok", payload)` or `("err", traceback)`.

Ops (kwarg-only): open(path), binexport(out), decompile_many(addrs),
release(), ping(), shutdown.
"""

from __future__ import annotations

# `import idapro` MUST be first — it bootstraps IDA's SDK (idaapi,
# ida_loader, …) into sys.path. Earlier imports of those modules fail
# with "No module named 'idaapi'".
import idapro  # noqa: F401, I001

import io
import sys
import time
import traceback
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Any


_open_path: Path | None = None


def _op_open(*, path: str) -> dict[str, Any]:
    """Load `path` into idalib; no-op if already loaded.

    Fast path: when `<path>.i64` exists, open with
    `run_auto_analysis=False`. `idapro.open_database` always re-runs
    auto-analysis when True regardless of cached state — on
    mshtml-class DLLs that's 5 s vs. 100+ s. The cold path runs
    analysis + saves so subsequent opens hit the fast branch.
    """
    global _open_path
    target = Path(path).resolve()
    if _open_path == target:
        return {"already_open": True, "cached_idb": True}
    if _open_path is not None:
        # save=False: binexport saves explicitly; otherwise this is an
        # interrupt path and a half-state save would be worse than none.
        idapro.close_database(save=False)
        _open_path = None

    idb_candidate = target.with_name(target.name + ".i64")
    have_cached_idb = idb_candidate.is_file()

    open_t0 = time.perf_counter()
    rc = idapro.open_database(
        str(target),
        run_auto_analysis=not have_cached_idb,
    )
    if rc != 0:
        raise RuntimeError(
            f"idapro.open_database({target.name}) returned {rc}"
        )
    _open_path = target
    analysis_s = round(time.perf_counter() - open_t0, 2)

    # Drain any straggler analysis queue before we trust the IDB —
    # partial-state DBs silently produce wrong decompiles.
    try:
        import ida_auto
        ida_auto.auto_wait()
    except Exception:
        pass

    # Populate the .i64 cache so subsequent opens hit the fast path.
    saved = False
    save_s = 0.0
    if not have_cached_idb:
        save_t0 = time.perf_counter()
        try:
            import ida_loader
            idb_path_str = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
            if idb_path_str:
                ida_loader.save_database(idb_path_str, 0)
                saved = True
        except Exception:
            # Best-effort: analysis already succeeded.
            pass
        save_s = round(time.perf_counter() - save_t0, 2)
    return {
        "opened": str(target),
        "cached_idb": have_cached_idb,
        "saved_idb": saved,
        "analysis_s": analysis_s,
        "save_s": save_s,
    }


def _op_binexport(*, out: str) -> dict[str, Any]:
    """Run BinExport on the open IDB and persist the database.

    BinExport's only entry point is the IDC `BinExportBinary("dst")`, so
    we route through `eval_idc_expr`. Forward-slash the path:
    backslashes in IDC string literals trigger escape parsing
    (`\\K` → `K`) and silently truncate the filename.
    """
    if _open_path is None:
        raise RuntimeError("binexport: no binary is open in this worker")
    import idaapi
    import ida_loader

    dst_fwd = str(Path(out).resolve()).replace("\\", "/")
    expr = f'BinExportBinary("{dst_fwd}");'
    result = idaapi.ida_expr.eval_idc_expr(None, idaapi.BADADDR, expr)
    # eval_idc_expr signature varies across IDA bindings: 9.x SWIG
    # returns a str (None/"" = success), some older builds return
    # (ok, errbuf). The file-existence check below catches plugin-side
    # failures that don't surface in either return shape.
    err: str | None = None
    if isinstance(result, tuple):
        ok = bool(result[0]) if result else True
        msg = result[1] if len(result) > 1 else ""
        if not ok:
            err = str(msg) if msg else "eval_idc_expr returned (False, ...)"
    elif result:
        err = str(result)
    out_path = Path(out)
    if err:
        raise RuntimeError(f"BinExportBinary failed: {err!r}")
    if not out_path.exists():
        raise RuntimeError(
            f"BinExportBinary returned success but {out_path} was not "
            "written. Confirm the BinExport plugin DLL is installed in IDA's "
            "plugins directory (run `patchdiff-ai install ida-plugins`)."
        )
    # Save is best-effort — the export already succeeded; cache miss on
    # the next run just re-runs auto-analysis.
    try:
        idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        if idb_path:
            ida_loader.save_database(idb_path, 0)
    except Exception as exc:  # save is best-effort
        return {"out": str(out_path), "save_warning": str(exc)}
    return {"out": str(out_path)}


def _op_decompile_many(*, addrs: list[int]) -> dict[int, str]:
    """Hex-Rays-decompile every EA → `{ea: c_source}`.

    Per-address failures (no Hex-Rays unit, malformed CFG) are absent
    from the result — caller handles missing entries.
    """
    if _open_path is None:
        raise RuntimeError("decompile_many: no binary is open in this worker")
    import ida_hexrays

    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError(
            "Hex-Rays decompiler is not available — check the IDA install "
            "has the matching `hexrays.dll` for this CPU."
        )
    out: dict[int, str] = {}
    for ea in addrs:
        try:
            cf = ida_hexrays.decompile(ea)
        except Exception:
            continue
        if cf is None:
            continue
        try:
            out[ea] = str(cf)
        except Exception:
            # `__str__` on a malformed cfunc occasionally raises.
            continue
    return out


def _op_release() -> dict[str, Any]:
    """Close the IDB without saving; the worker stays alive for reuse."""
    global _open_path
    if _open_path is None:
        return {"released": False}
    idapro.close_database(save=False)
    released = str(_open_path)
    _open_path = None
    return {"released": True, "path": released}


def _op_ping() -> dict[str, Any]:
    """Liveness probe. Returns the currently-loaded path (if any)."""
    return {"open": str(_open_path) if _open_path else None, "pid": _pid()}


_OPS = {
    "open": _op_open,
    "binexport": _op_binexport,
    "decompile_many": _op_decompile_many,
    "release": _op_release,
    "ping": _op_ping,
}


def _pid() -> int:
    import os
    return os.getpid()


def _format_exc() -> str:
    buf = io.StringIO()
    traceback.print_exc(file=buf)
    return buf.getvalue()


def worker_main(conn: Connection) -> None:
    """Dispatch loop; exits on `shutdown` or pipe EOF.

    Per-op exceptions return `("err", traceback)` and the worker stays
    alive — only unrecoverable errors (pipe broken, OS fault) break the
    loop, at which point the parent detects death via `proc.poll()`.
    """
    # Silence idapro's stdout chatter so it doesn't leak to the parent's
    # terminal. Errors still surface via the pipe.
    try:
        idapro.enable_console_messages(False)
    except Exception:
        pass

    while True:
        try:
            msg = conn.recv()
        except (EOFError, OSError):
            break
        if not isinstance(msg, tuple) or len(msg) != 2:
            conn.send(("err", f"malformed request: {msg!r}"))
            continue
        op, kwargs = msg
        if op == "shutdown":
            try:
                if _open_path is not None:
                    idapro.close_database(save=False)
            except Exception:
                pass
            break
        handler = _OPS.get(op)
        if handler is None:
            conn.send(("err", f"unknown op: {op!r}"))
            continue
        try:
            result = handler(**kwargs)
            conn.send(("ok", result))
        except BaseException:
            conn.send(("err", _format_exc()))
    try:
        conn.close()
    except Exception:
        pass


if __name__ == "__main__":
    sys.stderr.write(
        "This module is the IdalibPool worker entrypoint and is normally "
        "spawned by IdalibPool, not run directly.\n"
    )
    sys.exit(1)
