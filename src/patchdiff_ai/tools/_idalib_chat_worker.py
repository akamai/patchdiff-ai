"""Chat-mode idalib worker — direct pipe, no HTTP/MCP transport.

Hosts ida-pro-mcp's tool registry (api_* analysis + idalib_* lifecycle)
in-process and dispatches `(op, kwargs)` round-trips over a
`multiprocessing.Pipe`.

Ops: catalogue, open(path), call(name, args), close, shutdown. Replies
are `("ok", payload)` or `("err", traceback)`. Process isolation
contains idalib crashes / Hex-Rays wedges away from the chat REPL.
"""

from __future__ import annotations

# `import idapro` MUST be first — it bootstraps IDA's SDK (idaapi,
# ida_*) into sys.path. Earlier imports of those modules fail with
# "No module named 'idaapi'".
import idapro  # noqa: F401, I001

import io
import sys
import traceback
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Any


# Mirrors idalib_server's default `shared-fallback` mode (single context
# per process; we have no MCP transport context here).
_FALLBACK_CONTEXT_ID = "shared:fallback"


# Heavy imports paid lazily on first call.
_initialized = False
_session_manager: Any = None
_MCP_SERVER: Any = None
_MCP_UNSAFE: set[str] = set()
_MANAGEMENT_TOOLS: set[str] = set()


def _bootstrap() -> None:
    """Import ida-pro-mcp's registry + idalib lifecycle once.

    Two side-effect imports populate `MCP_SERVER.tools.methods`:
    `ida_pro_mcp.ida_mcp` (api_* analysis), then
    `ida_pro_mcp.idalib_server` (idalib_* lifecycle).

    We don't run `idalib_server.main()` — that installs HTTP handlers we
    don't need; the only piece we replicate (auto-activate-on-call) is
    in `_op_call`.
    """
    global _initialized, _session_manager, _MCP_SERVER, _MCP_UNSAFE, _MANAGEMENT_TOOLS
    if _initialized:
        return

    from ida_pro_mcp.ida_mcp import MCP_SERVER, MCP_UNSAFE  # type: ignore
    import ida_pro_mcp.idalib_server as _idalib_server  # type: ignore  # noqa: F401
    from ida_pro_mcp.idalib_session_manager import get_session_manager  # type: ignore

    _MCP_SERVER = MCP_SERVER
    _MCP_UNSAFE = set(MCP_UNSAFE)
    _MANAGEMENT_TOOLS = set(getattr(_idalib_server, "IDALIB_MANAGEMENT_TOOLS", set()))
    _session_manager = get_session_manager()

    # Silence idapro stdout so it doesn't leak to the parent's terminal.
    # Errors still surface via the pipe as `("err", ...)`.
    try:
        idapro.enable_console_messages(False)
    except Exception:
        pass

    _initialized = True


def _op_catalogue() -> list[dict[str, Any]]:
    """Snapshot the registry → `[{name, description, input_schema}]`."""
    _bootstrap()
    out: list[dict[str, Any]] = []
    for name, func in _MCP_SERVER.tools.methods.items():
        if name in _MCP_UNSAFE:
            continue
        try:
            schema = _MCP_SERVER._generate_tool_schema(name, func)
        except Exception:
            # One bad tool shouldn't kill the catalogue.
            continue
        out.append({
            "name": schema.get("name", name),
            "description": schema.get("description", ""),
            "input_schema": schema.get(
                "inputSchema",
                {"type": "object", "properties": {}},
            ),
        })
    return out


def _op_open(*, path: str, run_auto_analysis: bool = True) -> dict[str, Any]:
    """Load `path` and bind it to the shared fallback context.

    Subsequent `call` ops auto-activate this session, so analysis tools
    see the right database without an explicit `idalib_switch`.
    """
    _bootstrap()
    target = Path(path).resolve()
    if not target.is_file():
        raise FileNotFoundError(f"Binary not found: {target}")
    sid = _session_manager.open_binary(
        target, run_auto_analysis=run_auto_analysis
    )
    session = _session_manager.bind_context(
        _FALLBACK_CONTEXT_ID, sid, activate=True
    )
    return {"session_id": sid, **session.to_dict()}


def _op_call(*, name: str, args: dict[str, Any] | None = None) -> Any:
    """Invoke a registered tool by name with auto context activation.

    Non-management tools get the bound session activated first
    (replicating `_install_context_activation_hooks`); management tools
    (`idalib_*`) resolve their own context.
    """
    _bootstrap()
    args = args or {}
    if name in _MCP_UNSAFE:
        raise RuntimeError(f"Unsafe tool blocked: {name!r}")
    func = _MCP_SERVER.tools.methods.get(name)
    if func is None:
        raise RuntimeError(
            f"Unknown tool: {name!r}. Use `catalogue` to list available tools."
        )
    if name not in _MANAGEMENT_TOOLS:
        try:
            _session_manager.activate_context(_FALLBACK_CONTEXT_ID)
        except RuntimeError:
            return (
                "No binary is loaded. Call `open(path)` first, or use "
                "`call(\"idalib_open\", {\"input_path\": ...})`."
            )
    return func(**args)


def _op_close() -> dict[str, Any]:
    """Close every active session without exiting the worker."""
    _bootstrap()
    _session_manager.close_all_sessions()
    return {"closed": True}


_OPS = {
    "catalogue": _op_catalogue,
    "open": _op_open,
    "call": _op_call,
    "close": _op_close,
}


def _format_exc() -> str:
    buf = io.StringIO()
    traceback.print_exc(file=buf)
    return buf.getvalue()


def worker_main(conn: Connection) -> None:
    """Dispatch loop; exits on `shutdown` or pipe EOF.

    Per-op exceptions reply `("err", traceback)` and the worker stays
    alive — only unrecoverable errors break the loop.
    """
    while True:
        try:
            msg = conn.recv()
        except (EOFError, OSError):
            break
        if not isinstance(msg, tuple) or len(msg) != 2:
            try:
                conn.send(("err", f"malformed request: {msg!r}"))
            except Exception:
                break
            continue
        op, kwargs = msg
        if op == "shutdown":
            try:
                if _session_manager is not None:
                    _session_manager.close_all_sessions()
            except Exception:
                pass
            break
        handler = _OPS.get(op)
        if handler is None:
            try:
                conn.send(("err", f"unknown op: {op!r}"))
            except Exception:
                break
            continue
        try:
            result = handler(**(kwargs or {}))
            conn.send(("ok", result))
        except BaseException:
            try:
                conn.send(("err", _format_exc()))
            except Exception:
                break
    try:
        conn.close()
    except Exception:
        pass


if __name__ == "__main__":
    sys.stderr.write(
        "This module is the IdaChatService worker entrypoint and is "
        "normally spawned by IdaChatService, not run directly.\n"
    )
    sys.exit(1)
