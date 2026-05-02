"""Tool catalogue backing the `list_tools` / `describe_tool` / `call_tool` meta-tools.

Two registration paths: `register_native` for in-process callables,
`register_ida` for bulk-registered ida-pro-mcp tools dispatched
through a single async dispatcher.
"""

from __future__ import annotations

import inspect
from typing import Any, Awaitable, Callable

import structlog

from patchdiff_ai.tools.ida_mcp import IdaMcpUnavailable

from .constants import _DENY_IDA_TOOLS
from .envelope import (
    _extract_summary,
    _format_envelope,
    _build_hint,
    _stringify,
)
from .preview import (
    _PreviewResultStore,
    _preview_value,
    _TOP_LEVEL_STR_LEN,
)


log = structlog.get_logger(__name__)


class ToolCatalogue:
    """Registry behind the meta-tools (`list_tools`, `describe_tool`, `call_tool`).

    Two registration paths: `register_native` for in-process callables,
    `register_ida` for bulk-registered ida-pro-mcp tools dispatched
    through a single async dispatcher.
    """

    def __init__(self) -> None:
        self._entries: dict[str, dict[str, Any]] = {}
        # Cache backing the `read_result` chunk reader. Session-scoped.
        self._results = _PreviewResultStore()

    def register_native(
        self,
        name: str,
        description: str,
        input_schema: dict[str, Any],
        callable_: Callable[..., Any] | Callable[..., Awaitable[Any]],
        *,
        passthrough: bool = False,
        display: Callable[[Any], str] | None = None,
    ) -> None:
        """Register an in-process tool.

        `passthrough=True` prints the rendered body to the terminal and
        hands the LLM only a summary — used for "show me X" tools so the
        body isn't shoveled through input + completion tokens. `display`
        maps the raw return to the printed string (defaults: strings
        verbatim, anything else through `_stringify`).
        """
        self._entries[name] = {
            "name": name,
            "description": description,
            "input_schema": input_schema,
            "tier": "native",
            "_call": callable_,
            "passthrough": passthrough,
            "display": display,
        }

    def register_ida(
        self,
        entries: list[dict[str, Any]],
        dispatcher: Callable[[str, dict[str, Any]], Awaitable[str]],
    ) -> None:
        for entry in entries:
            name = entry["name"]
            if name in _DENY_IDA_TOOLS:
                continue
            self._entries[name] = {
                "name": name,
                "description": entry.get("description", ""),
                "input_schema": entry.get("input_schema", {"type": "object"}),
                "tier": "ida",
                "_call": dispatcher,
            }

    def list(self, name_filter: str = "") -> list[dict[str, Any]]:
        f = name_filter.lower().strip()
        return [
            {"name": e["name"], "description": e["description"], "tier": e["tier"]}
            for e in self._entries.values()
            if not f or f in e["name"].lower() or f in e["description"].lower()
        ]

    def describe(self, name: str) -> dict[str, Any] | None:
        e = self._entries.get(name)
        if e is None:
            return None
        return {
            "name": e["name"],
            "description": e["description"],
            "input_schema": e["input_schema"],
            "tier": e["tier"],
        }

    def get_result(self, result_id: str) -> str | None:
        """Fetch a previously cached full body by id, or None if evicted/missing.

        Public accessor for the `read_result` chunk-reader path. Bodies
        land in the cache when `dispatch` had to truncate a preview;
        callers walk them via offset/length slices.
        """
        return self._results.get(result_id)

    async def dispatch(self, name: str, args: dict[str, Any]) -> str:
        """Invoke the tool and return a JSON `{summary, result}` envelope.

        `result` is a preview: scalars verbatim, lists trimmed to
        `_PREVIEW_ITEMS`, strings to `_PREVIEW_STR_LEN`. Oversize bodies
        are cached in `self._results` and reachable via `read_result`
        using the `summary.result_id`.
        """
        e = self._entries.get(name)
        if e is None:
            return _format_envelope(
                {"tool": name, "tier": "unknown", "kind": "error",
                 "error": f"Unknown tool: {name!r}",
                 "hint": "Use list_tools() to discover available tools."},
                None,
            )
        log.info("catalogue_dispatch_start", tool_name=name, tier=e["tier"])
        log.trace(
            "tool_dispatch_resolved",
            tool=name,
            tier=e["tier"],
            args_keys=sorted(args.keys()) if args else [],
        )
        callable_ = e["_call"]
        try:
            if e["tier"] == "ida":
                raw = await callable_(name, args or {})
            else:
                raw = callable_(**(args or {}))
                if inspect.isawaitable(raw):
                    raw = await raw
        except IdaMcpUnavailable as exc:
            log.warning("catalogue_dispatch_ida_unavailable", tool_name=name, error=str(exc))
            return _format_envelope(
                {"tool": name, "tier": e["tier"], "kind": "error",
                 "error": f"IDA tools unavailable: {exc}"},
                None,
            )
        except Exception as exc:
            log.warning("catalogue_dispatch_failed", tool_name=name, error=str(exc))
            return _format_envelope(
                {"tool": name, "tier": e["tier"], "kind": "error",
                 "error": f"{type(exc).__name__}: {exc}"},
                None,
            )

        summary = _extract_summary(name, raw)

        if e.get("passthrough"):
            display_fn = e.get("display")
            if display_fn is not None:
                rendered = display_fn(raw)
            elif isinstance(raw, str):
                rendered = raw
            else:
                rendered = _stringify(raw)
            print(rendered)
            summary["tool"] = name
            summary["tier"] = e["tier"]
            summary["displayed"] = True
            summary["chars"] = len(rendered)
            summary["hint"] = (
                f"`{name}` output was displayed to the user directly. Do NOT "
                "repeat or paraphrase it in your response — just acknowledge "
                "briefly (e.g. 'Done.' or move on to the next step)."
            )
            log.trace(
                "tool_passthrough_displayed",
                tool=name,
                chars=len(rendered),
            )
            log.info(
                "catalogue_dispatch_done",
                tool_name=name,
                tier=e["tier"],
                kind=summary.get("kind"),
                bytes=0,
                bytes_total=len(rendered),
                preview_truncated=False,
                passthrough=True,
            )
            return _format_envelope(summary, None)

        full_body = raw if isinstance(raw, str) else _stringify(raw)
        full_size = len(full_body)

        if name == "read_result":
            # Verbatim: read_result is itself the chunk-fetch path; preview-
            # trimming would silently shrink the requested length.
            preview_body = full_body
        elif isinstance(raw, str):
            # Top-level text gets a larger cap than nested strings so 3-5 KB
            # listings inline without forcing a read_result round-trip.
            if len(raw) > _TOP_LEVEL_STR_LEN:
                preview_body = raw[:_TOP_LEVEL_STR_LEN] + f"... [{len(raw)} chars total]"
            else:
                preview_body = raw
        else:
            preview_body = _stringify(_preview_value(raw))
        preview_truncated = len(preview_body) < full_size

        result_id: str | None = None
        # `read_result` returns are already a slice of a cached body — don't
        # re-cache.
        if preview_truncated and name != "read_result":
            result_id = self._results.put(full_body)
        log.trace(
            "tool_preview_built",
            tool=name,
            full_bytes=full_size,
            preview_bytes=len(preview_body),
            truncated=preview_truncated,
            cached_id=result_id,
        )

        summary["tool"] = name
        summary["tier"] = e["tier"]
        summary["bytes"] = len(preview_body)
        summary["bytes_total"] = full_size
        summary["preview_truncated"] = preview_truncated
        if result_id is not None:
            summary["result_id"] = result_id
        summary["hint"] = _build_hint(summary)

        log.info(
            "catalogue_dispatch_done",
            tool_name=name,
            tier=e["tier"],
            kind=summary.get("kind"),
            count=summary.get("count"),
            total=summary.get("total"),
            next_offset=summary.get("next_offset"),
            bytes=len(preview_body),
            bytes_total=full_size,
            preview_truncated=preview_truncated,
            result_id=result_id,
        )
        return _format_envelope(summary, preview_body)
