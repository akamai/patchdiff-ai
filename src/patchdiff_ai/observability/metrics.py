"""LangChain callback handler that emits one structlog event per LLM invocation."""

from __future__ import annotations

import time
from collections import defaultdict
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Iterator
from uuid import UUID

import structlog
from langchain_core.callbacks import AsyncCallbackHandler
from langchain_core.outputs import LLMResult

from patchdiff_ai.llm.catalog import MODEL_CATALOG

log = structlog.get_logger("patchdiff_ai.llm")


# ---------------------------------------------------------------------------
# Per-run cost aggregator
# ---------------------------------------------------------------------------
# Mirrors the contextvar-bound `PhaseTracker` in `runtime/timer.py`.
# `LLMMetricsHandler.on_llm_end` feeds the bound tracker if any, no-op
# otherwise — keeps post-run chat costs out of the per-CVE total.


@dataclass
class _ModelStats:
    calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    cost_usd: float = 0.0


class CostTracker:
    """Per-run accumulator for LLM call cost + token usage, broken down by model."""

    def __init__(self) -> None:
        self._by_model: dict[str, _ModelStats] = defaultdict(_ModelStats)

    def add(
        self,
        *,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        total_tokens: int,
        cost_usd: float,
    ) -> None:
        s = self._by_model[model or "<unknown>"]
        s.calls += 1
        s.prompt_tokens += prompt_tokens
        s.completion_tokens += completion_tokens
        s.total_tokens += total_tokens
        s.cost_usd += cost_usd

    @property
    def total_cost_usd(self) -> float:
        return round(sum(s.cost_usd for s in self._by_model.values()), 6)

    @property
    def total_calls(self) -> int:
        return sum(s.calls for s in self._by_model.values())

    @property
    def total_tokens(self) -> int:
        return sum(s.total_tokens for s in self._by_model.values())

    def summary(self) -> list[dict[str, Any]]:
        """Per-model breakdown sorted by descending cost. Stable output for logs."""
        return [
            {
                "model": m,
                "calls": s.calls,
                "total_tokens": s.total_tokens,
                "cost_usd": round(s.cost_usd, 6),
            }
            for m, s in sorted(
                self._by_model.items(),
                key=lambda kv: (-kv[1].cost_usd, kv[0]),
            )
        ]

    def merge(self, other: "CostTracker") -> None:
        """Fold another tracker's per-model totals into this one."""
        for model, s in other._by_model.items():
            mine = self._by_model[model]
            mine.calls += s.calls
            mine.prompt_tokens += s.prompt_tokens
            mine.completion_tokens += s.completion_tokens
            mine.total_tokens += s.total_tokens
            mine.cost_usd += s.cost_usd


_cost_tracker: ContextVar[CostTracker | None] = ContextVar(
    "_cost_tracker", default=None
)


@contextmanager
def bind_cost_tracker() -> Iterator[CostTracker]:
    """Bind a fresh `CostTracker` for the duration of the scope.

    Sibling of `bind_phase_tracker` in `runtime/timer.py`; visible to
    any async task spawned inside via `_cost_tracker.get()`.

    On exit, the bound tracker's totals are folded into the parent
    tracker (if any) so nested binds aggregate cleanly: per-CVE binds
    inside the orchestrator roll up into the session-level bind in
    `cli/app.py:main()`, giving one global summary across single, batch,
    and chat runs without duplicated per-call recording.
    """
    parent = _cost_tracker.get()
    tracker = CostTracker()
    token = _cost_tracker.set(tracker)
    try:
        yield tracker
    finally:
        _cost_tracker.reset(token)
        if parent is not None:
            parent.merge(tracker)


def get_cost_tracker() -> CostTracker | None:
    """Return the cost tracker bound by `bind_cost_tracker`, or `None`."""
    return _cost_tracker.get()


def _model_name_from_serialized(serialized: dict[str, Any] | None) -> str | None:
    if not serialized:
        return None
    # LangChain nests the model id under kwargs.{model,model_name,deployment_name}.
    kw = serialized.get("kwargs") or {}
    return (
        kw.get("model")
        or kw.get("model_name")
        or kw.get("deployment_name")
        or serialized.get("name")
    )


def _extract_token_usage(response: LLMResult) -> tuple[int, int]:
    """Pull `(prompt_tokens, completion_tokens)` from an LLMResult.

    Probes three provider shapes in order: LangChain's standard
    `AIMessage.usage_metadata`, OpenAI's `llm_output["token_usage"]`,
    Anthropic's `llm_output["usage"]`. Returns (0, 0) if none present
    (streaming without final usage; embeddings).
    """
    prompt = 0
    completion = 0

    for batch in (response.generations or []):
        for gen in batch:
            msg = getattr(gen, "message", None)
            usage = getattr(msg, "usage_metadata", None) if msg else None
            if usage:
                prompt += int(usage.get("input_tokens") or 0)
                completion += int(usage.get("output_tokens") or 0)
    if prompt or completion:
        return prompt, completion

    llm_output = response.llm_output or {}
    tu = llm_output.get("token_usage") or {}
    if tu:
        return int(tu.get("prompt_tokens") or 0), int(tu.get("completion_tokens") or 0)

    au = llm_output.get("usage") or {}
    return int(au.get("input_tokens") or 0), int(au.get("output_tokens") or 0)


def _summarize_messages(messages: list[list[Any]]) -> list[list[dict[str, Any]]]:
    """Convert nested `BaseMessage` lists to plain dicts for JSON rendering."""
    out: list[list[dict[str, Any]]] = []
    for batch in messages:
        rendered = []
        for m in batch:
            content = getattr(m, "content", m)
            rendered.append({
                "type": getattr(m, "type", type(m).__name__),
                "content": content if isinstance(content, str) else str(content),
            })
        out.append(rendered)
    return out


class LLMMetricsHandler(AsyncCallbackHandler):
    """Emits `llm_call` events; at TRACE also full `llm_request` / `llm_response`."""

    def __init__(self) -> None:
        super().__init__()
        self._starts: dict[UUID, float] = {}

    async def on_chat_model_start(
        self,
        serialized: dict[str, Any],
        messages: list[list[Any]],
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        self._starts[run_id] = time.perf_counter()
        log.trace(
            "llm_request",
            kind="chat",
            model=_model_name_from_serialized(serialized),
            run_id=str(run_id),
            messages=_summarize_messages(messages),
        )

    async def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        self._starts[run_id] = time.perf_counter()
        log.trace(
            "llm_request",
            kind="completion",
            model=_model_name_from_serialized(serialized),
            run_id=str(run_id),
            prompts=prompts,
        )

    async def on_llm_end(self, response: LLMResult, *, run_id: UUID, **kwargs: Any) -> None:
        elapsed = time.perf_counter() - self._starts.pop(run_id, time.perf_counter())

        prompt_tokens, completion_tokens = _extract_token_usage(response)
        total = prompt_tokens + completion_tokens

        model_name = (response.llm_output or {}).get("model_name") or ""
        cost = self._estimate_cost(model_name, prompt_tokens, completion_tokens)

        log.info(
            "llm_call",
            model=model_name,
            elapsed_s=round(elapsed, 3),
            total_tokens=total,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            cost_usd=cost,
        )
        # No-op when no tracker is bound (e.g. chat-time calls).
        tracker = _cost_tracker.get()
        if tracker is not None:
            tracker.add(
                model=model_name,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total,
                cost_usd=cost,
            )
        # `generations` is list[list[Generation]] (outer = per prompt,
        # inner = per n>1 sample). Flatten to a list of texts.
        generations = [
            getattr(g, "text", "") for batch in (response.generations or []) for g in batch
        ]
        log.trace(
            "llm_response",
            model=model_name,
            run_id=str(run_id),
            elapsed_s=round(elapsed, 3),
            generations=generations,
        )

    async def on_llm_error(self, error: BaseException, *, run_id: UUID, **kwargs: Any) -> None:
        elapsed = time.perf_counter() - self._starts.pop(run_id, time.perf_counter())
        log.warning("llm_error", error=str(error), elapsed_s=round(elapsed, 3))

    @staticmethod
    def _estimate_cost(model_name: str, prompt_tokens: int, completion_tokens: int) -> float:
        if not model_name or (prompt_tokens + completion_tokens) == 0:
            return 0.0
        spec = MODEL_CATALOG.get(model_name)
        if spec is None:
            # API often returns a versioned deployment name
            # ("o4-mini-2025-04-16"). Longest-match by deployment so
            # "gpt-5.2-codex" wins over "gpt-5.2".
            lname = model_name.lower()
            for s in sorted(
                MODEL_CATALOG.values(),
                key=lambda x: len(x.deployment),
                reverse=True,
            ):
                d = s.deployment.lower()
                if lname == d or lname.startswith(d + "-"):
                    spec = s
                    break
        if spec is None:
            return 0.0
        # Per-direction rates win; fall back to blended `cost_per_mtok`
        # for catalog entries that haven't been split.
        in_rate = spec.cost_per_mtok_input if spec.cost_per_mtok_input is not None else spec.cost_per_mtok
        out_rate = spec.cost_per_mtok_output if spec.cost_per_mtok_output is not None else spec.cost_per_mtok
        cost = (prompt_tokens * in_rate + completion_tokens * out_rate) / 1_000_000
        return round(cost, 6)
