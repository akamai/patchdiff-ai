"""Provider-agnostic transient-error retry wrapper for LangChain runnables.

A single 529 / 5xx / connection blip from any provider used to crash a
multi-minute run. Every chain composed from a registry model should be wrapped
with `resilient(...)` so transient failures recover transparently.

Why a chain wrapper instead of wrapping the model in `ModelRegistry._build`:
LangChain's `RunnableRetry` (the object returned by `model.with_retry(...)`)
does not proxy `BaseChatModel`-specific methods like `with_structured_output`
and `bind_tools` — call sites that depend on those would silently break. So
the retry is applied at the composed-chain level: after `with_structured_output`
/ `bind_tools` / pipe composition, the entire `Runnable` is wrapped.

Retries cover transient errors only — never `BadRequestError`,
`AuthenticationError`, etc., which won't recover by retrying.
"""

from __future__ import annotations

from typing import TypeVar

import anthropic
import openai
from langchain_core.runnables import Runnable
from langchain_core.runnables.retry import ExponentialJitterParams

_TRANSIENT_EXCEPTIONS: tuple[type[BaseException], ...] = (
    openai.RateLimitError,
    openai.InternalServerError,
    openai.APITimeoutError,
    openai.APIConnectionError,
    anthropic.RateLimitError,
    anthropic.InternalServerError,
    anthropic.APITimeoutError,
    anthropic.APIConnectionError,
    anthropic._exceptions.OverloadedError,
)

R = TypeVar("R", bound=Runnable)


def resilient(chain: R) -> R:
    """Wrap a Runnable with provider-agnostic transient-error retries.

    Retries on rate limits, 5xx, connection errors, timeouts, and Anthropic
    `OverloadedError` (529). Apply to the final composed chain, e.g.
    `resilient(prompt | llm.with_structured_output(Schema))`.

    Budget: 3 attempts, exponential-jitter backoff initial=2s capped at 30s.
    Worst-case added wall time per call is ~32s — short enough that a stuck
    LLM deployment surfaces as a node failure instead of hiding minutes of
    silent waiting inside one ainvoke.
    """
    return chain.with_retry(
        retry_if_exception_type=_TRANSIENT_EXCEPTIONS,
        wait_exponential_jitter=True,
        exponential_jitter_params=ExponentialJitterParams(initial=2.0, max=30.0),
        stop_after_attempt=3,
    )
