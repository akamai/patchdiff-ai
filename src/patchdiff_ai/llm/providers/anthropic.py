from __future__ import annotations

from langchain_anthropic import ChatAnthropic

from patchdiff_ai.config.credentials import AnthropicCreds
from patchdiff_ai.llm.catalog import ModelSpec


def build_anthropic_chat(spec: ModelSpec, creds: AnthropicCreds) -> ChatAnthropic:
    api_key = creds.api_key.get_secret_value() if creds.api_key else None
    kwargs: dict = {
        "model": spec.deployment,
        "anthropic_api_url": creds.base_url,
        "api_key": api_key,
    }
    # Azure AI Foundry's APIM gateway authenticates via the `api-key`
    # header (no `x-` prefix). The Anthropic SDK only sends `x-api-key`,
    # which APIM ignores → 401 "invalid subscription key". Mirroring
    # the key into both headers is a no-op for the public Anthropic API
    # (it doesn't read `api-key`) and unblocks Azure passthroughs.
    if api_key and "azure.com" in creds.base_url:
        kwargs["default_headers"] = {"api-key": api_key}
    return ChatAnthropic(**kwargs)
