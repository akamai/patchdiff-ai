from __future__ import annotations

from typing import Any

from langchain_openai import AzureChatOpenAI, AzureOpenAIEmbeddings

from patchdiff_ai.config.credentials import AzureCreds
from patchdiff_ai.llm.catalog import ModelSpec


def build_azure_chat(spec: ModelSpec, creds: AzureCreds, token_provider) -> AzureChatOpenAI:
    kwargs: dict[str, Any] = dict(
        model=spec.deployment,
        azure_deployment=spec.deployment,
        api_version=spec.api_version,
        azure_endpoint=creds.endpoint,
        azure_ad_token_provider=token_provider,
        streaming=False,
        # Default is 2; openai SDK respects Retry-After so this gives roughly
        # 3 minutes of automatic 429 absorption before the exception bubbles
        # up to our tenacity wrapper.
        max_retries=6,
    )
    if spec.max_tokens is not None:
        kwargs["max_tokens"] = spec.max_tokens
    if spec.temperature is not None:
        kwargs["temperature"] = spec.temperature
    return AzureChatOpenAI(**kwargs)


def build_azure_embeddings(spec: ModelSpec, creds: AzureCreds, token_provider) -> AzureOpenAIEmbeddings:
    return AzureOpenAIEmbeddings(
        model=spec.deployment,
        azure_deployment=spec.deployment,
        api_version=spec.api_version,
        azure_endpoint=creds.endpoint,
        azure_ad_token_provider=token_provider,
        max_retries=6,
    )
