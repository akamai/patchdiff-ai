from __future__ import annotations

from langchain_google_genai import ChatGoogleGenerativeAI

from patchdiff_ai.config.credentials import GeminiCreds
from patchdiff_ai.llm.catalog import ModelSpec


def build_gemini_chat(spec: ModelSpec, creds: GeminiCreds) -> ChatGoogleGenerativeAI:
    api_key = creds.api_key.get_secret_value() if creds.api_key else None
    return ChatGoogleGenerativeAI(model=spec.deployment, google_api_key=api_key)
