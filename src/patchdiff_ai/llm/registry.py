"""ModelRegistry: lazy, per-purpose model lookup with provider isolation.

Replaces:
  - common.AgentModels static-attribute god-object
  - common.LLM dynamic class attributes (LLM.gpt_5_2 = ...)
  - common.init_*_models functions that mutated module state at import time
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import structlog

from patchdiff_ai.config.credentials import AnthropicCreds, AzureCreds, GeminiCreds
from patchdiff_ai.config.settings import Settings
from patchdiff_ai.llm.auth import (
    AzureAuthError,
    build_azure_credential,
    cognitive_token_provider,
)
from patchdiff_ai.llm.catalog import (
    DEFAULT_BY_PURPOSE,
    EVAL_MODELS,
    MODEL_CATALOG,
    ModelPurpose,
    ModelSpec,
    Provider,
)
from patchdiff_ai.llm.providers.anthropic import build_anthropic_chat
from patchdiff_ai.llm.providers.azure import build_azure_chat, build_azure_embeddings
from patchdiff_ai.llm.providers.gemini import build_gemini_chat

log = structlog.get_logger(__name__)


@dataclass
class ModelEntry:
    spec: ModelSpec
    model: Any  # BaseChatModel | Embeddings


class UnknownModelError(KeyError):
    pass


class ProviderUnavailableError(RuntimeError):
    pass


class ModelRegistry:
    """Builds chat / embedding clients on demand.

    A single registry per process; build via `ModelRegistry.from_settings(settings)`.
    """

    def __init__(
        self,
        azure: AzureCreds,
        anthropic: AnthropicCreds,
        gemini: GeminiCreds,
        purpose_overrides: dict[ModelPurpose, str | None],
    ) -> None:
        self._azure = azure
        self._anthropic = anthropic
        self._gemini = gemini
        self._purpose_overrides = purpose_overrides
        self._cache: dict[str, ModelEntry] = {}

        self._azure_credential = build_azure_credential(azure)
        self._azure_token_provider = None
        if self._azure_credential is not None:
            try:
                self._azure_token_provider = cognitive_token_provider(self._azure_credential)
            except AzureAuthError as exc:
                log.warning("azure_auth_failed", error=str(exc))
                self._azure_token_provider = None

    @classmethod
    def from_settings(cls, settings: Settings) -> "ModelRegistry":
        purpose_overrides = {
            ModelPurpose.EMBEDDING: settings.models.embedding,
            ModelPurpose.DEFAULT: settings.models.default,
            ModelPurpose.GATHER_INFO: settings.models.gather_info,
            ModelPurpose.PLATFORM_INTERNALS: settings.models.platform_internals,
            ModelPurpose.REVERSE_ENGINEERING: settings.models.reverse_engineering,
            ModelPurpose.RESEARCHER: settings.models.researcher,
        }
        return cls(
            azure=settings.azure,
            anthropic=settings.anthropic,
            gemini=settings.gemini,
            purpose_overrides=purpose_overrides,
        )

    def list_available(self) -> list[ModelSpec]:
        """All catalog entries whose provider has credentials configured."""
        out: list[ModelSpec] = []
        for spec in MODEL_CATALOG.values():
            if self._provider_available(spec.provider):
                out.append(spec)
        return out

    def list_chat_models(self) -> list[ModelSpec]:
        return [s for s in self.list_available() if not s.is_embedding]

    def get(self, name: str) -> ModelEntry:
        """Look up by exact catalog name (e.g. 'azure.o4-mini')."""
        if name in self._cache:
            return self._cache[name]

        spec = MODEL_CATALOG.get(name)
        if spec is None:
            # Tolerate the legacy "endswith name" lookup pattern.
            for cand in MODEL_CATALOG.values():
                if name.lower().endswith(cand.name):
                    spec = cand
                    break
        if spec is None:
            raise UnknownModelError(f"Unknown model: {name}")

        if not self._provider_available(spec.provider):
            raise ProviderUnavailableError(
                f"Provider {spec.provider} not configured for model {name}"
            )

        model = self._build(spec)
        entry = ModelEntry(spec=spec, model=model)
        self._cache[name] = entry
        return entry

    def for_purpose(self, purpose: ModelPurpose) -> ModelEntry:
        """Resolve a purpose to a concrete model, falling back to the default."""
        override = self._purpose_overrides.get(purpose)
        candidates = [override, DEFAULT_BY_PURPOSE.get(purpose)]
        for idx, name in enumerate(candidates):
            if not name:
                continue
            try:
                entry = self.get(name)
                log.trace(
                    "llm_model_resolved",
                    purpose=purpose.value,
                    model=entry.spec.name,
                    provider=getattr(entry.spec, "provider", None),
                    deployment=getattr(entry.spec, "deployment", None),
                    fallback_used=(idx > 0 or override is None),
                )
                return entry
            except (UnknownModelError, ProviderUnavailableError) as exc:
                log.warning(
                    "model_resolve_failed",
                    purpose=purpose.value,
                    name=name,
                    error=str(exc),
                )

        # Last-resort: any available chat model.
        for spec in self.list_chat_models():
            try:
                entry = self.get(spec.name)
                log.trace(
                    "llm_model_resolved",
                    purpose=purpose.value,
                    model=entry.spec.name,
                    provider=getattr(entry.spec, "provider", None),
                    deployment=getattr(entry.spec, "deployment", None),
                    fallback_used=True,
                )
                return entry
            except ProviderUnavailableError:
                continue
        raise ProviderUnavailableError(f"No model available for purpose {purpose.value}")

    def eval_models(self) -> list[ModelEntry]:
        out: list[ModelEntry] = []
        for name in EVAL_MODELS:
            try:
                out.append(self.get(name))
            except (UnknownModelError, ProviderUnavailableError) as exc:
                log.debug("eval_model_unavailable", name=name, error=str(exc))
        return out

    # internals

    def _provider_available(self, provider: Provider) -> bool:
        if provider is Provider.AZURE:
            return self._azure_token_provider is not None
        if provider is Provider.ANTHROPIC:
            return self._anthropic.api_key is not None
        if provider is Provider.GEMINI:
            return self._gemini.api_key is not None
        return False

    def _build(self, spec: ModelSpec) -> Any:
        if spec.provider is Provider.AZURE:
            assert self._azure_token_provider is not None
            if spec.is_embedding:
                return build_azure_embeddings(spec, self._azure, self._azure_token_provider)
            return build_azure_chat(spec, self._azure, self._azure_token_provider)
        if spec.provider is Provider.ANTHROPIC:
            return build_anthropic_chat(spec, self._anthropic)
        if spec.provider is Provider.GEMINI:
            return build_gemini_chat(spec, self._gemini)
        raise ProviderUnavailableError(f"Unsupported provider: {spec.provider}")
