"""Static model catalog. Replaces the dynamic-class-attribute LLM god-object."""

from dataclasses import dataclass
from enum import Enum


class Provider(str, Enum):
    AZURE = "azure"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"


class ModelPurpose(str, Enum):
    DEFAULT = "default"
    EMBEDDING = "embedding"
    GATHER_INFO = "gather_info"
    PLATFORM_INTERNALS = "platform_internals"
    REVERSE_ENGINEERING = "reverse_engineering"
    RESEARCHER = "researcher"


@dataclass(frozen=True)
class ModelSpec:
    name: str
    provider: Provider
    deployment: str
    api_version: str | None = None
    # Pricing — Anthropic, OpenAI, etc. charge different rates for input vs.
    # output tokens (output is 3-5× pricier). When `cost_per_mtok_input` /
    # `cost_per_mtok_output` are set, the metrics handler uses them; when
    # only `cost_per_mtok` is set it's treated as a blended single rate
    # applied to both directions (legacy / Azure entries that haven't been
    # split out yet).
    cost_per_mtok: float = 0.0
    cost_per_mtok_input: float | None = None
    cost_per_mtok_output: float | None = None
    max_tokens: int | None = None
    temperature: float | None = None
    is_embedding: bool = False


# Defaults per-purpose (used when env override is absent or invalid).
DEFAULT_BY_PURPOSE: dict[ModelPurpose, str] = {
    ModelPurpose.EMBEDDING: "azure.text-embedding-3-small",
    ModelPurpose.DEFAULT: "claude.sonnet-4.6",
    ModelPurpose.GATHER_INFO: "azure.gpt-4.1-mini",
    ModelPurpose.PLATFORM_INTERNALS: "azure.gpt-4.1-mini",
    ModelPurpose.REVERSE_ENGINEERING: "azure.o3-mini",
    ModelPurpose.RESEARCHER: "azure.o3",
}


MODEL_CATALOG: dict[str, ModelSpec] = {
    spec.name: spec
    for spec in [
        # Azure OpenAI — per-direction rates from Azure Foundry pricing.
        ModelSpec(
            name="azure.gpt-5.2",
            provider=Provider.AZURE,
            deployment="gpt-5.2",
            api_version="2025-01-01-preview",
            cost_per_mtok_input=1.75,
            cost_per_mtok_output=14.0,
        ),
        ModelSpec(
            name="azure.gpt-5.2-codex",
            provider=Provider.AZURE,
            deployment="gpt-5.2-codex",
            api_version="2025-01-01-preview",
            cost_per_mtok_input=1.75,
            cost_per_mtok_output=14.0,
        ),
        ModelSpec(
            name="azure.o3",
            provider=Provider.AZURE,
            deployment="o3",
            api_version="2024-12-01-preview",
            cost_per_mtok_input=2.0,
            cost_per_mtok_output=8.0,
        ),
        ModelSpec(
            name="azure.4o",
            provider=Provider.AZURE,
            deployment="gpt-4o",
            api_version="2024-12-01-preview",
            # Matches GPT-4o-2024-08-06 / 1120 pricing (current stable rates).
            cost_per_mtok_input=2.5,
            cost_per_mtok_output=10.0,
        ),
        ModelSpec(
            name="azure.o4-mini",
            provider=Provider.AZURE,
            deployment="o4-mini",
            api_version="2024-12-01-preview",
            cost_per_mtok_input=1.1,
            cost_per_mtok_output=4.4,
        ),
        ModelSpec(
            name="azure.o3-mini",
            provider=Provider.AZURE,
            deployment="o3-mini",
            api_version="2024-12-01-preview",
            cost_per_mtok_input=1.1,
            cost_per_mtok_output=4.4,
        ),
        ModelSpec(
            name="azure.gpt-4.1-nano",
            provider=Provider.AZURE,
            deployment="gpt-4.1-nano",
            api_version="2024-12-01-preview",
            cost_per_mtok_input=0.1,
            cost_per_mtok_output=0.4,
            max_tokens=250,
            temperature=0.0,
        ),
        ModelSpec(
            name="azure.gpt-4.1-mini",
            provider=Provider.AZURE,
            deployment="gpt-4.1-mini",
            api_version="2024-12-01-preview",
            cost_per_mtok_input=0.4,
            cost_per_mtok_output=1.6,
            temperature=1.0,
        ),
        ModelSpec(
            name="azure.text-embedding-3-small",
            provider=Provider.AZURE,
            deployment="text-embedding-3-small",
            api_version="2024-02-01",
            is_embedding=True,
        ),
        # Anthropic — input/output rates differ (output ~5x input).
        ModelSpec(
            name="claude.sonnet-4.6",
            provider=Provider.ANTHROPIC,
            deployment="claude-sonnet-4-6",
            cost_per_mtok_input=3.0,
            cost_per_mtok_output=15.0,
        ),
        ModelSpec(
            name="claude.haiku-4.5",
            provider=Provider.ANTHROPIC,
            deployment="claude-haiku-4-5-20251001",
            cost_per_mtok_input=1.0,
            cost_per_mtok_output=5.0,
        ),
        ModelSpec(
            name="claude.opus-4.6",
            provider=Provider.ANTHROPIC,
            deployment="claude-opus-4-6",
            cost_per_mtok_input=5.0,
            cost_per_mtok_output=25.0,
        ),
        ModelSpec(
            name="claude.opus-4.7",
            provider=Provider.ANTHROPIC,
            deployment="claude-opus-4-7",
            cost_per_mtok_input=5.0,
            cost_per_mtok_output=25.0,
        ),
        # Gemini
        ModelSpec(
            name="gemini.2.5-flash",
            provider=Provider.GEMINI,
            deployment="gemini-2.5-flash",
            cost_per_mtok=0.3,
        ),
        ModelSpec(
            name="gemini.2.5-pro",
            provider=Provider.GEMINI,
            deployment="gemini-2.5-pro",
            cost_per_mtok=1.25,
        ),
        ModelSpec(
            name="gemini.3-flash",
            provider=Provider.GEMINI,
            deployment="gemini-3-flash-preview",
            cost_per_mtok=0.5,
        ),
        ModelSpec(
            name="gemini.3-pro",
            provider=Provider.GEMINI,
            deployment="gemini-3-pro-preview",
            cost_per_mtok=2.0,
        ),
    ]
}


# Models used in evaluation mode (multi-model parallel report generation).
EVAL_MODELS: tuple[str, ...] = (
    "claude.sonnet-4.6",
    "claude.haiku-4.5",
    "claude.opus-4.7",
    "claude.opus-4.6",
    "azure.gpt-5.2",
)
