from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from patchdiff_ai.config.concurrency import Concurrency
from patchdiff_ai.config.credentials import AnthropicCreds, AzureCreds, GeminiCreds
from patchdiff_ai.config.paths import Paths
from patchdiff_ai.config.thresholds import Thresholds
from patchdiff_ai.config.tools import ToolPaths


class ModelChoices(BaseSettings):
    """Per-purpose model overrides; nested under MODELS__<field>."""

    embedding: str | None = Field(default=None, alias="MODELS_EMBEDDING")
    default: str | None = Field(default=None, alias="MODELS_DEFAULT")
    gather_info: str | None = Field(default=None, alias="MODELS_GATHER_INFO")
    platform_internals: str | None = Field(default=None, alias="MODELS_PLATFORM_INTERNALS")
    reverse_engineering: str | None = Field(default=None, alias="MODELS_REVERSE_ENGINEERING")
    researcher: str | None = Field(default=None, alias="MODELS_RESEARCHER")

    model_config = SettingsConfigDict(
        env_file=".env", populate_by_name=True, extra="ignore"
    )


class Settings(BaseSettings):
    """Single fail-fast point for environment validation.

    Reads from `.env` and process env. Nested models accept env via either
    the legacy flat names (AZURE_ENDPOINT) or `<group>__<field>` (PATHS__DB_DIR).
    """

    azure: AzureCreds = Field(default_factory=AzureCreds)
    anthropic: AnthropicCreds = Field(default_factory=AnthropicCreds)
    gemini: GeminiCreds = Field(default_factory=GeminiCreds)

    paths: Paths = Field(default_factory=Paths)
    tools: ToolPaths = Field(default_factory=ToolPaths)
    thresholds: Thresholds = Field(default_factory=Thresholds)
    concurrency: Concurrency = Field(default_factory=Concurrency)
    models: ModelChoices = Field(default_factory=ModelChoices)

    log_level: str = Field(default="INFO")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
        populate_by_name=True,
        extra="ignore",
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide cached Settings (one .env read per run)."""
    return Settings()
