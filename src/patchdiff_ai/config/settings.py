"""Settings: typed config with JSON file + env-var override.

Loads ``<%APPDATA%/patchdiff-ai>/config.json`` at startup. Env vars still
win over JSON (Pydantic precedence: ``init_args > env > json > defaults``)
so users can tweak one-off values without editing the file. Nested
fields use the ``__`` delimiter — ``PATHS__DB_DIR=...`` overrides
``paths.db_dir`` in JSON, exactly the same way it overrode the legacy
``.env`` defaults.

Flat aliases on credential sub-models (``AZURE_ENDPOINT``, ``ANTHROPIC_API_KEY``,
``GOOGLE_API_KEY``) keep working — those fire through each sub-model's own
``BaseSettings`` env source when the JSON file omits the credential section.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any, Tuple, Type

from pydantic import Field
from pydantic_settings import (
    BaseSettings,
    JsonConfigSettingsSource,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

from patchdiff_ai.config.concurrency import Concurrency
from patchdiff_ai.config.credentials import AnthropicCreds, AzureCreds, GeminiCreds
from patchdiff_ai.config.paths import Paths
from patchdiff_ai.config.thresholds import Thresholds
from patchdiff_ai.config.tools import ToolPaths
from patchdiff_ai.runtime.app_dirs import config_json_path


def _strip_blanks(value: Any) -> Any:
    """Drop ``None``-valued and empty-dict entries recursively.

    The auto-written ``config.json`` template uses ``null`` for "unset"
    placeholders so users can see every available knob. Without this
    pass, pydantic-settings would treat those nulls as explicit values
    and shadow lower-priority sources (env vars, model defaults). After
    stripping, the absent key naturally falls through to the next
    source, which is what users expect from a starter template.
    """
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for k, v in value.items():
            v = _strip_blanks(v)
            if v is None:
                continue
            if isinstance(v, dict) and not v:
                # Don't pass an empty `{}` for child BaseSettings models —
                # an empty kwargs dict still suppresses the child's env
                # source. Drop the key so default_factory fires instead.
                continue
            cleaned[k] = v
        return cleaned
    return value


class _BlankStrippedJsonSource(JsonConfigSettingsSource):
    """JSON source that filters out ``null`` placeholders before merging."""

    def __call__(self) -> dict[str, Any]:
        return _strip_blanks(super().__call__())


class ModelChoices(BaseSettings):
    """Per-purpose model overrides; nested under MODELS__<field>."""

    embedding: str | None = Field(default=None, alias="MODELS_EMBEDDING")
    default: str | None = Field(default=None, alias="MODELS_DEFAULT")
    gather_info: str | None = Field(default=None, alias="MODELS_GATHER_INFO")
    platform_internals: str | None = Field(default=None, alias="MODELS_PLATFORM_INTERNALS")
    reverse_engineering: str | None = Field(default=None, alias="MODELS_REVERSE_ENGINEERING")
    researcher: str | None = Field(default=None, alias="MODELS_RESEARCHER")

    model_config = SettingsConfigDict(populate_by_name=True, extra="ignore")


class Settings(BaseSettings):
    """Single fail-fast point for environment validation.

    Reads from ``<data_root>/config.json`` and process env. Nested models
    accept env via either the legacy flat names (``AZURE_ENDPOINT``) or
    ``<group>__<field>`` (``PATHS__DB_DIR``).
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
        env_nested_delimiter="__",
        populate_by_name=True,
        extra="ignore",
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: Type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> Tuple[PydanticBaseSettingsSource, ...]:
        # Precedence (highest first): explicit kwargs → env vars →
        # config.json → file_secrets → model defaults. Drops the legacy
        # `.env` source — JSON replaces it.
        return (
            init_settings,
            env_settings,
            _BlankStrippedJsonSource(settings_cls, json_file=config_json_path()),
            file_secret_settings,
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide cached Settings (one config.json read per run)."""
    return Settings()
