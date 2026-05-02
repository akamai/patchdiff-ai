from pydantic import Field
from pydantic.types import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class AzureCreds(BaseSettings):
    endpoint: str | None = Field(default=None, alias="AZURE_ENDPOINT")
    tenant_id: str | None = Field(default=None, alias="AZURE_TENANT_ID")
    client_id: str | None = Field(default=None, alias="AZURE_CLIENT_ID")
    client_secret: SecretStr | None = Field(default=None, alias="AZURE_CLIENT_SECRET")

    model_config = SettingsConfigDict(
        env_file=".env", populate_by_name=True, extra="ignore"
    )

    @property
    def has_service_principal(self) -> bool:
        return bool(self.tenant_id and self.client_id and self.client_secret)


class AnthropicCreds(BaseSettings):
    api_key: SecretStr | None = Field(default=None, alias="ANTHROPIC_API_KEY")
    base_url: str = Field(default="https://api.anthropic.com", alias="ANTHROPIC_BASE_URL")

    model_config = SettingsConfigDict(
        env_file=".env", populate_by_name=True, extra="ignore"
    )


class GeminiCreds(BaseSettings):
    api_key: SecretStr | None = Field(default=None, alias="GOOGLE_API_KEY")

    model_config = SettingsConfigDict(
        env_file=".env", populate_by_name=True, extra="ignore"
    )
