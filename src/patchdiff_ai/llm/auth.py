"""Azure credential resolver. Raises on failure; never calls sys.exit."""

from __future__ import annotations

from azure.core.credentials import TokenCredential
from azure.core.exceptions import ClientAuthenticationError
from azure.identity import (
    ClientSecretCredential,
    DefaultAzureCredential,
    get_bearer_token_provider,
)

from patchdiff_ai.config.credentials import AzureCreds


class AzureAuthError(RuntimeError):
    """Raised when Azure credentials cannot be acquired."""


def build_azure_credential(creds: AzureCreds) -> TokenCredential | None:
    """Return a credential or None if no Azure config was supplied."""
    if not creds.endpoint:
        return None

    if creds.has_service_principal:
        return ClientSecretCredential(
            tenant_id=creds.tenant_id,
            client_id=creds.client_id,
            client_secret=creds.client_secret.get_secret_value(),
        )
    return DefaultAzureCredential(exclude_environment_credential=True)


def cognitive_token_provider(credential: TokenCredential):
    """Return a token-provider callable for the cognitive-services scope."""
    scope = "https://cognitiveservices.azure.com/.default"
    try:
        credential.get_token(scope)
    except ClientAuthenticationError as exc:
        raise AzureAuthError(f"Azure auth failed for {scope}: {exc}") from exc
    return get_bearer_token_provider(credential, scope)
