import logging
import os

from langchain_openai import AzureChatOpenAI, AzureOpenAIEmbeddings
from azure.identity import ClientSecretCredential, get_bearer_token_provider, DefaultAzureCredential

logging.getLogger('azure').setLevel(logging.WARNING)
logging.getLogger('httpx').setLevel(logging.WARNING)

endpoint = "https://esg-research.openai.azure.com/"

# https://azure.microsoft.com/en-us/pricing/details/cognitive-services/openai-service/
tenant_id = os.environ.get("AZURE_TENANT_ID")
client_id = os.environ.get("AZURE_CLIENT_ID")
client_secret = os.environ.get("AZURE_CLIENT_SECRET")

if tenant_id and client_id and client_secret:
    credential = ClientSecretCredential(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
    )
else:
    credential = DefaultAzureCredential(
        exclude_environment_credential=True
    )


token_provider = get_bearer_token_provider(
    credential,
    "https://cognitiveservices.azure.com/.default",
)


class LLM:
    o3 = AzureChatOpenAI(
        model="o3",
        azure_deployment="o3",
        api_version="2024-12-01-preview",
        azure_endpoint=endpoint,
        azure_ad_token_provider=token_provider,
        streaming=False,
        # model_kwargs={'max_completion_tokens': 100000}
    )
    o4_mini = AzureChatOpenAI(
        model="o4-mini",
        azure_deployment="o4-mini",
        api_version="2024-12-01-preview",
        azure_endpoint=endpoint,
        azure_ad_token_provider=token_provider,
        streaming=False,
        # model_kwargs={'max_completion_tokens': 100000}
    )
    o3_mini = AzureChatOpenAI(
        model="o3-mini",
        azure_deployment="o3-mini",
        api_version="2024-12-01-preview",
        azure_endpoint=endpoint,
        azure_ad_token_provider=token_provider,
        streaming=False,
        # model_kwargs={'max_completion_tokens': 100000}
    )
    nano = AzureChatOpenAI(
        max_tokens=250,
        model="gpt-4.1-nano",
        azure_deployment="gpt-4.1-nano",
        api_version="2024-12-01-preview",
        azure_endpoint=endpoint,
        azure_ad_token_provider=token_provider,
        temperature=0.0,
        streaming=False,
    )
    mini = AzureChatOpenAI(
        model="gpt-4.1-mini",
        azure_deployment="gpt-4.1-mini",
        api_version="2024-12-01-preview",
        azure_endpoint=endpoint,
        azure_ad_token_provider=token_provider,
        temperature=1.0,
        streaming=False,
        # model_kwargs={'max_completion_tokens': 100000}
    )
    embedding = AzureOpenAIEmbeddings(
        model="text-embedding-3-small",
        azure_deployment="text-embedding-3-small",
        api_version="2024-02-01",
        azure_endpoint=endpoint,
        azure_ad_token_provider=token_provider
    )
