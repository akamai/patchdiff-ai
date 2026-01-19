import ctypes
import os
import sys
import threading
import uuid
import weakref
from pathlib import Path
import time
from contextlib import ContextDecorator, contextmanager

from azure.core.exceptions import ClientAuthenticationError
from dotenv import load_dotenv
import polars as pl

import logging
from logging.config import dictConfig
from collections import deque
from typing import Annotated, Literal, Hashable, Any

from bindiff import BinDiff
from bindiff.file import FunctionMatch
from langchain_openai import AzureChatOpenAI, AzureOpenAIEmbeddings
from azure.identity import (
    ClientSecretCredential,
    get_bearer_token_provider,
    DefaultAzureCredential,
)
from pydantic import BaseModel
from defaultdataclass import defaultdataclass, field

from langchain_anthropic import ChatAnthropic
from langchain_core.language_models.chat_models import BaseChatModel

from langgraph.graph import add_messages
from langchain_core.messages import AnyMessage

logging.getLogger("azure").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)

load_dotenv()


EXECUTABLE_EXTENSIONS = [".exe", ".dll", ".ocx", ".sys", ".com", ".scr", ".cpl"]


@defaultdataclass(frozen=True)
class StateInfo:
    messages: Annotated[list[type[AnyMessage]], add_messages] = field(
        default_factory=list
    )
    # node: deque[str] = field(default_factory=lambda: deque(maxlen=2))
    node: deque[str] = field(default_factory=lambda: deque())


@defaultdataclass
class CveMetadata:
    cve: str
    title: str
    description: str
    faq: list
    severity: str
    impact: str
    cvss: dict
    cwe: list
    publiclyDisclosed: str
    exploited: str
    products: list


@defaultdataclass
class CveDetails:
    cve: str
    description: str
    msrc_report: CveMetadata


@defaultdataclass
class Candidates:
    query: str
    results: list


@defaultdataclass
class PatchStoreEntry:
    name: str
    path: str
    kb: str
    hash: str
    arch: str
    package: str
    pubkey: str
    version: tuple[int, ...]
    ms_id: str
    uid: str = field(default_factory=lambda: str(uuid.uuid4()))

    # def from_dict(self, data: dict[str, any], overwrite=False):
    #     for k, v in data.items():
    #         if hasattr(self, k):
    #             if overwrite or getattr(self, k) is None:
    #                 setattr(self, k, v)
    #     return self


# @defaultdataclass
# class Artifact:
#     udiff: str
#     before_code: str
#     after_code: str
#     metadata: dict


@defaultdataclass
class Artifact:
    primary_file: PatchStoreEntry
    secondary_file: PatchStoreEntry
    changed: list[FunctionMatch]
    diff: BinDiff


@defaultdataclass
class Report:
    cve_details: CveDetails
    content: str
    confidence: float
    artifact: Artifact
    model: str


@defaultdataclass
class Threshold:
    candidates: float = 7.5
    """0.0 - 10.0 indicates the relevancy threshold for the candidate search."""
    security_modification: float = 0.25
    """0.0 - 1.0 indicates the relevancy threshold for the security modification search."""
    report: float = 0.1
    """0.0 - 1.0 indicates the confidence threshold for the report accuracy."""


#####


@defaultdataclass
class Model:
    name: str
    model: BaseChatModel | BaseModel


class LLM:
    @staticmethod
    def list_models() -> list[Model]:
        """Return all Model members defined on LLM."""
        models: list[Model] = []
        for attr_name in dir(LLM):
            if attr_name.startswith("_"):
                continue
            attr_value = getattr(LLM, attr_name)
            if isinstance(attr_value, Model):
                models.append(attr_value)
        return models

    @staticmethod
    def get_model(model_name: str | None, default: Model) -> Model:
        """Get model by name, returning default if name is None or not found."""
        if not model_name:
            return default

        for model_entry in LLM.list_models():
            if model_entry.name == model_name or model_name.lower().endswith(
                model_entry.name
            ):
                return model_entry

        available = ", ".join(m.name for m in LLM.list_models())
        logger.warning(
            f"Unknown model name: {model_name}, using default (available: {available})"
        )
        return default


class AgentModels:
    embedding_model = None
    reverse_engineering_model = None
    researcher_model = None
    platform_internals_model = None
    gather_info_model = None
    default_model = None


####


def get_winsxs():
    if sys.platform != "win32":
        return None

    path_len = ctypes.windll.kernel32.GetWindowsDirectoryW(None, 0)
    buffer = ctypes.create_unicode_buffer(path_len)
    ctypes.windll.kernel32.GetWindowsDirectoryW(buffer, len(buffer))
    winsxs = Path(buffer.value) / "WinSxS"

    if winsxs.exists():
        return winsxs
    return None


def get_latest_servicingstack_folder():
    base_path = get_winsxs()

    matching_folders = list(base_path.glob("amd64_microsoft-windows-servicingstack_*"))

    if not matching_folders:
        return "No matching folders found."

    try:
        latest_folder = max(matching_folders, key=lambda p: p.stat().st_ctime)
        return latest_folder
    except Exception as e:
        raise f"Error determining latest folder: {e}"


def retry_on_exception(
    _func: callable = None,
    max_retries: int = 3,
    exceptions: tuple[type[BaseException], ...] | type[BaseException] = BaseException,
    delay: float = 0.0,
):
    def wrapper(func: callable):
        def retry(*args, **kwargs):
            attempt = 0
            while True:
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    attempt += 1
                    if attempt > max_retries:
                        raise
                    logger.debug(
                        "Retrying %s (%d/%d) in %s[s], exception: %s",
                        func.__name__,
                        attempt,
                        max_retries,
                        delay,
                        e,
                    )
                    if delay:
                        time.sleep(delay)

        return retry

    # Support bare @retry_on_exception and @retry_on_exception(...)
    if callable(_func):
        return wrapper(_func)
    return wrapper


class Timer(ContextDecorator):
    def __init__(self, name: str = None):
        self.name = name
        self.start: float = 0.0
        self.elapsed: float = 0.0

    def __call__(self, func):
        self.name = self.name or func.__name__
        return super().__call__(func)

    def __enter__(self):
        self.start = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.elapsed = time.perf_counter() - self.start
        logger.info(
            f"[{self.name or 'time block'}] elapsed: {self.elapsed:.6f} seconds"
        )
        return False


def get_patch_store_df():
    cache = Path("db/.patch_store_df")

    if cache.exists():
        return pl.DataFrame.deserialize(cache)

    df = pl.DataFrame([PatchStoreEntry()])
    return df.clear()


LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": True,
    "formatters": {
        "standard": {
            "format": "%(module)s::%(funcName)s|%(asctime)s|%(levelname)s - \t%(message)s"
        },
        "minimal": {"format": "%(message)s"},
    },
    "handlers": {
        "console": {"class": "logging.StreamHandler", "formatter": "standard"},
        "minimal_console": {"class": "logging.StreamHandler", "formatter": "minimal"},
        "file": {
            "class": "logging.handlers.RotatingFileHandler",
            "formatter": "standard",
            "filename": "log.txt",
            "maxBytes": 10485760,  # 10MB
            "backupCount": 5,
            "encoding": "utf-8",
        },
    },
    "loggers": {
        "": {  # Root logger
            "handlers": ["console"],
            "level": "INFO",
            "propagate": True,
        },
    },
}

greeting_msg = """


####################################################################################################
<title>
####################################################################################################


"""


def create_logger(
    name: str,
    handlers: list[Literal["file", "console", "minimal_console"]],
    level: str = "INFO",
):
    handlers = handlers or ["console"]

    config = LOGGING_CONFIG.copy()
    config["loggers"][name] = {
        "handlers": handlers,
        "level": level,
        "propagate": False,
    }

    dictConfig(config)
    _logger = logging.getLogger(name=name)
    _logger.debug(
        greeting_msg.replace("<title>", f"  Logging {name} started  ".center(100, "#"))
    )
    return _logger


logger = create_logger("logger", handlers=["file"], level="DEBUG")  # , level='DEBUG'
console = create_logger(
    "console", handlers=["file", "minimal_console"]
)  # , level='DEBUG'

_lock_table: weakref.WeakValueDictionary[Hashable, threading.Lock] = (
    weakref.WeakValueDictionary()
)
_table_guard = threading.RLock()


def _get_lock(key: Hashable) -> threading.Lock:
    with _table_guard:
        lock = _lock_table.get(key)
        if lock is None:
            lock = threading.Lock()
            _lock_table[key] = lock
        return lock


@contextmanager
def resource_lock(key: Hashable):
    """
    Usage:
        with resource_lock(resource_id):
            ... critical section ...
    """
    if key is None:
        return

    lock = _get_lock(key)
    lock.acquire()
    try:
        yield
    finally:
        lock.release()


def save_to_file(
    reports: dict[str, Any], path=(Path(__file__).resolve().parent / "reports")
):
    for r, m in zip(reports.get("documents"), reports.get("metadatas")):
        text = f"{m}\n{r}"

        cve = m.get("cve")
        filename = m.get("file")
        base_path = path / f"{cve}_{filename}.txt"

        # Handle duplicates by adding an index
        if base_path.exists():
            index = 1
            while True:
                indexed_path = path / f"{cve}_{filename}_{index}.txt"
                if not indexed_path.exists():
                    f = indexed_path
                    break
                index += 1
        else:
            f = base_path

        f.parent.mkdir(exist_ok=True)
        f.write_text(text, encoding="utf-8")


def init_agents_models():
    AgentModels.embedding_model = LLM.get_model(
        os.environ.get("MODELS_EMBEDDING"), LLM.embedding
    )
    AgentModels.reverse_engineering_model = LLM.get_model(
        os.environ.get("MODELS_REVERSE_ENGINEERING"), LLM.o3_mini
    )
    AgentModels.researcher_model = LLM.get_model(
        os.environ.get("MODELS_RESEARCHER"), LLM.o3
    )
    AgentModels.platform_internals_model = LLM.get_model(
        os.environ.get("MODELS_PLATFORM_INTERNALS"), LLM.mini
    )
    AgentModels.default_model = LLM.get_model(
        os.environ.get("MODELS_DEFAULT"), LLM.o4_mini
    )
    AgentModels.gather_info_model = LLM.get_model(
        os.environ.get("MODELS_GATHER_INFO"), LLM.nano
    )


def init_azure_models(azure_credential):
    endpoint = os.environ.get("AZURE_ENDPOINT")

    if not azure_credential or not endpoint:
        return

    if not azure_credential.get_token("https://cognitiveservices.azure.com/.default"):
        return

    azure_token_provider = get_bearer_token_provider(
        azure_credential,
        "https://cognitiveservices.azure.com/.default",
    )

    LLM.gpt_5_2 = Model(
        name="azure.gpt-5.2",
        model=AzureChatOpenAI(
            model="gpt-5.2",
            azure_deployment="gpt-5.2",
            api_version="2024-12-01-preview",
            azure_endpoint=endpoint,
            azure_ad_token_provider=azure_token_provider,
            streaming=False,
            # model_kwargs={'max_completion_tokens': 100000}
        ),
    )
    LLM.o3 = Model(
        name="azure.o3",
        model=AzureChatOpenAI(
            model="o3",
            azure_deployment="o3",
            api_version="2024-12-01-preview",
            azure_endpoint=endpoint,
            azure_ad_token_provider=azure_token_provider,
            streaming=False,
            # model_kwargs={'max_completion_tokens': 100000}
        ),
    )
    LLM.o4_mini = Model(
        name="azure.o4-mini",
        model=AzureChatOpenAI(
            model="o4-mini",
            azure_deployment="o4-mini",
            api_version="2024-12-01-preview",
            azure_endpoint=endpoint,
            azure_ad_token_provider=azure_token_provider,
            streaming=False,
            # model_kwargs={'max_completion_tokens': 100000}
        ),
    )
    LLM.o3_mini = Model(
        name="azure.o3-mini",
        model=AzureChatOpenAI(
            model="o3-mini",
            azure_deployment="o3-mini",
            api_version="2024-12-01-preview",
            azure_endpoint=endpoint,
            azure_ad_token_provider=azure_token_provider,
            streaming=False,
            # model_kwargs={'max_completion_tokens': 100000}
        ),
    )
    LLM.nano = Model(
        name="azure.gpt-4.1-nano",
        model=AzureChatOpenAI(
            max_tokens=250,
            model="gpt-4.1-nano",
            azure_deployment="gpt-4.1-nano",
            api_version="2024-12-01-preview",
            azure_endpoint=endpoint,
            azure_ad_token_provider=azure_token_provider,
            max_retries=4,
            temperature=0.0,
            streaming=False,
        ),
    )
    LLM.mini = Model(
        name="azure.gpt-4.1-mini",
        model=AzureChatOpenAI(
            model="gpt-4.1-mini",
            azure_deployment="gpt-4.1-mini",
            api_version="2024-12-01-preview",
            azure_endpoint=endpoint,
            azure_ad_token_provider=azure_token_provider,
            temperature=1.0,
            streaming=False,
            # model_kwargs={'max_completion_tokens': 100000}
        ),
    )
    LLM.embedding = Model(
        name="azure.text-embedding-3-small",
        model=AzureOpenAIEmbeddings(
            model="text-embedding-3-small",
            azure_deployment="text-embedding-3-small",
            api_version="2024-02-01",
            azure_endpoint=endpoint,
            azure_ad_token_provider=azure_token_provider,
        ),
    )


def init_anthropic_models():
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return

    LLM.claude_sonnet = Model(
        name="claude.sonnet",
        model=ChatAnthropic(
            model="claude-sonnet-4-5",
        ),
    )
    LLM.claude_opus = Model(
        name="claude.opus",
        model=ChatAnthropic(
            model="claude-opus-4-5",
        ),
    )


# https://azure.microsoft.com/en-us/pricing/details/cognitive-services/openai-service/
tenant_id = os.environ.get("AZURE_TENANT_ID")
client_id = os.environ.get("AZURE_CLIENT_ID")
client_secret = os.environ.get("AZURE_CLIENT_SECRET")

try:
    azure_credential = None
    if tenant_id and client_id and client_secret:
        azure_credential = ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )
    else:
        azure_credential = DefaultAzureCredential(exclude_environment_credential=True)

    init_azure_models(azure_credential)
    init_anthropic_models()

    init_agents_models()

except ClientAuthenticationError as e:
    console.warning(f"DefaultAzureCredential failed to acquire a token. Details: {e}")
    console.error(f"Currently we are using azure.text-embedding-3-small as the embedded model."
                  f"Use other embedded model instead, and remove this validation.")
    exit(1)
