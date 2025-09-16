import asyncio
import operator
import pickle
import threading
import uuid
from asyncio import Semaphore
from typing import Annotated

import polars as pl
from pathlib import Path

from langchain_core.documents import Document
from langchain_core.messages import SystemMessage
from langchain_core.prompts import ChatPromptTemplate, HumanMessagePromptTemplate
from langgraph.graph import StateGraph
from agent import Agent
from agent_tools.vector_store import VectorStore
from common import StateInfo, CveDetails, logger, Timer, LLM, resource_lock, console
from defaultdataclass import defaultdataclass, field
from langgraph.constants import Send, END

from patch_analysis.files_collection import get_winsxs_df, get_report, get_update_dataframe, filter_executables, \
    file_desc
from patch_extractor import extractor, patch_tools
from patch_downloader import kb_downloader, get_os_data, cve_enrichment

file_info_update_mutex = threading.RLock()


@defaultdataclass
class PatchSources:
    current: str | Path | pl.dataframe.DataFrame
    previous: str | Path | pl.dataframe.DataFrame
    base: str | Path | pl.dataframe.DataFrame


@defaultdataclass
class OsDetails:
    name: str
    id: int
    arch: str


@defaultdataclass
class GatherInfoContext:
    state_info: StateInfo
    cve_details: CveDetails
    os: OsDetails
    KB: PatchSources
    extracted: PatchSources
    dataframes: PatchSources
    filtered_dataframes: PatchSources
    updates: Annotated[list[Document], operator.add] = field(default_factory=list)


@defaultdataclass
class GatherInfoContextOutput:
    state_info: StateInfo
    cve_details: CveDetails = field(default_factory=CveDetails)
    os: OsDetails = field(default_factory=OsDetails)
    KB: PatchSources = field(default_factory=PatchSources)
    extracted: PatchSources = field(default_factory=PatchSources)
    dataframes: PatchSources = field(default_factory=PatchSources)
    filtered_dataframes: PatchSources = field(default_factory=PatchSources)


def load_delta_modules(kb):
    extracted = kb.parent.resolve() / f'extracted_{kb.name}'
    dd = extracted / 'DesktopDeployment.cab' / 'UpdateCompression.dll'
    if dd.exists():
        patch_tools.PatchTools.load_delta_modules([str(dd.resolve())])


@Timer()
async def extract_kbs(prev, curr):
    tasks = [extractor.aextract(prev, None, False),
             extractor.aextract(curr, None, False)]

    load_delta_modules(prev)
    load_delta_modules(curr)

    await asyncio.gather(*tasks)


class Chatbot(Agent):
    """
    This class represents an agent responsible for gathering information, facilitating
    state management, and executing specific tasks such as retrieving CVE information,
    downloading and extracting updates, and adding file information to the vecotrstore.
    """
    semaphore: Semaphore = Semaphore(500)

    @defaultdataclass(frozen=True)
    class NODES:
        # get_info = "Get CVE information"
        chatbot = "Chatbot"

    def __init__(self):
        super().__init__(llm=LLM.nano)

    prompt_template = ChatPromptTemplate(
        input_variables=["filename", "package", "description"],
        messages=[SystemMessage('You are a senior Windows-internals analyst'),
                  HumanMessagePromptTemplate.from_template(
                      "Write a maximum of 80 token unformatted paragraph about the Windows executable "
                      "{filename} package: {package} description: {description}. Include only technical details about "
                      "its purpose in the system. Keep it short, consistent, and strictly one paragraph. "
                      "Do not repeat facts. Omit headings, bullets, and conjunctions; the output is "
                      "for embedding context.")
                  ])

    def _build(self):
        if self._graph:
            return

        builder = StateGraph(GatherInfoContext)

        builder.add_node(self.NODES.chatbot, self.chatbot)

        builder.set_entry_point(self.NODES.chatbot)
        # builder.add_edge(self.NODES.get_info, self.NODES.download)
        builder.add_edge(self.NODES.download, self.NODES.index)

        builder.add_conditional_edges(self.NODES.index, self.add_file_info_if_needed,
                                      [
                                          self.NODES.add_file_info,
                                          self.NODES.update_vs,
                                      ])

        builder.add_edge(self.NODES.add_file_info, self.NODES.update_vs)
        builder.set_finish_point(self.NODES.update_vs)

        self._graph = builder.compile()

    def chatbot(self, context: GatherInfoContext):
        pass

