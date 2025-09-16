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


class GatherInfo(Agent):
    """
    This class represents an agent responsible for gathering information, facilitating
    state management, and executing specific tasks such as retrieving CVE information,
    downloading and extracting updates, and adding file information to the vecotrstore.
    """
    semaphore: Semaphore = Semaphore(500)

    @defaultdataclass(frozen=True)
    class NODES:
        # get_info = "Get CVE information"
        download = "Download & extract updates"
        index = "Indexing"
        add_file_info = "Add to file info store"
        update_vs = "Update vecotrstore"

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

        # builder.add_node(self.NODES.get_info, self.get_info)
        builder.add_node(self.NODES.download, self.download_and_extract_updates)
        builder.add_node(self.NODES.index, self.index)
        builder.add_node(self.NODES.add_file_info, self.add_file_info)
        builder.add_node(self.NODES.update_vs, self.update_vector_store)

        builder.set_entry_point(self.NODES.download)
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

    @staticmethod
    def get_update_set(context: GatherInfoContext):
        update_set = set()
        exists_set = set()

        for row in context.filtered_dataframes.base.unique(subset=['name', 'package']).iter_rows(named=True):
            update_set.add((row['name'], row['package']))

        file_info_collection = VectorStore.file_info.get()
        for metadata in file_info_collection.get('metadatas'):
            exists_set.add((metadata['name'], metadata['package']))

        update_set = update_set - exists_set

        return update_set

    def add_file_info_if_needed(self, context: GatherInfoContext):
        updates = []

        update_set = self.get_update_set(context)

        if update_set:
            for row in context.filtered_dataframes.base.unique(subset=['name', 'package']).iter_rows(named=True):
                if (row['name'], row['package']) in update_set:
                    base = Path(row['path']).parents[1] / row['name']
                    updates.append(Send(self.NODES.add_file_info, (base, row['name'], row['package'])))

        return updates or self.NODES.update_vs

    async def download_and_extract_updates(self, context: GatherInfoContext):
        context.state_info.node.append(self.NODES.download)

        async def print_dots():
            try:
                dots = ""
                for i in range(50):
                    dots += "."
                    # Move cursor to beginning of line, clear it, and print progress
                    print(f"\rDownloading: {dots}", end="", flush=True)
                    await asyncio.sleep(0.1*i)
            except asyncio.CancelledError:
                pass

        dot_task = asyncio.create_task(print_dots())

        with Timer('download KBs'):
            curr_task = asyncio.create_task(
                asyncio.to_thread(kb_downloader.download_kb, context.KB.current,
                                  context.os.name, Path('_temp'), False)
            )
            prev_task = asyncio.create_task(
                asyncio.to_thread(kb_downloader.download_kb, context.KB.previous,
                                  context.os.name, Path('_temp'), False)
            )

            # Wait for both to complete
            curr, prev = await asyncio.gather(curr_task, prev_task, return_exceptions=True)
            dot_task.cancel()

            if not (curr.exists() and prev.exists()):
                raise RuntimeError('Downloading of update installation failed')

        with Timer('extract KBs'):
            console.info('[*] Start KBs extraction')
            await extract_kbs(prev, curr)
            context.extracted.previous = prev.parent / ('extracted_' + prev.name)
            context.extracted.current = curr.parent / ('extracted_' + curr.name)

    async def index(self, context: GatherInfoContext):
        context.state_info.node.append(self.NODES.index)

        winsxs_df = get_winsxs_df(context.KB.base)
        console.info('[+] WinSxS indexing completed')
        arch = context.os.arch

        # TODO: Support more architectures
        prev_report = get_report(context.extracted.previous / 'report.txt', arch)
        curr_report = get_report(context.extracted.current / 'report.txt', arch)

        prev_df = get_update_dataframe(context.KB.previous, prev_report,
                                       cache=context.extracted.previous / 'report.cache')
        curr_df = get_update_dataframe(context.KB.current, curr_report,
                                       cache=context.extracted.current / 'report.cache')

        winsxs_df = winsxs_df.filter(filter_executables)

        context.dataframes.previous = prev_df
        context.dataframes.current = curr_df
        context.dataframes.base = winsxs_df

        # Filter reverse patch files from the winsxs
        r_patch = winsxs_df.filter(pl.col("arch").eq(arch) & pl.col("delta_type").eq("r"))

        # All the files in the current KB that was changed from the last KB
        # and have a reverse patch in the WinSxS folder
        curr_relevant_df = (
            curr_df.filter(
                pl.col("arch").eq(arch)  # filter the x64 only and unmodified files
                & ~pl.col("hash").is_in(prev_df["hash"])
            ).join(r_patch.select("package", "pubkey", "arch").unique(),  # Correlate with the winsxs folder
                   on=["package", "pubkey", "arch"],
                   how="semi",
                   )
        )

        # Same for previous
        prev_relevant_df = (
            prev_df.filter(
                pl.col("arch").eq(arch)  # filter the x64 only and unmodified files
                & ~pl.col("hash").is_in(curr_df["hash"])
            ).join(r_patch.select("package", "pubkey", "arch").unique(),  # Correlate with the winsxs folder
                   on=["package", "pubkey", "arch"],
                   how="semi",
                   )
        )

        # Filter all matched reverse patches to current
        # It's enough since current update include previous updates
        # TODO: handle edge cases
        relevant_r_patch_df = r_patch.join(
            curr_relevant_df.select(["package", "pubkey", "arch"]).unique(),
            on=["package", "pubkey", "arch"],
            how="semi",
        )

        # Filter files names as well
        context.filtered_dataframes.previous = prev_relevant_df.filter(
            pl.col('name').str.to_lowercase().is_in(
                relevant_r_patch_df.get_column('name').str.to_lowercase()))

        context.filtered_dataframes.current = curr_relevant_df.filter(
            pl.col('name').str.to_lowercase().is_in(
                relevant_r_patch_df.get_column('name').str.to_lowercase()))

        context.filtered_dataframes.base = relevant_r_patch_df

        console.info(f'[+] {context.KB.current} and {context.KB.previous} indexing completed')

    async def add_file_info(self, args: tuple):
        base, name, package = args
        # The lock is reentrant, so it will not affect a single graph
        # execution, but will prevent file info db corruption.
        with file_info_update_mutex:
            async with self.semaphore:
                res = VectorStore.file_info.get(
                    where={'$and': [{'name': name}, {'package': package}]},
                )

                if res.get('ids'):
                    return

                console.info(f'[*] Adding {name} to file info store')
                desc = file_desc(base) or '_' if base.exists() else '_'

                chain = self.prompt_template | self.get_llm()
                result = await chain.ainvoke({"filename": name, 'package': package, "description": desc})
                logger.debug(result.content)

                doc = Document(page_content=result.content or '',
                               metadata={'name': name.lower(), 'package': package.lower(), 'description': desc.lower()})
                await VectorStore.file_info.aadd_documents(documents=[doc], ids=[str(uuid.uuid4())])

    def update_vector_store(self, context: GatherInfoContext):
        ''' Placeholder node '''
        context.state_info.node.append(self.NODES.update_vs)
