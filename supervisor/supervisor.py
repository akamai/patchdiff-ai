# Supervisor
import operator
from pathlib import Path
from typing import Annotated

import polars as pl
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage
from langchain_core.runnables import RunnableConfig

from langgraph.constants import END, Send

from agent import Agent
from agent_tools.vector_store import VectorStore
from common import StateInfo, logger, get_patch_store_df, PatchStoreEntry, Artifact, Report, CveDetails, resource_lock, \
    Threshold, console, LLM, save_to_file
from defaultdataclass import defaultdataclass, field

from langgraph.graph import StateGraph, add_messages

from patch_analysis.patch_delta import patch_entry
from patch_downloader import get_os_data
from re_agent.revearse_engineer_agent import ReverseEngineering, ReverseEngineeringOutput, ReverseEngineeringContext
from supervisor.cve_info import get_os_cvrf_data, get_articles
from supervisor.gather_info import GatherInfo, GatherInfoContextOutput
from supervisor.windows_internals import WindowsInternals, WindowsInternalsOutput
from vr_agent.vulnerability_researcher_agent import VulnerabilityResearchOutput, VulnerabilityResearch, \
    VulnerabilityResearchContext


@defaultdataclass(slots=True)
class SupervisorContext(GatherInfoContextOutput,
                        WindowsInternalsOutput,
                        ReverseEngineeringOutput,
                        VulnerabilityResearchOutput):
    cve_details: Annotated[CveDetails, lambda _, new: new] = field(default_factory=CveDetails)
    messages: Annotated[list[BaseMessage], add_messages] = field(default_factory=list)
    state_info: Annotated[StateInfo, lambda _, new: new] = field(default_factory=StateInfo)
    artifacts: Annotated[list[Artifact], operator.add] = field(default_factory=list)
    reports: Annotated[list[Report], operator.add] = field(default_factory=list)
    action: str = ''


class Supervisor(Agent):
    @defaultdataclass(frozen=True)
    class NODES:
        cve_info = "Get CVE information"
        gather_info = "Gather Information"
        wi_agent = "Windows Internals Agent"
        re_agent = "Reverse Engineering Agent"
        vr_agent = "Vulnerability Research Agent"
        assistant = "Assistant"
        # patch = "Patch candidates"

    def __init__(self):
        self.gather_info = GatherInfo()
        self.wi_agent = WindowsInternals()
        self.re_agent = ReverseEngineering()
        self.vr_agent = VulnerabilityResearch()
        self.llm = LLM.o4_mini
        super().__init__(draw=True)

    async def run(self, cve: str, config=None):
        initial_state = SupervisorContext()

        initial_state.cve_details.cve = cve
        initial_state.state_info.node.append('START')

        console.info(f'[*] Starting analysis of {cve}')
        async for step in self._graph.astream_events(initial_state, config, subgraphs=True):
            yield step

            # for node_name, state_dict in step.items():
            #     if state_dict:
            #         # state = {node_name: SupervisorContext(**state_dict)}
            #         yield state_dict
            #     else:
            #         yield None

    def _build(self):
        if self._graph:
            return

        builder = StateGraph(SupervisorContext)

        # builder.add_node(self.NODES.patch, self.patch)
        builder.add_node(self.NODES.assistant, self.assistant)
        builder.add_node(self.NODES.cve_info, self.get_cve_info)
        builder.add_node(self.NODES.gather_info, self.gather_info.get_graph())
        builder.add_node(self.NODES.wi_agent, self.wi_agent.get_graph())
        builder.add_node(self.NODES.re_agent, self.re_agent.get_graph())
        builder.add_node(self.NODES.vr_agent, self.vr_agent.get_graph())

        builder.set_entry_point(self.NODES.cve_info)
        builder.add_conditional_edges(self.NODES.cve_info, self.check_report_cache,
                                      [
                                          self.NODES.assistant,
                                          self.NODES.gather_info
                                      ])
        builder.add_edge(self.NODES.gather_info, self.NODES.wi_agent)
        builder.add_edge(self.NODES.wi_agent, self.NODES.assistant)
        builder.add_conditional_edges(self.NODES.assistant, self.router,
                                      [
                                          self.NODES.assistant,
                                          self.NODES.gather_info,
                                          self.NODES.wi_agent,
                                          self.NODES.re_agent,
                                          self.NODES.vr_agent,
                                          # self.NODES.patch,
                                          END
                                      ])

        # builder.add_conditional_edges(self.NODES.patch, self.router,
        #                               [
        #                                   self.NODES.assistant,
        #                                   self.NODES.re_agent,
        #                               ])
        builder.add_edge(self.NODES.wi_agent, self.NODES.assistant)
        builder.add_edge(self.NODES.re_agent, self.NODES.assistant)
        builder.add_edge(self.NODES.vr_agent, self.NODES.assistant)

        builder.set_finish_point(self.NODES.assistant)

        # memory = MemorySaver()
        self._graph = builder.compile()

    def check_report_cache(self, context: SupervisorContext):
        console.info('[*] Check for cached reports')
        docs = VectorStore.reports.get(
            where={'cve': context.cve_details.cve},
        )

        reports = []
        for i in range(len(docs.get('ids'))):
            doc = docs.get('documents')[i]
            metadata = docs.get('metadatas')[i]
            reports.append(Report(
                content=doc,
                cve_details=CveDetails(cve=metadata.get('cve')),
                artifact=Artifact(primary_file=PatchStoreEntry(name=metadata.get('file'),
                                                               kb=metadata.get('kb'),
                                                               uid=metadata.get('patch_store_uid'))),
                confidence=metadata.get('confidence')
            ))

        if reports:
            context.reports.extend(reports)
            return self.NODES.assistant

        return self.NODES.gather_info

    def get_cve_info(self, context: SupervisorContext):
        context.state_info.node.append(self.NODES.cve_info)

        console.debug('[*] Getting CVRF OS name and ID of this machine')
        context.os.name, context.os.id = get_os_cvrf_data()
        context.os.arch = get_os_data.processor_arch_tokens(
            {
                0: ("x86",),
                5: ("arm",),
                9: ("amd64",),
                12: ("arm64",),
            }
        )[0]
        console.info(f'[+] Currently running on {context.os.name} with ID {context.os.id}')

        logger.info(f'[*] Retrieve the metadata of {context.cve_details.cve}')
        get_articles(context)
        logger.info(
            f'[+] {context.cve_details.cve} - {context.cve_details.msrc_report.title}:\n'
            f'{context.cve_details.msrc_report.description}\n'
            f'patched in {context.KB.current} supercedence {context.KB.previous}')

    @staticmethod
    def _patch_candidates(context: SupervisorContext, ranked_df: pl.DataFrame):

        filter_df = (
                (pl.col('name').str.to_lowercase().is_in(
                    ranked_df.get_column('name').str.to_lowercase().implode())) &
                (pl.col('package').str.to_lowercase().is_in(
                    ranked_df.get_column('package').str.to_lowercase().implode()))
        )

        # At this point we got the candidates, and we want to see if they are
        # relevant to the current update
        subjects: pl.DataFrame = context.filtered_dataframes.current.filter(filter_df).join(
            ranked_df.select(['name', 'similarity score', 'relevancy']),
            on='name',
            how='left').sort("relevancy", descending=True)

        if subjects.is_empty():
            # There is no changes to these files in the current update
            return

        with resource_lock('update_patch_store'):
            patch_store_df = get_patch_store_df()

            try:
                results = []
                for row in subjects.iter_rows(named=True):
                    try:
                        base_entry, curr_entry, prev_entry = patch_entry(row,
                                                                         context.KB.base,
                                                                         context.KB.current,
                                                                         context.KB.previous,
                                                                         context.dataframes.previous,
                                                                         context.filtered_dataframes.base)
                        patched = [x for x in [base_entry, curr_entry, prev_entry] if x]
                        if patched:
                            results.append(pl.DataFrame(patched))
                    except BaseException as e:
                        console.warning(e)

                if results:
                    patch_store_df = pl.concat(
                        [patch_store_df, *results], how="vertical_relaxed"
                    )
            finally:
                patch_store_df.serialize(Path("db/.patch_store_df"), format="binary")
                with pl.Config(tbl_cols=-1, set_tbl_width_chars=300):
                    logger.debug(patch_store_df)

        return subjects

    def router(self, context: SupervisorContext, config: RunnableConfig):

        match context.state_info.node[-2]:
            case self.NODES.assistant:
                if context.action:
                    action = context.action
                    context.action = ''

                    match action:
                        case "reanalyze":
                            return self.NODES.gather_info

            case self.vr_agent.NODES.generate:
                if context.reports:
                    msg = f'[+] Generated {len(context.reports)} reports for {context.cve_details.cve}\n'
                    console.info(msg)
                    context.messages.append(AIMessage(content=msg))
                    for r in context.reports:
                        context.messages.append(AIMessage(content=r.content))
                else:
                    msg = f'[-] Failed to generate report for {context.cve_details.cve}\n'
                    console.info(msg)
                    context.messages.append(AIMessage(content=msg))

                return self.NODES.assistant

            case self.NODES.cve_info:
                msg = f'[+] Found {len(context.reports)} reports of {context.cve_details.cve}'
                console.info(msg)
                context.messages.append(AIMessage(content=msg))
                for r in context.reports:
                    context.messages.append(AIMessage(content=r.content))
                return self.NODES.assistant

            case self.wi_agent.NODES.rank:
                # From windows internals agent
                if not context.candidates.results:
                    raise RuntimeError('There is no valid candidates, '
                                       'need ask windows internals agent for new candidates')

                ranked_df = pl.DataFrame(
                    [{'name': doc.metadata.get('name'),
                      'package': doc.metadata.get('package'),
                      'similarity score': score,
                      'relevancy': rank} for doc, score, rank in context.candidates.results])
                console.info(f'\n{context.cve_details.cve} ranked candidates:\n{ranked_df}')

                subjects = self._patch_candidates(context, ranked_df)

                th = config.get('configurable', {}).get('threshold', Threshold())
                subjects = subjects.filter(pl.col('relevancy') > th.candidates)

                if subjects is None:
                    raise RuntimeError('There is no valid subjects, '
                                       'need ask windows internals agent for new candidates')

                patch_store_df = get_patch_store_df()

                targets = []
                for row in subjects.iter_rows(named=True):
                    patched_subjects = patch_store_df.filter((pl.col("name") == row.get("name")) &
                                                             (pl.col("package") == row.get("package")) &
                                                             (pl.col("arch") == row.get("arch")) &
                                                             pl.col("kb").is_in((context.KB.current,
                                                                                 context.KB.previous,
                                                                                 context.KB.base))
                                                             )
                    selected = [entry for entry in patched_subjects.iter_rows(named=True)]

                    if len(selected) < 2:
                        logger.error(f'No valid subjects found in patch store for {row.get("name")}')
                        continue

                    primary = next(filter(lambda x: x['kb'] == context.KB.current, selected), None)
                    if primary is None:
                        # If we couldn't patch the current, we cannot analyze the changes
                        # therefore, skip it gracefully.
                        continue

                    secondary = (next(filter(lambda x: x['kb'] == context.KB.previous, selected), None) or
                                 next(filter(lambda x: x['kb'] == context.KB.base, selected), None))

                    targets.append(Send(self.NODES.re_agent, ReverseEngineeringContext(
                        state_info=context.state_info,
                        primary_file=PatchStoreEntry().from_dict(primary, overwrite=True),
                        secondary_file=PatchStoreEntry().from_dict(secondary, overwrite=True),
                    )))

                if targets:
                    return targets
                else:
                    pass  # refine windows internals

            case self.re_agent.NODES.decompile:
                # From RE agent
                targets = []
                for artifact in context.artifacts:
                    targets.append(Send(self.NODES.vr_agent, VulnerabilityResearchContext(
                        state_info=context.state_info,
                        artifact=artifact,
                        cve_details=context.cve_details
                    )))

                if targets:
                    return targets

        return END

    def assistant(self, context: SupervisorContext, config: RunnableConfig):
        context.state_info.node.append(self.NODES.assistant)
        console.debug(context.state_info.node)  # TODO: remove

        if (config.get('configurable', {}).get('interrupt', False) and
                context.state_info.node[-2] == self.NODES.assistant):
            while True:
                user_input = input("\nYou: ").strip()
                if not user_input:
                    continue

                if user_input == "exit":
                    break

                match user_input:
                    case "help":
                        console.info(f'[+] Available commands:\n'
                                     f'    exit: exit the program\n'
                                     f'    help: show this help message\n'
                                     f'    reports: show the generated reports\n'
                                     f'    save reports: save reports to files\n'
                                     f'    delete all reports: delete all cached reports\n'
                                     f'    reanalyze: reanalyze the current CVE\n'
                                     f'    o3: Change the assistant model to O3\n'
                                     f'    o4-mini: Change the assistant model to O4 mini\n'
                                     )
                        continue

                    case "reports":
                        for r in context.reports:
                            console.info(f'[+] Report for {r.cve_details.cve}:\n'
                                         f'{r.content}\n'
                                         )

                        continue

                    case "save reports":
                        docs = VectorStore.reports.get(
                            where={'cve': context.cve_details.cve},
                        )
                        if docs:
                            save_to_file(docs, path=Path.cwd())
                            console.info(f'[+] Saved reports to {Path.cwd()}')
                        else:
                            console.info(f'[-] No reports found for {context.cve_details.cve}')
                        continue

                    case "delete all reports":
                        if input("Are you sure? [y/N] ").lower().startswith("y"):
                            docs = VectorStore.reports.get(
                                where={'cve': context.cve_details.cve},
                            )
                            if docs:
                                VectorStore.reports.delete(ids=docs.get('ids'))
                                console.info(f'[+] Deleted all reports for {context.cve_details.cve}')
                            else:
                                console.info(f'[-] No reports found for {context.cve_details.cve}')
                        continue

                    case "reanalyze":
                        return {'action': 'reanalyze'}

                    case "o3":
                        self.llm = LLM.o3
                        continue

                    case "o4-mini":
                        self.llm = LLM.o4_mini
                        continue

                context.messages.append(HumanMessage(content=user_input))

                res = self.llm.invoke(context.messages)
                context.messages.append(res)
                res.pretty_print()

        return {'action': ''}
