import asyncio
import json

from langchain_core.documents import Document
from langchain_core.messages import SystemMessage, HumanMessage
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langgraph.graph import StateGraph
from pydantic import BaseModel, Field

from agent import Agent
from agent_tools.vector_store import VectorStore
from common import AgentModels, StateInfo, CveDetails, Candidates, LLM, logger, console
from defaultdataclass import defaultdataclass
from langgraph.constants import END


@defaultdataclass
class WindowsInternalsContext:
    state_info: StateInfo
    cve_details: CveDetails
    query: str
    docs: list[tuple[Document, float]]


@defaultdataclass
class WindowsInternalsOutput:
    candidates: Candidates


@defaultdataclass
class PromptTemplate:
    collect: ChatPromptTemplate
    rank: ChatPromptTemplate


class FileScore(BaseModel):
    file: str = Field(..., description="Filename including extension")
    score: float = Field(..., description="Relevance score from 0.0 to 10.0, higher is more relevant")
    # reason: str = Field(..., description="One sentence about the reason for this score")


class FileScoreList(BaseModel):
    files: list[FileScore]


class Query(BaseModel):
    query: str = Field(..., description="Query to use for similarity search in the vectorstore")


class WindowsInternals(Agent):
    '''
    This agent has access to Windows executable files information
    through the file info vectorstore.
    It can find executables that could be related to a description
    of flow, vulnerability, and other scenarios.
    '''

    prompt_template: PromptTemplate = PromptTemplate(
        collect=ChatPromptTemplate([
            SystemMessage(
                # ---- WHAT TO DO -------------------------------------------------
                "You receive a JSON object that pinpoints WHERE the bug was fixed "
                "(driver / service / DLL / EXE name appears in the title or description).\n"
                "Write ONE paragraph, <= 80 tokens, plain ASCII.\n"
                "That paragraph must sound like a terse engineer-authored note for the "
                "*ordinary* behaviour of the exact file that got patched.\n"
                # ---- HOW TO DO IT ----------------------------------------------
                "Mandatory content:\n"
                "1) The executable’s primary job (e.g. ‘copies log sectors into caller buffer’).\n"
                "2) Key internal logic tied to that job (loops, size checks, pointer math, "
                "   registry access, IRP handling, etc.).\n"
                "3) Main OS components or APIs it talks to (Mm, Io, ALPC, SrvNet…).\n"
                "4) Its purpose to the wider system (transaction logging, credential caching, …).\n"
                # ---- HARD BANS ---------------------------------------------------
                "Never say: CVE, CVSS, CWE, ‘bug’, ‘vulnerability’, patch status, risk, exploit.\n"
                "No headings, lists, or newlines. No code blocks. No fluffy adjectives.\n"
                # ---- STYLE -------------------------------------------------------
                "Use present tense. Technical verbs only. Keep it punchy and factual."
            ),
            MessagesPlaceholder("json_metadata")
        ]),
        rank=ChatPromptTemplate.from_template(
            """
                You are an expert in Windows OS and at evaluating document relevance.
    
                ORIGINAL QUERY: {query}
                ORIGINAL JSON: {metadata}
    
                Below are documents retrieved from a vector store. Your task is to rerank them based on their relevance 
                to the original query and JSON data, assigning a score from 0.00 (completely irrelevant) to 10.00 (perfectly relevant).
    
                DOCUMENTS:
                {files}
    
                Analyze each document carefully and determine how well it addresses the information needs implied by the query and JSON.
                """
        ))

    @defaultdataclass(frozen=True)
    class NODES:
        collect = "Collect relevant files"
        rank = 'Rank relevancy'

    def __init__(self):
        super().__init__(llm=AgentModels.platform_internals_model.model)
        self.limit = 3

    def _build(self):
        if self._graph:
            return

        builder = StateGraph(WindowsInternalsContext)

        builder.add_node(self.NODES.collect, self.collect)
        builder.add_node(self.NODES.rank, self.rank)

        builder.set_entry_point(self.NODES.collect)
        builder.add_edge(self.NODES.collect, self.NODES.rank)

        builder.add_conditional_edges(self.NODES.rank, self.refinement,
                                      [
                                          self.NODES.rank,
                                          END
                                      ])

        builder.set_finish_point(self.NODES.rank)

        self._graph = builder.compile()

    def refinement(self, context: WindowsInternalsOutput):

        if 'ok':
            return END

        if 'not ok':
            if self.limit:
                self.limit -= 1
                return self.NODES.rank

        return END

    async def collect(self, context: WindowsInternalsContext):
        context.state_info.node.append(self.NODES.collect)
        console.info(f'[*] Searching for potential candidates')
        query_chain = self.prompt_template.collect | self.get_llm().with_structured_output(Query)
        metadata = json.dumps({k: v for k, v in context.cve_details.msrc_report.to_dict().items() if k != 'products'})

        result: Query = await query_chain.ainvoke(
            {'json_metadata': [HumanMessage(metadata)]})

        docs = await VectorStore.file_info.asimilarity_search_with_score(result.query, k=10)  # TODO: add config
        logger.info(f'Found {len(docs)} docs for query "{result.query}"')

        if len(docs):
            console.info(f'[+] Found {len(docs)} potential candidates for {context.cve_details.cve} (limit: 10)')
        else:
            console.info(f'[-] Failed to find candidates for {context.cve_details}')

        return {'docs': docs, 'query': result.query}

    async def rank(self, context: WindowsInternalsContext):
        context.state_info.node.append(self.NODES.rank)

        chain = self.prompt_template.rank | AgentModels.default_model.model.with_structured_output(FileScoreList)

        files = '\n\n'.join(f"name: {doc.metadata.get('name', '')}\n{doc.page_content}" for doc, _ in context.docs)
        metadata = json.dumps({k: v for k, v in context.cve_details.msrc_report.to_dict().items() if k != 'products'})

        console.info(f'[*] Ranking {context.cve_details.cve} candidates')

        result: FileScoreList = await chain.ainvoke({
            'query': context.query,
            'metadata': metadata,
            'files': files
        })

        score_map: dict[str, float] = {fs.file: fs.score for fs in result.files}
        ranked_docs = [(doc, score, score_map.get(doc.metadata.get("name"), 0.0)) for doc, score in context.docs]

        return {'candidates': Candidates(query=context.query,
                                         results=sorted(ranked_docs, key=lambda t: t[2],
                                                        reverse=True))}

