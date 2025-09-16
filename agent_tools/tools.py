import uuid
from pathlib import Path
from langchain.prompts import ChatPromptTemplate
from langchain_core.documents import Document

from agent_tools.vector_store import VectorStore
from common import logger, LLM
from patch_analysis.files_collection import file_desc

DESC_PROMPT = ChatPromptTemplate.from_template(
    "Write a maximum of 80 token unformatted paragraph about the Windows executable "
    "{filename} package: {package} description: {description}. Include only technical details about its "
    "purpose in the system. Keep it short, consistent, and strictly one paragraph. "
    "Do not repeat facts. Omit headings, bullets, and conjunctions; the output is "
    "for embedding context."
)


async def generate_file_info_if_needed(base_path: Path, name: str, package: str):
    res = VectorStore.file_info._collection.get(
        where={'$and': [{'name': name}, {'package': package}]},
    )

    if res.get('ids'):
        return

    desc = file_desc(base_path) or '' if base_path.exists() else ''
    chain = DESC_PROMPT | LLM.nano
    result = await chain.ainvoke({"filename": name, 'package': package, "description": desc})
    logger.debug(result.content)

    doc = Document(page_content=result.content,
                   metadata={'name': name.lower(), 'package': package.lower(), 'description': desc.lower()})
    await VectorStore.file_info.aadd_documents(documents=[doc], ids=[str(uuid.uuid4())])

# sample_path = Path(
#     r"E:\Git\snippets\patch_wednesday\patch_store\amd64_microsoft-onecore-s..dlers-speechprivacy_31bf3856ad364e35\settingshandlers_speechprivacy.dll\base\settingshandlers_speechprivacy.dll")
#
# print(file_desc(sample_path))
#
# ts, size = get_pe_ts_size_id(sample_path)
