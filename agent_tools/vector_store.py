import os

os.environ["ANONYMIZED_TELEMETRY"] = "FALSE"  
os.environ["CHROMA_TELEMETRY_ENABLED"] = "FALSE"

from langchain_chroma import Chroma
from common import LLM


class VectorStore:
    file_info = Chroma(
        persist_directory='./db',
        collection_name="windows.exe.desc",
        embedding_function=LLM.embedding,
        collection_metadata={"hnsw:space": "cosine"},
        create_collection_if_not_exists=True,
    )

    func_logic = Chroma(
        persist_directory='./db',
        collection_name="windows.exe.functions.logic",
        embedding_function=LLM.embedding,
        collection_metadata={"hnsw:space": "cosine"},
        create_collection_if_not_exists=True,
    )

    reports = Chroma(
        persist_directory='./db',
        collection_name="windows.exe.rca.reports",
        embedding_function=LLM.embedding,
        collection_metadata={"hnsw:space": "cosine"},
        create_collection_if_not_exists=True,
    )
