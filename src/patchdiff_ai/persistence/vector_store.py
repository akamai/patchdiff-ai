"""ChromaDB collections, scoped to an AppContext (no module globals)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

# Disable Chroma telemetry before chromadb is imported.
os.environ.setdefault("ANONYMIZED_TELEMETRY", "FALSE")
os.environ.setdefault("CHROMA_TELEMETRY_ENABLED", "FALSE")

from chromadb.config import Settings as ChromaSettings  # noqa: E402
from langchain_chroma import Chroma  # noqa: E402


@dataclass
class VectorStores:
    """Triplet of Chroma collections used across the agents."""

    file_info: Chroma
    func_logic: Chroma
    reports: Chroma

    @classmethod
    def open(cls, db_dir: Path, embedding_model) -> "VectorStores":
        db_dir.mkdir(parents=True, exist_ok=True)
        settings = ChromaSettings(anonymized_telemetry=False)
        common = dict(
            persist_directory=str(db_dir),
            embedding_function=embedding_model,
            collection_metadata={"hnsw:space": "cosine"},
            create_collection_if_not_exists=True,
            client_settings=settings,
        )
        return cls(
            file_info=Chroma(collection_name="windows.exe.desc", **common),
            func_logic=Chroma(collection_name="windows.exe.functions.logic", **common),
            reports=Chroma(collection_name="windows.exe.rca.reports", **common),
        )
