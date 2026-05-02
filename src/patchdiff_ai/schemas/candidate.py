from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Candidate(BaseModel):
    """A retrieved file-info document with its similarity score."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: str = ""
    package: str = ""
    page_content: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    similarity: float = 0.0


class RankedCandidate(Candidate):
    """A candidate with an LLM-assigned relevancy score (0.0 - 10.0)."""

    relevancy: float = 0.0


class Candidates(BaseModel):
    query: str = ""
    results: list[RankedCandidate] = Field(default_factory=list)
