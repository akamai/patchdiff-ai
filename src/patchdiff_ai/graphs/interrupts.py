"""Payloads exchanged across graph `interrupt()` boundaries.

Graph nodes never call `input()`. They yield one of these requests via
`interrupt(request)`. The orchestrator surfaces it to a `CliInteractor`
which prompts the user and resumes via `Command(resume=Response(...))`.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class RefinementKind(str, Enum):
    SEMANTIC = "semantic"
    FILENAME = "filename"


class RefinementOption(BaseModel):
    name: str
    score: float = 0.0
    payload: dict[str, Any] = Field(default_factory=dict)


class RefinementRequest(BaseModel):
    """Asks the CLI to let the user pick additional candidates."""

    cve: str
    prompt: str = "Refine candidate set?"
    available_kinds: list[RefinementKind] = Field(
        default_factory=lambda: [RefinementKind.SEMANTIC, RefinementKind.FILENAME]
    )


class RefinementResponse(BaseModel):
    skip: bool = True
    selected: list[RefinementOption] = Field(default_factory=list)


class RefinementPickCandidate(BaseModel):
    name: str
    score: float = 0.0


class RefinementPickRequest(BaseModel):
    """Asks the CLI to render search results from one refinement query and
    let the user pick which entries to add to the candidate set."""

    cve: str
    candidates: list[RefinementPickCandidate] = Field(default_factory=list)


class RefinementPickResponse(BaseModel):
    indices: list[int] = Field(default_factory=list)


class AssistantCommand(str, Enum):
    HELP = "help"
    REPORTS = "reports"
    SAVE_REPORTS = "save reports"
    DELETE_ALL_REPORTS = "delete all reports"
    REANALYZE = "reanalyze"
    CHANGE_ASSISTANT = "change assistant"
    EXIT = "exit"
