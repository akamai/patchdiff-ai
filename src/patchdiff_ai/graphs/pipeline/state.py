"""Pipeline state. Explicit Stage; no multi-inheritance from sub-agents."""

from __future__ import annotations

from typing import Annotated

from langchain_core.messages import BaseMessage
from pydantic import BaseModel, ConfigDict, Field

from patchdiff_ai.graphs.pipeline.routing import Stage
from patchdiff_ai.schemas.analysis import Artifact
from patchdiff_ai.schemas.candidate import Candidates
from patchdiff_ai.schemas.cve import CveDetails
from patchdiff_ai.schemas.patch_store import OsDetails, PatchSources
from patchdiff_ai.schemas.reducers import add_messages, append_list, replace
from patchdiff_ai.schemas.report import Report


class PipelineState(BaseModel):
    """Top-level state. Each sub-agent reads/writes the slice it cares about.

    Most "shared identity" fields (cve_details, os, KB, …) carry the
    `replace` reducer because the pipeline fans RE/VR sub-graphs out via
    `Send`. Each completing branch writes its sub-state back to the parent
    in a single super-step; without a reducer, the default last_value
    channel raises `InvalidUpdateError: Can receive only one value per
    step`. The values being merged are identical (every branch carries the
    same CVE/OS/KB context), so last-write-wins is functionally a no-op.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    stage: Annotated[Stage, replace] = Stage.START
    cve_details: Annotated[CveDetails, replace] = Field(default_factory=CveDetails)
    os: Annotated[OsDetails, replace] = Field(default_factory=OsDetails)
    KB: Annotated[PatchSources, replace] = Field(default_factory=PatchSources)

    # Set by gather_info subgraph
    extracted: Annotated[PatchSources, replace] = Field(default_factory=PatchSources)
    dataframes: Annotated[PatchSources, replace] = Field(default_factory=PatchSources)
    filtered_dataframes: Annotated[PatchSources, replace] = Field(default_factory=PatchSources)

    # Platform-internals output
    candidates: Annotated[Candidates, replace] = Field(default_factory=Candidates)

    # RE / VR output
    artifacts: Annotated[list[Artifact], append_list] = Field(default_factory=list)
    reports: Annotated[list[Report], append_list] = Field(default_factory=list)

    # Chat / event log
    messages: Annotated[list[BaseMessage], add_messages] = Field(default_factory=list)

    parse_errors: Annotated[list[str], append_list] = Field(default_factory=list)
