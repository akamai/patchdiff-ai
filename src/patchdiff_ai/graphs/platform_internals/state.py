from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from patchdiff_ai.schemas.candidate import Candidates
from patchdiff_ai.schemas.cve import CveDetails
from patchdiff_ai.schemas.patch_store import PatchSources


class PlatformInternalsState(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    cve_details: CveDetails = Field(default_factory=CveDetails)
    # Mirrors `PipelineState.filtered_dataframes` — Polars DataFrames of the
    # binaries that actually changed between the previous and current KB.
    # User refinement queries are constrained to this set so the user only
    # picks from files relevant to the patch under analysis.
    filtered_dataframes: PatchSources = Field(default_factory=PatchSources)
    query: str = ""
    docs: list[tuple[Any, float]] = Field(default_factory=list)  # (Document, similarity)
    user_docs: list[tuple[Any, float]] = Field(default_factory=list)
    candidates: Candidates = Field(default_factory=Candidates)
