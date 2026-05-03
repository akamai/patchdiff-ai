from typing import Annotated, Any

import polars as pl
from pydantic import BaseModel, ConfigDict, Field

from patchdiff_ai.schemas.cve import CveDetails
from patchdiff_ai.schemas.patch_store import OsDetails, PatchSources
from patchdiff_ai.schemas.reducers import append_list


class GatherInfoState(BaseModel):
    """Input/output state of the gather_info subgraph."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    cve_details: CveDetails = Field(default_factory=CveDetails)
    os: OsDetails = Field(default_factory=OsDetails)
    KB: PatchSources = Field(default_factory=PatchSources)
    extracted: PatchSources = Field(default_factory=PatchSources)
    dataframes: PatchSources = Field(default_factory=PatchSources)
    filtered_dataframes: PatchSources = Field(default_factory=PatchSources)
    updates: Annotated[list[Any], append_list] = Field(default_factory=list)
