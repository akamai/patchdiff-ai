from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from patchdiff_ai.schemas.analysis import Artifact
from patchdiff_ai.schemas.patch_store import PatchStoreEntry
from patchdiff_ai.schemas.reducers import append_list


class ReverseEngineeringState(BaseModel):
    """RE sub-graph state. Reads two binaries, produces an Artifact.

    The live `BinDiff` object used to live here as `diff: Any` between the
    diff and decompile nodes — but BinDiff wraps a `sqlite3.Connection` that
    pickle refuses to serialise, so any inter-node checkpoint write crashed
    the pipeline (when interactive=True). The diff and decompile steps are
    now one node, BinDiff stays in local scope, and only pickle-safe
    artifacts cross the boundary.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    primary_file: PatchStoreEntry = Field(default_factory=PatchStoreEntry)
    secondary_file: PatchStoreEntry = Field(default_factory=PatchStoreEntry)
    artifacts: Annotated[list[Artifact], append_list] = Field(default_factory=list)
