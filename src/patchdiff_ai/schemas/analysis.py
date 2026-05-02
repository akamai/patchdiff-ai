from pydantic import BaseModel, ConfigDict, Field

from patchdiff_ai.schemas.patch_store import PatchStoreEntry


class DecompiledFunctionMetadata(BaseModel):
    file: str = ""
    name: str = ""
    address: str = ""
    parents: str = ""


class DecompiledFunction(BaseModel):
    model_config = ConfigDict(extra="ignore")

    before: str = ""
    after: str = ""
    udiff: str = ""
    metadata: DecompiledFunctionMetadata = Field(default_factory=DecompiledFunctionMetadata)
    score: float | None = None


class FunctionMatchRef(BaseModel):
    """Self-contained Pydantic snapshot of a BinDiff FunctionMatch.

    Replaces holding a raw `bindiff.file.FunctionMatch` in `Artifact.changed`,
    which couldn't survive the pipeline's `Send(...).model_dump()` round-trip
    into the VR subgraph (it was getting flattened to a plain dict and losing
    attribute access). `parents` is pre-resolved in the RE node while the live
    BinDiff object is still in scope.
    """

    name1: str = ""
    name2: str = ""
    address1: int = 0
    address2: int = 0
    similarity: float = 0.0
    confidence: float = 0.0
    parents: list[str] | None = None


class Artifact(BaseModel):
    """Output of the RE pipeline for one binary pair."""

    model_config = ConfigDict(extra="ignore")

    primary_file: PatchStoreEntry = Field(default_factory=PatchStoreEntry)
    secondary_file: PatchStoreEntry = Field(default_factory=PatchStoreEntry)
    changed: list[FunctionMatchRef] = Field(default_factory=list)
