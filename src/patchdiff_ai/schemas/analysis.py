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
    """Self-contained Pydantic snapshot of one matched code unit.

    Originally a snapshot of `bindiff.file.FunctionMatch` for the binary
    flow (PE function pair, hex addresses, BinDiff similarity score).
    Generalised in M3 so source-code RE backends can produce instances
    of the same type — they leave the binary-only fields at their
    defaults and set `identifier` + `extension` instead.

    The pipeline downstream of RE (VR `indexing` / `_persist_func_logic`)
    looks up disk artefacts via `primary_key` / `secondary_key` (which
    fall back to the hex address when `identifier` is empty), so the
    binary path stays byte-identical to pre-M3.
    """

    name1: str = ""
    name2: str = ""
    # Binary-only: hex address of the matched function in primary /
    # secondary IDB. Both default to 0 (so existing call sites that set
    # them as ints stay unchanged); the source flow leaves these at 0
    # and sets `identifier` instead.
    address1: int = 0
    address2: int = 0
    # BinDiff scoring — meaningful only for binary flow. Source flow
    # leaves them at 0.0; VR's score-aware code paths treat 0.0 as
    # "no signal" the same way they always did.
    similarity: float = 0.0
    confidence: float = 0.0
    parents: list[str] | None = None
    # M3 additions — used by the source flow:
    #   identifier — stable disk key for both __funcs__/<key>.<ext>
    #     files (binary leaves this empty so the hex address falls back).
    #   extension — file suffix VR appends when reading the diff inputs
    #     ("c" for binary decompile output, "txt" for source diffs, ...).
    identifier: str = ""
    extension: str = "c"

    def primary_key(self) -> str:
        """Disk key for `<artifact.primary_dir>/__funcs__/<key>.<ext>`."""
        return self.identifier or f"{self.address1:X}"

    def secondary_key(self) -> str:
        """Disk key for `<artifact.secondary_dir>/__funcs__/<key>.<ext>`."""
        return self.identifier or f"{self.address2:X}"


class Artifact(BaseModel):
    """Output of the RE pipeline for one binary pair."""

    model_config = ConfigDict(extra="ignore")

    primary_file: PatchStoreEntry = Field(default_factory=PatchStoreEntry)
    secondary_file: PatchStoreEntry = Field(default_factory=PatchStoreEntry)
    changed: list[FunctionMatchRef] = Field(default_factory=list)
