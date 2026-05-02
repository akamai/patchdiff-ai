import uuid
from pathlib import Path
from typing import Any

import polars as pl
from pydantic import BaseModel, ConfigDict, Field, field_validator


class PatchStoreEntry(BaseModel):
    """A single binary version stored under db/patch_store."""

    model_config = ConfigDict(extra="ignore", arbitrary_types_allowed=True)

    name: str = ""
    path: str = ""
    kb: str = ""
    hash: str = ""
    arch: str = ""
    package: str = ""
    pubkey: str = ""
    version: tuple[int, ...] = ()
    ms_id: str = ""
    # Platform-id (matches `platforms.json` -> id). Patches produced under
    # one Windows release/SKU must not be reused for another — different
    # binaries, different deltas. Filtered on read in routing.py.
    platform: str = ""
    uid: str = Field(default_factory=lambda: str(uuid.uuid4()))

    @field_validator("version", mode="before")
    @classmethod
    def _parse_version(cls, v: Any) -> Any:
        # `to_row` flattens version to a dotted string for Polars storage.
        # Accept both tuple (in-memory) and string (round-tripped via patch_store_df
        # or LangGraph state coercion) so the round-trip stays lossless.
        if isinstance(v, str):
            return tuple(int(x) for x in v.split(".")) if v else ()
        if isinstance(v, list):
            return tuple(v)
        return v

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> "PatchStoreEntry":
        valid = {k: v for k, v in row.items() if k in cls.model_fields and v is not None}
        return cls.model_validate(valid)

    def to_row(self) -> dict[str, Any]:
        d = self.model_dump()
        d["version"] = ".".join(str(x) for x in self.version) if self.version else ""
        return d


class PatchSources(BaseModel):
    """The three KB versions involved in a diff: current / previous / base."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    current: str | Path | pl.DataFrame | None = None
    previous: str | Path | pl.DataFrame | None = None
    base: str | Path | pl.DataFrame | None = None


class OsDetails(BaseModel):
    name: str = ""
    id: int = 0
    arch: str = ""
