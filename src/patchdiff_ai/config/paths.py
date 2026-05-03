"""Filesystem layout.

Every generated artifact is anchored under a single ``data_root`` so the
tool behaves identically across CWDs (the alternative is parallel
ChromaDBs / report stores per shell). ``data_root`` defaults to
``%APPDATA%/patchdiff-ai`` (Windows) or ``~/.local/share/patchdiff-ai``
elsewhere — see [runtime/app_dirs.py](../runtime/app_dirs.py).

Each derived path may be omitted from ``config.json`` (or set to
``null``); the ``model_validator`` below fills it in relative to
``data_root``. This way users only override the paths they care about
(e.g. point ``db_dir`` at a fast SSD) and let everything else follow.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, model_validator

from patchdiff_ai.runtime.app_dirs import app_data_root


class Paths(BaseModel):
    """Filesystem layout, all paths absolute after model construction."""

    data_root: Path = Field(default_factory=app_data_root)

    db_dir: Path = Field(default=Path())
    reports_dir: Path = Field(default=Path())
    temp_dir: Path = Field(default=Path())
    logs_dir: Path = Field(default=Path())
    patch_store_dir: Path = Field(default=Path())
    windows_sxs_dir: Path = Field(default=Path())

    @model_validator(mode="before")
    @classmethod
    def _fill_defaults(cls, data: Any) -> Any:
        # `data` is either a dict (typical JSON / kwargs path) or already
        # a `Paths` instance (revalidation). Only the dict path needs work.
        if not isinstance(data, dict):
            return data

        root_raw = data.get("data_root")
        root = Path(root_raw).expanduser() if root_raw else app_data_root()
        if not root.is_absolute():
            root = root.resolve()
        data["data_root"] = root

        # ``None`` (json null) and missing are treated identically: fall
        # through to the data_root-relative default. Anything explicit
        # the user passed is left alone.
        derived = {
            "db_dir": root / "db",
            "reports_dir": root / "reports",
            "temp_dir": root / "_temp",
            "logs_dir": root / "logs",
            "windows_sxs_dir": root / "windows_sxs",
        }
        for key, default in derived.items():
            if data.get(key) is None:
                data[key] = default

        # `patch_store_dir` derives from `db_dir` (whatever it ended up at)
        # so an override of `db_dir` carries through automatically.
        if data.get("patch_store_dir") is None:
            data["patch_store_dir"] = Path(data["db_dir"]) / "patch_store"

        return data

    @property
    def patch_store_index(self) -> Path:
        return self.db_dir / ".patch_store_df"

    @property
    def platforms_manifest(self) -> Path:
        return self.windows_sxs_dir / "platforms.json"

    def ensure(self) -> None:
        for p in (
            self.data_root,
            self.db_dir,
            self.reports_dir,
            self.temp_dir,
            self.logs_dir,
            self.patch_store_dir,
            self.windows_sxs_dir,
        ):
            p.mkdir(parents=True, exist_ok=True)
