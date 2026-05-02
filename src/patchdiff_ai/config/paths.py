from pathlib import Path

from pydantic import BaseModel, Field


class Paths(BaseModel):
    """Filesystem layout. Defaults match the legacy implicit layout."""

    db_dir: Path = Field(default=Path("db"))
    reports_dir: Path = Field(default=Path("reports"))
    temp_dir: Path = Field(default=Path("_temp"))
    logs_dir: Path = Field(default=Path("logs"))
    patch_store_dir: Path = Field(default=Path("db/patch_store"))
    # Bundled per-platform WinSxS archives + manifest live here. Replaces
    # the old `db/winsxs.bin` snapshot of the host's `C:\Windows\WinSxS`.
    resources_dir: Path = Field(default=Path("resources"))

    @property
    def patch_store_index(self) -> Path:
        return self.db_dir / ".patch_store_df"

    @property
    def eval_cve_cache(self) -> Path:
        return Path("rsrc") / ".eval_cve_df"

    @property
    def windows_sxs_dir(self) -> Path:
        return self.resources_dir / "windows_sxs"

    @property
    def platforms_manifest(self) -> Path:
        return self.windows_sxs_dir / "platforms.json"

    def ensure(self) -> None:
        for p in (self.db_dir, self.reports_dir, self.temp_dir, self.logs_dir, self.patch_store_dir):
            p.mkdir(parents=True, exist_ok=True)
