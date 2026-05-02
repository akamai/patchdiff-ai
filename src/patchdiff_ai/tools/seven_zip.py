"""7-Zip wrapper: list / extract / extract-by-list."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Sequence

from patchdiff_ai.tools.process import ProcessResult, run

SUPPORTED_EXT: tuple[str, ...] = (
    ".7z", ".zip", ".rar", ".tar", ".gz", ".bz2", ".xz",
    ".iso", ".wim", ".cab", ".msu", ".msi", ".esd", ".arj",
    ".cpio", ".deb", ".lzh", ".lzma", ".rpm", ".udf",
    ".vhd", ".vhdx", ".xar", ".z",
)


class SevenZipTool:
    """Async 7-Zip wrapper. All paths come from injected `executable`."""

    def __init__(self, executable: Path, timeout: float = 60 * 30) -> None:
        self.executable = Path(executable)
        self.timeout = timeout

    @staticmethod
    def get_supported_ext() -> tuple[str, ...]:
        return SUPPORTED_EXT

    async def list_files(self, archive: Path) -> tuple[int, list[str], str]:
        """Return (rc, file_list, stderr). Empty list on failure."""
        cmd: list[str] = [str(self.executable), "l", "-slt", "-ba", str(archive)]
        try:
            res: ProcessResult = await run(cmd, timeout=self.timeout, check=False)
        except Exception as exc:
            return -1, [], str(exc)

        files: list[str] = []
        for line in res.stdout.splitlines():
            line = line.strip()
            if line.startswith("Path ="):
                files.append(line[len("Path ="):].strip())
        if res.returncode == 0:
            return 0, files, res.stderr
        return res.returncode, [], res.stderr

    async def extract_all(self, archive: Path, dest: Path, flat: bool = False) -> ProcessResult:
        dest.mkdir(parents=True, exist_ok=True)
        cmd: list[str] = [
            str(self.executable),
            "e" if flat else "x",
            str(archive),
            f"-o{dest}",
            "-y",
        ]
        return await run(cmd, timeout=self.timeout, check=False, capture=True)

    async def extract_by_list(
        self, archive: Path, files: Sequence[str], dest: Path, flat: bool = False
    ) -> ProcessResult:
        dest.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode="w+t", delete=False, encoding="utf-8") as tmp:
            tmp.write("\n".join(files))
            list_path = Path(tmp.name)
        try:
            cmd: list[str] = [
                str(self.executable),
                "e" if flat else "x",
                str(archive),
                f"-i@{list_path}",
                f"-o{dest}",
                "-y",
            ]
            return await run(cmd, timeout=self.timeout, check=False, capture=False)
        finally:
            try:
                list_path.unlink()
            except OSError:
                pass
