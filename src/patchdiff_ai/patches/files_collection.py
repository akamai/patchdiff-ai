"""KB-update DataFrame builders + PE descriptor utilities.

WinSxS used to be read off the host machine here. That code path is gone
— the per-platform archives in `<data_root>/windows_sxs/` (one `.7z` +
`.bin` per Windows release) are the only baseline source now. The
indexing logic (`get_files`) is kept since the `patchdiff-ai index`
command (see `cli/commands/index.py`) reuses it.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Generator, TYPE_CHECKING

import pefile
import polars as pl
import structlog

from patchdiff_ai.persistence.patch_store import resource_lock, safe_serialize

if TYPE_CHECKING:
    from patchdiff_ai.observability.progress import ProgressHandle

log = structlog.get_logger(__name__)


EXECUTABLE_EXTENSIONS = (".exe", ".dll", ".ocx", ".sys", ".com", ".scr", ".cpl")

COMPONENT_RE = re.compile(
    r"^(?P<arch>[^_]+)_"
    r"(?P<package>[^_]+(?:[._-][^_]+)*)_"
    r"(?P<pubkey>[0-9a-f]{16})_"
    r"(?P<version>[\d.]+)_"
    r"(?P<lang>[^_]+)_"
    r"(?P<checksum>[0-9a-f]+)$"
)


def file_hash(path: Path | bytes) -> str:
    h = hashlib.sha256()
    if isinstance(path, Path):
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(4096), b""):
                h.update(chunk)
    elif isinstance(path, (bytes, bytearray)):
        h.update(path)
    else:
        raise TypeError(f"Unsupported type {type(path)}")
    return h.hexdigest()


def version_tuple(ver: str) -> tuple[int, ...]:
    return tuple(int(x) for x in ver.split("."))


def get_files(
    kb: str,
    paths: Generator[Path, None, None] | list[Path],
    collect_hash: bool,
    progress: "ProgressHandle | None" = None,
) -> list[dict]:
    out: list[dict] = []
    for p in paths:
        if progress is not None:
            progress.advance(1)
        if not p.is_file():
            continue
        component = None
        for part in reversed(p.parts[:-1]):
            component = COMPONENT_RE.match(part)
            if component:
                break
        if component is None:
            continue
        gd = component.groupdict()
        gd["version"] = version_tuple(gd["version"])
        delta_type = p.parts[-2]
        try:
            row = {
                "path": str(p.absolute()),
                "name": p.name.lower(),
                "kb": kb,
                "hash": file_hash(p) if collect_hash else None,
                "delta_type": delta_type if delta_type in ("r", "f", "n") else None,
                **gd,
            }
            out.append(row)
        except PermissionError as exc:
            log.debug("permission_error", path=str(p), error=str(exc))
    return out


def generate_df(
    kb: str,
    paths: list[Path] | Path,
    collect_hash: bool,
    progress: "ProgressHandle | None" = None,
) -> pl.DataFrame:
    if isinstance(paths, Path):
        if not paths.is_dir():
            log.error("not_a_directory", path=str(paths))
            return pl.DataFrame()
        paths = paths.rglob("*")
    if progress is not None:
        # Materialize so we can show a real total. rglob is just dir traversal —
        # cheap relative to the per-file parsing inside get_files.
        paths = list(paths)
        progress.set_total(len(paths))
    return pl.DataFrame(
        get_files(kb, paths, collect_hash, progress=progress),
        schema_overrides={"delta_type": pl.Utf8, "hash": pl.Utf8},
    )


async def get_update_dataframe(
    kb: str,
    paths: list[Path] | Path,
    *,
    collect_hash: bool = True,
    cache: Path | None = None,
    progress: "ProgressHandle | None" = None,
) -> pl.DataFrame:
    log.info("indexing_kb", kb=kb)
    if cache is None:
        return generate_df(kb, paths, collect_hash, progress=progress)

    async with resource_lock(cache.resolve()):
        if cache.exists():
            return pl.DataFrame.deserialize(cache)
        df = generate_df(kb, paths, collect_hash, progress=progress)
        safe_serialize(df, cache)
    return df


def get_report(report: Path, arch: str) -> list[Path]:
    return [(report.parent / p) for p in report.read_text().splitlines() if arch in p]


filter_executables = pl.any_horizontal(
    [pl.col("name").str.to_lowercase().str.ends_with(ext) for ext in EXECUTABLE_EXTENSIONS]
)


def file_desc(file: Path) -> str | None:
    try:
        pe = pefile.PE(file, fast_load=True)
        pe.parse_data_directories(
            [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
        )
        for fi in pe.FileInfo:
            for v in fi:
                if v.name == "StringFileInfo":
                    for st in getattr(v, "StringTable", []):
                        desc = st.entries.get(b"FileDescription")
                        if desc is not None:
                            return desc.decode(errors="replace")
        return None
    except (AttributeError, pefile.PEFormatError):
        return None


def _pe_ts_size(file: Path | bytes) -> tuple[int, int]:
    if isinstance(file, Path):
        pe = pefile.PE(name=file, fast_load=True)
    elif isinstance(file, (bytes, bytearray)):
        pe = pefile.PE(data=bytes(file), fast_load=True)
    else:
        raise TypeError(f"{type(file)} is not supported")
    return pe.FILE_HEADER.TimeDateStamp, pe.OPTIONAL_HEADER.SizeOfImage


def get_pe_ms_id(file: Path | bytes) -> str:
    ts, size = _pe_ts_size(file)
    return f"{ts:08X}{size:X}"
