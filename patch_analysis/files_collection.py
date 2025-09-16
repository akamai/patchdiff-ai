import hashlib
import re
import uuid
from pathlib import Path
from typing import Generator

import pefile

from common import get_winsxs, logger, EXECUTABLE_EXTENSIONS, resource_lock, console
import polars as pl
from dataclasses import dataclass, field


@dataclass
class UpdatesInfo:
    os_name: str = None
    os_id: str = None
    prev_kb: str = None
    curr_kb: str = None
    prev_extracted: Path = None
    curr_extracted: Path = None
    prev_df: pl.dataframe.DataFrame = None
    curr_df: pl.dataframe.DataFrame = None
    relevant_df: pl.dataframe.DataFrame = None
    relevant_r_patch_df: pl.dataframe.DataFrame = None


@dataclass
class Metadata:
    path: str
    name: str
    hash: str
    kb: str
    delta_type: str
    arch: str
    package: str
    pubkey: str
    version: tuple[int, ...]
    lang: str
    checksum: str


component_pattern = re.compile(
    r"^(?P<arch>[^_]+)_"  # Architecture
    r"(?P<package>[^_]+(?:[._-][^_]+)*)_"  # Package name with potential dots/hyphens
    r"(?P<pubkey>[0-9a-f]{16})_"  # Public key (16 hex chars)
    r"(?P<version>[\d.]+)_"  # Version numbers
    r"(?P<lang>[^_]+)_"  # Language tag
    r"(?P<checksum>[0-9a-f]+)$"  # Component hash
)


def get_file_hash(file: Path | bytes) -> str:
    """Calculate SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    if isinstance(file, Path):
        with open(file, "rb") as f:
            # Read and update hash in chunks to handle large files efficiently
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
    elif isinstance(file, bytes):
        sha256_hash.update(file)
    else:
        raise TypeError('The provided file is not supported')

    return sha256_hash.hexdigest()


def version_tuple(ver: str) -> tuple[int, ...]:
    return tuple(int(part) for part in ver.split('.'))


def get_files(kb: str, paths: list[Path] | Generator, collect_hash) -> list[Metadata]:
    data: list[Metadata] = []
    for p in paths:
        if p.is_file():
            component = None
            for part in reversed(p.parts[:-1]):
                component = component_pattern.match(part)
                if component:
                    break

            if component is None:
                continue

            delta_type = p.parts[-2]
            gd = component.groupdict()
            gd["version"] = version_tuple(gd["version"])

            try:
                data.append(Metadata(
                    path=str(p.absolute()),
                    name=p.name.lower(),
                    kb=kb,
                    hash=get_file_hash(p) if collect_hash else None,
                    delta_type=delta_type if delta_type in ['r', 'f', 'n'] else None,
                    **gd
                ))
            except PermissionError as e:
                print(e)

    return data


def generate_df(kb: str, paths: list[Path] | Path, collect_hash) -> pl.DataFrame:
    if isinstance(paths, Path):
        if not paths.is_dir():
            logger.error('The path provided is not a directory')
            return
        else:
            paths = paths.rglob("*")

    files = get_files(kb, paths, collect_hash)
    df = pl.DataFrame(files)
    return df


# TODO: Remove and make it better
def get_update_dataframe(kb: str, paths: list[Path] | Path, collect_hash=True, cache: Path | None = None):
    console.info(f'[*] Indexing {kb} delta files')
    if cache:
        with resource_lock(cache.resolve()):
            if cache and cache.exists():
                return pl.DataFrame.deserialize(cache)

            df = generate_df(kb, paths, collect_hash)
            if cache:
                df.serialize(cache, format="binary")
    else:
        df = generate_df(kb, paths, collect_hash)

    return df


def get_winsxs_df(base: str):
    # TODO: support more OS versions using installation ISOs
    return get_update_dataframe('winsxs', get_winsxs(), collect_hash=False,
                                cache=Path('db/winsxs.bin'))


def get_report(report, arch):
    return [(report.parent / p) for p in report.read_text().splitlines() if arch in p]


filter_executables = pl.any_horizontal(
    [pl.col("name")
     .str.to_lowercase()
     .str.ends_with(ext)
     for ext in EXECUTABLE_EXTENSIONS]
)


def correlate_updates(info: UpdatesInfo):
    winsxs_df = get_winsxs_df(info.os_name)

    prev_report = get_report(info.prev_extracted / 'report.txt')
    curr_report = get_report(info.curr_extracted / 'report.txt')

    prev_df = get_update_dataframe(info.prev_kb, prev_report)
    curr_df = get_update_dataframe(info.curr_kb, curr_report)

    winsxs_df = winsxs_df.filter(filter_executables)
    r_patch = winsxs_df.filter(pl.col("arch").eq("amd64") & pl.col("delta_type").eq("r"))

    # All the files in the current KB that was changed from the last KB
    # and have a reverse patch in the WinSxS folder
    relevant_df = (
        curr_df.filter(
            pl.col("arch").eq("amd64")  # filter the x64 only and unmodified files
            & ~pl.col("hash").is_in(prev_df["hash"])
        ).join(r_patch.select("package", "pubkey", "arch").unique(),  # Correlate with the winsxs folder
               on=["package", "pubkey", "arch"],
               how="semi",
               )
    )

    relevant_r_patch_df = r_patch.join(
        relevant_df.select(["package", "pubkey", "arch"]).unique(),
        on=["package", "pubkey", "arch"],
        how="semi",
    )

    # Filter files names as well
    relevant_df = relevant_df.filter(
        pl.col('name').str.to_lowercase().is_in(
            relevant_r_patch_df.get_column('name').str.to_lowercase()))

    return prev_df, curr_df, relevant_df, relevant_r_patch_df


def file_desc(file: Path) -> str | None:
    try:
        pe = pefile.PE(file, fast_load=True)
        pe.parse_data_directories(
            [pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']]
        )

        for fi in pe.FileInfo:
            for v in fi:
                if v.name == 'StringFileInfo':
                    for st in getattr(v, 'StringTable', []):
                        return st.entries.get(b'FileDescription').decode(errors='replace')

        return None
    except (AttributeError, pefile.PEFormatError):
        return None


def get_pe_ts_size_id(file: Path | bytes):
    if isinstance(file, Path):
        pe = pefile.PE(name=file, fast_load=True)
    elif isinstance(file, bytes):
        pe = pefile.PE(data=file, fast_load=True)
    else:
        raise TypeError(f'{type(file)} is not supported')

    ts_raw = pe.FILE_HEADER.TimeDateStamp
    img_size = pe.OPTIONAL_HEADER.SizeOfImage

    return ts_raw, img_size


def get_pe_ms_id(file: Path | bytes):
    ts_raw, img_size = get_pe_ts_size_id(file)
    ms_id = f'{ts_raw:08X}{img_size:X}'
    return ms_id

    # logger.debug(f'File id is {ms_id}\n'
    #              f'https://msdl.microsoft.com/download/symbols/{file.name}/{ms_id}/{file.name}')


def main():
    pass


if __name__ == '__main__':
    main()
