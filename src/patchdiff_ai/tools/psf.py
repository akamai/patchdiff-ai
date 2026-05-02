"""PSF archive reader. Async context manager — closes mmap on exit."""

from __future__ import annotations

import asyncio
import errno
import json
import mmap
import struct
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional, TypedDict

import structlog

from patchdiff_ai.runtime.errors import DiskFullError, free_bytes_for
from patchdiff_ai.tools.delta import DeltaApi

log = structlog.get_logger(__name__)


class _Hash(TypedDict, total=False):
    alg: Optional[str]
    value: Optional[str]


class _Delta(TypedDict, total=False):
    offset: Optional[int]
    length: Optional[int]
    hash: _Hash


class _FileEntry(TypedDict, total=False):
    hash: _Hash
    delta: _Delta


class PsfArchive:
    """Async context manager around a PSF (PSTREAM) archive.

    Usage:
        async with PsfArchive(path, delta=delta_api) as psf:
            files = await psf.list_files()
            await psf.extract(files, dest)
    """

    SUPPORTED_EXT = (".psf",)

    def __init__(self, path: Path, *, delta: DeltaApi) -> None:
        self.path = Path(path)
        self._delta = delta
        self._fh = None
        self._mm: mmap.mmap | None = None

    async def __aenter__(self) -> "PsfArchive":
        self._fh = open(self.path, "r+b")
        self._mm = mmap.mmap(self._fh.fileno(), 0, access=mmap.ACCESS_COPY)
        if self._mm[:7] != b"PSTREAM":
            self._mm.close()
            self._fh.close()
            raise AssertionError(f"{self.path}: not a valid PSF file")
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._mm is not None:
            self._mm.close()
        if self._fh is not None:
            self._fh.close()
        self._mm = None
        self._fh = None

    async def list_files(self) -> dict[str, _FileEntry]:
        assert self._mm is not None
        manifest = self._extract_manifest(self._mm)
        return await asyncio.to_thread(self._parse_manifest, manifest)

    async def list_filenames(self) -> list[str]:
        return list((await self.list_files()).keys())

    async def extract(self, names: set[str] | list[str], dest: Path, *, flat: bool = False) -> None:
        assert self._mm is not None
        results = await self.list_files()
        names = set(names)
        dest.mkdir(parents=True, exist_ok=True)
        for path, file in results.items():
            if path not in names:
                continue
            target = dest / (Path(path).name if flat else path)
            try:
                offset = file["delta"]["offset"]
                length = file["delta"]["length"]
                self._mm.seek(offset)
                data = self._mm.read(length)
                target.parent.mkdir(parents=True, exist_ok=True)
                try:
                    target.write_bytes(data)
                except OSError as exc:
                    if exc.errno == errno.ENOSPC:
                        raise DiskFullError(
                            target, free_bytes=free_bytes_for(target)
                        ) from exc
                    raise
            except DiskFullError:
                raise
            except Exception as exc:
                log.warning("psf_extract_failed", path=path, error=str(exc))
        try:
            (dest / "manifest.json").write_text(json.dumps(results))
        except OSError as exc:
            if exc.errno == errno.ENOSPC:
                raise DiskFullError(
                    dest / "manifest.json", free_bytes=free_bytes_for(dest)
                ) from exc
            log.debug("psf_manifest_write_failed", error=str(exc))

    def _extract_manifest(self, mm: mmap.mmap) -> bytes:
        manifest_offset = struct.unpack("<I", mm[40:44])[0]
        manifest_length = struct.unpack("<I", mm[44:48])[0]
        return self._delta.apply(
            None, memoryview(mm[manifest_offset:manifest_offset + manifest_length])
        )

    @staticmethod
    def _parse_manifest(xml_bytes: bytes) -> dict[str, _FileEntry]:
        root = ET.fromstring(xml_bytes)
        if not root.tag.endswith("Container") or root.attrib.get("type") != "PSF":
            raise ValueError("XML is not a PSF Container")
        ns = {"c": "urn:ContainerIndex"}
        files_elem = root.find("c:Files", ns)
        if files_elem is None:
            raise ValueError("No <Files> in PSF manifest")
        out: dict[str, _FileEntry] = {}
        for f in files_elem.findall("c:File", ns):
            hash_e = f.find("c:Hash", ns)
            delta_e = f.find("c:Delta", ns)
            src_e = delta_e.find("c:Source", ns) if delta_e is not None else None
            src_hash = src_e.find("c:Hash", ns) if src_e is not None else None
            out[f.get("name")] = _FileEntry(
                hash=_Hash(
                    alg=hash_e.get("alg") if hash_e is not None else None,
                    value=hash_e.get("value") if hash_e is not None else None,
                ),
                delta=_Delta(
                    offset=int(src_e.get("offset")) if src_e is not None else None,
                    length=int(src_e.get("length")) if src_e is not None else None,
                    hash=_Hash(
                        alg=src_hash.get("alg") if src_hash is not None else None,
                        value=src_hash.get("value") if src_hash is not None else None,
                    ),
                ),
            )
        return out
