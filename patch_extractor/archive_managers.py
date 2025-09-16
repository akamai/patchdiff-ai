# archive_manager.py
import asyncio
import json
import mmap
import os
import struct
import tempfile
from pathlib import Path
from typing import Type
import xml.etree.ElementTree as ET
from typing import Optional, TypedDict

from common import logger
from patch_extractor.patch_tools import PatchTools


class HashDict(TypedDict, total=False):
    alg: Optional[str]
    value: Optional[str]


class DeltaDict(TypedDict, total=False):
    offset: Optional[int]
    length: Optional[int]
    hash: HashDict


class FileResult(TypedDict, total=False):
    hash: HashDict
    delta: DeltaDict


_7ZIP_PATH = 'C:/Program Files/7-Zip/7z.exe'


class ArchiveManager:
    @staticmethod
    async def run_process(cmd, capture=True):
        if capture:
            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            return process.returncode, stdout.decode('utf-8', errors='replace'), stderr.decode('utf-8',
                                                                                               errors='replace')
        else:
            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE
            )
            _, stderr = await process.communicate()
            return process.returncode, None, stderr.decode('utf-8', errors='replace')

    @staticmethod
    async def stream_process(cmd):
        process = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )

        while True:
            line = await process.stdout.readline()
            if not line:
                break
            yield line.decode('utf-8', errors='replace')

        stderr = await process.stderr.read()
        stderr_str = stderr.decode('utf-8', errors='replace')
        return_code = await process.wait()

        yield return_code, stderr_str

    async def extract_file(self, archive: Path, dest, flat=False):
        raise NotImplementedError()

    async def list_files(self, archive: Path):
        raise NotImplementedError()

    async def extract_all(self, archive: Path, dest, flat=False):
        raise NotImplementedError()

    async def extract_by_list(self, archive: Path, files, dest, flat=False):
        raise NotImplementedError()

    @staticmethod
    def get_supported_ext() -> list[str]:
        raise NotImplementedError()


class PSF(ArchiveManager):
    @staticmethod
    def get_supported_ext():
        return ['.psf']

    @staticmethod
    def _parse_psf_xml(xml_data):
        root = ET.fromstring(xml_data)

        if not root.tag.endswith('Container') or root.attrib.get('type') != 'PSF':
            raise ValueError("XML does not represent a PSF Container")

        ns = {'c': 'urn:ContainerIndex'}
        files_elem = root.find('c:Files', ns)
        if files_elem is None:
            raise ValueError("No <Files> section found in the XML")

        result: dict[str, FileResult] = {}
        for file in files_elem.findall('c:File', ns):
            hash_elem = file.find('c:Hash', ns)
            delta_elem = file.find('c:Delta', ns)
            source_elem = delta_elem.find('c:Source', ns)
            source_hash = source_elem.find('c:Hash', ns) if source_elem is not None else None

            # Build dictionary structure
            result[file.get('name')] = FileResult(
                hash=HashDict(alg=hash_elem.get('alg') if hash_elem is not None else None,
                              value=hash_elem.get(
                                  'value') if hash_elem is not None else None),
                delta=DeltaDict(offset=int(source_elem.get(
                    'offset')) if source_elem is not None else None,
                                length=int(source_elem.get(
                                    'length')) if source_elem is not None else None,
                                hash=HashDict(alg=source_hash.get(
                                    'alg') if source_hash is not None else None,
                                              value=source_hash.get(
                                                  'value') if source_hash is not None else None)))

        return result

    @staticmethod
    def _get_manifest(psf: mmap.mmap):
        manifest_offset = struct.unpack("<I", psf[40:44])[0]
        manifest_length = struct.unpack("<I", psf[44:48])[0]
        pt = PatchTools()
        manifest = pt.apply(None, memoryview(psf[manifest_offset: manifest_offset + manifest_length]))
        return manifest

    async def _list_files(self, psf) -> dict[str, FileResult]:
        if psf[:7] != b'PSTREAM':
            raise AssertionError('Not a valid PSF file')
        manifest = self._get_manifest(psf)
        return await asyncio.to_thread(self._parse_psf_xml, manifest)

    async def list_files(self, archive: Path):
        dd = archive.parent.parent / 'DesktopDeployment.cab' / 'UpdateCompression.dll'
        if dd.exists():
            PatchTools(dd)

        mm = PatchTools.map_file(archive)
        results = await self._list_files(mm)
        return 0, [file for file in results], None

    async def extract_by_list(self, archive: Path, files, dest: Path, flat=False):
        mm = PatchTools.map_file(archive)
        results: dict[str, FileResult] = await self._list_files(mm)
        dest.mkdir(parents=True, exist_ok=True)
        for path, file in results.items():
            if path in files:
                try:
                    mm.seek(file['delta']['offset'])
                    data = mm.read(file['delta']['length'])
                    try:
                        file_path = dest / (Path(path).name if flat else path)
                        file_path.parent.mkdir(parents=True, exist_ok=True)
                        file_path.write_bytes(data)
                    except Exception as e:
                        print(f"Error writing to destination file: {e}")
                except Exception as e:
                    print(f"Error reading the memory region: {e}")
                    return

        try:
            (dest / 'manifest.json').write_text(json.dumps(results))
        except IOError:
            logger.error('Cannot write psf manifest')
            pass


class SevenZip(ArchiveManager):
    @staticmethod
    def get_supported_ext():
        return ['.7z', '.zip', '.rar', '.tar', '.gz', '.bz2', '.xz',
                '.iso', '.wim', '.cab', '.msu', '.msi', '.esd', '.arj',
                '.cpio', '.deb', '.lzh', '.lzma', '.rpm', '.udf',
                '.vhd', '.vhdx', '.xar', '.z']

    def __init__(self, executable_path=_7ZIP_PATH):
        self.executable = executable_path

    async def extract_file(self, archive: Path, dest, flat=False):
        cmd = [self.executable, "x", archive, "-y"]
        if dest:
            cmd.append(f"-o{dest}")
            os.makedirs(dest, exist_ok=True)
        return await self.run_process(cmd)

    async def list_files(self, archive: Path):
        cmd = [self.executable, "l", "-slt", "-ba", archive]

        files = []
        return_code = -1
        stderr = ""

        async for line_or_result in self.stream_process(cmd):
            # Check if this is the final yield containing return code and stderr
            if isinstance(line_or_result, tuple):
                return_code, stderr = line_or_result
                break

            line = line_or_result.strip()
            if not line or not line.startswith('Path ='):
                continue

            files.append(line[7:].strip())

        if return_code == 0:
            return return_code, files, stderr

        return return_code, [], stderr

    async def extract_by_list(self, archive: Path, files, dest, flat=False):
        list_file = None
        with tempfile.NamedTemporaryFile(mode='w+t', delete=False) as tmp:
            tmp.write('\n'.join(files))
            tmp.flush()
            list_file = tmp.name

        if list_file:
            try:
                cmd = [
                    self.executable,
                    'e' if flat else 'x',
                    archive,
                    f"-i@{list_file}",
                    f"-o{dest}",
                    "-y"
                ]

                return await self.run_process(cmd, False)
            finally:
                os.remove(list_file)


class Selector:
    managers: list[ArchiveManager] = []

    def add_manager(self, manager: Type[ArchiveManager]):
        self.managers.append(manager())

    def get_manager(self, ext: str) -> ArchiveManager | None:
        for m in self.managers:
            if ext in m.get_supported_ext():
                return m

        return None

    def get_supported(self):
        supported = []
        for m in self.managers:
            supported.extend(m.get_supported_ext())

        return supported
