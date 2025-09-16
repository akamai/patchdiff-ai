# main.py
import asyncio
import shutil
import time
from enum import Enum
from pathlib import Path

from patch_extractor.manifest_extractor import ManifestExtractor
from common import logger, get_latest_servicingstack_folder, EXECUTABLE_EXTENSIONS, console
from patch_extractor.archive_managers import Selector, SevenZip, ArchiveManager, PSF


class ARCH(Enum):
    all = 1
    x64 = 2
    x86 = 3
    msil = 4
    wow64 = 5


class KBExtractor:
    def __init__(self, selector: Selector, n_workers=5):
        self.dest: Path = Path()
        self.stop_flag = False
        self.selector = selector
        self.archives = asyncio.Queue()
        self.supported_ext = selector.get_supported()

        self.workers = []
        for i in range(n_workers):
            self.workers.append(asyncio.create_task(self._extraction_worker()))

        self.extracted: list[Path] = []
        self.keep_manifests = False

    def extract(self, kb_path, dest, manifests: bool):
        self.keep_manifests = manifests

        if dest:
            self.dest = Path(dest)
        else:
            kb = Path(kb_path)
            self.dest = kb.parent.absolute() / f'extracted_{kb.name}'

        self.archives.put_nowait(kb_path)

    async def _extraction_worker(self):
        while True:
            try:
                archive = await self.archives.get()
            except asyncio.CancelledError:
                logger.debug('worker exits')
                return
            except Exception as e:
                raise e

            try:
                await self._extract(archive)
            finally:
                self.archives.task_done()

    async def _extract_files(self, manager: ArchiveManager, archive: Path, files: list[str], sub_dir, flat=False):
        return await manager.extract_by_list(archive, files, Path(self.dest) / sub_dir, flat)

    async def _extract_nested_archives(self, manager, archive, files):
        nested = [x for x in files if Path(x).suffix.lower() in self.supported_ext]
        if nested:
            # logger.info(nested)
            dest = Path('archives') / archive.name
            await self._extract_files(manager, archive, nested, dest, True)

            for nested_file in nested:
                nested_path = Path(self.dest) / dest / Path(nested_file).name
                if nested_path.exists():
                    self.extracted.append(dest / Path(nested_file).name)
                    self.archives.put_nowait(nested_path)

    async def _extract_executables(self, manager, archive, files):
        executables = [x for x in files if Path(x).suffix.lower() in EXECUTABLE_EXTENSIONS]
        if executables:
            await self._extract_files(manager, archive, executables, archive.name)
            for e in executables:
                self.extracted.append(Path(archive.name) / e)

    async def _extract_manifests(self, manager, archive, files):
        manifests = [x for x in files if Path(x).suffix.lower() in ['.manifest']]
        if manifests:
            # logger.info(executables)
            await self._extract_files(manager, archive, manifests, 'manifests', True)
            extractor = ManifestExtractor(get_latest_servicingstack_folder() / 'wcp.dll')
            for m in manifests:
                try:
                    m_path = Path('manifests') / Path(m).name
                    self.extracted.append(m_path)
                    extractor.extract(self.dest / m_path)
                except (IOError, RuntimeError):
                    logger.debug(f'Failed to extract the manifest {m}')

    async def _extract(self, path):
        archive = Path(path)
        manager = self.selector.get_manager(archive.suffix.lower())
        if not manager:
            logger.error(f'Archive {archive.suffix.lower()} is not supported')
            return

        logger.info(f'Extract {archive}')
        _, files, stderr = await manager.list_files(archive)
        if not files:
            logger.error(f'Failed to extract {archive} with error: {" ".join(stderr.split())}')
            return

        tasks = [self._extract_nested_archives(manager, archive, files),
                 self._extract_executables(manager, archive, files)]

        if self.keep_manifests:
            tasks.append(self._extract_manifests(manager, archive, files))

        await asyncio.gather(*tasks)

    async def join(self):
        await self.archives.join()
        for worker in self.workers:
            worker.cancel()
        await asyncio.gather(*self.workers)


async def aextract(kb_path: Path, dest: Path | None, manifests: bool):
    kb = Path(kb_path)
    dest = dest or kb.parent.absolute() / f'extracted_{kb.name}'
    if dest.exists() and (dest / 'report.txt').exists():
        console.info(f'[+] {kb.name} extracted folder was found, skip extraction')
        return

    start_time = time.time()
    selector = Selector()
    selector.add_manager(SevenZip)
    selector.add_manager(PSF)
    extractor = KBExtractor(selector)
    extractor.extract(kb_path, dest, manifests)
    await extractor.join()

    elapsed_time = time.time() - start_time
    console.info(f"[*] Extraction finished within {elapsed_time:.2f} seconds")

    archives = extractor.dest / 'archives'
    shutil.rmtree(archives)

    report = (extractor.dest / 'report.txt').absolute()
    with open(report, 'w') as f:
        for e in extractor.extracted:
            if e.suffix.lower() in EXECUTABLE_EXTENSIONS:
                f.write(str(e) + '\n')

    # __report_breakdown(extractor)

    console.info(f'[+] Extracted {len(extractor.extracted)} files, report in {report}')


def __report_breakdown(extractor):
    i = 0
    file_count = 0

    while i < len(extractor.extracted):
        with open(extractor.dest / f'report_amd64_{file_count}.txt', 'w') as f:
            lines_written = 0
            for e in extractor.extracted[i:]:
                rel = str(e)
                i += 1
                if 'amd64' in rel:
                    f.write(rel + '\n')
                    lines_written += 1
                    if lines_written >= 1000:
                        break
        file_count += 1


def extract(kb_path, dest='', manifests=False, arch=ARCH.x64):
    asyncio.run(aextract(kb_path, dest, manifests, arch))


if __name__ == '__main__':
    extract('')
