import asyncio
import difflib
from pathlib import Path

import binexport
from bindiff import BinDiff
from langchain_core.documents import Document
import polars as pl

from common import PatchStoreEntry, logger, Timer
from patch_analysis import ida_analysis


async def bindiff_files(subjects: pl.DataFrame, curr_kb, prev_kb):
    with Timer('analyze and export'):
        analysis_tasks: list[ida_analysis.ExecArgs] = []
        for subject in subjects.filter(pl.col('kb') != 'base').iter_rows(named=True):
            subject = PatchStoreEntry().from_dict(subject, overwrite=True)
            analysis_tasks.append(ida_analysis.ExecArgs(target=Path(subject.path)))

        await ida_analysis.batch_analysis(analysis_tasks, lambda file: not file.target.with_name(
            file.target.name + '.BinExport').exists())

    diffs: list[BinDiff] = []

    with Timer('generate bindiff'):
        for subject in subjects.filter((pl.col('kb') == curr_kb)).iter_rows(named=True):
            subject = PatchStoreEntry().from_dict(subject, overwrite=True)
            logger.info(
                f'Diffing {subject.name} from {curr_kb} against {prev_kb}')  # TODO: If there is no prev version use base

            prev_subject = subjects.filter((pl.col('kb') == prev_kb) &
                                           (pl.col('name') == subject.name)).row(0, named=True)

            if not prev_subject:
                logger.warning(f'There is no {prev_kb} version available')
                continue

            prev_subject = PatchStoreEntry().from_dict(prev_subject, overwrite=True)

            curr_binexport = subject.path + '.BinExport'
            prev_binexport = prev_subject.path + '.BinExport'
            bindiff_path = f'{subject.path}.{prev_kb}.BinDiff'

            diff = BinDiff.from_binexport_files(curr_binexport, prev_binexport, bindiff_path)
            if not diff:
                logger.warning(f'Faild to bindiff {subject.name}')
                continue

            diffs.append(diff)

    return diffs


def create_diff_text(before: Path, after: Path):
    if not (before.exists() and after.exists()):
        return None, None, None

    before_code = before.read_text(encoding="utf-8")
    after_code = after.read_text(encoding="utf-8")

    udiff = difflib.unified_diff(
        before_code.splitlines(),
        after_code.splitlines(),
        fromfile=f'{before.name} before',
        tofile=f'{after.name} after',
        lineterm=""
    )

    return "\n".join(udiff), before_code, after_code


@Timer()
async def analyze_diff(diff: BinDiff):
    decompile = Path('patch_analysis/idapython/decompile.py')

    changed = [v for k, v in diff.primary_functions_match.items() if v.similarity < 1.0]
    primary_funcs = {f'{f.address1:X}' for f in changed} - {i.stem for i in
                                                            (diff.primary.path.parent / '__funcs__').glob('*.c')}
    secondary_funcs = {f'{f.address2:X}' for f in changed} - {i.stem for i in
                                                              (diff.secondary.path.parent / '__funcs__').glob('*.c')}

    analysis_tasks: list[ida_analysis.ExecArgs] = []

    def add_to_tasks(export: binexport.program.ProgramBinExport, functions: list[str]):
        idb = export.path.with_suffix('.i64')
        if idb.exists():
            N: int = 500
            for i in range(0, len(functions), N):
                analysis_tasks.append(ida_analysis.ExecArgs(target=idb,
                                                            script=decompile,
                                                            args=[f for f in functions[i:i + N]],
                                                            log=f'logs/{idb.name}.log'
                                                            ))

    add_to_tasks(diff.primary, list(primary_funcs))
    add_to_tasks(diff.secondary, list(secondary_funcs))

    await ida_analysis.batch_analysis(analysis_tasks)

    return sorted(changed, key=lambda x: (x.similarity, -x.confidence))
