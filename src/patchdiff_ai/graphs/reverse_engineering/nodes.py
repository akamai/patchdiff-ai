"""Reverse-engineering nodes: analyze (IDA -> BinExport) -> diff -> decompile."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import binexport
import structlog

from patchdiff_ai.graphs.reverse_engineering._shared import discover_parents
from patchdiff_ai.graphs.reverse_engineering.state import ReverseEngineeringState
from patchdiff_ai.runtime.app_context import AppContext
from patchdiff_ai.runtime.timer import Timer
from patchdiff_ai.schemas.analysis import Artifact, FunctionMatchRef
from patchdiff_ai.tools.ida import IdaJob

log = structlog.get_logger(__name__)

_IDAPY_DIR = Path(__file__).resolve().parents[2] / "tools" / "idapython"
_ANALYZE_SCRIPT = _IDAPY_DIR / "analyze.py"
_DECOMPILE_SCRIPT = _IDAPY_DIR / "decompile.py"


def make_nodes(ctx: AppContext):
    async def analyze(state: ReverseEngineeringState) -> dict[str, Any]:
        log.info("re_analyze_start", file=state.primary_file.name)
        run_start = time.time()
        logs_dir = ctx.settings.paths.logs_dir
        async with Timer("ida_export"):
            prim = Path(state.primary_file.path)
            sec = Path(state.secondary_file.path)
            # Include parent dir (KB number) in the log filename — primary
            # and secondary share the same DLL filename, so without it both
            # IDA processes write to the same log and the output interleaves
            # unreadably.
            jobs = [
                IdaJob(
                    target=prim,
                    script=_ANALYZE_SCRIPT,
                    log=str(logs_dir / f"{prim.parent.name}.{prim.name}.analyze.log"),
                ),
                IdaJob(
                    target=sec,
                    script=_ANALYZE_SCRIPT,
                    log=str(logs_dir / f"{sec.parent.name}.{sec.name}.analyze.log"),
                ),
            ]
            # Snapshot which targets we actually expect IDA to refresh in
            # this batch. Used after the run to distinguish "IDA was skipped
            # because the .BinExport already existed" from "IDA was launched
            # but failed to update the file" (a stale crash leftover).
            ran_targets = {
                j.target
                for j in jobs
                if not j.target.with_name(j.target.name + ".BinExport").exists()
            }
            log.trace(
                "re_analyze_cache",
                file=state.primary_file.name,
                targets_to_run=len(ran_targets),
                targets_skipped=len(jobs) - len(ran_targets),
            )
            await ctx.tools.ida.batch(
                jobs, condition=lambda j: j.target in ran_targets
            )

        # Verify each expected .BinExport. Two failure modes to surface:
        #   1. file missing: IDA crashed before writing, or BinExport plugin
        #      not installed.
        #   2. file present but older than run_start AND IDA was supposed to
        #      refresh it: IDA crashed mid-run leaving a previous version in
        #      place. bindiff would silently consume that and produce garbage
        #      matches (e.g. shell32 with rc=0xC0000374 still shipped 603
        #      "changed" functions downstream). Remove it so downstream fails
        #      cleanly via the existing `bindiff_failed` path.
        for src in (state.primary_file.path, state.secondary_file.path):
            be = Path(src + ".BinExport")
            if not be.exists():
                log.error(
                    "binexport_output_missing",
                    target=str(be),
                    hint="IDA may have crashed before writing the export, or the BinExport plugin is missing — run `patchdiff-ai health-check`.",
                )
                continue
            if Path(src) in ran_targets and be.stat().st_mtime < run_start:
                log.error(
                    "binexport_stale_after_ida_failed",
                    target=str(be),
                    mtime=be.stat().st_mtime,
                    run_start=run_start,
                    age_s=round(run_start - be.stat().st_mtime, 1),
                    hint="IDA was launched but didn't refresh this export — likely crashed mid-run. Removing so bindiff fails cleanly instead of running on stale data.",
                )
                try:
                    be.unlink()
                except OSError as exc:
                    log.warning(
                        "binexport_unlink_failed",
                        target=str(be),
                        error=str(exc),
                    )
        return {}

    async def diff_and_decompile(state: ReverseEngineeringState) -> dict[str, Any]:
        # BinDiff (sqlite3-backed) used to be returned from a separate `diff`
        # node into `state.diff`. Once the pipeline graph runs with a
        # checkpointer (interactive runs do, for `Command(resume=...)`),
        # langgraph pickles every state write between nodes — and pickle
        # rejects `sqlite3.Connection`. The BinDiff object never needs to
        # cross node boundaries (the existing comment at the top of this file
        # already notes that), so we keep it in this single function's local
        # scope and only return pickle-safe artifacts.
        async with Timer("bindiff"):
            curr = Path(state.primary_file.path + ".BinExport")
            prev = Path(state.secondary_file.path + ".BinExport")
            out = Path(f"{state.primary_file.path}.{state.secondary_file.kb}.BinDiff")
            bd = await ctx.tools.bindiff.diff(curr, prev, out)
            if bd is None:
                log.warning("bindiff_failed", file=state.primary_file.name)
                return {"artifacts": []}

        async with Timer("decompile_diff"):
            changed = [
                v
                for k, v in bd.primary_functions_match.items()
                if v.similarity < 1.0
            ]
            primary_funcs = {f"{f.address1:X}" for f in changed} - {
                i.stem for i in (bd.primary.path.parent / "__funcs__").glob("*.c")
            }
            secondary_funcs = {f"{f.address2:X}" for f in changed} - {
                i.stem for i in (bd.secondary.path.parent / "__funcs__").glob("*.c")
            }

            jobs: list[IdaJob] = []

            def add(export: binexport.program.ProgramBinExport, funcs: list[str]) -> None:
                idb = export.path.with_suffix(".i64")
                if not idb.exists():
                    return
                N = 500
                for i in range(0, len(funcs), N):
                    jobs.append(
                        IdaJob(
                            target=idb,
                            script=_DECOMPILE_SCRIPT,
                            args=funcs[i : i + N],
                            log=str(
                                ctx.settings.paths.logs_dir
                                / f"{idb.parent.name}.{idb.name}.log"
                            ),
                        )
                    )

            add(bd.primary, list(primary_funcs))
            add(bd.secondary, list(secondary_funcs))
            log.trace(
                "re_decompile_plan",
                file=state.primary_file.name,
                changed_funcs=len(changed),
                primary_unseen=len(primary_funcs),
                secondary_unseen=len(secondary_funcs),
                batched_jobs=len(jobs),
            )
            await ctx.tools.ida.batch(jobs)

            sorted_changed = sorted(changed, key=lambda x: (x.similarity, -x.confidence))
            log.info(
                "re_decompile_done",
                file=state.primary_file.name,
                changed=len(sorted_changed),
            )
            # Snapshot raw matches into FunctionMatchRef so the artifact survives
            # the Send(VR_AGENT, ...).model_dump() round-trip. Pre-resolve the
            # caller chain per match while the live BinDiff object is still
            # in scope.
            refs = [
                FunctionMatchRef(
                    name1=m.name1,
                    name2=m.name2,
                    address1=m.address1,
                    address2=m.address2,
                    similarity=m.similarity,
                    confidence=m.confidence,
                    parents=next(
                        discover_parents(bd.secondary.get(m.address1)),
                        None,
                    ),
                )
                for m in sorted_changed
            ]
            artifact = Artifact(
                primary_file=state.primary_file,
                secondary_file=state.secondary_file,
                changed=refs,
            )
            return {"artifacts": [artifact]}

    return analyze, diff_and_decompile
