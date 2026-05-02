"""idalib-backed reverse-engineering nodes (drop-in for `nodes.py`).

Same input state, same `Artifact` output shape, same node names as
[`nodes.py`](nodes.py) — the legacy idat-subprocess flow — so the pipeline
graph swaps between the two transparently based on `ctx.tools.idalib`.

Two nodes:
  * `analyze` — opens primary + secondary in idalib (one worker each, in
    parallel) and emits `<binary>.BinExport` files.
  * `diff_and_decompile` — runs BinDiff exactly as before (the bundled
    `bindiff.exe` from `resources/bindiff_ida_9.3/`), then asks idalib for
    the decompiled C of every changed function in one round-trip per
    binary.

`__funcs__/<ea>.c` files are still written so the downstream chat tools
(`show_decompiled`, `show_diff`) and the VR graph keep reading the same
artefacts.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import structlog

from patchdiff_ai.graphs.reverse_engineering._shared import (
    decompile_set_via_idalib,
    discover_parents,
    hexish,
)
from patchdiff_ai.graphs.reverse_engineering.state import ReverseEngineeringState
from patchdiff_ai.runtime.app_context import AppContext
from patchdiff_ai.runtime.timer import Timer
from patchdiff_ai.schemas.analysis import Artifact, FunctionMatchRef

log = structlog.get_logger(__name__)


def _pair_id(state: ReverseEngineeringState) -> str:
    return f"{state.primary_file.kb}_{state.secondary_file.kb}_{state.primary_file.name}"


def make_nodes(ctx: AppContext):
    async def analyze(state: ReverseEngineeringState) -> dict[str, Any]:
        import structlog as _structlog
        _structlog.contextvars.bind_contextvars(pair_id=_pair_id(state))
        log.info(
            "re_idalib_analyze_start",
            file=state.primary_file.name,
            kb_primary=state.primary_file.kb,
            kb_secondary=state.secondary_file.kb,
        )
        assert ctx.tools.idalib is not None  # selector guarantees this
        prim = Path(state.primary_file.path)
        sec = Path(state.secondary_file.path)

        async with Timer("ida_export"):
            # Cross-binary parallelism: prim and sec land on different
            # workers (round-robin), so `gather` runs the auto-analysis
            # for both DLLs concurrently.
            await asyncio.gather(*(
                ctx.tools.idalib.binexport(
                    src,
                    src.with_name(src.name + ".BinExport"),
                    skip_if_exists=True,
                )
                for src in (prim, sec)
            ))

        # Surface missing exports for downstream debugging — bindiff's
        # error message when a .BinExport is missing is opaque.
        for src_path in (state.primary_file.path, state.secondary_file.path):
            be = Path(src_path + ".BinExport")
            if not be.exists():
                log.error(
                    "binexport_output_missing",
                    target=str(be),
                    hint=(
                        "BinExportBinary returned without writing the file. "
                        "Confirm the BinExport plugin DLL is in IDA's "
                        "plugins/ via `patchdiff-ai install ida-plugins`."
                    ),
                )
        log.info("re_idalib_analyze_done", file=state.primary_file.name)
        return {}

    async def diff_and_decompile(state: ReverseEngineeringState) -> dict[str, Any]:
        import structlog as _structlog
        _structlog.contextvars.bind_contextvars(pair_id=_pair_id(state))
        log.info(
            "re_idalib_diff_decompile_start",
            file=state.primary_file.name,
        )
        assert ctx.tools.idalib is not None
        prim = Path(state.primary_file.path)
        sec = Path(state.secondary_file.path)

        # Overlap IDB warm-up with bindiff so by the time bindiff
        # finishes, the workers have the IDBs loaded and ready for
        # decompile. Restricted to binaries with a cached `.i64` —
        # those load in ~5-10s, the cost is bounded, and the win when
        # we end up needing decompile is bindiff's full elapsed time.
        # For cold `.i64`s the lazy open inside `decompile_many` still
        # pays full auto-analysis but we don't risk wasting ~2 min on a
        # hot-cache run where bindiff turns out to need no decompile work.
        warmup_tasks: list[asyncio.Task[None]] = []
        for binary in (prim, sec):
            if (binary.with_name(binary.name + ".i64")).is_file():
                warmup_tasks.append(
                    asyncio.create_task(ctx.tools.idalib.open(binary))
                )

        async with Timer("bindiff"):
            curr = Path(state.primary_file.path + ".BinExport")
            prev = Path(state.secondary_file.path + ".BinExport")
            out = Path(f"{state.primary_file.path}.{state.secondary_file.kb}.BinDiff")
            bd = await ctx.tools.bindiff.diff(curr, prev, out)
            if bd is None:
                log.warning("bindiff_failed", file=state.primary_file.name)
                if warmup_tasks:
                    await asyncio.gather(*warmup_tasks, return_exceptions=True)
                for binary in (prim, sec):
                    try:
                        await ctx.tools.idalib.release(binary)
                    except Exception:
                        pass
                return {"artifacts": []}

        # Block on the warmups so decompile sees a fully-loaded IDB.
        if warmup_tasks:
            await asyncio.gather(*warmup_tasks, return_exceptions=True)

        async with Timer("decompile_diff"):
            changed = [
                v
                for k, v in bd.primary_functions_match.items()
                if v.similarity < 1.0
            ]
            primary_funcs_dir = bd.primary.path.parent / "__funcs__"
            secondary_funcs_dir = bd.secondary.path.parent / "__funcs__"
            primary_funcs_dir.mkdir(parents=True, exist_ok=True)
            secondary_funcs_dir.mkdir(parents=True, exist_ok=True)

            primary_addrs = {f.address1 for f in changed} - {
                int(i.stem, 16) for i in primary_funcs_dir.glob("*.c") if hexish(i.stem)
            }
            secondary_addrs = {f.address2 for f in changed} - {
                int(i.stem, 16) for i in secondary_funcs_dir.glob("*.c") if hexish(i.stem)
            }

            await asyncio.gather(
                decompile_set_via_idalib(ctx, bd.primary, primary_funcs_dir, primary_addrs),
                decompile_set_via_idalib(ctx, bd.secondary, secondary_funcs_dir, secondary_addrs),
            )

            sorted_changed = sorted(changed, key=lambda x: (x.similarity, -x.confidence))
            log.info(
                "re_idalib_decompile_done",
                file=state.primary_file.name,
                changed=len(sorted_changed),
            )
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

        # Release the workers — all artefacts for this pair are now on disk
        # so we don't need the live IDBs anymore. `release` shuts the worker
        # process down, which reclaims the 1-2 GB RSS the IDB held.
        for finished in (Path(state.primary_file.path), Path(state.secondary_file.path)):
            try:
                await ctx.tools.idalib.release(finished)
            except Exception as exc:
                log.warning(
                    "idalib_release_pair_failed",
                    file=finished.name,
                    error=str(exc),
                )
        log.info("re_idalib_diff_decompile_done", file=state.primary_file.name)
        return {"artifacts": [artifact]}

    return analyze, diff_and_decompile
