"""Stage a binary into `db/patch_store/<platform>/<arch>_<package>_<pubkey>/<name>/<kb>/<name>`.

Builds patch-store entries for base / current / previous KBs by recursively
applying delta patches. Uses the **injected** `DeltaApi` (not module globals).

The `<platform>` segment isolates patched binaries per Windows release/SKU
so the same `(name, package, arch)` from a different platform's archive
can't accidentally be reused as a baseline — their reverse-deltas chain to
different RTM bytes.
"""

from __future__ import annotations

from pathlib import Path

import polars as pl
import structlog

from patchdiff_ai.patches.files_collection import file_hash, get_pe_ms_id, version_tuple
from patchdiff_ai.schemas.patch_store import PatchStoreEntry
from patchdiff_ai.tools.delta import DeltaApi

log = structlog.get_logger(__name__)


def store_path(patch_store_dir: Path, platform_id: str, entry: dict) -> Path:
    """Patch-store layout: `<platform>/<arch>_<package>_<pubkey>/<name>`."""
    folder = f"{entry['arch']}_{entry['package']}_{entry['pubkey']}"
    return patch_store_dir / platform_id / folder / entry["name"]


def _entry_path_relative(patch_store_dir: Path, abs_path: Path) -> str:
    """Forward-slashed relative form for `PatchStoreEntry.path` storage.

    The dataframe holds relative-to-``patch_store_dir`` strings; the
    pipeline absolutizes once at the routing→RE boundary.
    """
    return str(abs_path.relative_to(patch_store_dir)).replace("\\", "/")


def _apply_forward(
    delta: DeltaApi,
    base_bytes: bytes,
    f_delta_bytes: bytes,
    r_delta_bytes: bytes | None,
) -> tuple[bytes | None, str]:
    """Apply an MSU forward delta to the WinSxS-installed binary.

    Two layouts are observed in the wild:

      - **Direct** (e.g. KB5082063): the MSU's `f/` delta is generated
        against the installed CU binary at `<component>/<file>` (i.e. the
        same bytes we copy as ``base_bytes``). One ``recursive_apply``
        call produces the patched output.

      - **Via manifest baseline** (the legacy "regular" path the user
        documented): the MSU's `f/` delta is generated against the
        r-delta-derived manifest baseline. We must first apply the
        component's r-delta to ``base_bytes`` and then apply the f-delta
        to that intermediate result. ``recursive_apply`` handles the
        case where the f-delta produces another patch on its first apply
        (the user's "f patch on itself" variant) via its inner while-loop.

    Returns ``(output_bytes_or_None, mode)`` where ``mode`` is one of:
    ``"direct"``, ``"via_baseline"``, ``"failed_no_r_delta"``,
    ``"failed_baseline_apply"``, or ``"failed_both"``. Callers log
    ``mode`` so a regression to the unsupported-layout case is observable
    rather than silent.
    """
    out = delta.recursive_apply(base_bytes, f_delta_bytes)
    if out is not None:
        return out, "direct"

    if r_delta_bytes is None:
        return None, "failed_no_r_delta"

    baseline = delta.recursive_apply(base_bytes, r_delta_bytes)
    if baseline is None or baseline == base_bytes:
        return None, "failed_baseline_apply"

    out = delta.recursive_apply(baseline, f_delta_bytes)
    if out is None:
        return None, "failed_both"
    return out, "via_baseline"


def _r_delta_cache_path(base_kb_path: Path, entry_name: str) -> Path:
    """Where we stash the component's r-delta bytes alongside the base.

    Cached so a second-run scenario where the base file is reused (no
    extraction) but a new f-delta needs the r-delta fallback can still
    find it without re-extracting the whole archive.
    """
    return base_kb_path / f"{entry_name}.rpatch"


def patch_entry(
    delta: DeltaApi,
    patch_store_dir: Path,
    entry: dict,
    *,
    platform_id: str,
    base_kb: str,
    curr_kb: str,
    prev_kb: str,
    prev_df: pl.DataFrame,
    filtered_base_df: pl.DataFrame,
) -> tuple[PatchStoreEntry | None, PatchStoreEntry | None, PatchStoreEntry | None]:
    """Apply forward / reverse / self patches; return PatchStoreEntry triple."""
    base_path = store_path(patch_store_dir, platform_id, entry)
    base_kb_path = base_path / base_kb

    base_entry: PatchStoreEntry | None = None
    curr_entry: PatchStoreEntry | None = None
    prev_entry: PatchStoreEntry | None = None

    entry_df = pl.DataFrame([entry])

    # base — see `_apply_forward` for why this is a copy of the WinSxS
    # primary file rather than the legacy r-delta-derived "manifest
    # baseline". The r-delta bytes are cached alongside the base so the
    # cross-run fallback path stays available even when extraction is
    # short-circuited.
    r_delta_cache = _r_delta_cache_path(base_kb_path, entry["name"])
    r_delta_bytes: bytes | None = None

    if not (base_kb_path / entry["name"]).exists():
        winsxs_patch = filtered_base_df.join(
            entry_df,
            on=["name", "package", "arch", "pubkey"],
            how="semi",
        )
        if winsxs_patch.is_empty():
            return base_entry, curr_entry, prev_entry

        # Two row shapes (see gather_info/nodes.py r_patch construction):
        #   * delta_type == "r": path is `<component>/r/<file>`; the
        #     materialized binary sits two levels up next to r/. The
        #     r-delta bytes are needed for the "via baseline" fallback in
        #     `_apply_forward`, so cache them alongside the staged base.
        #   * delta_type IS NULL: vanilla WinSxS, the path itself is the
        #     materialized baseline; no r-delta exists. _apply_forward's
        #     "direct" path handles `r_delta_bytes=None`.
        row = winsxs_patch.row(0, named=True)
        if row.get("delta_type") == "r":
            reverse_path = Path(row["path"])
            primary_path = reverse_path.parents[1] / row["name"]
            r_delta_bytes = reverse_path.read_bytes()
        else:
            primary_path = Path(row["path"])
            r_delta_bytes = None

        base = primary_path.read_bytes()

        base_kb_path.mkdir(parents=True, exist_ok=True)
        (base_kb_path / entry["name"]).write_bytes(base)
        if r_delta_bytes is not None:
            r_delta_cache.write_bytes(r_delta_bytes)
        log.debug("base_copied", name=entry["name"], has_r_delta=r_delta_bytes is not None)

        base_entry = PatchStoreEntry.from_row(row)
        base_entry.path = _entry_path_relative(patch_store_dir, base_kb_path / entry["name"])
        base_entry.kb = base_kb
        base_entry.hash = file_hash(base)
        base_entry.ms_id = get_pe_ms_id(base)
        base_entry.version = version_tuple(base_kb) if "." in base_kb else ()
        base_entry.platform = platform_id
    else:
        base = (base_kb_path / entry["name"]).read_bytes()
        if r_delta_cache.exists():
            r_delta_bytes = r_delta_cache.read_bytes()

    # current
    if not (base_path / curr_kb / entry["name"]).exists():
        np_bytes = Path(entry["path"]).read_bytes()
        np, mode = _apply_forward(delta, base, np_bytes, r_delta_bytes)
        if np:
            (base_path / curr_kb).mkdir(parents=True, exist_ok=True)
            (base_path / curr_kb / entry["name"]).write_bytes(np)
            curr_entry = PatchStoreEntry.from_row(entry)
            curr_entry.path = _entry_path_relative(patch_store_dir, base_path / curr_kb / entry["name"])
            curr_entry.kb = curr_kb
            curr_entry.hash = file_hash(np)
            curr_entry.ms_id = get_pe_ms_id(np)
            curr_entry.platform = platform_id
            log.debug("curr_patched", name=entry["name"], kb=curr_kb, mode=mode)
        else:
            log.warning(
                "curr_patch_failed",
                name=entry["name"],
                kb=curr_kb,
                mode=mode,
                r_delta_available=r_delta_bytes is not None,
            )

    # previous
    if not (base_path / prev_kb / entry["name"]).exists():
        old_patch = prev_df.join(
            entry_df,
            on=["name", "package", "arch", "pubkey"],
            how="semi",
        )
        if not old_patch.is_empty():
            prev_path = Path(old_patch.item(0, column="path"))
            op_bytes = prev_path.read_bytes()
            op, mode = _apply_forward(delta, base, op_bytes, r_delta_bytes)
            if op:
                (base_path / prev_kb).mkdir(parents=True, exist_ok=True)
                (base_path / prev_kb / entry["name"]).write_bytes(op)
                row = old_patch.row(0, named=True)
                prev_entry = PatchStoreEntry.from_row(row)
                prev_entry.path = _entry_path_relative(patch_store_dir, base_path / prev_kb / entry["name"])
                prev_entry.kb = prev_kb
                prev_entry.hash = file_hash(op)
                prev_entry.ms_id = get_pe_ms_id(op)
                prev_entry.platform = platform_id
                log.debug("prev_patched", name=entry["name"], kb=prev_kb, mode=mode)
            else:
                log.warning(
                    "prev_patch_failed",
                    name=entry["name"],
                    kb=prev_kb,
                    mode=mode,
                    r_delta_available=r_delta_bytes is not None,
                )

    return base_entry, curr_entry, prev_entry
