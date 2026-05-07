"""`patchdiff-ai windows recover-cache` — rebuild stale `report.cache` files.

`get_update_dataframe` (see `patches/files_collection.py`) caches the
indexed KB DataFrame next to its extraction as `report.cache`. When the
data root moves (different user profile, copied AppData, partial
extraction tree) the cached `path` column may no longer resolve to
real files and `patch_entry` fails with `[Errno 2]` for every
candidate.

This command scans the user-supplied path for
`extracted_*.msu/report.cache` files, detects unreadable / stale
entries, and re-runs the indexer in place so subsequent CVE runs hit
a valid cache.
"""

from __future__ import annotations

import re
import time
from pathlib import Path

import click
import polars as pl
import structlog

from patchdiff_ai.patches.files_collection import (
    generate_df,
    get_report,
    rebase_paths,
)
from patchdiff_ai.persistence.patch_store import safe_serialize

log = structlog.get_logger(__name__)


_KB_RE = re.compile(r"-(kb\d+)-", re.IGNORECASE)


def _kb_from_extracted_dir(extracted_dir: Path) -> str:
    """Recover the KB id from `extracted_<msu_basename>/`. Falls back to
    the dir name so we can still emit a useful log line if the regex
    misses (no functional dependency — `kb` is just a label column)."""
    m = _KB_RE.search(extracted_dir.name)
    return m.group(1).upper() if m else extracted_dir.name


def _classify(cache: Path) -> tuple[str, pl.DataFrame | None]:
    """Decide whether `cache` needs a rebuild.

    Returns `(verdict, df)` where verdict is one of:
      * "ok"      — relative paths that resolve under the current
                    extracted-KB root.
      * "stale"   — absolute paths (legacy format — pinned to whichever
                    machine wrote them, won't survive a data-root move),
                    OR relative paths that don't resolve (moved /
                    partially deleted extraction tree); rebuild.
      * "broken"  — couldn't even deserialize; rebuild.
    `df` is the deserialized frame when available, else None.
    """
    try:
        df = pl.DataFrame.deserialize(cache)
    except Exception:
        return "broken", None
    if df.is_empty() or "path" not in df.columns:
        return "ok", df
    sample = df["path"][0]
    if Path(sample).is_absolute():
        return "stale", df
    if not (cache.parent / sample).exists():
        return "stale", df
    return "ok", df


def _infer_arch(df: pl.DataFrame | None, fallback: str) -> str:
    """Pick the arch the original indexer used. The runtime indexer in
    `gather_info/nodes.py` filters by a single `state.os.arch`, so the
    cache only ever holds one arch — the dominant value from the stale
    frame is the right one. ``fallback`` is used when the frame can't
    be deserialized."""
    if df is None or df.is_empty() or "arch" not in df.columns:
        return fallback
    counts = df["arch"].value_counts(sort=True)
    return counts[0, "arch"]


def _rebuild(cache: Path, df: pl.DataFrame | None, *, dry_run: bool, arch_fallback: str) -> bool:
    """Rebuild a single `report.cache` from its sibling `report.txt`."""
    extracted = cache.parent
    report_txt = extracted / "report.txt"
    if not report_txt.exists():
        click.echo(f"  [!] {cache}: missing sibling report.txt — skipping")
        return False

    kb = _kb_from_extracted_dir(extracted)
    arch = _infer_arch(df, arch_fallback)
    paths = get_report(report_txt, arch)
    if not paths:
        click.echo(f"  [!] {cache}: no entries match arch={arch!r} in report.txt — skipping")
        return False

    if dry_run:
        click.echo(f"  [=] would rebuild {cache} (arch={arch}, files={len(paths)})")
        return True

    t0 = time.perf_counter()
    df_new = generate_df(kb, paths, collect_hash=True)
    if df_new.is_empty():
        click.echo(f"  [!] {cache}: indexer produced an empty frame — skipping")
        return False

    # Persist with the same relative-path convention `get_update_dataframe`
    # writes so the next runtime read goes through the fast path.
    safe_serialize(rebase_paths(df_new, root=extracted, to_relative=True), cache)
    click.echo(
        f"  [+] rebuilt {cache} ({len(df_new)} rows, "
        f"{time.perf_counter() - t0:.1f}s)"
    )
    return True


def _resolve_caches(target: Path) -> list[Path]:
    """Resolve ``target`` into the list of `report.cache` files to inspect.

    Three accepted shapes:
      * a `report.cache` file — single-cache mode.
      * an `extracted_*.msu` directory — its sibling cache (if any).
      * any other directory — globbed for `extracted_*.msu/report.cache`.
    """
    if target.is_file():
        if target.name != "report.cache":
            raise click.BadParameter(
                f"{target} is a file but not named report.cache; pass the cache "
                f"file itself or a directory containing extracted_*.msu/ entries."
            )
        return [target]

    direct = target / "report.cache"
    if direct.is_file():
        return [direct]

    return sorted(target.glob("extracted_*.msu/report.cache"))


@click.command(
    "recover-cache",
    help="Detect and rebuild stale/legacy report.cache files under PATH.",
)
@click.argument(
    "path",
    type=click.Path(exists=True, path_type=Path, resolve_path=True),
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Report what would be rebuilt without touching anything.",
)
@click.option(
    "--arch",
    default="amd64",
    show_default=True,
    help="Fallback arch for caches that can't be deserialized; for stale "
    "caches the arch is read from the existing frame.",
)
def recover_cache_command(path: Path, dry_run: bool, arch: str) -> None:
    caches = _resolve_caches(path)
    if not caches:
        click.echo(f"[*] no report.cache files found under {path}; nothing to do.")
        return

    # Pick a stable display root so per-cache lines stay readable: when the
    # user pointed at a single cache or an extracted dir, anchor on its
    # parent; otherwise show paths relative to the supplied directory.
    display_root = path if path.is_dir() and len(caches) > 1 else caches[0].parent.parent

    click.echo(f"[*] scanning {len(caches)} cache file(s) under {path} ...")
    counts = {"ok": 0, "stale": 0, "broken": 0, "rebuilt": 0, "failed": 0}
    for cache in caches:
        verdict, df = _classify(cache)
        counts[verdict] += 1
        try:
            rel = cache.relative_to(display_root)
        except ValueError:
            rel = cache
        if verdict == "ok":
            click.echo(f"  [.] {rel}: ok")
            continue
        click.echo(f"  [*] {rel}: {verdict}")
        if _rebuild(cache, df, dry_run=dry_run, arch_fallback=arch):
            if not dry_run:
                counts["rebuilt"] += 1
        else:
            counts["failed"] += 1

    click.echo(
        f"[+] done: {counts['ok']} ok, "
        f"{counts['stale']} stale, {counts['broken']} broken, "
        f"{counts['rebuilt']} rebuilt, {counts['failed']} failed"
        + (" (dry-run)" if dry_run else "")
    )
