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
      * "ok"      — paths resolve under the current extracted-KB root.
      * "stale"   — paths don't resolve (foreign absolute paths from
                    another machine, moved extraction tree, partially
                    deleted contents); rebuild. Path-join semantics
                    fold absolute strings through `cache.parent / sample`
                    to themselves, so foreign abs paths land here too.
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
    if not (cache.parent / sample).exists():
        return "stale", df
    return "ok", df


def _rebuild(cache: Path, *, dry_run: bool) -> bool:
    """Rebuild a single `report.cache` from its sibling `report.txt`.

    Returns True on (would-be) success. The extracted-KB root is the
    parent dir; we walk every arch present in `report.txt` so the
    rebuilt cache matches whatever the original indexer produced.
    """
    extracted = cache.parent
    report_txt = extracted / "report.txt"
    if not report_txt.exists():
        click.echo(f"  [!] {cache}: missing sibling report.txt — skipping")
        return False

    kb = _kb_from_extracted_dir(extracted)

    # `get_report` filters by arch; rebuild covers every arch listed
    # in report.txt so we don't silently drop x86 entries on an x64 box.
    arches = sorted({
        line.split("_", 1)[0]
        for line in report_txt.read_text().splitlines()
        if "_" in line and line.split("_", 1)[0]
    })
    if not arches:
        click.echo(f"  [!] {cache}: report.txt has no arch-prefixed entries — skipping")
        return False

    paths: list[Path] = []
    for arch in arches:
        paths.extend(get_report(report_txt, arch))

    if dry_run:
        click.echo(f"  [=] would rebuild {cache} (arches={arches}, files={len(paths)})")
        return True

    t0 = time.perf_counter()
    df = generate_df(kb, paths, collect_hash=True)
    if df.is_empty():
        click.echo(f"  [!] {cache}: indexer produced an empty frame — skipping")
        return False

    # Persist with the same relative-path convention `get_update_dataframe`
    # writes so the next runtime read goes through the fast path.
    safe_serialize(rebase_paths(df, root=extracted, to_relative=True), cache)
    click.echo(
        f"  [+] rebuilt {cache} ({len(df)} rows, "
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
def recover_cache_command(path: Path, dry_run: bool) -> None:
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
        verdict, _df = _classify(cache)
        counts[verdict] += 1
        try:
            rel = cache.relative_to(display_root)
        except ValueError:
            rel = cache
        if verdict == "ok":
            click.echo(f"  [.] {rel}: ok")
            continue
        click.echo(f"  [*] {rel}: {verdict}")
        if _rebuild(cache, dry_run=dry_run):
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
