"""Offline indexer + packer for a per-Windows-version WinSxS dump.

The patchdiff-ai pipeline used to read its baseline binaries straight off
`C:\\Windows\\WinSxS` on the host. This script replaces that with a
self-contained output: hand it a WinSxS folder (typically extracted from
a Windows install ISO) and it produces:

  * ``{product_id}.{slug}.bin`` — polars DataFrame indexing every
    executable in the WinSxS dump (path is relative to the output root).
  * ``{product_id}.{slug}/`` (default) — directory containing only the
    executables, moved from the source. Fast (same-volume rename).
  * ``{product_id}.{slug}.7z`` (with ``--archive``) — 7-zip archive
    containing the executables. Slower but more compact.

The output files are written to ``resources/windows_sxs/`` (next to this
script). The ``platforms.json`` manifest in that dir is created/updated
to register the new platform.

Usage:

    python resources/index_winsxs.py <winsxs_path> \\
        --product-name "Windows 11 Version 24H2" \\
        --slug windows_11_24h2 \\
        [--msrc-month 2026-Apr]      # default: current month
        [--product-ids 12390,12391]   # skip the interactive pick
        [--archive]                  # produce .7z instead of directory
        [--seven-zip C:/Path/to/7z.exe] \\
        [--keep-non-executables]     # skip the destructive cleanup (archive mode only)

The MSRC ``productId``(s) are resolved by tokenising ``--product-name`` and
finding every product in the monthly CVRF whose name is a token-superset
of the query. The script then presents an interactive numbered menu so
multiple SKUs (e.g. x64 + ARM64 + 32-bit + Server siblings sharing the
same servicing channel) can be mapped to the same archive. The first
selected entry becomes the ``primary_product_id``; the full set is
written to ``msrc_product_ids`` in ``platforms.json``. Pass
``--product-ids`` (comma-separated, primary first) to bypass the prompt.

Idempotent: re-running on the same folder overwrites the .bin and output,
and in directory mode re-moves any files that reappeared. The script can
run inside the project's venv (it imports ``patchdiff_ai`` for the indexing
logic) or standalone with PyPI-installed deps (polars + the 7-zip
executable).
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
from datetime import date, datetime
from pathlib import Path

_MSRC_MONTH_RE = re.compile(
    r"^\d{4}-(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$",
    re.IGNORECASE,
)

_TOKEN_RE = re.compile(r"[^a-z0-9]+")


def _tokens(text: str) -> set[str]:
    """Lowercase + split-on-non-alnum, drop empties. Mirrors the tokeniser in
    `_temp/reference/.../filter_by_platform.py:words` so MSRC names ("Windows
    11 Version 24H2 for x64-based Systems") and queries ("windows 11 24h2")
    decompose into the same units."""
    return {t for t in _TOKEN_RE.sub(" ", text.lower()).split() if t}


def _msrc_month_arg(value: str) -> str:
    """Validate + normalise the `YYYY-MMM` format MSRC's CVRF endpoints want."""
    if not _MSRC_MONTH_RE.match(value):
        raise argparse.ArgumentTypeError(
            f"invalid --msrc-month {value!r}; expected YYYY-MMM "
            "(e.g. 2026-Apr)."
        )
    year, mon = value.split("-")
    return f"{year}-{mon.capitalize()}"

# Make patchdiff_ai importable when invoked as `python resources/index_winsxs.py`
_REPO_ROOT = Path(__file__).resolve().parents[1]
_SRC = _REPO_ROOT / "src"
if _SRC.exists() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import polars as pl  # noqa: E402

from patchdiff_ai.patches.files_collection import (  # noqa: E402
    EXECUTABLE_EXTENSIONS,
    get_files,
)
from patchdiff_ai.patches.os_detection import (  # noqa: E402
    get_cvrf_data,
    load_product_tree,
)
from patchdiff_ai.persistence.patch_store import safe_serialize  # noqa: E402


def _index(winsxs_root: Path) -> pl.DataFrame:
    """Walk the WinSxS dump and return a DataFrame indexed by the same schema
    the pipeline used for the on-host `C:\\Windows\\WinSxS` (see
    [files_collection.py:get_files](src/patchdiff_ai/patches/files_collection.py)).

    `path` is rewritten to be **relative to `winsxs_root`** so it matches the
    layout inside the .7z archive that follows. `delta_type` ('r' / 'f' /
    'n' / None) is preserved — the pipeline filters to reverse deltas only,
    but the indexer keeps the full set so different consumers can re-filter.
    """
    paths = list(winsxs_root.rglob("*"))
    rows = get_files("winsxs", paths, collect_hash=False)
    if not rows:
        return pl.DataFrame()
    df = pl.DataFrame(rows, schema_overrides={"delta_type": pl.Utf8, "hash": pl.Utf8})
    # Rewrite absolute paths to in-archive relative paths.
    root_str = str(winsxs_root.resolve())
    df = df.with_columns(
        pl.col("path").map_elements(
            lambda p: str(Path(p).resolve().relative_to(root_str)).replace("\\", "/"),
            return_dtype=pl.Utf8,
        )
    )
    return df


def _move_executables(winsxs_root: Path, dest_dir: Path, exec_df: pl.DataFrame) -> int:
    """Move executable files listed in `exec_df` from `winsxs_root` into
    `dest_dir`, preserving relative paths. Returns the count of files moved.
    Idempotent: skips files that already exist at the destination."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    moved = 0
    for rel_path in exec_df["path"].to_list():
        src = winsxs_root / rel_path
        dst = dest_dir / rel_path
        if dst.exists():
            continue
        if not src.exists():
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dst))
        moved += 1
    return moved


def _cleanup_non_executables(winsxs_root: Path) -> int:
    """Delete every non-executable file under `winsxs_root`. Returns
    bytes freed. Empty dirs are left alone — 7-zip handles them fine
    and pruning them risks deleting placeholder folders the user cares
    about."""
    freed = 0
    for path in winsxs_root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() in EXECUTABLE_EXTENSIONS:
            continue
        try:
            freed += path.stat().st_size
        except OSError:
            pass
        try:
            path.unlink()
        except OSError as exc:
            print(f"[!] could not delete {path}: {exc}", file=sys.stderr)
    return freed


def _default_msrc_month() -> str:
    """`YYYY-MMM` for the current month, formatted the way MSRC's CVRF
    documents are keyed (e.g. ``2026-Apr``)."""
    return datetime.now().strftime("%Y-%b")


def _interactive_pick(options: list[tuple[int, str]]) -> list[tuple[int, str]]:
    """Render a numbered list and accept a comma-separated selection (e.g.
    ``"2,1,3"``). The first selected entry is treated as primary by the
    caller. Bare Enter defaults to ``[options[0]]``; empty / all-invalid
    input falls back to the same default."""
    print("Possible matches:")
    for i, (pid, name) in enumerate(options, 1):
        print(f"  {i:>2}) {pid:>6}  {name}")
    sel = input(
        f"Choose 1-{len(options)} (comma-sep, primary first) [1]: "
    ).strip()
    if not sel:
        return [options[0]]
    picked: list[tuple[int, str]] = []
    seen: set[int] = set()
    for tok in sel.split(","):
        tok = tok.strip()
        if not tok.isdigit():
            continue
        idx = int(tok) - 1
        if 0 <= idx < len(options) and idx not in seen:
            picked.append(options[idx])
            seen.add(idx)
    return picked or [options[0]]


def _resolve_product_ids(query: str, msrc_month: str) -> tuple[int, list[int]]:
    """Fetch the monthly CVRF and let the user pick one or more matching
    products via interactive prompt. Returns ``(primary_id, all_ids)``.

    Token-superset match wins: every product whose name contains all of
    the query's tokens is offered. If exactly one matches it's auto-picked.
    If none match, the top 10 by token-overlap are offered as a fallback
    so a typo or extra word doesn't block the run.
    """
    print(f"[*] fetching MSRC CVRF for {msrc_month} ...")
    try:
        data = get_cvrf_data(msrc_month)
    except Exception as exc:
        raise RuntimeError(
            f"failed to fetch CVRF for {msrc_month!r}: {exc}. "
            f"Pass --product-ids <id,...> to skip the lookup, or try a "
            f"different --msrc-month."
        ) from exc

    try:
        tree = load_product_tree(data)
    except (KeyError, TypeError) as exc:
        raise RuntimeError(
            f"CVRF for {msrc_month!r} has no usable ProductTree: {exc}. "
            f"Try a different month or pass --product-ids explicitly."
        ) from exc

    needle = _tokens(query)
    full_hits = [
        (pid, name) for pid, name in tree.items()
        if needle.issubset(_tokens(name))
    ]

    if full_hits:
        full_hits.sort(key=lambda x: (x[1], x[0]))
        if len(full_hits) == 1:
            pid, name = full_hits[0]
            print(f"[+] resolved {name!r} -> productId={pid}")
            return pid, [pid]
        picked = _interactive_pick(full_hits)
    else:
        scored = sorted(
            tree.items(),
            key=lambda kv: len(needle & _tokens(kv[1])),
            reverse=True,
        )[:10]
        if not scored:
            raise RuntimeError(
                f"CVRF for {msrc_month!r} has no products at all."
            )
        print(
            f"[!] no products contain all tokens of {query!r}; "
            f"showing top {len(scored)} by overlap."
        )
        picked = _interactive_pick(scored)

    primary_id = picked[0][0]
    all_ids = [pid for pid, _ in picked]
    summary = ", ".join(f"{pid}={name!r}" for pid, name in picked)
    print(f"[+] selected: primary={primary_id}; all={all_ids} ({summary})")
    return primary_id, all_ids


def _resolve_seven_zip(override: Path | None) -> Path:
    if override is not None:
        if not override.exists():
            raise FileNotFoundError(f"--seven-zip {override} does not exist")
        return override
    # Try the project's settings (works inside the venv).
    try:
        from patchdiff_ai.config.settings import get_settings  # type: ignore
        sz = get_settings().tools.seven_zip
        if sz and Path(sz).exists():
            return Path(sz)
    except Exception:
        pass
    # Fall back to PATH.
    found = shutil.which("7z") or shutil.which("7z.exe")
    if found:
        return Path(found)
    raise FileNotFoundError(
        "7-Zip not found. Pass --seven-zip <path> or set the project's "
        "TOOLS__SEVEN_ZIP env var."
    )


def _compress(seven_zip: Path, archive: Path, winsxs_root: Path) -> None:
    """Run 7z to compress `winsxs_root` into `archive`. Files inside the
    archive carry paths relative to `winsxs_root` (no top-level prefix) so
    the runtime can extract by the same relative paths the DataFrame stores.

    We `cd` into the parent of `winsxs_root` and pass the dir name itself
    so 7-zip preserves the structure but with `<dirname>/...` as the
    in-archive prefix. The DataFrame paths are then rewritten with that
    prefix in the caller.
    """
    archive.parent.mkdir(parents=True, exist_ok=True)
    if archive.exists():
        archive.unlink()  # 7z would otherwise update-in-place
    # Use globbed contents to avoid any prefix; the DataFrame paths are
    # already root-relative.
    cmd = [
        str(seven_zip),
        "a",
        "-mx=7",
        "-y",
        str(archive),
        ".",
    ]
    print(f"[*] running: {' '.join(cmd)} (cwd={winsxs_root})")
    res = subprocess.run(cmd, cwd=str(winsxs_root))
    if res.returncode != 0:
        raise RuntimeError(f"7z exited with code {res.returncode}")


def _update_manifest(
    manifest_path: Path,
    *,
    product_id: int,
    msrc_product_ids: list[int],
    slug: str,
    archive_name: str,
    dataframe_name: str,
    product_name: str | None,
    msrc_month: str | None = None,
    mode: str = "archive",
) -> None:
    """Insert/update an entry in `platforms.json`. Creates the file with a
    skeleton if missing."""
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    else:
        manifest = {"_generated_at": "", "_msrc_month": "", "platforms": []}
    platforms: list[dict] = manifest.setdefault("platforms", [])

    entry = {
        "id": slug,
        "primary_product_id": product_id,
        "slug": slug,
        "type": mode,
        "archive": archive_name,
        "dataframe": dataframe_name,
        # Full set of MSRC product IDs that map to this archive — picked
        # interactively at index time (or passed via --product-ids). The
        # `msrc_product_name_pattern` below is the original query, kept
        # verbatim so `refresh-platforms` can re-derive the same set
        # against future monthly CVRFs.
        "msrc_product_ids": msrc_product_ids,
        "msrc_product_name_pattern": product_name or "",
    }

    # Replace by id, else append.
    for i, p in enumerate(platforms):
        if p.get("id") == slug:
            platforms[i] = entry
            break
    else:
        platforms.append(entry)

    manifest["_generated_at"] = date.today().isoformat()
    if msrc_month:
        manifest["_msrc_month"] = msrc_month
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    print(f"[+] platforms.json updated: {slug} -> productId={product_id}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("winsxs_path", type=Path,
                        help="Path to the WinSxS folder dump (e.g. resources/windows_sxs/windows_server_2025).")
    parser.add_argument("--product-name", required=True,
                        help="MSRC product-name query (e.g. 'Windows 11 Version "
                             "24H2'). Tokenised + matched against the monthly "
                             "CVRF; matching products are presented in an "
                             "interactive multi-pick. Stored verbatim in the "
                             "manifest as `msrc_product_name_pattern` so a "
                             "future `refresh-platforms` can re-derive the "
                             "same set against newer CVRFs.")
    parser.add_argument("--slug", required=True,
                        help="Descriptive identifier (e.g. windows_11_24h2).")
    parser.add_argument("--msrc-month", type=_msrc_month_arg, default=None,
                        help="MSRC CVRF month tag (e.g. '2026-Apr'). Defaults "
                             "to the current month.")
    parser.add_argument("--product-ids", default=None,
                        help="Comma-separated MSRC productIds (primary first). "
                             "Skips the interactive pick when set.")
    parser.add_argument("--seven-zip", type=Path, default=None,
                        help="Override the 7-Zip executable path.")
    parser.add_argument("--archive", action="store_true",
                        help="Produce a .7z archive instead of a directory. "
                             "Slower but more compact.")
    parser.add_argument("--keep-non-executables", action="store_true",
                        help="Skip the destructive cleanup (archive mode only).")
    args = parser.parse_args()

    winsxs_root: Path = args.winsxs_path.resolve()
    if not winsxs_root.is_dir():
        print(f"[!] {winsxs_root} is not a directory", file=sys.stderr)
        return 2

    msrc_month = args.msrc_month or _default_msrc_month()

    if args.product_ids:
        try:
            id_list = [int(x) for x in args.product_ids.split(",") if x.strip()]
        except ValueError:
            print(f"[!] --product-ids must be comma-separated ints, got "
                  f"{args.product_ids!r}", file=sys.stderr)
            return 2
        if not id_list:
            print("[!] --product-ids was empty after parsing", file=sys.stderr)
            return 2
        product_id, msrc_product_ids = id_list[0], id_list
    else:
        try:
            product_id, msrc_product_ids = _resolve_product_ids(
                args.product_name, msrc_month
            )
        except RuntimeError as exc:
            print(f"[!] {exc}", file=sys.stderr)
            return 3

    out_dir = Path(__file__).resolve().parent / "windows_sxs"
    out_dir.mkdir(parents=True, exist_ok=True)
    bin_name = f"{product_id}.{args.slug}.bin"
    if args.archive:
        dest_name = f"{product_id}.{args.slug}.7z"
    else:
        dest_name = f"{product_id}.{args.slug}"
    bin_path = out_dir / bin_name
    dest_path = out_dir / dest_name
    manifest_path = out_dir / "platforms.json"

    print(f"[*] indexing {winsxs_root} ...")
    t0 = time.perf_counter()
    df = _index(winsxs_root)
    print(f"[*] indexed {len(df)} files in {time.perf_counter()-t0:.1f}s")
    if df.is_empty():
        print("[!] no files matched the WinSxS component-name regex; aborting.",
              file=sys.stderr)
        return 1

    # Filter to executables for the persisted DataFrame. The .7z still
    # gets compressed AFTER the source dir is pruned, so its contents
    # also match.
    exec_df = df.filter(
        pl.any_horizontal([
            pl.col("name").str.to_lowercase().str.ends_with(ext)
            for ext in EXECUTABLE_EXTENSIONS
        ])
    )
    print(f"[*] keeping {len(exec_df)} executables (dropped {len(df) - len(exec_df)} non-executables)")

    safe_serialize(exec_df, bin_path)
    print(f"[+] wrote DataFrame -> {bin_path}")

    if args.archive:
        # --- archive mode: cleanup + compress into .7z ----------------------
        if not args.keep_non_executables:
            print("[*] deleting non-executables from the source dir ...")
            freed = _cleanup_non_executables(winsxs_root)
            print(f"[+] freed {freed // (1024 * 1024)} MB")

        seven_zip = _resolve_seven_zip(args.seven_zip)
        print(f"[*] compressing with {seven_zip} -> {dest_path}")
        _compress(seven_zip, dest_path, winsxs_root)
        dest_size_mb = dest_path.stat().st_size // (1024 * 1024)
        print(f"[+] archive ready: {dest_path} ({dest_size_mb} MB)")
    else:
        # --- directory mode: move executables into convention-named folder ---
        if args.keep_non_executables:
            print("[*] note: --keep-non-executables has no effect in directory mode")
        print(f"[*] moving {len(exec_df)} executables -> {dest_path}")
        t1 = time.perf_counter()
        moved = _move_executables(winsxs_root, dest_path, exec_df)
        print(f"[+] moved {moved} files in {time.perf_counter()-t1:.1f}s")

    mode = "archive" if args.archive else "directory"

    _update_manifest(
        manifest_path,
        product_id=product_id,
        msrc_product_ids=msrc_product_ids,
        slug=args.slug,
        archive_name=dest_name,
        dataframe_name=bin_name,
        product_name=args.product_name,
        msrc_month=msrc_month,
        mode=mode,
    )

    print("[+] done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
