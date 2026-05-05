"""`patchdiff-ai windows index` — index a per-Windows-version WinSxS dump.

Produces ``{product_id}.{slug}.bin`` (polars DataFrame of executables) and,
in archive mode, ``{product_id}.{slug}.7z``. Outputs land in
``settings.paths.windows_sxs_dir`` and `platforms.json` is updated in place.

Two modes:
  * ``--type directory`` (default): keep files on disk, manifest points at
    the staged folder. Faster, larger footprint.
  * ``--type archive``: compress executables into a .7z; runtime extracts
    on demand.

The user's input folder is never modified — every run stages a working copy
under ``<windows_sxs_dir>/<slug>/`` first.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import time
from datetime import date, datetime
from pathlib import Path

import click
import polars as pl
import structlog
from dateutil.relativedelta import relativedelta

from patchdiff_ai.config.settings import get_settings
from patchdiff_ai.patches.files_collection import EXECUTABLE_EXTENSIONS, get_files
from patchdiff_ai.patches.os_detection import get_cvrf_data, load_product_tree
from patchdiff_ai.persistence.patch_store import safe_serialize
from patchdiff_ai.platforms.windows.cycle import normalize_month

log = structlog.get_logger(__name__)

_TOKEN_RE = re.compile(r"[^a-z0-9]+")


def _tokens(text: str) -> set[str]:
    """Same tokeniser the CVRF matcher uses, so MSRC names and queries
    decompose into the same units."""
    return {t for t in _TOKEN_RE.sub(" ", text.lower()).split() if t}


def _default_msrc_month() -> str:
    return (datetime.now() - relativedelta(months=1)).strftime("%Y-%b")


def _index(winsxs_root: Path) -> pl.DataFrame:
    """Walk the dump and return a DataFrame with paths relative to ``winsxs_root``."""
    paths = list(winsxs_root.rglob("*"))
    rows = get_files("winsxs", paths, collect_hash=False)
    if not rows:
        return pl.DataFrame()
    df = pl.DataFrame(rows, schema_overrides={"delta_type": pl.Utf8, "hash": pl.Utf8})
    root_str = str(winsxs_root.resolve())
    df = df.with_columns(
        pl.col("path").map_elements(
            lambda p: str(Path(p).resolve().relative_to(root_str)).replace("\\", "/"),
            return_dtype=pl.Utf8,
        )
    )
    return df


def _cleanup_non_executables(winsxs_root: Path) -> int:
    """Delete every non-executable file under ``winsxs_root``; return bytes freed.

    Also prunes empty directories left behind: many WinSxS components are
    pure manifest/catalog dirs (no executables) and would otherwise leave
    a long tail of empty folders staged on disk.
    """
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
        except PermissionError:
            # WinSxS-derived files may carry the read-only attribute; clear and retry.
            try:
                os.chmod(path, stat.S_IWRITE)
                path.unlink()
            except OSError as exc:
                click.echo(f"[!] could not delete {path}: {exc}", err=True)
        except OSError as exc:
            click.echo(f"[!] could not delete {path}: {exc}", err=True)

    # Bottom-up empty-dir sweep. Sort by depth descending so children are
    # visited before parents — a component dir holding only `r/`, `f/`,
    # `n/` empties becomes empty itself only after they're removed.
    dirs = [p for p in winsxs_root.rglob("*") if p.is_dir()]
    dirs.sort(key=lambda p: len(p.parts), reverse=True)
    for d in dirs:
        try:
            if not any(d.iterdir()):
                d.rmdir()
        except OSError:
            pass
    return freed


def _interactive_pick(options: list[tuple[int, str]]) -> list[tuple[int, str]]:
    """Numbered prompt; comma-separated selection, primary first."""
    click.echo("Possible matches:")
    for i, (pid, name) in enumerate(options, 1):
        click.echo(f"  {i:>2}) {pid:>6}  {name}")
    sel = click.prompt(
        f"Choose 1-{len(options)} (comma-sep, primary first)",
        default="1",
        show_default=True,
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
    """Fetch the monthly CVRF and let the user pick matching products."""
    click.echo(f"[*] fetching MSRC CVRF for {msrc_month} ...")
    try:
        data = get_cvrf_data(msrc_month)
    except Exception as exc:
        raise click.ClickException(
            f"failed to fetch CVRF for {msrc_month!r}: {exc}. "
            f"Pass --product-ids <id,...> to skip the lookup, or try a different --msrc-month."
        ) from exc
    try:
        tree = load_product_tree(data)
    except (KeyError, TypeError) as exc:
        raise click.ClickException(
            f"CVRF for {msrc_month!r} has no usable ProductTree: {exc}. "
            f"Try a different month or pass --product-ids explicitly."
        ) from exc

    needle = _tokens(query)
    full_hits = [
        (pid, name) for pid, name in tree.items() if needle.issubset(_tokens(name))
    ]

    if full_hits:
        full_hits.sort(key=lambda x: (x[1], x[0]))
        if len(full_hits) == 1:
            pid, name = full_hits[0]
            click.echo(f"[+] resolved {name!r} -> productId={pid}")
            return pid, [pid]
        picked = _interactive_pick(full_hits)
    else:
        scored = sorted(
            tree.items(),
            key=lambda kv: len(needle & _tokens(kv[1])),
            reverse=True,
        )[:10]
        if not scored:
            raise click.ClickException(f"CVRF for {msrc_month!r} has no products at all.")
        click.echo(
            f"[!] no products contain all tokens of {query!r}; "
            f"showing top {len(scored)} by overlap."
        )
        picked = _interactive_pick(scored)

    primary_id = picked[0][0]
    all_ids = [pid for pid, _ in picked]
    summary = ", ".join(f"{pid}={name!r}" for pid, name in picked)
    click.echo(f"[+] selected: primary={primary_id}; all={all_ids} ({summary})")
    return primary_id, all_ids


def _parse_msrc_month(value: str) -> str:
    try:
        return normalize_month(value)
    except ValueError as exc:
        raise click.BadParameter(str(exc))


def _force_rmtree(target: Path) -> None:
    """`shutil.rmtree` that survives WinSxS-derived ACLs / read-only bits.

    Files copied out of ``C:\\Windows\\WinSxS`` often carry the read-only
    attribute (and TrustedInstaller-owned ACLs); a naive ``rmtree`` then
    fails with ``WinError 5`` mid-walk. The handler clears the read-only
    bit and retries the failing op.
    """
    def _onexc(func, path, _exc):
        try:
            os.chmod(path, stat.S_IWRITE)
        except OSError:
            pass
        func(path)

    # Python 3.12+ uses `onexc`; older releases use `onerror` with the
    # same callable signature.
    try:
        shutil.rmtree(target, onexc=_onexc)
    except TypeError:
        shutil.rmtree(target, onerror=_onexc)


def _ignore_non_executables(src_dir: str, names: list[str]) -> set[str]:
    """`shutil.copytree` ignore-callable: drop non-executable files at copy time.

    Subdirectories are always kept (their parent name carries the
    component metadata `COMPONENT_RE` matches against). Only regular
    files whose suffix isn't in `EXECUTABLE_EXTENSIONS` are skipped.
    """
    skip: set[str] = set()
    for name in names:
        full = os.path.join(src_dir, name)
        try:
            if os.path.isfile(full) and not name.lower().endswith(EXECUTABLE_EXTENSIONS):
                skip.add(name)
        except OSError:
            # Unstattable entry — let copytree see it and surface its own error.
            pass
    return skip


def _prepare_working_copy(
    source: Path,
    target: Path,
    *,
    force_recopy: bool = False,
    keep_non_executables: bool = False,
) -> bool:
    """Replace ``target`` with a fresh copy of ``source``.

    If ``target`` already exists and is non-empty, the copy is skipped
    (the slug is treated as the cache key). Pass ``force_recopy=True``
    to wipe and re-stage from scratch. When ``keep_non_executables`` is
    False (the default), non-executable files are filtered out at copy
    time so we don't waste I/O on files that get deleted anyway.

    Returns True if a fresh copy was made, False if an existing copy
    was reused (caller may need a fallback cleanup pass on reused dirs).
    """
    src_r = source.resolve()
    tgt_r = target.resolve()
    # Refuse source == target: would mutate the user's source folder.
    if src_r == tgt_r:
        raise click.ClickException(
            f"source path {source} is the same as the working location "
            f"{target}. Pick a different --slug, or move the source "
            f"outside windows_sxs_dir — the indexer must not modify your source."
        )
    # Refuse target inside source: shutil.copytree would recurse forever.
    if tgt_r.is_relative_to(src_r):
        raise click.ClickException(
            f"working location {target} is inside the source path "
            f"{source}; copying would recurse. Move the source or set "
            f"`paths.windows_sxs_dir` outside it."
        )

    if target.exists() and any(target.iterdir()):
        if not force_recopy:
            click.echo(f"[=] reusing existing working copy at {target} (pass --force-recopy to rebuild)")
            return False
        click.echo(f"[*] removing stale working copy at {target}")
        _force_rmtree(target)
    elif target.exists():
        # Empty dir — drop it so copytree's mkdir succeeds.
        target.rmdir()
    target.parent.mkdir(parents=True, exist_ok=True)
    filter_msg = "" if keep_non_executables else " (executables only)"
    click.echo(f"[*] copying {source} -> {target}{filter_msg} (this may take a while) ...")
    t0 = time.perf_counter()
    ignore = None if keep_non_executables else _ignore_non_executables
    shutil.copytree(source, target, ignore=ignore)
    click.echo(f"[+] copied in {time.perf_counter() - t0:.1f}s")
    return True


def _compress(seven_zip: Path, archive: Path, winsxs_root: Path) -> None:
    """Compress ``winsxs_root`` into ``archive`` via 7z."""
    archive.parent.mkdir(parents=True, exist_ok=True)
    if archive.exists():
        archive.unlink()
    cmd = [str(seven_zip), "a", "-mx=7", "-y", str(archive), "."]
    click.echo(f"[*] running: {' '.join(cmd)} (cwd={winsxs_root})")
    res = subprocess.run(cmd, cwd=str(winsxs_root))
    if res.returncode != 0:
        raise click.ClickException(f"7z exited with code {res.returncode}")


def _update_manifest(
    manifest_path: Path,
    *,
    product_id: int,
    msrc_product_ids: list[int],
    slug: str,
    archive_name: str,
    dataframe_name: str,
    product_name: str | None,
    msrc_month: str | None,
    archive_type: str,
) -> None:
    """Insert / update an entry in ``platforms.json``."""
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    else:
        manifest = {"_generated_at": "", "_msrc_month": "", "platforms": []}
    platforms: list[dict] = manifest.setdefault("platforms", [])

    entry = {
        "id": slug,
        "primary_product_id": product_id,
        "slug": slug,
        "archive": archive_name,
        "dataframe": dataframe_name,
        "type": archive_type,
        "msrc_product_ids": msrc_product_ids,
        "msrc_product_name_pattern": product_name or "",
    }
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
    click.echo(f"[+] platforms.json updated: {slug} -> productId={product_id}")


@click.command(
    "index",
    help="Index + pack a per-Windows-version WinSxS dump into windows_sxs_dir.",
)
@click.argument(
    "winsxs_path",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
)
@click.option(
    "--product-name",
    required=True,
    help="MSRC product-name query (e.g. 'Windows 11 Version 24H2'). "
         "Tokenised + matched against the monthly CVRF; matching products "
         "are presented interactively. Stored verbatim in the manifest.",
)
@click.option("--slug", required=True, help="Descriptive identifier (e.g. windows_11_24h2).")
@click.option(
    "--msrc-month",
    default=None,
    help="MSRC CVRF month tag (YYYY-MMM, e.g. '2026-Apr'). Defaults to current month.",
)
@click.option(
    "--product-ids",
    default=None,
    help="Comma-separated MSRC productIds (primary first). Skips the interactive pick.",
)
@click.option(
    "--keep-non-executables",
    is_flag=True,
    default=False,
    help="Skip the destructive cleanup (useful for a dry re-index).",
)
@click.option(
    "--force-recopy",
    is_flag=True,
    default=False,
    help="Wipe and rebuild the working copy even if one already exists for this slug.",
)
@click.option(
    "--type",
    "archive_type",
    type=click.Choice(["archive", "directory"]),
    default="directory",
    show_default=True,
    help="directory (default): leave files on disk and point the manifest "
         "at the source folder (no compression; faster runs, larger "
         "footprint, less portable). archive: compress source into a .7z "
         "(portable, smaller; runtime extracts on demand).",
)
def index_command(
    winsxs_path: Path,
    product_name: str,
    slug: str,
    msrc_month: str | None,
    product_ids: str | None,
    keep_non_executables: bool,
    force_recopy: bool,
    archive_type: str,
) -> None:
    settings = get_settings()
    settings.paths.ensure()

    # 7-Zip is only required for archive mode.
    seven_zip = settings.tools.seven_zip
    if archive_type == "archive" and not Path(seven_zip).exists():
        raise click.ClickException(
            f"7-Zip not found at {seven_zip}. Set `tools.seven_zip` in config.json "
            f"or `TOOLS__SEVEN_ZIP=...` env var."
        )

    winsxs_root = winsxs_path.resolve()
    msrc_month = _parse_msrc_month(msrc_month) if msrc_month else _default_msrc_month()

    if product_ids:
        try:
            id_list = [int(x) for x in product_ids.split(",") if x.strip()]
        except ValueError:
            raise click.BadParameter(
                f"--product-ids must be comma-separated ints, got {product_ids!r}"
            )
        if not id_list:
            raise click.BadParameter("--product-ids was empty after parsing")
        product_id, msrc_product_ids = id_list[0], id_list
    else:
        product_id, msrc_product_ids = _resolve_product_ids(product_name, msrc_month)

    out_dir = settings.paths.windows_sxs_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    bin_name = f"{product_id}.{slug}.bin"
    bin_path = out_dir / bin_name
    manifest_path = out_dir / "platforms.json"

    working_dir = out_dir / slug
    fresh_copy = _prepare_working_copy(
        winsxs_root,
        working_dir,
        force_recopy=force_recopy,
        keep_non_executables=keep_non_executables,
    )

    click.echo(f"[*] indexing {working_dir} ...")
    t0 = time.perf_counter()
    df = _index(working_dir)
    click.echo(f"[*] indexed {len(df)} files in {time.perf_counter() - t0:.1f}s")
    if df.is_empty():
        shutil.rmtree(working_dir, ignore_errors=True)
        raise click.ClickException("no files matched the WinSxS component-name regex; aborting.")

    exec_df = df.filter(
        pl.any_horizontal([
            pl.col("name").str.to_lowercase().str.ends_with(ext)
            for ext in EXECUTABLE_EXTENSIONS
        ])
    )
    click.echo(
        f"[*] keeping {len(exec_df)} executables "
        f"(dropped {len(df) - len(exec_df)} non-executables)"
    )

    safe_serialize(exec_df, bin_path)
    click.echo(f"[+] wrote DataFrame -> {bin_path}")

    # Fresh copies were already filtered at copytree time via the `ignore`
    # callback, so the post-walk delete is only needed when reusing a dir
    # staged by an older version (or a prior `--keep-non-executables` run).
    if not keep_non_executables and not fresh_copy:
        click.echo("[*] deleting non-executables from the working copy ...")
        freed = _cleanup_non_executables(working_dir)
        click.echo(f"[+] freed {freed // (1024 * 1024)} MB")

    if archive_type == "archive":
        archive_field = f"{product_id}.{slug}.7z"
        archive_path = out_dir / archive_field
        click.echo(f"[*] compressing with {seven_zip} -> {archive_path}")
        _compress(Path(seven_zip), archive_path, working_dir)
        archive_size_mb = archive_path.stat().st_size // (1024 * 1024)
        click.echo(f"[+] archive ready: {archive_path} ({archive_size_mb} MB)")
        click.echo(f"[*] removing working copy at {working_dir}")
        _force_rmtree(working_dir)
    else:
        archive_field = slug
        click.echo(f"[+] directory entry kept at {working_dir}")

    _update_manifest(
        manifest_path,
        product_id=product_id,
        msrc_product_ids=msrc_product_ids,
        slug=slug,
        archive_name=archive_field,
        dataframe_name=bin_name,
        product_name=product_name,
        msrc_month=msrc_month,
        archive_type=archive_type,
    )
    click.echo("[+] done.")
