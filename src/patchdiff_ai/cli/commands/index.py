"""`patchdiff-ai index` — index + pack a per-Windows-version WinSxS dump.

Replaces the host's ``C:\\Windows\\WinSxS`` baseline with a self-contained
archive: hand it a WinSxS folder (typically extracted from a Windows
install ISO) and it produces:

* ``{product_id}.{slug}.bin`` — polars DataFrame indexing every executable
  in the dump (path is relative to the archive root).
* ``{product_id}.{slug}.7z`` — 7-zip archive containing only the
  executables. Non-executables are deleted from the source folder
  (destructive in-place) before compression to save storage.

Outputs are written to ``settings.paths.windows_sxs_dir`` (defaults to
``<data_root>/windows_sxs/``). The ``platforms.json`` manifest there is
created/updated to register the new platform — the runtime reads it via
:class:`patchdiff_ai.platforms.winsxs_archive.PlatformsManifest`.

The MSRC ``productId``\\ s are resolved by tokenising ``--product-name``
and finding every product in the monthly CVRF whose name is a token
superset of the query; an interactive numbered menu lets multiple SKUs
share one archive. The first selected entry becomes the
``primary_product_id``. Pass ``--product-ids`` to skip the prompt.

Idempotent: re-running on the same folder overwrites the .bin / .7z and
re-deletes any non-executables that crept back.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from datetime import date, datetime
from pathlib import Path

import click
import polars as pl
import structlog

from patchdiff_ai.config.settings import get_settings
from patchdiff_ai.patches.files_collection import EXECUTABLE_EXTENSIONS, get_files
from patchdiff_ai.patches.os_detection import get_cvrf_data, load_product_tree
from patchdiff_ai.persistence.patch_store import safe_serialize

log = structlog.get_logger(__name__)

_MSRC_MONTH_RE = re.compile(
    r"^\d{4}-(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$",
    re.IGNORECASE,
)
_TOKEN_RE = re.compile(r"[^a-z0-9]+")


def _tokens(text: str) -> set[str]:
    """Lowercase + split-on-non-alnum, drop empties — same tokeniser the
    CVRF matcher uses, so MSRC names ("Windows 11 Version 24H2 for
    x64-based Systems") and queries ("windows 11 24h2") decompose into
    the same units."""
    return {t for t in _TOKEN_RE.sub(" ", text.lower()).split() if t}


def _parse_msrc_month(value: str) -> str:
    if not _MSRC_MONTH_RE.match(value):
        raise click.BadParameter(
            f"invalid --msrc-month {value!r}; expected YYYY-MMM (e.g. 2026-Apr)."
        )
    year, mon = value.split("-")
    return f"{year}-{mon.capitalize()}"


def _default_msrc_month() -> str:
    return datetime.now().strftime("%Y-%b")


def _index(winsxs_root: Path) -> pl.DataFrame:
    """Walk the WinSxS dump and return a DataFrame with the same schema
    `patchdiff_ai.patches.files_collection.get_files` produces. Paths are
    rewritten relative to ``winsxs_root`` so they match the in-archive
    layout the .7z below carries."""
    paths = list(winsxs_root.rglob("*"))
    rows = get_files("winsxs", paths, collect_hash=False)
    if not rows:
        return pl.DataFrame()
    df = pl.DataFrame(rows)
    root_str = str(winsxs_root.resolve())
    df = df.with_columns(
        pl.col("path").map_elements(
            lambda p: str(Path(p).resolve().relative_to(root_str)).replace("\\", "/"),
            return_dtype=pl.Utf8,
        )
    )
    return df


def _cleanup_non_executables(winsxs_root: Path) -> int:
    """Delete every non-executable file under ``winsxs_root``. Returns
    bytes freed. Empty dirs are left alone — 7-zip handles them, and
    pruning risks deleting placeholders the user cares about."""
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
            click.echo(f"[!] could not delete {path}: {exc}", err=True)
    return freed


def _interactive_pick(options: list[tuple[int, str]]) -> list[tuple[int, str]]:
    """Render a numbered list and accept a comma-separated selection
    (e.g. ``"2,1,3"``). The first selected entry is treated as primary
    by the caller. Bare Enter / empty / all-invalid input → ``[options[0]]``."""
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


def _compress(seven_zip: Path, archive: Path, winsxs_root: Path) -> None:
    """Run 7z to compress ``winsxs_root`` into ``archive``. The archive
    layout matches the relative paths in the DataFrame (we cd into the
    source dir and pass ``.``)."""
    archive.parent.mkdir(parents=True, exist_ok=True)
    if archive.exists():
        archive.unlink()  # 7z would otherwise update-in-place
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
) -> None:
    """Insert / update an entry in `platforms.json`. Creates the file
    with a skeleton if missing."""
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
        # Full set of MSRC product IDs that map to this archive — picked
        # interactively at index time (or passed via --product-ids).
        # `msrc_product_name_pattern` is the original query, kept verbatim
        # so a future `refresh-platforms` can re-derive the same set
        # against newer monthly CVRFs.
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
def index_command(
    winsxs_path: Path,
    product_name: str,
    slug: str,
    msrc_month: str | None,
    product_ids: str | None,
    keep_non_executables: bool,
) -> None:
    settings = get_settings()
    settings.paths.ensure()

    seven_zip = settings.tools.seven_zip
    if not Path(seven_zip).exists():
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
    archive_name = f"{product_id}.{slug}.7z"
    bin_path = out_dir / bin_name
    archive_path = out_dir / archive_name
    manifest_path = out_dir / "platforms.json"

    click.echo(f"[*] indexing {winsxs_root} ...")
    t0 = time.perf_counter()
    df = _index(winsxs_root)
    click.echo(f"[*] indexed {len(df)} files in {time.perf_counter() - t0:.1f}s")
    if df.is_empty():
        raise click.ClickException("no files matched the WinSxS component-name regex; aborting.")

    # Filter to executables for the persisted DataFrame. The .7z gets
    # compressed AFTER the source dir is pruned, so its contents match.
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

    if not keep_non_executables:
        click.echo("[*] deleting non-executables from the source dir ...")
        freed = _cleanup_non_executables(winsxs_root)
        click.echo(f"[+] freed {freed // (1024 * 1024)} MB")

    click.echo(f"[*] compressing with {seven_zip} -> {archive_path}")
    _compress(Path(seven_zip), archive_path, winsxs_root)
    archive_size_mb = archive_path.stat().st_size // (1024 * 1024)
    click.echo(f"[+] archive ready: {archive_path} ({archive_size_mb} MB)")

    _update_manifest(
        manifest_path,
        product_id=product_id,
        msrc_product_ids=msrc_product_ids,
        slug=slug,
        archive_name=archive_name,
        dataframe_name=bin_name,
        product_name=product_name,
        msrc_month=msrc_month,
    )
    click.echo("[+] done.")
