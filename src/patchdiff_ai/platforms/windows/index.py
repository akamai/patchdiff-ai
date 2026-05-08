"""`patchdiff-ai windows index` — index a per-Windows-version WinSxS dump.

Produces ``{product_id}.{slug}.bin`` (polars DataFrame of executables) and,
in archive mode, ``{product_id}.{slug}.7z``. Outputs land in
``settings.paths.windows_sxs_dir`` and `platforms.json` is updated in place.

Two source modes:
  * **folder**: a pre-extracted WinSxS dump on disk. The indexer walks
    the source, builds the dataframe, then copies only the executables
    we kept into the working dir.
  * **iso**: a Windows installer ISO. The indexer extracts
    ``sources/install.wim``, parses ``[1].xml`` to enumerate images,
    prompts the user to pick one, lists its WinSxS, builds the
    dataframe from names alone, then extracts exactly those files
    via ``7z -i@list``.

Two output modes:
  * ``--type directory`` (default): keep files on disk, manifest points at
    the staged folder. Faster, larger footprint.
  * ``--type archive``: compress executables into a .7z; runtime extracts
    on demand.

The user's input folder is never modified — every run produces a fresh
working copy under ``<windows_sxs_dir>/<slug>/``.
"""

from __future__ import annotations

import asyncio
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
from patchdiff_ai.observability.progress import ProgressHandle, ProgressReporter, make_reporter
from patchdiff_ai.patches.files_collection import (
    EXECUTABLE_EXTENSIONS,
    generate_df,
    get_files_from_names,
    rebase_paths,
)
from patchdiff_ai.patches.os_detection import get_cvrf_data, load_product_tree
from patchdiff_ai.persistence.patch_store import safe_serialize
from patchdiff_ai.platforms.windows.cycle import normalize_month
from patchdiff_ai.platforms.windows.iso import (
    ImageInfo,
    extract_install_wim,
    read_wim_images,
    strip_wim_prefix,
    validate_iso,
    wim_winsxs_files,
)
from patchdiff_ai.tools.seven_zip import SevenZipTool

log = structlog.get_logger(__name__)

_TOKEN_RE = re.compile(r"[^a-z0-9]+")


def _tokens(text: str) -> set[str]:
    """Same tokeniser the CVRF matcher uses, so MSRC names and queries
    decompose into the same units."""
    return {t for t in _TOKEN_RE.sub(" ", text.lower()).split() if t}


def _default_msrc_month() -> str:
    return (datetime.now() - relativedelta(months=1)).strftime("%Y-%b")


def _slug_default_from_image(img: ImageInfo) -> str:
    """Sanitised slug suggestion derived from the chosen WIM image."""
    raw = f"{img.edition_id}_{img.version_str}".lower()
    return re.sub(r"[^a-z0-9]+", "_", raw).strip("_") or f"image_{img.index}"


def _index_folder(
    winsxs_root: Path, *, slug: str, progress: ProgressHandle | None
) -> pl.DataFrame:
    """Walk the dump and return a DataFrame with paths relative to ``winsxs_root``.

    `generate_df` materialises the rglob list and forwards the progress
    handle to `get_files`, so the bar advances per file.
    """
    df = generate_df(slug, winsxs_root, collect_hash=False, progress=progress)
    if df.is_empty():
        return df
    return rebase_paths(df, root=winsxs_root, to_relative=True)


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


def _check_paths(source: Path, target: Path) -> None:
    """Refuse source==target and target-inside-source — both would corrupt
    the user's input folder."""
    src_r = source.resolve()
    tgt_r = target.resolve()
    if src_r == tgt_r:
        raise click.ClickException(
            f"source path {source} is the same as the working location "
            f"{target}. Pick a different --slug, or move the source "
            f"outside windows_sxs_dir — the indexer must not modify your source."
        )
    if tgt_r.is_relative_to(src_r):
        raise click.ClickException(
            f"working location {target} is inside the source path "
            f"{source}; copying would recurse. Move the source or set "
            f"`paths.windows_sxs_dir` outside it."
        )


def _should_reuse(working_dir: Path, force_recopy: bool) -> bool:
    """Slug-as-cache-key: skip the copy step if `working_dir` already
    has files and the user didn't pass `--force-recopy`."""
    return (
        working_dir.exists()
        and any(working_dir.iterdir())
        and not force_recopy
    )


def _copy_executables(
    source: Path,
    working_dir: Path,
    exec_df: pl.DataFrame,
    progress: ProgressHandle | None,
) -> None:
    """Copy each row's file from `source` to `working_dir`, preserving
    relative layout. Bar advances once per file."""
    if progress is not None:
        progress.set_total(len(exec_df))
    working_dir.mkdir(parents=True, exist_ok=True)
    paths = exec_df["path"].to_list()
    for rel in paths:
        src = source / rel
        dst = working_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        if progress is not None:
            progress.advance(1)
    if progress is not None:
        progress.complete()


def _filter_executables(df: pl.DataFrame) -> pl.DataFrame:
    return df.filter(
        pl.any_horizontal([
            pl.col("name").str.to_lowercase().str.ends_with(ext)
            for ext in EXECUTABLE_EXTENSIONS
        ])
    )


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


# --- folder branch -----------------------------------------------------------

def _run_folder(
    *,
    winsxs_root: Path,
    working_dir: Path,
    slug: str,
    progress: ProgressReporter,
    force_recopy: bool,
) -> pl.DataFrame:
    """Index the source folder and stage executables under `working_dir`.

    Order: index source → filter executables → copy (or reuse) → return df.
    """
    _check_paths(winsxs_root, working_dir)

    click.echo(f"[*] indexing {winsxs_root} ...")
    t0 = time.perf_counter()
    df = _index_folder(
        winsxs_root, slug=slug, progress=progress.index_task(f"walk {slug}")
    )
    click.echo(f"[*] indexed {len(df)} files in {time.perf_counter() - t0:.1f}s")
    if df.is_empty():
        raise click.ClickException("no files matched the WinSxS component-name regex; aborting.")

    exec_df = _filter_executables(df)
    click.echo(
        f"[*] keeping {len(exec_df)} executables "
        f"(dropped {len(df) - len(exec_df)} non-executables)"
    )

    if _should_reuse(working_dir, force_recopy):
        click.echo(f"[=] reusing existing working copy at {working_dir} (pass --force-recopy to rebuild)")
    else:
        if working_dir.exists():
            click.echo(f"[*] removing stale working copy at {working_dir}")
            _force_rmtree(working_dir)
        click.echo(f"[*] copying {len(exec_df)} executables -> {working_dir} ...")
        t0 = time.perf_counter()
        _copy_executables(
            winsxs_root, working_dir, exec_df,
            progress=progress.index_task(f"copy {slug}"),
        )
        click.echo(f"[+] copied in {time.perf_counter() - t0:.1f}s")

    return exec_df


# --- iso branch --------------------------------------------------------------

async def _run_iso_pipeline(
    *,
    iso: Path,
    out_dir: Path,
    slug_hint: str,
    image_index: int | None,
    seven_zip: SevenZipTool,
    progress: ProgressReporter,
) -> tuple[pl.DataFrame, ImageInfo, Path]:
    """Validate ISO → extract install.wim → pick image → list WinSxS →
    build df from names → extract by list → rename into final slug folder.

    Returns ``(exec_df, chosen_image, working_dir)``. The slug used for
    the working_dir is computed from the image AFTER pick, so callers
    can derive a sensible default if `--slug` was omitted.
    """
    iso_staging = out_dir / f".{slug_hint}.iso_staging"
    iso_staging.mkdir(parents=True, exist_ok=True)

    try:
        click.echo(f"[*] validating {iso} ...")
        await validate_iso(seven_zip, iso)
        click.echo("[+] looks like a Windows installer ISO")

        wim_path = await extract_install_wim(seven_zip, iso, iso_staging)

        click.echo("[*] reading WIM image metadata ([1].xml) ...")
        images = await read_wim_images(seven_zip, wim_path)
        click.echo(f"[+] found {len(images)} images")

        if image_index is not None:
            chosen = next((i for i in images if i.index == image_index), None)
            if chosen is None:
                avail = ", ".join(str(i.index) for i in images)
                raise click.ClickException(
                    f"--image-index {image_index} not in WIM (available: {avail})"
                )
        else:
            with progress.pause():
                opts = [(img.index, img.label()) for img in images]
                picked = _interactive_pick(opts)
            chosen_idx = picked[0][0]
            chosen = next(i for i in images if i.index == chosen_idx)
        click.echo(f"[+] selected image #{chosen.index}: {chosen.label()}")

        click.echo(f"[*] listing WinSxS files in image #{chosen.index} ...")
        t0 = time.perf_counter()
        wim_paths = await wim_winsxs_files(seven_zip, wim_path, chosen.index)
        click.echo(f"[+] listed {len(wim_paths)} entries in {time.perf_counter() - t0:.1f}s")
        if not wim_paths:
            raise click.ClickException(
                f"image #{chosen.index} has no Windows/WinSxS/ entries — "
                f"this image isn't a full Windows install."
            )

        rel_paths = strip_wim_prefix(wim_paths, chosen.index)

        click.echo("[*] building dataframe from WIM listing ...")
        t0 = time.perf_counter()
        idx_handle = progress.index_task(f"index {slug_hint}")
        idx_handle.set_total(len(rel_paths))
        rows = get_files_from_names(slug_hint, rel_paths, progress=idx_handle)
        idx_handle.complete()
        df = pl.DataFrame(
            rows, schema_overrides={"delta_type": pl.Utf8, "hash": pl.Utf8}
        )
        click.echo(
            f"[*] indexed {len(df)} rows (from {len(rel_paths)} listings) "
            f"in {time.perf_counter() - t0:.1f}s"
        )
        if df.is_empty():
            raise click.ClickException(
                "no files matched the WinSxS component-name regex; aborting."
            )

        exec_df = _filter_executables(df)
        click.echo(
            f"[*] keeping {len(exec_df)} executables "
            f"(dropped {len(df) - len(exec_df)} non-executables)"
        )
        if exec_df.is_empty():
            raise click.ClickException("no executables in the listing; aborting.")

        wim_relatives = [
            f"{chosen.index}/Windows/WinSxS/{p}" for p in exec_df["path"].to_list()
        ]
        click.echo(f"[*] extracting {len(wim_relatives)} executables from WIM ...")
        t0 = time.perf_counter()
        res = await seven_zip.extract_by_list(
            wim_path, wim_relatives, iso_staging, flat=False
        )
        if res.returncode != 0:
            raise click.ClickException(
                f"7z failed to extract executables (rc={res.returncode}) from {wim_path}"
            )
        click.echo(f"[+] extracted in {time.perf_counter() - t0:.1f}s")

        # Promote the extracted tree to <out_dir>/<slug>/.
        winsxs_subtree = iso_staging / str(chosen.index) / "Windows" / "WinSxS"
        if not winsxs_subtree.is_dir():
            raise click.ClickException(
                f"expected extracted WinSxS at {winsxs_subtree} but it's missing — "
                f"7z output may have been redirected unexpectedly."
            )
        working_dir = out_dir / slug_hint
        if working_dir.exists():
            click.echo(f"[*] removing stale working copy at {working_dir}")
            _force_rmtree(working_dir)
        os.replace(winsxs_subtree, working_dir)
        click.echo(f"[+] staged at {working_dir}")
        return exec_df, chosen, working_dir
    finally:
        if iso_staging.exists():
            _force_rmtree(iso_staging)


# --- click entry -------------------------------------------------------------

@click.command(
    "index",
    help=(
        "Index + pack a per-Windows-version WinSxS source into windows_sxs_dir.\n\n"
        "SOURCE may be either a pre-extracted WinSxS folder OR a Windows "
        "installer .iso (the indexer extracts sources/install.wim, prompts "
        "for an image, and pulls the WinSxS tree from it)."
    ),
)
@click.argument(
    "winsxs_path",
    type=click.Path(exists=True, path_type=Path),
)
@click.option(
    "--product-name",
    default=None,
    help="MSRC product-name query (e.g. 'Windows 11 Version 24H2'). "
         "Tokenised + matched against the monthly CVRF; matching products "
         "are presented interactively. ISO mode auto-derives this from the "
         "chosen WIM image when omitted; folder mode prompts for it.",
)
@click.option(
    "--slug",
    default=None,
    help="Descriptive identifier (e.g. windows_11_24h2). Prompted when omitted.",
)
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
    "--image-index",
    type=int,
    default=None,
    help="ISO mode only. Pre-pick the WIM image by index (skip the interactive prompt).",
)
@click.option(
    "--force-recopy",
    is_flag=True,
    default=False,
    help="Folder mode only. Wipe and rebuild the working copy even if one already "
         "exists for this slug.",
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
    product_name: str | None,
    slug: str | None,
    msrc_month: str | None,
    product_ids: str | None,
    image_index: int | None,
    force_recopy: bool,
    archive_type: str,
) -> None:
    settings = get_settings()
    settings.paths.ensure()

    seven_zip = settings.tools.seven_zip
    if not Path(seven_zip).exists():
        # 7z is needed for ISO mode and for archive output. Folder/directory
        # mode could in principle skip the check, but we never get here
        # without 7z being a hard dependency anyway.
        if archive_type == "archive" or winsxs_path.is_file():
            raise click.ClickException(
                f"7-Zip not found at {seven_zip}. Set `tools.seven_zip` in config.json "
                f"or `TOOLS__SEVEN_ZIP=...` env var."
            )

    is_iso = winsxs_path.is_file() and winsxs_path.suffix.lower() == ".iso"
    if winsxs_path.is_file() and not is_iso:
        raise click.ClickException(
            f"{winsxs_path} is a file but not an .iso. Pass either a WinSxS folder "
            f"or a Windows installer ISO."
        )

    msrc_month = _parse_msrc_month(msrc_month) if msrc_month else _default_msrc_month()
    out_dir = settings.paths.windows_sxs_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = out_dir / "platforms.json"

    with make_reporter() as progress:
        # ----------------------------------------------------------------
        # Branch A: ISO mode — image pick happens BEFORE slug/product-name
        # so we can suggest sensible defaults derived from the image.
        # ----------------------------------------------------------------
        if is_iso:
            sevenz = SevenZipTool(Path(seven_zip))
            slug_hint = slug or f"image_{image_index or 'pending'}"
            exec_df, image, working_dir = asyncio.run(_run_iso_pipeline(
                iso=winsxs_path,
                out_dir=out_dir,
                slug_hint=slug_hint,
                image_index=image_index,
                seven_zip=sevenz,
                progress=progress,
            ))

            # If the user didn't pre-pick a slug, the staging used a
            # placeholder; now that we know the image, derive a real slug
            # and rename the working dir.
            if not slug:
                with progress.pause():
                    default_slug = _slug_default_from_image(image)
                    slug = click.prompt("slug", default=default_slug, show_default=True).strip()
                if slug != slug_hint:
                    new_wd = out_dir / slug
                    if new_wd.exists():
                        click.echo(f"[*] removing stale working copy at {new_wd}")
                        _force_rmtree(new_wd)
                    os.replace(working_dir, new_wd)
                    working_dir = new_wd

            if not product_name:
                product_name = f"{image.name} ({image.edition_id})".strip(" ()")
                click.echo(f"[+] product-name auto-derived: {product_name!r}")

        # ----------------------------------------------------------------
        # Branch B: folder mode — slug/product-name prompted up-front.
        # ----------------------------------------------------------------
        else:
            if not slug:
                with progress.pause():
                    slug = click.prompt("slug").strip()
            if not product_name and not product_ids:
                with progress.pause():
                    product_name = click.prompt(
                        "MSRC product name (e.g. 'Windows 11 Version 24H2')"
                    ).strip()
            working_dir = out_dir / slug

            exec_df = _run_folder(
                winsxs_root=winsxs_path.resolve(),
                working_dir=working_dir,
                slug=slug,
                progress=progress,
                force_recopy=force_recopy,
            )

        # ----------------------------------------------------------------
        # Shared: resolve product IDs, serialize df, optional compress, manifest.
        # ----------------------------------------------------------------
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
            with progress.pause():
                product_id, msrc_product_ids = _resolve_product_ids(
                    product_name or "", msrc_month
                )

        bin_name = f"{product_id}.{slug}.bin"
        bin_path = out_dir / bin_name
        safe_serialize(exec_df, bin_path)
        click.echo(f"[+] wrote DataFrame -> {bin_path}")

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
