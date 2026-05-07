"""One-shot fix for legacy `.patch_store_df` files written with absolute paths.

The current code writes the `path` column relative to `paths.patch_store_dir`
(forward-slashed), e.g. `windows10_22h2/amd64_microsoft-windows-clfs_31bf.../clfs.sys/<KB>/clfs.sys`.
Older runs stored absolute paths, which don't survive a data-root move.

This script rebuilds the `path` column from the canonical row fields so it
matches what `delta_apply._entry_path_relative` produces, then re-serializes
the DataFrame in place (with a `.bak` of the original).

Usage:
    python resources/fix_legacy_patch_store.py <path-to-.patch_store_df> [--dry-run]
"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

import polars as pl


def relative_path(row: dict) -> str:
    folder = f"{row['arch']}_{row['package']}_{row['pubkey']}"
    return f"{row['platform']}/{folder}/{row['name']}/{row['kb']}/{row['name']}"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("path", type=Path, help="Path to .patch_store_df")
    ap.add_argument("--dry-run", action="store_true", help="Print sample without writing")
    args = ap.parse_args()

    df = pl.DataFrame.deserialize(args.path)
    if df.is_empty():
        print(f"[*] {args.path} is empty; nothing to do.")
        return

    fixed = df.with_columns(
        pl.struct("platform", "arch", "package", "pubkey", "name", "kb")
        .map_elements(relative_path, return_dtype=pl.Utf8)
        .alias("path")
    )

    print(f"[*] {len(df)} rows; before -> after (first 3):")
    for before, after in zip(df["path"].to_list()[:3], fixed["path"].to_list()[:3]):
        print(f"    - {before}\n      {after}")

    if args.dry_run:
        print("[=] dry-run; no changes written.")
        return

    backup = args.path.with_suffix(args.path.suffix + ".bak")
    shutil.copy2(args.path, backup)
    fixed.serialize(args.path, format="binary")
    print(f"[+] rewrote {args.path} (backup at {backup})")


if __name__ == "__main__":
    main()
