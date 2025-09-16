from pathlib import Path

from patch_analysis.files_collection import get_file_hash, get_pe_ms_id, version_tuple
from patch_extractor import patch_tools
from common import logger, PatchStoreEntry, console
import polars as pl

pt = patch_tools.PatchTools()


def recursive_patch(base, patch):
    try:
        while pt.is_patch(patch):
            try:
                patch = pt.apply(memoryview(base), memoryview(patch))
            except RuntimeError:
                patch = pt.apply(None, memoryview(patch))
    except RuntimeError:
        return None

    return patch


def patch_entry(entry: dict,
                base_kb: str,
                curr_kb: str,
                prev_kb: str,
                prev_df: pl.DataFrame,
                filtered_base_df: pl.DataFrame
                ) -> tuple[PatchStoreEntry | None, PatchStoreEntry | None, PatchStoreEntry | None]:
    collect_files: dict[str, Path] = {}
    entry_df = pl.DataFrame([entry])

    base_path = Path('db') / 'patch_store' / f"{entry['arch']}_{entry['package']}_{entry['pubkey']}" / entry['name']

    base_kb_path = base_path / base_kb

    base_entry = None
    curr_entry = None
    prev_entry = None

    if not (base_kb_path / entry['name']).exists():
        winsxs_patch = filtered_base_df.join(
            entry_df,
            on=['name', 'package', 'arch', 'pubkey'],
            how='semi')

        if winsxs_patch.is_empty():
            return base_entry, curr_entry, prev_entry

        collect_files['reverse_delta'] = Path(winsxs_patch.item(0, column="path"))
        collect_files['current'] = collect_files['reverse_delta'].parents[1] / winsxs_patch.item(0, column="name")

        current = collect_files['current'].open('rb').read()
        reverse = collect_files['reverse_delta'].open('rb').read()

        base = recursive_patch(current, reverse)

        if base is None:
            console.error(f"[-] Patching base {entry['name']} failed")
            return base_entry, curr_entry, prev_entry

        base_kb_path.mkdir(parents=True, exist_ok=True)

        (base_kb_path / entry['name']).write_bytes(base)

        console.debug(f'[+] {entry["name"]} base is patched')

        base_entry = PatchStoreEntry(
            path=str(base_kb_path / entry['name']),
            kb=base_kb,
            hash=get_file_hash(base),
            ms_id=get_pe_ms_id(base),
            version=version_tuple(base_kb)
        )
        base_entry.from_dict(winsxs_patch.row(0, named=True))
    else:
        # logger.debug(f'[+] {base_path} is already exist, skip patch')
        base = (base_kb_path / entry['name']).read_bytes()

    if not (base_path / curr_kb / entry['name']).exists():
        collect_files['new_delta'] = Path(entry['path'])

        np = pt.map_file(collect_files['new_delta'])
        np = recursive_patch(base, np)

        if np:
            (base_path / curr_kb).mkdir(parents=True, exist_ok=True)
            (base_path / curr_kb / entry['name']).write_bytes(np)

            console.debug(f'[+] {curr_kb} {entry["name"]} is patched')
            curr_entry = PatchStoreEntry(
                path=str(base_path / curr_kb / entry['name']),
                kb=curr_kb,
                hash=get_file_hash(np),
                ms_id=get_pe_ms_id(np)
            )
            curr_entry.from_dict(entry)
        else:
            console.error(f"[-] Patching {curr_kb} {entry['name']} failed")

    if not (base_path / prev_kb / entry['name']).exists():
        old_patch = prev_df.join(
            entry_df,
            on=['name', 'package', 'arch', 'pubkey'],
            how='semi')

        if old_patch.is_empty():
            logger.debug(f'Cannot find near patch for {entry["name"]}, fallback to base')
        else:
            collect_files['previous_delta'] = Path(old_patch.item(0, column="path"))

            op = pt.map_file(collect_files['previous_delta'])
            op = recursive_patch(base, op)

            if op:
                (base_path / prev_kb).mkdir(parents=True, exist_ok=True)
                (base_path / prev_kb / entry['name']).write_bytes(op)

                console.debug(f'[+] {prev_kb} {entry["name"]} is patched')

                prev_entry = PatchStoreEntry(
                    path=str(base_path / prev_kb / entry['name']),
                    kb=prev_kb,
                    hash=get_file_hash(op),
                    ms_id=get_pe_ms_id(op)
                )
                prev_entry.from_dict(old_patch.row(0, named=True))
            else:
                console.debug(f"[-] Patching {prev_kb} {entry['name']} failed")

    return base_entry, curr_entry, prev_entry
