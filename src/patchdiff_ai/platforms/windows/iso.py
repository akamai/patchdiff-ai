"""Windows installer ISO + install.wim helpers for the indexer.

Used by `patchdiff-ai windows index` when the user passes an `.iso`
instead of a pre-extracted WinSxS folder. All functions are async and
go through `SevenZipTool` (i.e. `tools/process.py:run`) so subprocess
discipline (timeouts, no shell=True, structured errors) is uniform.
"""

from __future__ import annotations

import tempfile
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

import click
import structlog

from patchdiff_ai.tools.seven_zip import SevenZipTool

log = structlog.get_logger(__name__)


@dataclass(frozen=True)
class ImageInfo:
    """One <IMAGE> entry from install.wim's [1].xml metadata."""

    index: int
    name: str
    edition_id: str
    version_str: str
    arch: str

    def label(self) -> str:
        edition = self.edition_id or "?"
        ver = self.version_str or "?"
        return f"#{self.index}: {self.name} — {edition} ({ver})"


# --- ISO validation ----------------------------------------------------------

# A Windows installer ISO has install.wim plus at least one of these
# top-level boot artifacts. Linux live ISOs and generic data ISOs lack them.
_WINDOWS_ISO_MARKERS = ("setup.exe", "bootmgr", "boot/bcd")


async def validate_iso(seven_zip: SevenZipTool, iso: Path) -> None:
    """Raise `click.ClickException` if `iso` doesn't look like a Windows
    installer ISO (must contain `sources/install.wim` plus a boot marker)."""
    rc, files, stderr = await seven_zip.list_files(iso)
    if rc != 0:
        raise click.ClickException(
            f"7z failed to list {iso} (rc={rc}): {stderr.strip() or '<no stderr>'}"
        )
    norm = {f.replace("\\", "/").lower() for f in files}
    if "sources/install.wim" not in norm:
        raise click.ClickException(
            f"{iso} doesn't contain sources/install.wim — not a Windows installer ISO."
        )
    if not any(m in norm for m in _WINDOWS_ISO_MARKERS):
        raise click.ClickException(
            f"{iso} has install.wim but no boot marker ({', '.join(_WINDOWS_ISO_MARKERS)}). "
            f"Refusing — looks like a malformed or repacked ISO."
        )


async def extract_install_wim(
    seven_zip: SevenZipTool, iso: Path, dest_dir: Path
) -> Path:
    """Extract `sources/install.wim` from the ISO into `dest_dir`. Returns
    the full path to the extracted WIM. `dest_dir` must already exist."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    click.echo(f"[*] extracting sources/install.wim from {iso.name} ...")
    t0 = time.perf_counter()
    # `e` (flat) so install.wim lands directly in dest_dir, not under sources/.
    res = await seven_zip.extract_by_list(
        iso, ["sources/install.wim"], dest_dir, flat=True
    )
    if res.returncode != 0:
        raise click.ClickException(
            f"7z failed to extract install.wim from {iso} (rc={res.returncode})"
        )
    wim = dest_dir / "install.wim"
    if not wim.exists():
        raise click.ClickException(
            f"install.wim not found at {wim} after extraction; check 7z output."
        )
    click.echo(f"[+] extracted install.wim ({wim.stat().st_size // (1024*1024)} MB) "
               f"in {time.perf_counter() - t0:.1f}s")
    return wim


# --- WIM image enumeration ---------------------------------------------------

def _decode_wim_xml(data: bytes) -> str:
    """WIM XML metadata is UTF-16LE with BOM. Some custom WIMs use UTF-8.
    Try the standard form first, fall back to UTF-8."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16")
    try:
        return data.decode("utf-16")
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace")


def _parse_images(xml_text: str) -> list[ImageInfo]:
    """Parse the [1].xml WIM metadata into ImageInfo records."""
    root = ET.fromstring(xml_text)
    out: list[ImageInfo] = []
    for img in root.findall("IMAGE"):
        try:
            idx = int(img.get("INDEX") or "0")
        except ValueError:
            continue
        if idx <= 0:
            continue
        name = (img.findtext("NAME") or "").strip()
        windows_el = img.find("WINDOWS")
        edition_id = ""
        version_str = ""
        arch = ""
        if windows_el is not None:
            edition_id = (windows_el.findtext("EDITIONID") or "").strip()
            arch = (windows_el.findtext("ARCH") or "").strip()
            ver = windows_el.find("VERSION")
            if ver is not None:
                parts = [
                    (ver.findtext("MAJOR") or "").strip(),
                    (ver.findtext("MINOR") or "").strip(),
                    (ver.findtext("BUILD") or "").strip(),
                    (ver.findtext("SPBUILD") or "").strip(),
                ]
                version_str = ".".join(p for p in parts if p)
        out.append(ImageInfo(
            index=idx,
            name=name,
            edition_id=edition_id,
            version_str=version_str,
            arch=arch,
        ))
    out.sort(key=lambda i: i.index)
    return out


async def read_wim_images(seven_zip: SevenZipTool, wim: Path) -> list[ImageInfo]:
    """Extract `[1].xml` from the WIM, parse it, return one record per image."""
    with tempfile.TemporaryDirectory(prefix="wim_xml_") as tmp:
        tmp_dir = Path(tmp)
        # `[` is a wildcard char in 7z — quoting via the list-file form
        # (extract_by_list) avoids that. Flat extract puts it at <tmp>/[1].xml.
        res = await seven_zip.extract_by_list(wim, ["[1].xml"], tmp_dir, flat=True)
        if res.returncode != 0:
            raise click.ClickException(
                f"7z failed to extract [1].xml from {wim} (rc={res.returncode}); "
                f"WIM may be corrupt or non-standard."
            )
        xml_path = tmp_dir / "[1].xml"
        if not xml_path.exists():
            raise click.ClickException(
                f"[1].xml not found at {xml_path} after extraction; "
                f"7z may not have followed the WIM XML convention."
            )
        text = _decode_wim_xml(xml_path.read_bytes())
    images = _parse_images(text)
    if not images:
        raise click.ClickException(
            f"{wim} has no <IMAGE> entries in [1].xml — not a Windows install image."
        )
    return images


# --- WinSxS listing ----------------------------------------------------------

async def wim_winsxs_files(
    seven_zip: SevenZipTool, wim: Path, image_index: int
) -> list[str]:
    """List every file under `<image_index>/Windows/WinSxS/` in the WIM.

    Returns forward-slash, WIM-relative paths with the `<idx>/Windows/WinSxS/`
    prefix kept — those strings go straight to `extract_by_list`'s include
    list. Use `strip_wim_prefix` to derive the dataframe-side relatives.
    """
    rc, all_files, stderr = await seven_zip.list_files(wim)
    if rc != 0:
        raise click.ClickException(
            f"7z failed to list {wim} (rc={rc}): {stderr.strip() or '<no stderr>'}"
        )
    prefix_lc = f"{image_index}/windows/winsxs/"
    out: list[str] = []
    for raw in all_files:
        norm = raw.replace("\\", "/")
        if norm.lower().startswith(prefix_lc):
            out.append(norm)
    return out


def strip_wim_prefix(paths: list[str], image_index: int) -> list[str]:
    """Drop `<image_index>/Windows/WinSxS/` from each path. Case-insensitive
    on the prefix (WIM listings can use mixed case for `Windows`)."""
    prefix_lc = f"{image_index}/windows/winsxs/"
    out: list[str] = []
    for p in paths:
        norm = p.replace("\\", "/")
        if norm.lower().startswith(prefix_lc):
            out.append(norm[len(prefix_lc):])
    return out
