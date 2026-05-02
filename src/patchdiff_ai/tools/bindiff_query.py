"""Read-only query surface over the per-pair `.BinDiff` SQLite files.

The pipeline drops one `.BinDiff` SQLite next to each primary binary
(`{primary_path}.{secondary_kb}.BinDiff`) plus matching `.BinExport`
files for both sides. Chat-agent tools call into this service to ask
post-pipeline questions about function matches, unmatched functions,
basic-block matches, and similarity statistics — without re-running
BinDiff or re-loading IDA.

Two layers of caching:
  - `BindiffFile` (cheap)  — SQLite-only; matches and counts.
  - `BinDiff`     (heavy)  — adds the two BinExport programs so we can
                              enumerate unmatched functions and walk
                              basic blocks.

The cheap layer covers `stats` and `function_matches`; the heavy layer
is opened lazily on first `unmatched` / `basic_blocks` request. Same
pattern as `DataframeRegistry`'s polars-frame cache.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from bindiff import BinDiff
from bindiff.file import BindiffFile

from patchdiff_ai.schemas.analysis import Artifact


def _bindiff_path(art: Artifact) -> Path:
    """Mirror of the convention in graphs/reverse_engineering/nodes.py."""
    return Path(f"{art.primary_file.path}.{art.secondary_file.kb}.BinDiff")


def _binexport_paths(art: Artifact) -> tuple[Path, Path]:
    return (
        Path(art.primary_file.path + ".BinExport"),
        Path(art.secondary_file.path + ".BinExport"),
    )


def _parse_addr(value: str) -> int:
    """Accept '0x18001b2080', '18001B2080', '18001b2080'."""
    s = value.strip().lower().removeprefix("0x")
    return int(s, 16)


def _bucket(value: float, edges: list[float]) -> str:
    """Map `value` into a labelled bucket (descending edges)."""
    for edge in edges:
        if value >= edge:
            return f">={edge}"
    return f"<{edges[-1]}"


class BindiffQueryService:
    """Lazy reader over the per-artifact `.BinDiff` files for one chat session."""

    # Bucket boundaries (descending) for similarity / confidence histograms.
    _SIM_EDGES: list[float] = [1.0, 0.9, 0.5]
    _CONF_EDGES: list[float] = [0.9, 0.5, 0.1]

    def __init__(self, artifacts: list[Artifact]) -> None:
        self._artifacts: list[Artifact] = list(artifacts)
        self._by_name: dict[str, Artifact] = {
            a.primary_file.name.lower(): a for a in self._artifacts
        }
        self._files: dict[str, BindiffFile] = {}
        self._diffs: dict[str, BinDiff] = {}

    # ------------------------------------------------------------------ public

    def list_pairs(self) -> list[dict[str, Any]]:
        """One row per artifact with primary/secondary identity + paths."""
        out: list[dict[str, Any]] = []
        for art in self._artifacts:
            bd = _bindiff_path(art)
            primary_be, secondary_be = _binexport_paths(art)
            out.append({
                "file": art.primary_file.name,
                "primary_kb": art.primary_file.kb,
                "secondary_kb": art.secondary_file.kb,
                "primary_path": str(art.primary_file.path),
                "secondary_path": str(art.secondary_file.path),
                "bindiff_path": str(bd),
                "primary_binexport": str(primary_be),
                "secondary_binexport": str(secondary_be),
                "exists": bd.is_file(),
                "changed_count": len(art.changed),
            })
        return out

    def stats(self, file: str) -> dict[str, Any]:
        bf = self._open_file(file)
        sim_buckets = {f">={e}": 0 for e in self._SIM_EDGES} | {
            f"<{self._SIM_EDGES[-1]}": 0
        }
        conf_buckets = {f">={e}": 0 for e in self._CONF_EDGES} | {
            f"<{self._CONF_EDGES[-1]}": 0
        }
        for fm in bf.primary_functions_match.values():
            sim_buckets[_bucket(fm.similarity, self._SIM_EDGES)] += 1
            conf_buckets[_bucket(fm.confidence, self._CONF_EDGES)] += 1
        return {
            "file": self._resolve(file).primary_file.name,
            "matched": len(bf.primary_functions_match),
            "unmatched_primary": bf.unmatched_primary_count,
            "unmatched_secondary": bf.unmatched_secondary_count,
            "primary_total_functions": (
                bf.primary_file.functions + bf.primary_file.libfunctions
            ),
            "secondary_total_functions": (
                bf.secondary_file.functions + bf.secondary_file.libfunctions
            ),
            "basic_block_matches": len(bf.basicblock_matches),
            "overall_similarity": bf.similarity,
            "overall_confidence": bf.confidence,
            "similarity_buckets": sim_buckets,
            "confidence_buckets": conf_buckets,
        }

    def function_matches(
        self,
        file: str,
        *,
        min_similarity: float = 0.0,
        max_similarity: float = 1.0,
        min_confidence: float = 0.0,
        name_contains: str = "",
        address: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> dict[str, Any]:
        bf = self._open_file(file)
        needle = name_contains.lower()
        addr_filter = _parse_addr(address) if address else None

        rows: list[dict[str, Any]] = []
        for fm in bf.primary_functions_match.values():
            if fm.similarity < min_similarity or fm.similarity > max_similarity:
                continue
            if fm.confidence < min_confidence:
                continue
            if needle and needle not in (fm.name1 or "").lower() and needle not in (fm.name2 or "").lower():
                continue
            if addr_filter is not None and fm.address1 != addr_filter and fm.address2 != addr_filter:
                continue
            rows.append({
                "address1": f"{fm.address1:X}",
                "address2": f"{fm.address2:X}",
                "name1": fm.name1,
                "name2": fm.name2,
                "similarity": fm.similarity,
                "confidence": fm.confidence,
            })

        rows.sort(key=lambda r: (r["similarity"], r["address1"]))
        total = len(rows)
        page = rows[offset : offset + max(1, int(limit))]
        next_offset = offset + len(page) if (offset + len(page)) < total else None
        return {
            "file": self._resolve(file).primary_file.name,
            "data": page,
            "total": total,
            "next_offset": next_offset,
        }

    def unmatched(
        self,
        file: str,
        *,
        side: str = "both",
        limit: int = 100,
        offset: int = 0,
    ) -> dict[str, Any]:
        if side not in ("primary", "secondary", "both"):
            return {"kind": "error", "error": f"side must be primary|secondary|both, got {side!r}"}
        diff = self._open_diff(file)
        rows: list[dict[str, Any]] = []
        if side in ("primary", "both"):
            for fn in diff.primary_unmatched_function():
                rows.append({"address": f"{fn.addr:X}", "name": fn.name, "side": "primary"})
        if side in ("secondary", "both"):
            for fn in diff.secondary_unmatched_function():
                rows.append({"address": f"{fn.addr:X}", "name": fn.name, "side": "secondary"})
        rows.sort(key=lambda r: (r["side"], r["address"]))
        total = len(rows)
        page = rows[offset : offset + max(1, int(limit))]
        next_offset = offset + len(page) if (offset + len(page)) < total else None
        return {
            "file": self._resolve(file).primary_file.name,
            "side": side,
            "data": page,
            "total": total,
            "next_offset": next_offset,
        }

    def basic_blocks(self, file: str, function_address: str) -> dict[str, Any]:
        diff = self._open_diff(file)
        addr1 = _parse_addr(function_address)
        fm = diff.primary_functions_match.get(addr1)
        if fm is None:
            return {
                "kind": "error",
                "error": (
                    f"No function match at primary address {function_address!r} "
                    f"in {self._resolve(file).primary_file.name}. Use "
                    "bindiff_function_matches to discover matched addresses."
                ),
            }
        # iter_basicblock_matches needs the BinExport function objects.
        try:
            f1 = diff.primary[fm.address1]
            f2 = diff.secondary[fm.address2]
        except KeyError:
            return {
                "kind": "error",
                "error": (
                    f"Function present in match table but missing from BinExport "
                    f"at {fm.address1:X} / {fm.address2:X}."
                ),
            }
        bbs: list[dict[str, Any]] = []
        for _bb1, _bb2, m in diff.iter_basicblock_matches(f1, f2):
            bbs.append({
                "address1": f"{m.address1:X}",
                "address2": f"{m.address2:X}",
                "algorithm": str(m.algorithm),
            })
        return {
            "file": self._resolve(file).primary_file.name,
            "function": {
                "address1": f"{fm.address1:X}",
                "address2": f"{fm.address2:X}",
                "name1": fm.name1,
                "name2": fm.name2,
                "similarity": fm.similarity,
                "confidence": fm.confidence,
            },
            "data": bbs,
            "total": len(bbs),
        }

    # ----------------------------------------------------------------- internal

    def _resolve(self, file: str) -> Artifact:
        art = self._by_name.get(file.lower())
        if art is None:
            available = sorted(self._by_name.values(), key=lambda a: a.primary_file.name)
            names = [a.primary_file.name for a in available]
            raise ValueError(
                f"No artifact for {file!r}. Available: {names}"
            )
        return art

    def _open_file(self, file: str) -> BindiffFile:
        art = self._resolve(file)
        key = art.primary_file.name.lower()
        cached = self._files.get(key)
        if cached is not None:
            return cached
        path = _bindiff_path(art)
        if not path.is_file():
            raise FileNotFoundError(
                f"BinDiff database missing on disk: {path}. The pipeline "
                "may have skipped this pair (re-run with --force)."
            )
        bf = BindiffFile(path, permission="ro")
        self._files[key] = bf
        return bf

    def _open_diff(self, file: str) -> BinDiff:
        art = self._resolve(file)
        key = art.primary_file.name.lower()
        cached = self._diffs.get(key)
        if cached is not None:
            return cached
        bd_path = _bindiff_path(art)
        primary_be, secondary_be = _binexport_paths(art)
        for label, p in (
            ("BinDiff", bd_path),
            ("primary BinExport", primary_be),
            ("secondary BinExport", secondary_be),
        ):
            if not p.is_file():
                raise FileNotFoundError(
                    f"{label} missing on disk: {p}. Required for unmatched / "
                    "basic-block queries."
                )
        diff = BinDiff(str(primary_be), str(secondary_be), str(bd_path))
        self._diffs[key] = diff
        # `BinDiff` super-init already loaded the same SQLite tables; share
        # it as the file-level cache too so a later `stats`/`function_matches`
        # call doesn't reopen the SQLite.
        self._files[key] = diff
        return diff
