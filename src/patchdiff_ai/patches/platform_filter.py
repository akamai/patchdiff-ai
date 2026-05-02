"""CVRF platform picking. No `input()` — picking is now a pure function."""

from __future__ import annotations

import re
import textwrap
from typing import Iterable, Sequence

import polars as pl
import requests
import structlog

log = structlog.get_logger(__name__)

TOKEN = re.compile(r"[^a-z0-9]+")


def words(text: str) -> list[str]:
    return TOKEN.sub(" ", text.lower()).split()


def download_cvrf(month: str) -> dict:
    """Fetch the CVRF for `YYYY-MMM`."""
    res = requests.get(
        f"https://api.msrc.microsoft.com/cvrf/{month}",
        headers={"Accept": "application/json"},
        timeout=30,
    )
    res.raise_for_status()
    return res.json()


def product_pool(cvrf: dict) -> Sequence[dict]:
    return cvrf["ProductTree"]["FullProductName"]


def full_token_matches(needle_tokens: set[str], candidates: Iterable[dict]) -> list[dict]:
    return [p for p in candidates if needle_tokens.issubset(words(p["Value"]))]


def pick_ids(
    cvrf: dict,
    query: str | None,
    ids: set[str],
) -> tuple[set[str], list[str]]:
    """Pure version of legacy `pick_ids`: never prompts; if query is ambiguous,
    selects the highest-scoring match."""
    name_by_id = {p["ProductID"]: p["Value"] for p in cvrf["ProductTree"]["FullProductName"]}
    chosen_names = [name_by_id[i] for i in ids if i in name_by_id]

    if query:
        tokens = set(words(query))
        pool = product_pool(cvrf)
        hits = full_token_matches(tokens, pool)
        if hits:
            names = sorted({h["Value"] for h in hits})
            chosen = names[0]
            ids = set(ids)
            ids.update(p["ProductID"] for p in hits if p["Value"] == chosen)
            chosen_names.append(chosen)
        else:
            scored = sorted(
                pool,
                key=lambda p: len(tokens & set(words(p["Value"]))),
                reverse=True,
            )[:1]
            if scored:
                ids = set(ids)
                ids.add(scored[0]["ProductID"])
                chosen_names.append(scored[0]["Value"])

    return ids, chosen_names


def get_platforms_by_ids(ids: set[str]) -> set[tuple[str, int]]:
    """Resolve product IDs against the latest CVRF."""
    from patchdiff_ai.patches.os_detection import get_cvrf_data, load_product_tree

    data = get_cvrf_data()
    name_by_id = {str(k): v for k, v in load_product_tree(data).items()}
    return {(name_by_id.get(str(i), str(i)), int(i)) for i in ids}


def collect_cves(cvrf: dict, wanted: set[str]) -> list[dict]:
    rows = []
    for v in cvrf["Vulnerability"]:
        affected = set()
        for st in v.get("ProductStatuses", []):
            pids = st.get("ProductID", [])
            if isinstance(pids, str):
                pids = [pids]
            affected.update(pids)
        if not (affected & wanted):
            continue

        title = v["Title"]
        cvss_scores = [
            (x or {}).get("BaseScore", 0)
            for x in v["CVSSScoreSets"]
            if set(x["ProductID"]) & wanted
        ] or [None]
        rows.append(
            {
                "CVE": v["CVE"],
                "CVSS": cvss_scores[0],
                "Title": title["Value"] if isinstance(title, dict) else title,
            }
        )
    return rows


def get_pt_cve_list_by_platform(
    month: str, targets: set[str], name: str | None = None
) -> tuple[pl.DataFrame, list[str], set[str]]:
    data = download_cvrf(month)
    targets, names = pick_ids(data, name, targets)
    records = collect_cves(data, targets)
    return pl.DataFrame(records).sort("CVE"), names, targets


def print_cve_list(df: pl.DataFrame) -> str:
    wrapped = df.with_columns(
        pl.col("Title").map_elements(
            lambda s: "\n".join(textwrap.wrap(s, 60)),
            return_dtype=pl.Utf8,
        )
    )
    with pl.Config(tbl_rows=wrapped.height, tbl_cols=wrapped.width, fmt_str_lengths=200):
        return str(wrapped)
