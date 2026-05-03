"""MSRC CVRF helpers for Patch Tuesday batch enumeration.

Moved from the now-defunct top-level `patches/platform_filter.py`. Lives
inside the windows plugin because Patch Tuesday is an MSRC-only concept.
Consumers: `windows month` (in `cli.py`) and the legacy `cached --month`
flow in `cli/commands/cached.py`.
"""

from __future__ import annotations

import re
from typing import Iterable, Sequence

import requests
import structlog

log = structlog.get_logger(__name__)

MONTH_RE = re.compile(
    r"^\d{4}-(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$",
    re.IGNORECASE,
)
TOKEN = re.compile(r"[^a-z0-9]+")


def normalize_month(value: str) -> str:
    """Validate and canonicalise a `YYYY-MMM` Patch Tuesday tag."""
    if not MONTH_RE.match(value):
        raise ValueError(
            "Invalid month format; expected YYYY-MMM (e.g. 2025-Jul)"
        )
    year, mon = value.split("-")
    return f"{year}-{mon.capitalize()}"


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
    """Pure picker: never prompts; if `query` is ambiguous, picks the
    highest-scoring product by token overlap."""
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


