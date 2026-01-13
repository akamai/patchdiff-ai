#!/usr/bin/env python3
import argparse, json, re, sys
import textwrap
from pathlib import Path
from typing import Iterable, Sequence

import polars as pl
import requests

from common import logger

TOKEN = re.compile(r"[^a-z0-9]+")


def words(text: str) -> list[str]:
    return TOKEN.sub(" ", text.lower()).split()


def download(month: str) -> dict:
    res = requests.get(
        f"https://api.msrc.microsoft.com/cvrf/{month}",
        headers={"Accept": "application/json"},
        timeout=30,
    )
    if res.status_code != 200:
        sys.exit(f"HTTP {res.status_code}: {res.text[:120]}")
    try:
        return res.json()
    except json.JSONDecodeError:
        sys.exit("Server did not return JSON")


def product_pool(cvrf: dict) -> Sequence[dict]:
    return cvrf["ProductTree"]["FullProductName"]


def full_token_matches(
        needle_tokens: set[str], candidates: Iterable[dict]
) -> list[dict]:
    hits = []
    for p in candidates:
        if needle_tokens.issubset(words(p["Value"])):
            hits.append(p)
    return hits


def interactive_pick(options: Sequence[str]) -> str:
    print("Possible matches:")
    for i, name in enumerate(options, 1):
        print(f"{i}) {name}")
    sel = input(f"Choose 1-{len(options)} [1]: ").strip()
    try:
        idx = int(sel) - 1
    except ValueError:
        idx = 0
    if not 0 <= idx < len(options):
        idx = 0
    return options[idx]


def pick_ids(
        cvrf: dict,
        query: str | None,
        ids: set[str],
) -> tuple[set[str], list[str]]:
    name_by_id = {
        p["ProductID"]: p["Value"]
        for p in cvrf["ProductTree"]["FullProductName"]
    }
    chosen_names: list[str] = [name_by_id[i] for i in ids if i in name_by_id]

    if query:
        tokens = set(words(query))
        pool = product_pool(cvrf)
        hits = full_token_matches(tokens, pool)

        if not hits:
            scored = sorted(
                pool,
                key=lambda p: len(tokens & set(words(p["Value"]))),
                reverse=True,
            )[:10]
            chosen = interactive_pick([p["Value"] for p in scored])
            ids.update(p["ProductID"] for p in scored if p["Value"] == chosen)
            chosen_names.append(chosen)
        else:
            names = sorted({h["Value"] for h in hits})
            chosen = names[0] if len(names) == 1 else interactive_pick(names)
            ids.update(p["ProductID"] for p in hits if p["Value"] == chosen)
            chosen_names.append(chosen)

    print(f"Selected product id: {ids}")
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
        if affected & wanted:
            t = v["Title"]
            cvss = [(x or {}).get('BaseScore', 0) for x in v["CVSSScoreSets"] if set(x["ProductID"]) & wanted]
            rows.append(
                {"CVE": v["CVE"], "CVSS": cvss, "Title": t["Value"] if isinstance(t, dict) else t}
            )
    return rows


def get_pt_cve_list_by_platform(month: str, targets: set[str], name: str = None):
    """
    :param name: Full or partial name of the platform, e.g. "Windows" or "Windows Server
    :param month: Patch Tuesday month (YYYY-MMM)
    :param targets: set of ProductIDs
    """
    data = download(month)
    targets, name = pick_ids(data, name, targets)
    records = collect_cves(data, targets)
    return pl.DataFrame(records).sort("CVE"), name, targets


def print_cve_list(df: pl.DataFrame) -> str:
    wrapped = (
        df.with_columns(
            pl.col("Title").map_elements(
                lambda s: "\n".join(textwrap.wrap(s, 60)),
                return_dtype=pl.Utf8,
            )
        )
    )

    with pl.Config(tbl_rows=wrapped.height,
                   tbl_cols=wrapped.width,
                   fmt_str_lengths=200):
        return str(wrapped)


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--month")
    ap.add_argument("--platform-name")
    ap.add_argument("--product-ids")
    ap.add_argument("--cve")
    args = ap.parse_args(argv)

    if not args.month:
        args.month = input("Patch Tuesday month (YYYY-MMM): ").strip()
    if not (args.platform_name or args.product_ids):
        if input("Filter by name? [y/N] ").lower().startswith("y"):
            args.platform_name = input("Platform name substring: ").strip()
        else:
            args.product_ids = input("Comma-separated ProductIDs: ").strip()

    explicit = {s for s in (args.product_ids or "").split(",") if s}
    data = download(args.month)
    targets, targets_names = pick_ids(data, args.platform_name, explicit)
    if not targets:
        sys.exit("No matching ProductIDs")

    records = collect_cves(data, targets)
    if not records:
        sys.exit("No CVEs found")

    df = pl.DataFrame(records).sort("CVE")

    print(f'Results for {targets_names}')
    print_cve_list(df)

    if args.csv:
        out = Path(args.csv).expanduser()
        df.write_csv(out)
        print("Saved →", out)


if __name__ == "__main__":
    main()
