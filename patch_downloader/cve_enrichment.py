#!/usr/bin/env python3
import argparse
import html
import json
import re

import requests

from common import CveMetadata

BASE_VULN = "https://api.msrc.microsoft.com/sug/v2.0/sugodata/v2.0/en-US"
BASE_AFFECT = "https://api.msrc.microsoft.com/sug/v2.0/en-US"
HDRS = {"Accept": "application/json"}


def get_vuln_record(cve: str) -> dict:
    url = f"{BASE_VULN}/vulnerability?$filter=cveNumber in ('{cve}')"
    resp = requests.get(url, headers=HDRS, timeout=30)
    resp.raise_for_status()
    items = resp.json().get("value", [])
    if not items:
        raise RuntimeError(f"{cve} not found in SUG.")
    return items[0]


def get_affected_products(cve: str) -> list[dict]:
    url = f"{BASE_AFFECT}/affectedProduct?$filter=cveNumber in ('{cve}')"
    resp = requests.get(url, headers=HDRS, timeout=30)
    resp.raise_for_status()
    return resp.json().get("value", [])


def report(cve: str) -> CveMetadata:
    vuln = get_vuln_record(cve)
    products = get_affected_products(cve)

    def strip_html(s):
        re.sub(r"<[^>]+>", "", html.unescape(s)).replace("\\n", "\n").strip()

    out = CveMetadata(
        cve=vuln.get("cveNumber", cve),
        title=vuln.get("cveTitle", ""),
        description=vuln.get("unformattedDescription", ""),
        faq=[strip_html(a["description"]) for a in vuln.get("articles") if a.get("articleType") == "FAQ"],
        severity=vuln.get("severity"),
        impact=vuln.get("impact"),
        cvss=dict(
            baseScore=float(vuln.get("baseScore") or 0.0),
            vectorString=vuln.get("vectorString", ""),
        ),
        cwe=vuln.get("cweList", []),
        publiclyDisclosed=vuln.get("publiclyDisclosed", False),
        exploited=vuln.get("exploited", False),
        products=[],
    )

    seen: set[int] = set()

    for p in products:
        pid = p.get("productId")
        kb_list = p.get("kbArticles") or []
        articles = []
        for kb in kb_list:
            articles.append(dict(
                article=kb.get("articleName"),
                supercedence=kb.get("supercedence"),
                type=kb.get("downloadName").lower(),
                fixedBuild=kb.get("fixedBuildNumber")
            ))
        key = pid
        if key in seen:
            continue
        seen.add(key)

        out.products.append(
            dict(
                product=p.get("product"),
                productId=pid,
                architecture=p.get("architecture"),
                baseVersion=p.get("baseProductVersion"),
                articles=articles,
                # initialReleaseDate=p.get("initialReleaseDate"),
            )
        )

    return out


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("cve", help="CVE-ID (e.g. CVE-2025-27480)")
    args = parser.parse_args()
    print(json.dumps(report(args.cve), indent=2))


if __name__ == "__main__":
    main()
