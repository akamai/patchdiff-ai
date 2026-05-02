"""MSRC SUG report enrichment for a given CVE."""

from __future__ import annotations

import html as html_mod
import re

import requests

from patchdiff_ai.schemas.cve import CveMetadata

BASE_VULN = "https://api.msrc.microsoft.com/sug/v2.0/sugodata/v2.0/en-US"
BASE_AFFECT = "https://api.msrc.microsoft.com/sug/v2.0/en-US"
HDRS = {"Accept": "application/json"}


def _strip_html(s: str) -> str:
    if not s:
        return ""
    return re.sub(r"<[^>]+>", "", html_mod.unescape(s)).replace("\\n", "\n").strip()


def _get_vuln_record(cve: str) -> dict:
    url = f"{BASE_VULN}/vulnerability?$filter=cveNumber in ('{cve}')"
    resp = requests.get(url, headers=HDRS, timeout=30)
    resp.raise_for_status()
    items = resp.json().get("value", [])
    if not items:
        raise RuntimeError(f"{cve} not found in SUG.")
    return items[0]


def _get_affected_products(cve: str) -> list[dict]:
    url = f"{BASE_AFFECT}/affectedProduct?$filter=cveNumber in ('{cve}')"
    resp = requests.get(url, headers=HDRS, timeout=30)
    resp.raise_for_status()
    return resp.json().get("value", [])


def report(cve: str) -> CveMetadata:
    vuln = _get_vuln_record(cve)
    products = _get_affected_products(cve)

    out = CveMetadata(
        cve=vuln.get("cveNumber", cve),
        title=vuln.get("cveTitle", ""),
        description=vuln.get("unformattedDescription", ""),
        faq=[
            _strip_html(a["description"])
            for a in vuln.get("articles") or []
            if a.get("articleType") == "FAQ"
        ],
        severity=vuln.get("severity") or "",
        impact=vuln.get("impact") or "",
        cvss={
            "baseScore": float(vuln.get("baseScore") or 0.0),
            "vectorString": vuln.get("vectorString", ""),
        },
        cwe=vuln.get("cweList", []),
        publicly_disclosed=vuln.get("publiclyDisclosed", False),
        exploited=vuln.get("exploited", False),
        products=[],
    )

    seen: set[int | None] = set()
    for p in products:
        pid = p.get("productId")
        if pid in seen:
            continue
        seen.add(pid)

        articles = []
        for kb in p.get("kbArticles") or []:
            articles.append(
                {
                    "article": kb.get("articleName"),
                    "supercedence": kb.get("supercedence"),
                    "type": (kb.get("downloadName") or "").lower(),
                    "fixedBuild": kb.get("fixedBuildNumber"),
                }
            )

        out.products.append(
            {
                "product": p.get("product"),
                "productId": pid,
                "architecture": p.get("architecture"),
                "baseVersion": p.get("baseProductVersion"),
                "articles": articles,
            }
        )

    return out
