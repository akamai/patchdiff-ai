"""NVD CPE lookup for CVE→provider auto-detect.

`cpes_for(cve_id)` returns the flattened list of `cpe_match.criteria`
strings from NVD's `configurations` block for a given CVE. Cached on
disk under `<paths.db_dir>/.nvd/<cve>.json` with a 30-day TTL so
repeat runs don't hit the unauthenticated 5-req/30-s rate limit.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import requests
import structlog

from patchdiff_ai.config.settings import get_settings

log = structlog.get_logger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TTL_SECONDS = 30 * 24 * 3600


def _cache_path(cve_id: str) -> Path:
    settings = get_settings()
    return settings.paths.db_dir / ".nvd" / f"{cve_id.upper()}.json"


def _read_cache(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    age = time.time() - path.stat().st_mtime
    if age > TTL_SECONDS:
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _write_cache(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    tmp.replace(path)


def _flatten_cpes(payload: dict[str, Any]) -> list[str]:
    """Walk NVD's configurations.[].nodes.[].cpeMatch.[].criteria."""
    out: list[str] = []
    seen: set[str] = set()
    vulns = payload.get("vulnerabilities") or []
    for v in vulns:
        cve = v.get("cve") or {}
        for cfg in cve.get("configurations") or []:
            for node in cfg.get("nodes") or []:
                for match in node.get("cpeMatch") or []:
                    criteria = match.get("criteria")
                    if not criteria or criteria in seen:
                        continue
                    seen.add(criteria)
                    out.append(criteria)
    return out


def cpes_for(cve_id: str) -> list[str]:
    """Return the list of CPE 2.3 criteria strings affected by `cve_id`.

    Empty list means "NVD has no record / no CPE configuration for this
    CVE" (e.g. very recent CVE not yet ingested by NVD). Callers treat
    that as a soft failure and surface it to the user as a "pass
    --platform <name>" hint.
    """
    cve_id = cve_id.upper()
    path = _cache_path(cve_id)
    cached = _read_cache(path)
    if cached is not None:
        return _flatten_cpes(cached)

    log.info("nvd_lookup", cve=cve_id)
    try:
        res = requests.get(
            NVD_URL,
            params={"cveId": cve_id},
            headers={"Accept": "application/json"},
            timeout=30,
        )
        res.raise_for_status()
        payload = res.json()
    except requests.RequestException as exc:
        log.warning("nvd_lookup_failed", cve=cve_id, error=str(exc))
        return []

    _write_cache(path, payload)
    return _flatten_cpes(payload)
