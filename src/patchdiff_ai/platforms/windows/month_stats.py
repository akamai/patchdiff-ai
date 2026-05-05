"""`patchdiff-ai windows month-stats` — aggregate per-cycle results.

Walks the Patch Tuesday CVE list (MSRC CVRF) and the cached reports
collection in Chroma to produce a coverage + highlights summary:

    total_cves          — every CVE the cycle's MSRC products are affected by
    analyzed            — CVEs with at least one persisted report row
    failed_or_missing   — total - analyzed (Chroma can't tell apart "tried &
                          failed" from "never ran"; logs are the source of
                          truth for that distinction)
    high_confidence     — reports with confidence >= 0.75
    incomplete_patches  — reports whose body matches an incomplete-patch
                          heuristic (regex set, tunable below)

Default output is a human-readable text block; `--json` emits the same
data as a single JSON document on stdout (consumed by the slack bot).

Note: only `found=true` reports are persisted (see
`graphs/vulnerability_research/nodes.py:365`), so every Chroma row in
this collection is by definition a "found" hit. There is no `found`
filter here.
"""

from __future__ import annotations

import json
import re

import click

from patchdiff_ai.config.settings import get_settings
from patchdiff_ai.platforms.windows.cycle import (
    collect_cves,
    download_cvrf,
    normalize_month,
    pick_ids,
)
from patchdiff_ai.platforms.windows.provider import WindowsProvider
from patchdiff_ai.runtime.app_context import AppContext

HIGH_CONFIDENCE_THRESHOLD = 0.75
SNIPPET_CHARS = 240

INCOMPLETE_PATCH_PATTERNS = [
    re.compile(r"\bincomplete\s+(patch|fix)\b", re.IGNORECASE),
    re.compile(r"\bpartially?\s+(patched|fixed|mitigat)", re.IGNORECASE),
    re.compile(r"\bstill\s+(vulnerable|exploitable)\b", re.IGNORECASE),
    re.compile(r"\bbypass(es|able)?\b.*\bpatch\b", re.IGNORECASE),
]


def _validate_month(ctx: click.Context, param: click.Parameter, value: str) -> str:
    try:
        return normalize_month(value)
    except ValueError as exc:
        raise click.BadParameter(str(exc))


def _format_body(document: str) -> str:
    """Strip the JSON `{title, content}` wrapper some models emit.

    Mirrors `cached._format_report_body`; duplicated here rather than
    imported so the two commands stay independently editable.
    """
    try:
        parsed = json.loads(document)
    except (ValueError, TypeError):
        return document
    if isinstance(parsed, dict) and isinstance(parsed.get("content"), str):
        return parsed["content"]
    return document


def _matches_incomplete_patch(body: str) -> bool:
    return any(p.search(body) for p in INCOMPLETE_PATCH_PATTERNS)


def _summary_for_row(meta: dict, body: str) -> dict:
    return {
        "cve": meta.get("cve", ""),
        "model": meta.get("model_name", ""),
        "file": meta.get("file", ""),
        "confidence": float(meta.get("confidence", 0.0)),
        "snippet": body[:SNIPPET_CHARS].strip(),
    }


@click.command(
    "month-stats",
    help="Aggregate cached-report stats for a Patch Tuesday cycle.",
)
@click.argument("cycle_id", metavar="YYYY-MMM", callback=_validate_month)
@click.option(
    "--platform-id",
    type=int,
    default=None,
    help="Force a specific MSRC product ID. Same semantics as `windows month`.",
)
@click.option(
    "--platform-name",
    default="",
    help="MSRC product-name filter (e.g. 'Windows 11 Version 24H2').",
)
@click.option(
    "--json",
    "json_output",
    is_flag=True,
    default=False,
    help="Emit the stats as JSON on stdout (for machine consumers like the slack bot).",
)
def month_stats_command(
    cycle_id: str,
    platform_id: int | None,
    platform_name: str,
    json_output: bool,
) -> None:
    settings = get_settings()
    settings.paths.ensure()
    ctx = AppContext.build(settings)

    try:
        cvrf = download_cvrf(cycle_id)

        # Default product-ID filter mirrors `windows month`: every MSRC
        # product the bundled WindowsProvider versions know about.
        provider = WindowsProvider()
        if platform_id is not None:
            ids: set[str] = {str(platform_id)}
        elif platform_name:
            ids = set()
        else:
            ids = {
                str(pid)
                for v in provider.versions
                for pid in v.spec.msrc_product_ids
            }

        targets, _names = pick_ids(cvrf, platform_name or None, ids)
        if not targets:
            raise click.ClickException("No matching ProductIDs")

        cve_rows = collect_cves(cvrf, targets)
        total = len(cve_rows)
        cycle_cves = {row["CVE"] for row in cve_rows}

        stores = ctx.open_vector_stores()

        analyzed_cves: set[str] = set()
        high_confidence: list[dict] = []
        incomplete_patches: list[dict] = []

        for cve in sorted(cycle_cves):
            res = stores.reports.get(where={"cve": cve})
            ids_ = res.get("ids") or []
            if not ids_:
                continue
            analyzed_cves.add(cve)
            docs = res.get("documents") or []
            metas = res.get("metadatas") or []
            for doc, meta in zip(docs, metas):
                body = _format_body(doc)
                summary = _summary_for_row(meta, body)
                if summary["confidence"] >= HIGH_CONFIDENCE_THRESHOLD:
                    high_confidence.append(summary)
                if _matches_incomplete_patch(body):
                    incomplete_patches.append(summary)

        analyzed = len(analyzed_cves)
        failed_or_missing = total - analyzed

        stats = {
            "cycle": cycle_id,
            "total_cves": total,
            "analyzed": analyzed,
            "failed_or_missing": failed_or_missing,
            "high_confidence": sorted(
                high_confidence, key=lambda x: x["confidence"], reverse=True
            ),
            "incomplete_patches": sorted(incomplete_patches, key=lambda x: x["cve"]),
        }

        if json_output:
            click.echo(json.dumps(stats, indent=2, sort_keys=True))
            return

        click.echo(f"== Patch Tuesday {cycle_id} ==")
        click.echo(f"  total CVEs        = {total}")
        click.echo(f"  analyzed          = {analyzed}")
        click.echo(f"  failed/missing    = {failed_or_missing}")

        click.echo(f"\n-- High-confidence findings (>= {HIGH_CONFIDENCE_THRESHOLD}) --")
        if not stats["high_confidence"]:
            click.echo("  (none)")
        for h in stats["high_confidence"]:
            click.echo(
                f"  {h['cve']:18} {h['confidence']:.2f}  {h['model']:24} {h['file']}"
            )

        click.echo("\n-- Incomplete-patch flags (heuristic) --")
        if not stats["incomplete_patches"]:
            click.echo("  (none)")
        for h in stats["incomplete_patches"]:
            click.echo(f"  {h['cve']:18} {h['model']:24} {h['file']}")
            click.echo(f"    {h['snippet'][:120]}{'...' if len(h['snippet']) > 120 else ''}")
    finally:
        ctx.close()
