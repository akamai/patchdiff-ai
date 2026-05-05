"""`patchdiff-ai cached` — print previously cached reports."""

from __future__ import annotations

import json
from pathlib import Path

import click

from patchdiff_ai.cli.validators import cve_value
from patchdiff_ai.config.settings import get_settings
from patchdiff_ai.platforms.windows.cycle import normalize_month
from patchdiff_ai.runtime.app_context import AppContext


def _validate_cve(ctx: click.Context, param: click.Parameter, value: str) -> str:
    if not value:
        return value
    return cve_value(value)


def _validate_month(ctx: click.Context, param: click.Parameter, value: str) -> str:
    if not value:
        return value
    try:
        return normalize_month(value)
    except ValueError as exc:
        raise click.BadParameter(str(exc))


def _platform_ids(value: str | None) -> set[str]:
    if not value:
        return set()
    return {x.strip() for x in value.split(",") if x.strip()}


def _format_report_body(document: str) -> str:
    """Render the stored RCA body as readable text.

    Some researchers (notably Claude with structured output) wrap the
    `report` field as a JSON object `{"title": ..., "content": ...}`
    instead of returning plain ASCII; the persisted document then has
    `\\n`-escaped content. Detect that shape and unwrap it; fall back
    to the raw string for the plain-text case.
    """
    try:
        parsed = json.loads(document)
    except (ValueError, TypeError):
        return document
    if isinstance(parsed, dict) and isinstance(parsed.get("content"), str):
        return parsed["content"]
    return document


def _save_reports(reports: dict, path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    for r, m in zip(reports.get("documents") or [], reports.get("metadatas") or []):
        header = json.dumps(m, indent=2, default=str, sort_keys=True)
        body = _format_report_body(r)
        text = f"{header}\n\n{body}\n"
        cve = m.get("cve")
        filename = m.get("file")
        base = path / f"{cve}_{filename}.txt"
        target = base
        idx = 1
        while target.exists():
            target = path / f"{cve}_{filename}_{idx}.txt"
            idx += 1
        target.write_text(text, encoding="utf-8")


@click.command(
    "cached",
    help="Print or save reports already cached in the vector store.",
)
@click.option("--cve", default="", callback=_validate_cve,
              help="Restore reports for a single CVE.")
@click.option("--month", default="", callback=_validate_month,
              help="Restore every cached report for a Patch Tuesday cycle (YYYY-MMM).")
@click.option("--platform-ids", "platforms_csv", default="",
              help="Comma-separated MSRC product IDs to filter the month scan.")
def cached_command(cve: str, month: str, platforms_csv: str) -> None:
    if not cve and not month:
        raise click.BadParameter("Provide --cve OR --month")

    settings = get_settings()
    settings.paths.ensure()
    ctx = AppContext.build(settings)
    try:
        stores = ctx.open_vector_stores()

        if cve:
            reports = stores.reports.get(where={"cve": cve})
            if not reports.get("ids"):
                click.echo("Not found")
                return
            _save_reports(reports, settings.paths.reports_dir)
            click.echo(f"[+] Saved cached reports for {cve} -> {settings.paths.reports_dir}")
            return

        from patchdiff_ai.platforms.windows.cycle import (
            collect_cves,
            download_cvrf,
            pick_ids,
        )

        cvrf = download_cvrf(month)
        targets, names = pick_ids(cvrf, None, _platform_ids(platforms_csv))
        cve_rows = collect_cves(cvrf, targets)
        os_name = "".join(x.replace(" ", "_") for x in (names or []))
        os_id = "".join(str(x) for x in (targets or []))
        sub = settings.paths.reports_dir / f"{month}.{os_name}.{os_id}".lower()

        for row in cve_rows:
            reports = stores.reports.get(where={"cve": row["CVE"]})
            if reports.get("ids"):
                _save_reports(reports, sub)

        click.echo(f"[+] Saved cached reports for {month} -> {sub}")
    finally:
        ctx.close()
