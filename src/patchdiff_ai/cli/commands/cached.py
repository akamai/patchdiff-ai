"""`patchdiff-ai cached` — print previously cached reports."""

from __future__ import annotations

import json
import re
from pathlib import Path

import typer

from patchdiff_ai.cli.validators import cve_value
from patchdiff_ai.config.settings import get_settings
from patchdiff_ai.runtime.app_context import AppContext

app = typer.Typer()


_MONTH_RE = re.compile(
    r"^\d{4}-(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$",
    re.IGNORECASE,
)


def _month_value(value: str) -> str:
    if not value:
        return value
    if not _MONTH_RE.match(value):
        raise typer.BadParameter(
            "Invalid month format; expected YYYY-MMM (e.g. 2025-Jul)"
        )
    year, mon = value.split("-")
    return f"{year}-{mon.capitalize()}"


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


@app.callback(invoke_without_command=True)
def cached_command(
    cve: str = typer.Option("", "--cve", callback=lambda v: cve_value(v) if v else v),
    month: str = typer.Option("", "--month", callback=lambda v: _month_value(v) if v else v),
    platforms_csv: str = typer.Option("", "--platform-ids"),
) -> None:
    """Print or save reports already cached in the vector store."""
    if not cve and not month:
        raise typer.BadParameter("Provide --cve OR --month")

    settings = get_settings()
    settings.paths.ensure()
    ctx = AppContext.build(settings)
    stores = ctx.open_vector_stores()

    if cve:
        reports = stores.reports.get(where={"cve": cve})
        if not reports.get("ids"):
            typer.echo("Not found")
            return
        _save_reports(reports, settings.paths.reports_dir)
        typer.echo(f"[+] Saved cached reports for {cve} -> {settings.paths.reports_dir}")
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

    typer.echo(f"[+] Saved cached reports for {month} -> {sub}")
    ctx.close()
