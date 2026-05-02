"""Typer parameter validators (CLI-side guard against malformed input)."""

from __future__ import annotations

import re

import typer

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
MONTH_RE = re.compile(
    r"^\d{4}-(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$",
    re.IGNORECASE,
)


def cve_value(value: str) -> str:
    if not CVE_RE.match(value):
        raise typer.BadParameter(
            "Invalid CVE format; expected CVE-YYYY-NNNN[...] (e.g. CVE-2025-32713)"
        )
    return value.upper()


def month_value(value: str) -> str:
    if not MONTH_RE.match(value):
        raise typer.BadParameter(
            "Invalid month format; expected YYYY-MMM (e.g. 2025-Jul)"
        )
    year, mon = value.split("-")
    return f"{year}-{mon.capitalize()}"


def platform_ids(value: str | None) -> set[str]:
    if not value:
        return set()
    return {x.strip() for x in value.split(",") if x.strip()}
