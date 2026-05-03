"""CLI parameter validators (CLI-side guard against malformed input).

After M1 only `cve_value` survives; the Patch Tuesday `YYYY-MMM` regex
and the MSRC product-id CSV parser were both Windows-specific and now
live inside the windows plugin (`platforms/windows/cycle.py`).
"""

from __future__ import annotations

import re

import click

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)


def cve_value(value: str) -> str:
    if not CVE_RE.match(value):
        raise click.BadParameter(
            "Invalid CVE format; expected CVE-YYYY-NNNN[...] (e.g. CVE-2025-32713)"
        )
    return value.upper()
