"""CVE + Patch-Tuesday cycle regex validators.

Intentionally a small copy rather than importing patchdiff_ai — keeps
the bot's process boundary clean. If these drift from the CLI's
validators it is not a correctness problem (the CLI re-validates
anyway when the subprocess actually runs); this is just a friendly
pre-flight.
"""

from __future__ import annotations

import re

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
MONTH_RE = re.compile(
    r"^\d{4}-(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$",
    re.IGNORECASE,
)


def normalize_cve(value: str) -> str:
    value = (value or "").strip()
    if not CVE_RE.match(value):
        raise ValueError(f"Expected CVE-YYYY-NNNNN, got {value!r}")
    return value.upper()


def normalize_month(value: str) -> str:
    value = (value or "").strip()
    if not MONTH_RE.match(value):
        raise ValueError(f"Expected YYYY-MMM (e.g. 2025-Apr), got {value!r}")
    year, mon = value.split("-")
    return f"{year}-{mon.capitalize()}"
