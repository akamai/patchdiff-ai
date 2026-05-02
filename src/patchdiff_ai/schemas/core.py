"""Newtypes / aliases for primary identifiers."""

from typing import Annotated

from pydantic import StringConstraints

CveId = Annotated[str, StringConstraints(pattern=r"^CVE-\d{4}-\d{4,7}$")]
KbId = Annotated[str, StringConstraints(pattern=r"^KB?\d+$")]
