from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class CveMetadata(BaseModel):
    """Result of MSRC SUG enrichment for a CVE."""

    model_config = ConfigDict(extra="ignore")

    cve: str = ""
    title: str = ""
    description: str = ""
    faq: list[str] = Field(default_factory=list)
    severity: str = ""
    impact: str = ""
    cvss: dict[str, Any] = Field(default_factory=dict)
    cwe: list[Any] = Field(default_factory=list)
    publicly_disclosed: bool | str = False
    exploited: bool | str = False
    products: list[dict[str, Any]] = Field(default_factory=list)


class CveDetails(BaseModel):
    """Per-CVE state used through every graph."""

    model_config = ConfigDict(extra="ignore")

    cve: str = ""
    description: str = ""
    msrc_report: CveMetadata = Field(default_factory=CveMetadata)
