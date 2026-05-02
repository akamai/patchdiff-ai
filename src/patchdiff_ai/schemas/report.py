from pydantic import BaseModel, ConfigDict, Field

from patchdiff_ai.schemas.analysis import Artifact
from patchdiff_ai.schemas.cve import CveDetails


class FunctionMetadata(BaseModel):
    file: str = Field(..., description="Filename where the function resides (e.g., 'kernel32.dll')")
    name: str = Field(..., description="Function name (e.g., 'NtCreateFile')")
    address: str = Field(..., description="Function address or RVA (e.g., '0x7FFFB12A')")


class FunctionRelevancy(BaseModel):
    metadata: FunctionMetadata = Field(...)
    score: float = Field(
        ...,
        description=(
            "Scoring rubric (hard boundaries):\n"
            "0.00 ... Clearly cosmetic / refactor\n"
            "0.25 ... Unlikely security, minor logic tweak\n"
            "0.50 ... Possibly related (some safety hints)\n"
            "0.75 ... Probable security fix (strong indicators)\n"
            "1.00 ... Direct, obvious patch for a vulnerability"
        ),
    )
    why: str = Field(..., description="Why this score?")


class VulnFuncs(BaseModel):
    functions: list[FunctionRelevancy] = Field(default_factory=list)


class VulnReport(BaseModel):
    """Structured-output schema for the per-model report."""

    found: bool = Field(..., description="Whether the vulnerability was identified")
    confidence: float = Field(..., ge=0.0, le=1.0)
    report: str = Field(..., description="Plain-ASCII RCA text")


class Report(BaseModel):
    """The persisted report; one per model on a per-CVE per-binary basis."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    cve_details: CveDetails = Field(default_factory=CveDetails)
    content: str = ""
    confidence: float = 0.0
    artifact: Artifact = Field(default_factory=Artifact)
    model: str = ""
