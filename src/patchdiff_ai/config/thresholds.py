from pydantic import BaseModel, Field


class Thresholds(BaseModel):
    """Cut-off scores used across the graphs."""

    candidates: float = Field(default=7.5, ge=0.0, le=10.0)
    """Relevancy threshold for filtering candidate executables (0.0 - 10.0)."""

    security_modification: float = Field(default=0.25, ge=0.0, le=1.0)
    """Relevancy threshold for picking which decompiled diffs to analyze."""

    report: float = Field(default=0.1, ge=0.0, le=1.0)
    """Confidence threshold for accepting a generated report."""
