"""Helpers used by PipelineRouter that need polars but no LangGraph."""

from __future__ import annotations

from typing import TYPE_CHECKING

import polars as pl

if TYPE_CHECKING:
    from patchdiff_ai.graphs.pipeline.state import PipelineState


def build_subjects_df(state: "PipelineState", ranked_df: pl.DataFrame) -> pl.DataFrame | None:
    """Restrict the current update DataFrame to ranked candidates and join scores."""
    if state.filtered_dataframes.current is None:
        return None

    filter_expr = (
        pl.col("name").str.to_lowercase().is_in(
            ranked_df.get_column("name").str.to_lowercase().implode()
        )
    ) & (
        pl.col("package").str.to_lowercase().is_in(
            ranked_df.get_column("package").str.to_lowercase().implode()
        )
    )

    subjects = (
        state.filtered_dataframes.current.filter(filter_expr)
        .join(
            ranked_df.select(["name", "similarity", "relevancy"]),
            on="name",
            how="left",
        )
        .sort("relevancy", descending=True)
    )

    return subjects if not subjects.is_empty() else None
