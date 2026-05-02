"""Render every LangGraph in the project as a PNG under `docs/`.

Outputs:
- `Pipeline.png` — the top-level pipeline graph plus all four subgraphs
  (gather_info, platform_internals, reverse_engineering, vulnerability_research)
  expanded via `xray=True`.
- `ChatAgent.png` — the post-run ReAct chat agent (the `--chat` REPL). It's
  a separate graph at a separate lifecycle stage (it runs after `run_cve`
  returns), so it gets its own image.

Non-graph runtime components (Platform plugin protocol, AppContext DI bundle,
ModelRegistry, Tools, patches/* I/O modules, persistence, observability,
prompts) are not LangGraphs and can't be rendered as one. They're documented
in `docs/Architecture.md` instead.

Usage:
    python docs/render_pipeline_graph.py
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from langchain_core.runnables.graph import CurveStyle, MermaidDrawMethod, NodeStyles
from langchain_core.runnables.graph_mermaid import draw_mermaid_png

from patchdiff_ai.cli.chat_agent import build_chat_agent
from patchdiff_ai.config.settings import get_settings
from patchdiff_ai.graphs.gather_info.graph import build_gather_graph
from patchdiff_ai.graphs.pipeline.graph import build_pipeline_graph
from patchdiff_ai.llm.catalog import ModelPurpose
from patchdiff_ai.runtime.app_context import AppContext


NEON_THEME = {
    "config": {
        "theme": "dark",
        "themeVariables": {
            "background": "#5E5E5E",
            "fontFamily": "'Fira Code', monospace",
            "primaryColor": "#1f6feb",
            "primaryBorderColor": "#3b8eea",
            "primaryTextColor": "#f0f6fc",
            "lineColor": "#58a6ff",
            "nodeBorderRadius": 8,
            "edgeLabelBackground": "#00000000",
        },
        "flowchart": {"curve": "basis", "layout": "elk"},
    }
}

NODE_STYLES = NodeStyles(
    default="fill:#1f6feb33,stroke:#3b8eea,stroke-width:2px,color:#f0f6fc",
    first="fill:#06d6a033,stroke:#06d6a0,stroke-width:2px,color:#f0f6fc",
    last="fill:#ff006e33,stroke:#ff006e,stroke-width:2px,color:#f0f6fc",
)


def _render(graph: Any, out: Path) -> None:
    """Render a compiled LangGraph to a PNG using the shared neon theme."""
    mermaid_syntax = graph.get_graph(xray=True).draw_mermaid(
        curve_style=CurveStyle.BASIS,
        node_colors=NODE_STYLES,
        wrap_label_n_words=4,
        frontmatter_config=NEON_THEME,
    )
    draw_mermaid_png(
        mermaid_syntax=mermaid_syntax,
        output_file_path=str(out),
        draw_method=MermaidDrawMethod.API,
        background_color="#5E5E5E",
        padding=10,
        max_retries=1,
        retry_delay=1.0,
    )
    print(f"Wrote {out}")


def main() -> None:
    docs_dir = Path(__file__).resolve().parent

    ctx = AppContext.build(get_settings())
    try:
        # Pipeline: inject the compiled gather subgraph directly so xray expands
        # its internals. Production runs use `make_gather_node(ctx)` which
        # delegates to `ctx.platform.gather_packages()` and hides the subgraph
        # from the rendering — fine at runtime, useless for a documentation
        # diagram.
        pipeline = build_pipeline_graph(ctx, gather_node=build_gather_graph(ctx))
        _render(pipeline, docs_dir / "Pipeline.png")

        # Chat agent: post-run ReAct REPL (only active under `--chat`). The
        # model entry is required by `build_chat_agent` but irrelevant for
        # graph topology, so the DEFAULT-purpose model is fine here. cve and
        # state are placeholders; the resulting graph shape is the same.
        model_entry = ctx.registry.for_purpose(ModelPurpose.DEFAULT)
        # `build_chat_agent` is async because it discovers MCP tools via a live
        # handshake. Drive it through a one-shot loop just for rendering.
        chat_agent = asyncio.run(
            build_chat_agent(ctx, "CVE-RENDER-0000", None, model_entry)
        )
        _render(chat_agent, docs_dir / "ChatAgent.png")
    finally:
        ctx.close()


if __name__ == "__main__":
    main()
