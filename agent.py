import dataclasses
from pathlib import Path

from langchain_core.runnables.graph import NodeStyles, CurveStyle, MermaidDrawMethod
from langchain_openai import AzureChatOpenAI
from langgraph.graph.state import CompiledStateGraph
import abc
from langchain_core.runnables.graph_mermaid import draw_mermaid_png

from common import LLM

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
        "flowchart": {
            "curve": "basis",
            "layout": "elk"
        },
    }
}

NODE_STYLES = NodeStyles(
    default="fill:#1f6feb33,stroke:#3b8eea,stroke-width:2px,color:#f0f6fc",
    first="fill:#06d6a033,stroke:#06d6a0,stroke-width:2px,color:#f0f6fc",
    last="fill:#ff006e33,stroke:#ff006e,stroke-width:2px,color:#f0f6fc"
)


def dummy(state):
    print(state)
    return {}


class Agent(abc.ABC):
    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if cls is Agent:
            return

        nodes = getattr(cls, "NODES", None)
        if nodes is None:
            raise TypeError(f"{cls.__name__} must declare a nested `NODES` dataclass")

        if not (
                dataclasses.is_dataclass(nodes)
                and nodes.__dataclass_params__.frozen
        ):
            raise TypeError(
                f"{cls.__name__}.NODES must be decorated with @defaultdataclass(frozen=True)"
            )

        wrong = [
            (name, f.type)
            for name, f in nodes.__dataclass_fields__.items()  # type: ignore[attr-defined]
            if f.type is not str
        ]
        if wrong:
            bad = ", ".join(f"{n}: {t!r}" for n, t in wrong)
            raise TypeError(
                f"{cls.__name__}.NODES fields must be 'str' – offending: {bad}"
            )

    def __init__(self, llm: AzureChatOpenAI = LLM.mini, draw: bool = False):
        self._llm = llm
        self._graph: CompiledStateGraph = None
        self._build()
        if draw:
            self._draw_graph()

    def get_graph(self):
        return self._graph

    def get_llm(self):
        return self._llm

    @abc.abstractmethod
    def _build(self):
        ...

    def _draw_graph(self):
        if self._graph:
            mermaid_syntax = self._graph.get_graph(xray=True).draw_mermaid(
                curve_style=CurveStyle.BASIS,
                node_colors=NODE_STYLES,
                wrap_label_n_words=4,
                frontmatter_config=NEON_THEME,
            )

            draw_mermaid_png(
                mermaid_syntax=mermaid_syntax,
                output_file_path=f'{self.__class__.__name__}.png',
                draw_method=MermaidDrawMethod.API,
                background_color="#5E5E5E",
                padding=10,
                max_retries=1,
                retry_delay=1.0,
            )

    # except Exception as e:
    #
    #     pass

    # Definitions of all nodes

    # Definitions of all conditional edges
