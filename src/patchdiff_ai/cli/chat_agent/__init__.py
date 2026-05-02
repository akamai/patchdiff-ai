"""ReAct chat agent for free-form REPL turns.

Public surface — `build_chat_agent` to compile the agent, `run_turn`
to drive a single user turn against it. Internals are split across
sibling modules: `catalogue` (tool registry), `envelope` (uniform
result shape), `preview` (chunked-result cache), `tools/*` (per-domain
tool registrations), `agent` (build), `turn` + `approval` (REPL
driver).
"""

from .agent import build_chat_agent
from .turn import run_turn


__all__ = ["build_chat_agent", "run_turn"]
