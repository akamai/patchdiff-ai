"""CliInteractor: the *only* place `input()` is allowed.

Graph nodes raise `interrupt(RefinementRequest)`; the orchestrator catches it
and hands it to `CliInteractor.handle(...)`, which prompts the user and
returns the corresponding `RefinementResponse`.
"""

from __future__ import annotations

from contextlib import nullcontext

import structlog

from patchdiff_ai.graphs.interrupts import (
    RefinementKind,
    RefinementOption,
    RefinementPickRequest,
    RefinementPickResponse,
    RefinementRequest,
    RefinementResponse,
)
from patchdiff_ai.observability.progress import ProgressReporter

log = structlog.get_logger(__name__)


class CliInteractor:
    """Prompts the user for refinement input. Replace with a non-interactive
    impl in batch mode."""

    def __init__(
        self,
        *,
        enabled: bool = True,
        progress: ProgressReporter | None = None,
    ) -> None:
        self.enabled = enabled
        # When a Rich progress reporter is active, its Live region constantly
        # redraws the bars on stderr and clobbers the cursor right where
        # input() prints its prompt — typed characters never appear because
        # the redraw paints over them. The interactor pauses the reporter
        # around every input() call so line-input echoes correctly.
        self.progress = progress

    def _input(self, prompt: str) -> str:
        ctx = self.progress.pause() if self.progress is not None else nullcontext()
        with ctx:
            return input(prompt)

    def handle(self, request: RefinementRequest) -> RefinementResponse:
        if not self.enabled:
            return RefinementResponse(skip=True)

        print(f"\n[?] {request.prompt} ({request.cve})")
        kinds = {k.value: k for k in request.available_kinds}
        while True:
            print("Options: " + " | ".join(kinds) + "  (Enter to continue)")
            try:
                choice = self._input("Select: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                return RefinementResponse(skip=True)
            if not choice:
                return RefinementResponse(skip=True)
            if choice not in kinds:
                continue

            kind = kinds[choice]
            if kind is RefinementKind.SEMANTIC:
                try:
                    query = self._input("Query: ").strip()
                except (EOFError, KeyboardInterrupt):
                    return RefinementResponse(skip=True)
                if not query:
                    continue
                return RefinementResponse(
                    skip=False,
                    selected=[RefinementOption(name="__semantic__", payload={"query": query})],
                )
            if kind is RefinementKind.FILENAME:
                try:
                    pattern = self._input("Pattern: ").strip()
                except (EOFError, KeyboardInterrupt):
                    return RefinementResponse(skip=True)
                if not pattern:
                    continue
                return RefinementResponse(
                    skip=False,
                    selected=[RefinementOption(name="__filename__", payload={"pattern": pattern})],
                )

    def handle_pick(self, request: RefinementPickRequest) -> RefinementPickResponse:
        """Render one search round's results and ask the user which to add.

        Empty input or any parse failure returns `indices=[]` so the
        refinement loop continues without adding anything from this round.
        """
        if not self.enabled or not request.candidates:
            return RefinementPickResponse(indices=[])

        for idx, c in enumerate(request.candidates, start=1):
            print(f"{idx}. {c.name} (score: {c.score:.3f})")
        try:
            selection = self._input("Select (e.g., 1,3,5 or 'all'): ").strip()
        except (EOFError, KeyboardInterrupt):
            return RefinementPickResponse(indices=[])
        if not selection:
            return RefinementPickResponse(indices=[])

        if selection.lower() == "all":
            return RefinementPickResponse(indices=list(range(len(request.candidates))))

        indices: list[int] = []
        for token in selection.split(","):
            token = token.strip()
            if not token.isdigit():
                continue
            i = int(token) - 1
            if 0 <= i < len(request.candidates):
                indices.append(i)
        return RefinementPickResponse(indices=indices)
