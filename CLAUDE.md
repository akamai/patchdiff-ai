# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Status

The greenfield rewrite is the active codebase. The original implementation is kept as a parity reference only.

- **Active package**: [src/patchdiff_ai/](src/patchdiff_ai/) — Pydantic v2 + DI `AppContext` + structlog + LangGraph. Pip-installed via `pip install -e .` and exposed as the `patchdiff-ai` console entry point.
- **Reference (do not edit, gitignored)**: [patchdiff-ai-wip-models_config/](patchdiff-ai-wip-models_config/) — the original LangGraph multi-agent system. Read it for parity questions, never edit it.
- **Refactor plan**: [.plan/refactor-plan.md](.plan/refactor-plan.md) — original M1→M6 design. M1 (platform plugin seam) has landed; the rest are partially complete or superseded.
- **Architecture write-up**: [docs/Architecture.md](docs/Architecture.md) — the source of truth for how the new package fits together.

## What the project does

PatchDiff-AI takes a CVE ID, downloads the relevant Windows Update package from MSRC, extracts binaries, diffs vulnerable vs. patched versions with IDA Pro + BinDiff, decompiles changed functions, and produces a markdown root-cause analysis report. Orchestrated with LangGraph; uses Azure OpenAI primarily (with Anthropic/Gemini fallbacks) and ChromaDB as a vector store.

Platform-specific work (advisory fetch, package gather, candidate-ranking prompts) lives behind a `Platform` plugin protocol so other distros / vendors can be added without touching the pipeline graph.

## Working on this codebase

- Locked-in technical decisions: Pydantic v2 BaseModel for state; `pydantic-settings` for config; `AppContext` for DI; structlog for observability; LangGraph kept as the orchestrator; **no `input()` inside graph nodes** (interactivity lives in the CLI via LangGraph `interrupt()`).
- Patterns worth porting verbatim from the old folder are listed in [.plan/refactor-plan.md](.plan/refactor-plan.md).
- Verification is a parity smoke run against the old folder on `CVE-2025-29824` / `2025-Apr` — no automated test suite.
- Read [docs/Architecture.md](docs/Architecture.md) before making structural changes; the layer boundaries (CLI → Runtime → Graphs → Platforms / Tools / Patches / Persistence / LLM) are deliberate.

## External tools required at runtime

Python 3.11 x64, IDA Pro 8.x, BinDiff 8.0 + BinExport 12+, 7-Zip 22+. Paths are configured via `pydantic-settings` (no hardcoded paths in code). Run `patchdiff-ai health-check` to validate `.env`, tool paths, and provider credentials end-to-end.
