# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What the project does

PatchDiff-AI takes a CVE ID (e.g. `CVE-2025-29824`) or a Patch Tuesday cycle (e.g. `2025-Apr`), downloads the relevant Windows Update package from MSRC, extracts binaries (7-Zip + nested `.cab`/`.psf` + forward/reverse delta apply via `UpdateCompression.dll`), diffs vulnerable vs. patched versions with IDA Pro + BinDiff, decompiles changed functions, and produces a markdown root-cause analysis report.

Orchestrated with **LangGraph**; primary LLM provider is **Azure OpenAI** (with Anthropic / Gemini as eval / fallback). Vector store is local **ChromaDB** under [db/](db/).

Platform-specific work (advisory fetch, package gather, candidate-ranking prompts) lives behind a `Platform` plugin protocol so other distros / vendors can be added without touching the pipeline graph.

## Status & references

- **Active package**: [src/patchdiff_ai/](src/patchdiff_ai/) — Pydantic v2 + DI `AppContext` + structlog + LangGraph. Pip-installed via `pip install -e .` and exposed as the `patchdiff-ai` console entry point.
- **Reference (do not edit, gitignored)**: [patchdiff-ai-wip-models_config/](patchdiff-ai-wip-models_config/) — the original LangGraph multi-agent system. Read it for parity questions, never edit it.
- **Architecture write-up**: [docs/Architecture.md](docs/Architecture.md) — the source of truth for how the package fits together. Read this before structural changes.
- **Refactor plan**: [.plan/refactor-plan.md](.plan/refactor-plan.md) — original M1→M6 design. M1 (platform plugin seam) has landed; the rest are partially complete or superseded.
- **User-facing docs**: [readme.md](readme.md) — installation, configuration, full CLI surface (chat tools, IDA/MCP tools, eval mode).

## Common commands

```powershell
# Install (editable) — entry point becomes `patchdiff-ai`
pip install -e .

# Validate .env, tool paths, and provider credentials end-to-end
patchdiff-ai health-check

# Run a single CVE
patchdiff-ai cve CVE-2025-29824

# Run a whole Patch Tuesday, filtered to a product
patchdiff-ai month 2025-Apr --platform-ids 12390

# Pause for interactive candidate refinement before RE
patchdiff-ai cve CVE-2025-29824 --interrupt

# Drop into chat REPL after the run (gated tool calls)
patchdiff-ai cve CVE-2025-29824 --chat

# Run report-gen across the full EVAL_MODELS set in parallel
patchdiff-ai cve CVE-2025-29824 --eval

# Read back already-cached reports (no graph run)
patchdiff-ai cached --cve CVE-2025-29824

# Verbose / trace logging (trace = full crash tracebacks)
patchdiff-ai -L debug cve CVE-2025-29824
patchdiff-ai -L trace cve CVE-2025-29824
```

There is **no automated test suite**. Verification is a parity smoke run against the old folder on `CVE-2025-29824` / `2025-Apr` (the canonical golden-reference). Logs are JSON to `logs/<unix>.<uuid>.log`; reports land in [reports/](reports/) and Chroma collection `windows.exe.rca.reports`.

## External tools required at runtime

Python 3.11 x64, IDA Pro 8.x or 9.x (idalib activated for the preferred path), BinDiff 8.0 + BinExport 12+, 7-Zip 22+. Paths are configured via `pydantic-settings` (no hardcoded paths in code). When `tools.ida` isn't set, [config/tools.py](src/patchdiff_ai/config/tools.py) auto-discovers installs under `Program Files`. The bundled BinDiff lives under [resources/bindiff_ida_9.3/](resources/bindiff_ida_9.3/) and is wired in via `BINDIFF_PATH` in `AppContext.build()`.

## Architecture cheat sheet

Layered top-down; lower layers don't import higher ones:

```
CLI (typer) → Runtime (AppContext + orchestrator) → Graphs (LangGraph subgraphs)
                                                      ↓
                       Platforms · Tools · Patches · Persistence · LLM Registry · Schemas · Observability · Prompts
```

The pipeline is a **deterministic** state machine, not an LLM-driven supervisor. Stages: `CVE_INFO → GATHER → PI_AGENT → RE_AGENT → VR_AGENT → FINALIZE`. Routing in [graphs/pipeline/routing.py](src/patchdiff_ai/graphs/pipeline/routing.py) is pure functions of state. Fan-out (per candidate, per artifact) uses LangGraph `Send`. Cache hits short-circuit straight to `FINALIZE`.

The chat REPL ([cli/chat.py](src/patchdiff_ai/cli/chat.py), [cli/chat_agent.py](src/patchdiff_ai/cli/chat_agent.py)) lives **outside** the graph. The hybrid tool catalogue is 3 native tools + 3 meta-tools (`list_tools` / `describe_tool` / `call_tool`) that proxy ~60 ida-pro-mcp tools. The MCP subprocess is **lazy-spawned** on first `call_tool(<ida tool>, ...)`.

## Working on this codebase — locked-in technical decisions

- **Pydantic v2 BaseModel** for state, settings, cross-agent contracts. Cross-node merging uses LangGraph reducers (`Annotated[list[T], append_list]`, `add_messages`).
- **`pydantic-settings`** for config. Nested fields use `__` delimiter (`PATHS__DB_DIR`, `TOOLS__SEVEN_ZIP`, `CONCURRENCY__RE_WORKERS`). The per-purpose model overrides (`MODELS_DEFAULT`, `MODELS_GATHER_INFO`, …) are a deliberate **flat** exception via `Field(alias=...)`.
- **`AppContext` for DI** — built once in [cli/app.py](src/patchdiff_ai/cli/app.py)'s `main()`, threaded through every node / tool / command. **No module-level singletons, no `AgentModels`-style god-objects, no import-time `sys.exit(1)`.**
- **structlog** for observability (JSON to disk, console renderer to stderr). `bind_cve(cve, run_id)` uses contextvars so every event auto-tags. `LLMMetricsHandler` emits per-call tokens / latency / cost.
- **LangGraph kept as the orchestrator**; LangChain 1.x is the floor (`langchain.agents.create_agent` replaced the deprecated `langgraph.prebuilt.create_react_agent`).
- **No `input()` inside graph nodes.** Interactivity lives in the CLI via LangGraph `interrupt()` → `CliInteractor.handle(...)` in [runtime/interactive.py](src/patchdiff_ai/runtime/interactive.py).
- **Subprocess discipline.** Every external-tool wrapper is async, list-arg, and goes through [tools/process.py](src/patchdiff_ai/tools/process.py)'s `run()`: mandatory timeout, `create_subprocess_exec` (no `shell=True`), `ToolError` / `ToolTimeout`, Ctrl-C-clean cleanup.
- **No external telemetry.** [cli/app.py](src/patchdiff_ai/cli/app.py)'s `_bootstrap()` force-pins `LANGCHAIN_TRACING_V2=false` / `LANGSMITH_TRACING=false` and strips inherited keys / endpoints **before** LangGraph imports (LangChain captures those at import time). Chroma's anonymous telemetry is disabled before `chromadb` imports. Everything stays in `logs/`.
- **Dependency versions are frozen** in [pyproject.toml](pyproject.toml). Bump deliberately, not casually.

## Where to add things (smallest fitting seam first)

- **New platform** (Linux distro / Android / macOS): implement the `Platform` Protocol at [platforms/base.py](src/patchdiff_ai/platforms/base.py) (5 methods: `matches`, `enrich_cve`, `gather_packages`, `candidate_prompts`, `candidate_metadata`) and register in [platforms/__init__.py](src/patchdiff_ai/platforms/__init__.py). [windows.py](src/patchdiff_ai/platforms/windows.py) is the reference implementation.
- **New analysis stage** inside an existing subgraph: add a node in `graphs/<name>/nodes.py` and wire edges in `graph.py`.
- **New subgraph**: `state.py` + `nodes.py` + `graph.py`, register on the pipeline at [graphs/pipeline/graph.py](src/patchdiff_ai/graphs/pipeline/graph.py), wire transition in [graphs/pipeline/routing.py](src/patchdiff_ai/graphs/pipeline/routing.py).
- **New LLM provider**: factory under `llm/providers/<name>.py`, register the `Provider` enum value, extend the catalog, wire `ModelRegistry._build`.
- **New external tool**: drop under [tools/](src/patchdiff_ai/tools/), build on `process.py`'s `run()`, expose its path via [config/tools.py](src/patchdiff_ai/config/tools.py)'s `ToolPaths`, inject through `AppContext.tools`.
