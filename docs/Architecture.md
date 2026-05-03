# PatchDiff-AI — Architecture

This document describes how PatchDiff-AI is built end-to-end: the layers, the data
flow, the state machine, the tools, the I/O, and the design constraints that shaped
the rewrite. It covers the greenfield package at [src/patchdiff_ai/](../src/patchdiff_ai/).

> If you only want to run the tool, start at [readme.md](../readme.md). If you want
> to understand how it works or extend it, this is the right document.

---

## Table of contents

1. [Design principles](#design-principles)
2. [The CVE → report lifecycle](#the-cve--report-lifecycle)
3. [Process model](#process-model)
4. [Layers](#layers)
   1. [CLI](#1-cli-srcpatchdiff_aicli)
   2. [Configuration](#2-configuration-srcpatchdiff_aiconfig)
   3. [AppContext (DI)](#3-appcontext-dependency-injection-srcpatchdiff_airuntimeapp_contextpy)
   4. [LLM registry & providers](#4-llm-registry--providers-srcpatchdiff_aillm)
   5. [Tools (subprocess discipline)](#5-tools-srcpatchdiff_aitools)
   6. [Patches pipeline](#6-patches-pipeline-srcpatchdiff_aipatches)
   7. [Persistence](#7-persistence-srcpatchdiff_aipersistence)
   8. [Schemas](#8-schemas-srcpatchdiff_aischemas)
   9. [Graphs](#9-graphs-srcpatchdiff_aigraphs)
   10. [Runtime / orchestrator](#10-runtime--orchestrator-srcpatchdiff_airuntime)
   11. [Observability](#11-observability-srcpatchdiff_aiobservability)
   12. [Prompts](#12-prompts-srcpatchdiff_aiprompts)
   13. [Platforms](#13-platforms-srcpatchdiff_aiplatforms)
5. [State machine](#state-machine)
6. [Interrupts & interactivity](#interrupts--interactivity)
7. [Concurrency model](#concurrency-model)
8. [Caching strategy](#caching-strategy)
9. [Error handling & cancellation](#error-handling--cancellation)
10. [On-disk layout](#on-disk-layout)
11. [Walk-through: CVE-2025-29824](#walk-through-cve-2025-29824)
12. [Extending the system](#extending-the-system)

---

## Design principles

The greenfield rewrite was driven by a small number of constraints that the legacy
implementation violated and that we wanted to fix once and for all:

1. **No module globals.** Every component takes an `AppContext`. There are no
   class-level mutable singletons (the legacy `AgentModels` god-object), no
   import-time `sys.exit(1)` on auth failures, and no module-level `pt = PatchTools()`
   handles that survive across CVE runs. The DI bundle is built once in
   [`cli/app.py`](../src/patchdiff_ai/cli/app.py) and threaded through.
2. **`input()` lives only in the CLI process.** Graph nodes never call `input()`.
   When refinement is needed, a node yields `interrupt(RefinementRequest)`; the
   orchestrator surfaces it to a `CliInteractor`, which is the only place that
   actually prompts the user.
3. **Async correctness.** `await asyncio.to_thread(async_fn)` is gone. Tool wrappers
   use `asyncio.create_subprocess_exec` (no `shell=True`) with mandatory timeouts.
   Cross-CVE state shared between graph runs is replaced with explicit per-run state.
4. **Pydantic v2 everywhere.** State models, settings, and cross-agent contracts are
   `BaseModel` subclasses. Cross-node merging uses LangGraph reducers
   (`Annotated[list[T], append_list]`, `add_messages`).
5. **Explicit state machine.** The pipeline graph uses a `Stage` enum and a
   `PipelineRouter` whose methods are pure functions of state. There is no
   `match` on `state_info.node[-2]`. (The pipeline isn't a "supervisor" in the
   LangGraph multi-agent sense — there's no LLM-driven routing; every
   transition is a deterministic function of state.)
6. **Subprocess discipline.** A single
   [`tools/process.py`](../src/patchdiff_ai/tools/process.py) `run()` helper enforces
   timeouts, structured `ToolError`/`ToolTimeout` exceptions, argv-style invocation,
   and Ctrl-C-clean child cleanup. Every tool wrapper depends on it.
7. **Centralized prompts and structured observability.** Prompts are markdown files
   under [`prompts/`](../src/patchdiff_ai/prompts/), loaded by `PromptRegistry`.
   Logging is structlog JSON tee'd to disk; LLM calls are instrumented via a
   LangChain callback handler that records tokens, latency, and cost per call.

---

## The CVE → report lifecycle

```
   user invokes:  patchdiff-ai cve CVE-2025-29824
        │
        ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 1. CVE info                                                            │
│    - Resolve OS / product ID (cached on disk)                          │
│    - Fetch MSRC CVRF + SUG report for the CVE                          │
│    - Pick the (current, previous) KB pair                              │
│    - If a cached report already exists in Chroma → short-circuit       │
└────────────────────────────────────────────────────────────────────────┘
        │
        ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 2. Gather info                                                         │
│    - Download both KBs (.msu) from the Update Catalog                  │
│    - Extract: 7-Zip → nested .cab/.psf → forward / reverse delta apply │
│      (UpdateCompression.dll RAII-wrapped)                              │
│    - Build executable index (Polars DataFrames):                       │
│        prev / curr KB + winsxs r-patch baseline                        │
│    - For each unseen (name, package) pair, ask an LLM for an 80-token  │
│      file description and embed it into Chroma `windows.exe.desc`      │
└────────────────────────────────────────────────────────────────────────┘
        │
        ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 3. Platform internals                                                  │
│    - LLM derives a similarity-search query from CVE metadata           │
│    - Top-10 file_info candidates retrieved by vector search            │
│    - LLM rescores them on a 0-10 relevancy scale                       │
│    - Optional: interrupt() → CLI lets user add semantic / filename     │
│      candidates                                                        │
└────────────────────────────────────────────────────────────────────────┘
        │  Send fan-out (one per candidate above the relevancy threshold)
        ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 4. Reverse engineering (per candidate)                                 │
│    - IDA: produce .BinExport for primary + secondary binary            │
│    - BinDiff: build .BinDiff database (one bounded retry on            │
│      sqlite corruption with override=True)                             │
│    - For each function with similarity < 1.0: decompile to C in        │
│      __funcs__/<address>.c (via IDA decompile.py script, batched)      │
│    - Emit one Artifact per candidate                                   │
└────────────────────────────────────────────────────────────────────────┘
        │  Send fan-out (one per Artifact)
        ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 5. Vulnerability research (per Artifact)                               │
│    - Index decompiled functions and compute udiffs                     │
│    - LLM scores each function on a 0-1 security-relevancy rubric       │
│      (with token-aware truncation at ~100k tokens)                     │
│    - Refinement loop: if no high-confidence report yet and             │
│      iter_remaining > 0, drop the analyzed slice and rank the rest     │
│    - Functions above the security_modification threshold → analyzed    │
│    - In --eval mode: parallel report generation across multiple LLMs   │
│    - Persist each Report into Chroma `windows.exe.rca.reports`         │
└────────────────────────────────────────────────────────────────────────┘
        │
        ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 6. Finalize                                                            │
│    - Log cve_run_complete with report count                            │
│    - Reports flow back through PipelineState                           │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Process model

A single `patchdiff-ai` invocation is one OS process. Inside it:

- **One asyncio event loop** drives everything. CPU- or blocking-I/O-bound work
  (Chroma writes, sync HTTP via `requests-html`, `BinDiff.from_binexport_files`) is
  pushed onto the default thread-pool via `asyncio.to_thread` or
  `loop.run_in_executor`.
- **External tools** (`7z.exe`, `idat64.exe`) run as child processes through
  `asyncio.create_subprocess_exec`. They are timeout-bounded; on cancellation the
  process is `terminate()`-then-`kill()`ed.
- **Vector stores** are local Chroma collections persisted to `db/`.

Per CVE:

- A single LangGraph `Send` fan-out spawns the RE subgraph for each ranked candidate.
- Each RE run produces an `Artifact` that is fanned out again to a VR subgraph.
- All fan-outs occur within the same event loop and rely on LangGraph's built-in
  scheduling — there is no manual thread pool.

---

## Layers

The package is layered top-down: **CLI → Runtime/Orchestrator → Graphs (subagents) →
Tools / Patches / Persistence / LLM Registry / Schemas / Observability**. Lower
layers don't import from higher ones.

### 1. CLI ([`src/patchdiff_ai/cli/`](../src/patchdiff_ai/cli/))

The CLI uses **Click** for the plugin-aware surface and keeps **typer** for
the legacy `cached` command (mounted via `typer.main.get_command(...)`).
[`cli/root.py`](../src/patchdiff_ai/cli/root.py) defines the Click root
and mounts a thin generic core plus one self-registered sub-group per
platform provider.

```
patchdiff-ai [-L LOG_LEVEL]
├── cve <CVE-ID> [--platform N] [--eval] [--interrupt] [--chat] [--chat-permissive]
│       # auto-detects via parallel native (MSRC/USN/...) → NVD fallback
├── health-check          # core checks + every provider's health_check()
├── install               # core IDA assets + every provider's install()
├── cached                # legacy typer command (mounted via typer→click bridge)
├── windows               # registered by WindowsProvider
│   ├── cve <CVE-ID> [--platform-id N] [--eval] [--interrupt] [--chat] [--chat-permissive]
│   ├── health-check
│   ├── install
│   └── month <YYYY-MMM> [--platform-id N] [--platform-name X]
└── linux                 # registered by LinuxProvider (skeleton)
    ├── cve <CVE-ID> [--distro X] [--release Y]
    ├── health-check
    └── install
```

Conventions:

- [`cli/app.py`](../src/patchdiff_ai/cli/app.py)'s `main()` is a thin adapter:
  it runs `_bootstrap()` (env-strip + tracing-disable BEFORE LangGraph imports)
  and then dispatches to the Click root in [`cli/root.py`](../src/patchdiff_ai/cli/root.py).
- The root group's `-L/--log-level` callback runs first and configures structlog
  before any subcommand body.
- `_bootstrap()` force-disables LangSmith / LangChain tracing
  (`LANGCHAIN_TRACING_V2=false`, `LANGSMITH_TRACING=false`) plus strips any
  inherited API key / endpoint. LangChain captures `LANGCHAIN_*` at import time,
  so this has to happen first.
- Shared CVE-running flags (`--eval / --interrupt / --chat / --chat-permissive`)
  are factored into a `@cve_options` decorator in
  [`cli/options.py`](../src/patchdiff_ai/cli/options.py); every `cve`-style
  command uses it so help stays consistent.
- All three `cve` entry points (root `cve`, `windows cve`, `linux cve`) delegate
  to a single dispatcher in [`cli/runner.py`](../src/patchdiff_ai/cli/runner.py)
  (`run_single_cve`). The CLI never builds an `AppContext` directly.
- `cli/validators.py` is now down to just `cve_value`. The `YYYY-MMM` regex
  (`MONTH_RE`) and CSV parsing for `--platform-id` moved into the windows
  plugin.
- `KeyboardInterrupt` / `EOFError` exit with code 130 (the standard "Ctrl-C" code).

### 2. Configuration ([`src/patchdiff_ai/config/`](../src/patchdiff_ai/config/))

Built on **pydantic-settings**. The root model is `Settings` in
[`config/settings.py`](../src/patchdiff_ai/config/settings.py). It composes:

- `AzureCreds`, `AnthropicCreds`, `GeminiCreds` — provider credentials.
- `Paths` — filesystem layout (`db_dir`, `reports_dir`, `temp_dir`, `logs_dir`,
  derived properties for the patch-store index, winsxs cache, OS cache, and eval
  CVE cache).
- `ToolPaths` — executable paths and a global `process_timeout_seconds` (default
  30 minutes; IDA/BinDiff jobs can be long).
- `Thresholds` — three knobs:
  - `candidates: 7.5` (0-10) — minimum LLM relevancy to send a candidate to the RE pipeline.
  - `security_modification: 0.25` (0-1) — minimum function-level security score for the VR pass.
  - `report: 0.1` (0-1) — confidence threshold above which we accept a generated report and stop iterating.
- `Concurrency` — semaphores and worker counts (`file_info_semaphore=500`,
  `re_workers=5`, `extractor_workers=5`, `llm_eval_parallel=4`). Tune via
  `CONCURRENCY__<field>=N`.
- `ModelChoices` — per-purpose model name overrides. Each field uses a single-
  underscore alias (`MODELS_DEFAULT`, `MODELS_GATHER_INFO`, …) — *not* the
  nested `MODELS__<field>` form. This is a deliberate exception to the
  general nesting rule so model overrides remain flat in `.env`.

Settings are read from `.env` + process env. Nested fields use the `__` delimiter
(`PATHS__DB_DIR=/data/db`, `TOOLS__SEVEN_ZIP=...`, `CONCURRENCY__RE_WORKERS=...`).
Legacy flat names (`AZURE_ENDPOINT`, `ANTHROPIC_API_KEY`) and the per-purpose
model overrides are honored via `Field(alias=...)`.

`get_settings()` is `lru_cache`d so `.env` is read once per process.

### 3. AppContext (dependency injection) ([`src/patchdiff_ai/runtime/app_context.py`](../src/patchdiff_ai/runtime/app_context.py))

The single DI bundle. Every node, tool, and CLI command takes one. It holds:

```python
@dataclass
class AppContext:
    settings: Settings
    registry: ModelRegistry
    tools: Tools                       # SevenZipTool, IdaTool, BindiffTool, DeltaApi, ...
    log: structlog.BoundLogger
    vector_stores: VectorStores | None # opened lazily (needs the embedding model)
    prompts: PromptRegistry | None
    progress: ProgressReporter         # Rich-driven; NullProgressReporter by default
```

`AppContext.build(settings)` constructs everything except `vector_stores` (those are
opened on demand because they require resolving an embedding model from the
registry). `AppContext.close()` releases the `DeltaApi` Win32 handle.

### 4. LLM registry & providers ([`src/patchdiff_ai/llm/`](../src/patchdiff_ai/llm/))

The legacy `AgentModels` god-object (six untyped class attributes mutated at import
time, with `sys.exit(1)` on auth failure) is replaced by an explicit, lazy registry.

- [`llm/catalog.py`](../src/patchdiff_ai/llm/catalog.py) — a frozen `MODEL_CATALOG`
  dict of `ModelSpec` entries (name, provider, deployment, api_version,
  cost_per_mtok, max_tokens, temperature, is_embedding). Six purposes are defined
  in `ModelPurpose`: `EMBEDDING`, `DEFAULT`, `GATHER_INFO`, `PLATFORM_INTERNALS`,
  `REVERSE_ENGINEERING`, `RESEARCHER`. Each has a default model in
  `DEFAULT_BY_PURPOSE`. `EVAL_MODELS` is the tuple used in `--eval` mode.
- [`llm/registry.py`](../src/patchdiff_ai/llm/registry.py) — `ModelRegistry` resolves
  a `ModelPurpose` to a `ModelEntry(spec, model)` lazily. Lookup order:
  env override → purpose default → any available chat model. Failures become
  `ProviderUnavailableError`, never silent fallbacks. `list_available()` reports
  which catalog entries have configured credentials.
- [`llm/auth.py`](../src/patchdiff_ai/llm/auth.py) — `build_azure_credential` resolves
  to either a `ClientSecretCredential` (if the SP trio is set) or
  `DefaultAzureCredential`. `cognitive_token_provider` builds a callable token
  provider for the Cognitive Services scope. **No `sys.exit` on failure.** The
  registry warns and marks Azure as unavailable.
- [`llm/providers/{azure,anthropic,gemini}.py`](../src/patchdiff_ai/llm/providers/) —
  thin per-provider factories that turn a `ModelSpec` + creds into a LangChain chat
  or embedding client.

### 5. Tools ([`src/patchdiff_ai/tools/`](../src/patchdiff_ai/tools/))

Every tool wrapper is async, list-arg, timeout-bound, and built on
[`tools/process.py`](../src/patchdiff_ai/tools/process.py)'s `run()` helper.

| Module                                                                       | Purpose                                                                                                  |
|------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------|
| [`process.py`](../src/patchdiff_ai/tools/process.py)                         | `run(args, *, timeout, ...)` — `create_subprocess_exec`, kill on timeout, `ToolError` / `ToolTimeout`    |
| [`seven_zip.py`](../src/patchdiff_ai/tools/seven_zip.py)                     | `SevenZipTool.list_files(...)` / `extract_by_list(...)` — reads supported extensions from `7z i`         |
| [`psf.py`](../src/patchdiff_ai/tools/psf.py)                                 | `PsfArchive` — async ctx mgr; mmap **closed** on exit (legacy leak fixed)                                |
| [`ida.py`](../src/patchdiff_ai/tools/ida.py)                                 | `IdaTool.run_script(IdaJob)` — `-S<script>` arg via `subprocess.list2cmdline`; `batch()` dedupes targets |
| [`ida_mcp.py`](../src/patchdiff_ai/tools/ida_mcp.py)                         | `IdaMcpService` — chat-only ida-pro-mcp wrapper; `get_catalogue()` (no spawn) + `call_tool(name, args)` (lazy spawn). Used by the chat tool catalogue. |
| [`idalib_pool.py`](../src/patchdiff_ai/tools/idalib_pool.py)                 | `IdalibPool` — N-worker `multiprocessing.spawn` pool driving idalib directly. Used by the RE pipeline (no MCP overhead). `None` when idalib isn't activated. |
| [`_subprocess_lifecycle.py`](../src/patchdiff_ai/tools/_subprocess_lifecycle.py) | Shared atexit-killed PID registry + port helpers + terminate dance; used by both `idalib_pool` and `ida_mcp`. |
| [`bindiff.py`](../src/patchdiff_ai/tools/bindiff.py)                         | `BindiffTool.diff(...)` — one bounded retry on sqlite corruption (override=True), no infinite loop       |
| [`delta.py`](../src/patchdiff_ai/tools/delta.py)                             | `DeltaApi` — instance-scoped ctypes loader for `UpdateCompression.dll`; DLLs stay mapped until process exit (FreeLibrary mid-shutdown crashed Py_Finalize) |
| [`manifest.py`](../src/patchdiff_ai/tools/manifest.py)                       | `WcpManifestExtractor` — guarded `string_at` for WCP manifest decoding                                   |
| [`idapython/`](../src/patchdiff_ai/tools/idapython/)                         | `analyze.py` and `decompile.py` — legacy IDA-side scripts invoked via `idat64.exe -A -S<script>` (8.x fallback) |

Conventions:

- Executable paths come from `Settings.tools` — no hardcoded `'C:/Program Files/...'`.
  When `tools.ida` isn't set, [`config/tools.py`](../src/patchdiff_ai/config/tools.py)
  discovers all installs under `Program Files` (recognising `IDA Pro 8.x`,
  `IDA Professional 9.x`) and picks the newest. `idat.exe` (9.3+) and
  `idat64.exe` (8.x / 9.0) are both supported.
- `SevenZipTool` is **never** invoked with `shell=True`.
- `IdaTool.batch` deduplicates jobs by target path because IDA cannot share an `.i64`
  file across concurrent processes.
- `IdaJob.args` is escaped via `subprocess.list2cmdline` exactly once before being
  passed in `-S`.
- `BindiffTool.diff` retries once on `sqlite3.DatabaseError`. Two failures in a row
  return `None`; the RE pipeline treats that as "skip this candidate". The
  bundled `bindiff.exe` ships under [`resources/bindiff_ida_9.3/`](../resources/bindiff_ida_9.3/)
  and is wired in via `BINDIFF_PATH` (set in `AppContext.build()`), so users
  don't need a separate BinDiff install.
- The chat agent uses a **hybrid tool catalogue** ([`cli/chat_agent.py`](../src/patchdiff_ai/cli/chat_agent.py)):
  3 always-on native tools (`list_changed_functions`, `show_decompiled`,
  `show_diff`) + 3 meta-tools (`list_tools`, `describe_tool`, `call_tool`)
  proxy everything else (report queries, reanalyze, all 60+ ida-pro-mcp
  tools). The `idalib-mcp` subprocess only spawns on the first
  `call_tool(<ida tool>, ...)` — chat sessions that never touch live IDA
  pay zero spawn cost. Catalogue snapshot is built without spawning by
  importing `ida_pro_mcp.ida_mcp` and walking the in-process `@tool`
  registry.
- The RE pipeline drives idalib through `IdalibPool` directly (no MCP
  overhead) when the resolved IDA is 9.0+ with idalib activated; 8.x
  setups keep using the legacy subprocess flow.

### 6. Patches pipeline ([`src/patchdiff_ai/patches/`](../src/patchdiff_ai/patches/))

This is the I/O-heavy layer that owns everything between "user gave us a CVE ID" and
"we have an executable index ready to embed".

| Module                                                                              | Responsibility                                                                                            |
|-------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------|
| [`cve_enrichment.py`](../src/patchdiff_ai/patches/cve_enrichment.py)                | Fetch the MSRC SUG report for a CVE, return `CveMetadata`                                                 |
| [`platform_filter.py`](../src/patchdiff_ai/patches/platform_filter.py)              | Download a CVRF for a Patch Tuesday, pick product IDs, collect CVEs                                       |
| [`os_detection.py`](../src/patchdiff_ai/patches/os_detection.py)                    | `(name, productId)` from CVRF; `processor_arch_tokens()` from the host. **No `input()`** — pure functions |
| [`kb_downloader.py`](../src/patchdiff_ai/patches/kb_downloader.py)                  | `download_kb(...)` — `requests-html` + `tenacity`, streamed to disk under `resource_lock`, cancellable    |
| [`extractor.py`](../src/patchdiff_ai/patches/extractor.py)                          | `extract_kb(...)` — `_KBExtractor` worker pool (default 5) handling 7-Zip + PSF + nested archives         |
| [`files_collection.py`](../src/patchdiff_ai/patches/files_collection.py)            | Polars DataFrame builders for winsxs / update reports; `file_desc()` (PE-version-info reader)             |
| [`manifest_extractor.py`](../src/patchdiff_ai/patches/manifest_extractor.py)        | Pulls package / publisher tokens from WCP manifests                                                       |
| [`delta_apply.py`](../src/patchdiff_ai/patches/delta_apply.py)                      | `patch_entry(...)` — apply forward / reverse deltas through the injected `DeltaApi`                       |

Disk-full is a first-class signal: `extract_kb` raises `DiskFullError` (from
[`runtime/errors.py`](../src/patchdiff_ai/runtime/errors.py)) instead of letting the
worker pool deadlock. The CLI catches it, logs once, and exits non-zero with no
traceback.

### 7. Persistence ([`src/patchdiff_ai/persistence/`](../src/patchdiff_ai/persistence/))

| Module                                                                              | What                                                                                                                        |
|-------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------|
| [`vector_store.py`](../src/patchdiff_ai/persistence/vector_store.py)                | `VectorStores` — three Chroma collections: `windows.exe.desc`, `windows.exe.functions.logic`, `windows.exe.rca.reports`. Telemetry disabled before import. |
| [`patch_store.py`](../src/patchdiff_ai/persistence/patch_store.py)                  | `safe_serialize` (atomic write-temp → fsync → rename), `get_patch_store_df`, `resource_lock` (asyncio version of the legacy weakref-Lock table) |
| [`caches.py`](../src/patchdiff_ai/persistence/caches.py)                            | `DiskCache` — small JSON-on-disk cache used for `os` selection and any one-shot lookups                                     |

The `windows.exe.rca.reports` collection is the persistent layer for the report
short-circuit: a CVE's first run writes its reports here; subsequent runs (without
`--eval`) detect the cached entries in the `cve_info` node and skip everything.

### 8. Schemas ([`src/patchdiff_ai/schemas/`](../src/patchdiff_ai/schemas/))

Cross-agent contracts. All Pydantic v2.

| Module          | Models                                                                                                  |
|-----------------|---------------------------------------------------------------------------------------------------------|
| `core.py`       | Type aliases: `CveId`, `KbId`                                                                           |
| `cve.py`        | `CveMetadata` (MSRC payload), `CveDetails` (CVE id + description + msrc_report)                         |
| `patch_store.py`| `PatchStoreEntry`, `PatchSources` (`base / current / previous`), `OsDetails`                            |
| `analysis.py`   | `Artifact` (primary/secondary file + diff + changed funcs), `DecompiledFunction`, `FunctionMatchRef`    |
| `candidate.py`  | `Candidate`, `RankedCandidate` (adds 0-10 LLM relevancy), `Candidates` (query + results)                |
| `report.py`     | `FunctionRelevancy`, `VulnFuncs`, `VulnReport` (LLM structured-output schema), `Report` (the artifact persisted to Chroma) |
| `messages.py`   | `MessagesState` mixin                                                                                   |
| `reducers.py`   | `append_list`, `replace`, re-export of `add_messages`                                                   |

All `Artifact`-bearing states use `arbitrary_types_allowed=True` because we keep raw
`bindiff.BinDiff` and `bindiff.FunctionMatch` objects on the state — they aren't
Pydantic models but they don't need to be serialized across the wire.

### 9. Graphs ([`src/patchdiff_ai/graphs/`](../src/patchdiff_ai/graphs/))

Each subgraph follows the same shape:

```
graphs/<name>/
├── state.py     # Pydantic v2 BaseModel with reducer-annotated fields
├── nodes.py     # `make_nodes(ctx)` factory returning callables
└── graph.py     # `build_<name>_graph(ctx)` returning a compiled StateGraph
```

[`graphs/builder.py`](../src/patchdiff_ai/graphs/builder.py) holds shared
constructor helpers; [`graphs/interrupts.py`](../src/patchdiff_ai/graphs/interrupts.py)
defines the cross-process payloads (see [Interrupts & interactivity](#interrupts--interactivity)).

#### Pipeline graph ([`graphs/pipeline/`](../src/patchdiff_ai/graphs/pipeline/))

The top-level state machine. Despite the LangGraph "supervisor" terminology
the legacy code used, this is a deterministic pipeline with conditional
fan-out — every transition is a pure function of state, no LLM-driven
routing.

- **State** (`state.py`): `PipelineState` with `stage: Stage`, CVE / OS / KB
  slices, three Polars DataFrame slices (raw, filtered, base), `candidates`,
  `artifacts` (reducer: `append_list`), `reports` (reducer: `append_list`),
  `messages` (reducer: `add_messages`), and `parse_errors`.
- **Routing** (`routing.py`): a `Stage` enum + a `PipelineRouter` class with one
  method per source stage:
  - `from_cve_info` — short-circuit to FINALIZE if reports were cached, else GATHER.
  - `from_gather` — straight to PI_AGENT.
  - `from_internals` — fan-out via `Send` to RE for each candidate above the
    `candidates` threshold whose patch_store entry has at least two KBs available.
  - `from_re` — fan-out via `Send` to VR for each `Artifact`.
  - `from_vr` — straight to FINALIZE.
  - `from_finalize` — straight to END.
- **Nodes** (`nodes.py`):
  - `cve_info_node` — reads `ctx.platform` (resolved at the CLI layer
    before `run_cve` was invoked), delegates the advisory fetch + KB
    selection to `ctx.platform.enrich_cve(state, ctx)`, then checks the
    Chroma reports cache and optionally short-circuits to FINALIZE.
  - `gather_node` — thin wrapper around `ctx.platform.gather_packages(state, ctx)`.
    The Windows plugin invokes the existing gather subgraph here; future
    platforms own their own implementation. Calls `ctx.progress.stop_live()`
    on exit so the PI / RE / VR phases run on a clean tty (no live progress
    bars to clobber refinement input).
  - `finalize_node` — logs `cve_run_complete` and sets the stage.
- **Graph topology** (`graph.py`):
  ```
  CVE_INFO ──► [GATHER | FINALIZE]
   GATHER ──► PI_AGENT
  PI_AGENT ──► [Send(RE_AGENT) ... | FINALIZE]
   RE_AGENT ──► [Send(VR_AGENT) ... | FINALIZE]
   VR_AGENT ──► FINALIZE ──► END
  ```

#### Gather subgraph ([`platforms/windows/gather_info/`](../src/patchdiff_ai/platforms/windows/gather_info/))

This subgraph is **plugin-internal to the Windows provider** — the shared
`graphs/` tree no longer contains any Windows-specific code. Other
providers may implement `gather_packages` however they like (as a
subgraph, a coroutine, anything that returns
`{extracted, dataframes, filtered_dataframes}`); they don't import from
here.

- **Nodes**:
  - `download` — concurrent `download_kb` for current + previous, then concurrent
    `extract_kb`, then `load_delta_dlls` (each KB carries its own
    `UpdateCompression.dll`).
  - `index` — Polars-driven join of curr/prev/winsxs DataFrames, filtered by
    architecture and r-patch availability.
  - `add_file_info_if_needed` — conditional edge: for each unseen `(name, package)`,
    `Send` an `add_file_info` task.
  - `add_file_info` — bounded by `Concurrency.file_info_semaphore`. Embeds an
    80-token LLM file description into `windows.exe.desc`.
  - `update_vector_store` — placeholder; the `file_info` collection is updated
    incrementally above.
- **Topology**: `DOWNLOAD → INDEX → (ADD_FILE_INFO* | UPDATE_VS) → UPDATE_VS → END`.

LLM `add_file_info` calls are wrapped with `tenacity` (5 attempts, exponential
backoff up to 60 s) on `RateLimitError`. The "Windows executable" file-description
prompt lives at [`prompts/windows/file_description.system.md`](../src/patchdiff_ai/prompts/windows/file_description.system.md)
(`PromptId.WINDOWS_FILE_DESC`).

#### Platform-internals subgraph ([`graphs/platform_internals/`](../src/patchdiff_ai/graphs/platform_internals/))

Platform-driven candidate ranking: `collect` and `rank` look up their
prompts via `ctx.platform.candidate_prompts()` and project the advisory
metadata via `ctx.platform.candidate_metadata(state.cve_details)`. Only the
data sources are platform-dependent; the ranking algorithm itself is shared.

- **Nodes**:
  - `collect` — LLM derives a search query from the platform-projected
    advisory metadata; top-10 candidates pulled from `windows.exe.desc` via
    `asimilarity_search_with_score`.
  - `rank` — LLM rescores each candidate on a 0-10 relevancy rubric; sorted
    by relevancy. Renders the candidates table to terminal once per run
    (no longer DEBUG-gated).
  - `user_refinement` — interrupt-based, two-phase per loop iteration:
    1. `interrupt(RefinementRequest)` — CLI prompts kind (`semantic` / `filename`)
       and the query/pattern.
    2. The node runs the search inside the graph (filename = case-insensitive
       substring match on the `filtered_dataframes` changed-files DataFrame;
       semantic = vector search at `k=50` then filtered to changed-files set).
    3. `interrupt(RefinementPickRequest)` — CLI renders a numbered list and
       prompts `Select (e.g., 1,3,5 or 'all')`. Only picked entries are
       added to `user_docs`.
    Loops until the user enters an empty kind (skip).
- **Topology**: `COLLECT → RANK → (USER_REFINEMENT | END)`. Whether refinement
  runs depends on the `interrupt: bool` from the run config.
- Prompts live in [`prompts/platform_internals/{collect,rank}.system.md`](../src/patchdiff_ai/prompts/platform_internals/) (the default Windows set; the active platform plugin can override the prompt IDs).

#### Reverse-engineering router + backends ([`graphs/reverse_engineering/`](../src/patchdiff_ai/graphs/reverse_engineering/))

RE_AGENT is a **router** ([`router.py`](../src/patchdiff_ai/graphs/reverse_engineering/router.py))
that picks a backend per Send by asking
`ctx.platform.classify_candidate(candidate) -> RECategory`. Two
backends today, both produce the same `Artifact` / `FunctionMatchRef`
shape so VR is agnostic:

- **Binary backend** ([`binary_graph.py`](../src/patchdiff_ai/graphs/reverse_engineering/binary_graph.py))
  — IDA + BinDiff + Hex-Rays decompile. Selected for `RECategory.BINARY`
  (Windows always; Linux when the candidate ends in `.so`/`.dylib`/
  `.exe`/...). Picks between two `make_nodes` implementations at build
  time based on `ctx.tools.idalib`:
  - **idalib-backed** (preferred, [`nodes_idalib.py`](../src/patchdiff_ai/graphs/reverse_engineering/nodes_idalib.py))
    — drives idalib directly through `IdalibPool`. No subprocess per
    pair, warm IDB cache reuse, batched Hex-Rays decompile in one
    round-trip. Selected when `ctx.tools.idalib is not None`
    (IDA 9.0+ with idalib activated).
  - **idat-subprocess legacy** ([`nodes.py`](../src/patchdiff_ai/graphs/reverse_engineering/nodes.py))
    — fallback for 8.x setups. Spawns `idat.exe -A -S<analyze.py>`
    then `-S<decompile.py>` (batched 500 funcs per `.i64`). The IDA-side
    script explicitly `idc.save_database("", 0)`s before `qexit` so
    the `.i64` survives the run.

  Topology: `ANALYZE → DIFF_AND_DECOMPILE → END`. Shared helpers
  (`discover_parents`, `hexish`, `decompile_set_via_idalib`) live in
  [`_shared.py`](../src/patchdiff_ai/graphs/reverse_engineering/_shared.py).

- **Source backend** ([`source_graph.py`](../src/patchdiff_ai/graphs/reverse_engineering/source_graph.py))
  — text udiff for source-code candidates. No IDA, no BinDiff. Selected
  for `RECategory.SOURCE` (Linux source-package diffs, kernel patches,
  scripts). Single node `DIFF_SOURCES`: reads pre/post text, writes
  `__funcs__/<identifier>.txt` for both sides, emits one
  `FunctionMatchRef(identifier=<filename-stem>, extension="txt")` per
  changed file. Per-function splitting is left as follow-up — the
  schema and VR support multiple `FunctionMatchRef`s per `Artifact`
  already.

The `FunctionMatchRef` schema in
[`schemas/analysis.py`](../src/patchdiff_ai/schemas/analysis.py) carries
both the binary-only fields (`address1/2: int`, `similarity / confidence:
float`) and the M3 generalised fields (`identifier: str`, `extension:
str`). VR's disk lookup is `<__funcs__>/<key>.<ext>` where
`primary_key()` / `secondary_key()` fall back to the hex address when
`identifier` is empty — so the binary path stays byte-identical to
pre-M3.

> Why the merged diff+decompile node in the binary backend? Splitting
> them caused `cannot pickle 'sqlite3.Connection' object` when the
> checkpointer tried to serialize a live `BinDiff` between nodes — true
> for both idalib and subprocess implementations.

> Adding a new backend (script-runtime, manifest, ...) is additive: drop
> a new `<kind>_graph.py`, add an `RECategory.<KIND>` enum value in
> [`platforms/base.py`](../src/patchdiff_ai/platforms/base.py), register
> it in `router.py`'s `_BACKENDS`, and have at least one `Platform`'s
> `classify_candidate` return the new value.

#### Vulnerability-research subgraph ([`graphs/vulnerability_research/`](../src/patchdiff_ai/graphs/vulnerability_research/))

- **State** carries the per-Artifact slice: `artifact`, `cve_details`, `decompiled`
  (list of `DecompiledFunction`), `reports` (with `append_list` reducer),
  `iter_remaining: int = 3`.
- **Nodes**:
  - `indexing` — read each changed function's `.c` files (before / after), compute
    a unified diff, build `DecompiledFunction` entries (with parent call-stack from
    the BinDiff secondary side).
  - `rank` — score functions on a 0-1 security-relevancy rubric using
    `with_structured_output(VulnFuncs, include_raw=True)`. Applies a
    *token-aware truncation*: drops trailing functions until the prompt fits under
    100 k tokens. `parsing_error`s are logged, not swallowed.
  - `analyze` — picks functions above `thresholds.security_modification`, then:
    - In normal mode: one call to `MODELS_RESEARCHER` with structured `VulnReport`.
    - In `--eval` mode: parallel calls across `EVAL_MODELS` using
      `asyncio.gather(..., return_exceptions=True)`.
    - Per-(cve, file, model) caching short-circuits already-generated reports.
    - Decrements `iter_remaining` and removes the analyzed slice from `decompiled`.
  - `refinement` (conditional edge): if a high-confidence report exists →
    `GENERATE`; else if `iter_remaining > 0` and there are still functions →
    re-run `RANK` on the remainder; else → `GENERATE`.
  - `generate` — persist accepted reports to `windows.exe.rca.reports` with
    metadata (cve, kb, file, patch_store_uid, confidence, change_count, date,
    model_name, cvss).
- **Topology**: `INDEXING → RANK → ANALYZE → (RANK | GENERATE) → END`.
- Prompts live in [`prompts/vulnerability_research/{score_functions,generate_report}.system.md`](../src/patchdiff_ai/prompts/vulnerability_research/).

### 10. Runtime / orchestrator ([`src/patchdiff_ai/runtime/`](../src/patchdiff_ai/runtime/))

| Module                                                                              | Responsibility                                                                                          |
|-------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------|
| [`app_context.py`](../src/patchdiff_ai/runtime/app_context.py)                      | The DI bundle — built once, threaded everywhere.                                                        |
| [`orchestrator.py`](../src/patchdiff_ai/runtime/orchestrator.py)                    | `run_cve(ctx, cve, ...)` — invokes the pipeline graph, resumes on `__interrupt__`, returns final state |
| [`interactive.py`](../src/patchdiff_ai/runtime/interactive.py)                      | `CliInteractor.handle(RefinementRequest) -> RefinementResponse` — the *only* place `input()` is allowed |
| [`timer.py`](../src/patchdiff_ai/runtime/timer.py)                                  | `async with Timer("label"):` — async-safe span timer logged via structlog                               |
| [`cancel.py`](../src/patchdiff_ai/runtime/cancel.py)                                | `run_cancellable(coro)` — Ctrl-C-clean entry point used by the CLI commands                             |
| [`errors.py`](../src/patchdiff_ai/runtime/errors.py)                                | `DiskFullError` + `free_bytes_for(path)` — domain errors that the CLI exits on cleanly                  |

The orchestrator is deliberately small. The legacy implementation wrapped an `async
def run` in `asyncio.to_thread()` and never awaited the generator — that bug is
fixed simply by `await graph.ainvoke(...)`.

The interrupt loop:

```python
feed = initial
while True:
    state = await graph.ainvoke(feed, config=config)
    if "__interrupt__" not in state:
        break
    req = state["__interrupt__"][0].value
    if isinstance(req, RefinementRequest):
        response = interactor.handle(req)
        feed = Command(resume=response)
    else:
        break
```

`config["configurable"]` carries the per-run knobs that nodes consult (cve, evaluate
flag, interrupt flag, platform tuple, threshold dict). `config["callbacks"]`
carries the LLM metrics handler.

### 11. Observability ([`src/patchdiff_ai/observability/`](../src/patchdiff_ai/observability/))

| Module                                                                              | Responsibility                                                                                          |
|-------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------|
| [`logging.py`](../src/patchdiff_ai/observability/logging.py)                        | `configure_logging(level, logs_dir)` — dual-stream structlog: Console renderer to terminal, JSONRenderer to the per-run file in `logs_dir`. Also defines the `TRACE` level (below DEBUG).|
| [`trace.py`](../src/patchdiff_ai/observability/trace.py)                            | `bind_cve(cve, run_id)` — contextvar binding so every event carries the CVE / run id automatically      |
| [`metrics.py`](../src/patchdiff_ai/observability/metrics.py)                        | `LLMMetricsHandler` — LangChain callback emitting `llm_call` events with model, tokens, latency, cost   |
| [`progress.py`](../src/patchdiff_ai/observability/progress.py)                      | Rich-driven `ProgressReporter` (download / extract bars). `NullProgressReporter` is the default         |

Logging output is JSON by default and tee'd to `logs/<unix>.<uuid>.log` so every
run leaves a durable trace on disk.

No external telemetry. `cli/app.py` `_bootstrap()` pins
`LANGCHAIN_TRACING_V2=false` and `LANGSMITH_TRACING=false` and strips any
inherited `LANGCHAIN_*` / `LANGSMITH_*` API key / endpoint *before* it imports
the LangGraph modules (LangChain captures those at import time). Chroma's
anonymous telemetry is disabled before `chromadb` imports
([`vector_store.py`](../src/patchdiff_ai/persistence/vector_store.py)). All
observability stays local — structlog → `logs/<unix>.<uuid>.log`.

### 12. Prompts ([`src/patchdiff_ai/prompts/`](../src/patchdiff_ai/prompts/))

System prompts are markdown files. `PromptRegistry.default()` loads them at
construction. Nodes look them up via a `PromptId` enum:

```
prompts/
├── registry.py
├── platform_internals/
│   ├── collect.system.md       # used by pi.collect (search-query derivation)
│   └── rank.system.md          # used by pi.rank (file relevancy scoring)
├── windows/
│   └── file_description.system.md  # Windows provider: `add_file_info` embed prompt
└── vulnerability_research/
    ├── score_functions.system.md   # used by vr.rank (function relevancy scoring)
    └── generate_report.system.md   # used by vr.analyze (RCA report generation)
```

Provider-specific prompts (today: only `windows/`) live under
`prompts/<provider>/`. New providers add their own subdirectory and a
matching `PromptId` enum entry.

Inline f-strings for CVE metadata are replaced with a JSON-formatted
`HumanMessage`-builder helper inside the VR nodes.

### 13. Platforms ([`src/patchdiff_ai/platforms/`](../src/patchdiff_ai/platforms/))

The pipeline is platform-shaped, not Windows-shaped. Two protocols at
[`platforms/base.py`](../src/patchdiff_ai/platforms/base.py):

- **`PlatformProvider`** — group-level (one per `windows`, `linux`, ...).
  Owns the Click sub-group, runs auto-detect, aggregates `health_check`
  / `install`, resolves CLI overrides to a concrete `Platform`.
- **`Platform`** — per-version (one per Windows release, one per
  distro/release pair, ...). Owns the pipeline-facing methods:
  `enrich_cve`, `gather_packages`, `candidate_prompts`,
  `candidate_metadata`.

| Module                                                                              | Responsibility                                                                                          |
|-------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------|
| [`base.py`](../src/patchdiff_ai/platforms/base.py)                                  | `Platform` + `PlatformProvider` Protocols + `UnknownPlatform` / `UnsupportedPlatform` exceptions.       |
| [`__init__.py`](../src/patchdiff_ai/platforms/__init__.py)                          | `providers()` registry + `resolve_for_cve(cve_id, platform_override=None)` (parallel native → NVD fallback). |
| [`nvd.py`](../src/patchdiff_ai/platforms/nvd.py)                                    | NVD CPE lookup helper, on-disk cached at `<db_dir>/.nvd/<cve>.json` (30-day TTL). Used as the fallback in `resolve_for_cve`. |
| [`windows/`](../src/patchdiff_ai/platforms/windows/)                                | `WindowsProvider` (real impl). Owns N `WindowsVersionedPlatform` instances loaded from `platforms.json`. `matches_native` hits MSRC; `matches_nvd` matches Windows CPE prefixes. |
| [`linux/`](../src/patchdiff_ai/platforms/linux/)                                    | `LinuxProvider` (skeleton). Pre-declares ubuntu/debian distros so the CLI tree shows up; pipeline-facing methods raise `NotImplementedError` until wired. |
| [`add_platform.md`](../src/patchdiff_ai/platforms/add_platform.md)                  | Step-by-step instructions for adding a new provider. Read this when you start.                          |

Protocol surfaces:

```python
class Platform(Protocol):
    name: str
    async def enrich_cve(self, state, ctx) -> dict[str, Any]: ...
    async def gather_packages(self, state, ctx) -> dict[str, Any]: ...
    def candidate_prompts(self) -> tuple[PromptId, PromptId]: ...
    def candidate_metadata(self, cve) -> dict[str, Any]: ...

class PlatformProvider(Protocol):
    name: str
    def cli_group(self) -> click.Group: ...
    def health_check(self) -> bool: ...
    def install(self) -> None: ...
    async def matches_native(self, cve_id: str) -> Platform | None: ...
    def matches_nvd(self, cpes: list[str]) -> Platform | None: ...
    def resolve(self, **overrides: Any) -> Platform: ...
```

**CVE → platform resolution** ([`platforms/__init__.py:resolve_for_cve`](../src/patchdiff_ai/platforms/__init__.py)):

1. **`--platform <name>` override** → look up that provider, ask it to
   pick the right version (native first, then NVD, then provider's
   default).
2. **No override → parallel native round.** Every provider's
   `matches_native(cve_id)` runs concurrently via `asyncio.gather`.
   First non-`None` wins; ties pick by registration order (warning
   logged).
3. **All native missed → NVD fallback.** Hit NVD's CPE list once, ask
   each provider's `matches_nvd(cpes)` in registration order.
4. **Both rounds missed → `UnsupportedPlatform`** with a hint pointing
   at `--platform <name>`.

The CLI does the resolution before invoking the orchestrator. The
chosen `Platform` is stashed on `ctx.platform` at `run_cve` entry, and
every downstream node reads from there. There is no `select_platform`
inside the runtime any more, and no `platform_ids_hint` side channel.

---

## State machine

The pipeline's `Stage` enum is the single source of truth for "where are we in
the pipeline?". Routing decisions never inspect message history or node names — only
state. The actual graph topology is a six-node sequence; every "branch" is a
short-circuit straight to FINALIZE, never a sideways jump:

```
   START
     │
     ▼
   CVE_INFO ─────► reports already cached?
     │                         │
     │ no                      │ yes
     ▼                         │
   GATHER                      │
     │                         │
     ▼                         │
   PI_AGENT ─────► no candidates above threshold?
     │                         │
     │ Send(RE_AGENT)          │ yes
     │   per candidate         │
     ▼                         │
   RE_AGENT ─────► no artifacts produced?
     │                         │
     │ Send(VR_AGENT)          │ yes
     │   per artifact          │
     ▼                         │
   VR_AGENT                    │
     │                         │
     └──────────┬──────────────┘
                ▼
            FINALIZE
                │
                ▼
              END
```

The `Stage` enum (`START`, `CVE_INFO_DONE`, `GATHER_DONE`, `INTERNALS_DONE`,
`RE_DONE`, `VR_DONE`, `COMPLETE`) is updated by the nodes as state metadata,
but routing reads the substantive state slices (`reports`, `candidates`,
`artifacts`) — not the enum.

The router methods at
[`graphs/pipeline/routing.py`](../src/patchdiff_ai/graphs/pipeline/routing.py)
mirror the diagram. They are pure functions of `(PipelineState, AppContext)` —
they read DataFrames and the patch store but do not mutate state. Mutations happen
inside nodes.

---

## Interrupts & interactivity

The hard rule: **graph nodes never call `input()`**. Otherwise the graph cannot run
under web servers, subprocess hosts, or batch schedulers.

Implementation:

1. A node yields `interrupt(RefinementRequest(cve=...))`. LangGraph captures
   this and surfaces it on the next `ainvoke` result under
   `state["__interrupt__"]`.
2. The orchestrator catches it, dispatches by type:
   - `RefinementRequest` → `CliInteractor.handle(...)` — prompts kind +
     query/pattern.
   - `RefinementPickRequest` → `CliInteractor.handle_pick(...)` — renders
     the search results from one refinement round and prompts
     `Select (e.g., 1,3,5 or 'all')`.
   These are the only code paths that call `input()`.
3. The interactor returns the matching `Refinement{Response,PickResponse}`;
   the orchestrator resumes via `Command(resume=response)`.
4. The same node receives the response, runs the search inside the graph,
   yields the next `interrupt(...)` for picks, then loops back for the next
   round — or returns normally if the user skipped.

`RefinementRequest` / `RefinementResponse` / `RefinementOption` /
`RefinementPickRequest` / `RefinementPickResponse` / `RefinementPickCandidate` /
`AssistantCommand` are defined in
[`graphs/interrupts.py`](../src/patchdiff_ai/graphs/interrupts.py).

When `--interrupt` is on, the pipeline graph compiles with a
`MemorySaver(serde=_PickleSerde())` checkpointer (required by
`Command(resume=...)`). The custom serde is needed because pipeline state
carries live Polars DataFrames + `pathlib.Path` fields that the default
JSON/msgpack serdes choke on. Non-interactive runs skip the checkpointer
entirely (no `interrupt()` will fire, no need to pay the per-step
serialization cost).

The post-run "assistant chat" — `help`, `reports`, `save reports`,
`delete all reports`, `reanalyze`, `change assistant`, `exit` — used to live
inside the graph (and broke when subgraphs were missing nodes). It now lives
entirely outside, in [`cli/chat.py`](../src/patchdiff_ai/cli/chat.py).
Hardcoded commands (`AssistantCommand` enum) dispatch directly; anything else
routes through a ReAct agent ([`cli/chat_agent.py`](../src/patchdiff_ai/cli/chat_agent.py))
with six tools (`list_changed_functions`, `show_decompiled`, `show_diff`,
`show_report`, `search_reports`, `reanalyze`).

Tool execution is gated by default: `build_chat_agent` compiles with
`interrupt_before=["tools"]` so every tool call pauses on a `[y/N]` user
approval. `--chat-permissive` (which implies `--chat`) drops that flag —
the agent then runs tools straight through without asking. The two modes
share the same tool set and the same REPL; only the gating differs.

`reanalyze` re-enters `make_reporter()` and forwards `force=True` so the
cache short-circuit in `cve_info_node` doesn't make the rerun a no-op.

---

## Concurrency model

The asyncio loop is the single concurrency primitive. Bounds:

| Bound                                       | Default | Where                                                  |
|---------------------------------------------|---------|--------------------------------------------------------|
| Concurrent file_info LLM calls              | 500     | `Concurrency.file_info_semaphore` → `asyncio.Semaphore` in `platforms/windows/gather_info/nodes.py:add_file_info` |
| RE workers (per-CVE, fan-out limit)         | 5       | `Concurrency.re_workers` (currently advisory)          |
| Extractor workers per KB                    | 5       | `Concurrency.extractor_workers` → `_KBExtractor` pool  |
| LLM eval parallelism                        | 4       | `Concurrency.llm_eval_parallel`                        |

LangGraph handles the `Send`-based fan-out (RE per candidate, VR per artifact)
internally. We don't manage that thread pool.

Locking:

- `resource_lock(key)` (in
  [`persistence/patch_store.py`](../src/patchdiff_ai/persistence/patch_store.py)) is
  the asyncio replacement for the legacy `threading.RLock` weak-ref table. Used to
  serialize KB downloads and patch-store writes by stable key (e.g. `dest.resolve()`).
- `_file_info_mutex = threading.RLock()` in `platforms/windows/gather_info/nodes.py` is intentionally
  reentrant; it serializes Chroma writes within a single graph execution. The
  `Concurrency.file_info_semaphore` is the actual concurrency cap — the lock
  exists only because Chroma's writer is not async.

---

## Caching strategy

There are several caches, each at a different layer:

| Cache                                                | Backed by                                          | What it short-circuits                                            |
|------------------------------------------------------|----------------------------------------------------|-------------------------------------------------------------------|
| Chroma `windows.exe.rca.reports`                     | Chroma                                             | Re-running a CVE in non-eval mode (`cve_info_node` short-circuits to FINALIZE if any report exists) |
| Chroma `windows.exe.desc`                            | Chroma                                             | Re-embedding the same `(name, package)` file description          |
| `db/.patch_store_df`                                 | Polars binary serialization (atomic via `safe_serialize`) | Re-extracting / re-deltaing the same `(name, package, arch, kb)` tuple |
| `db/.os` (`DiskCache`)                               | JSON                                               | Re-prompting for OS / product ID                                  |
| Per-KB `report.txt` next to extracted dir            | Plain text                                         | Re-extracting an MSU                                              |
| `report.cache` next to each KB extraction            | Pickled DataFrame                                  | Re-building the per-KB update DataFrame                           |
| `__funcs__/<addr>.c` next to each `.i64`             | C-source decompilation                             | Re-decompiling individual functions inside an existing IDB        |
| Per-(cve, file, model_name) entries in `reports`     | Chroma                                             | Re-asking a specific model for the same artifact in `--eval` mode |

Cache invalidation is *manual* — `--eval` re-runs the analysis even if reports
exist, but it still respects per-model cache hits. Deleting `db/` is the way to
force a full re-run.

---

## Error handling & cancellation

- **Subprocess timeouts**: `tools/process.py` enforces a hard timeout. On expiry it
  `proc.kill()`s and raises `ToolTimeout(args, timeout, stderr_tail)`.
- **Subprocess failure**: non-zero exit raises `ToolError(args, returncode,
  stderr_tail)` if `check=True`.
- **Cancellation**: `tools/process.py`'s `run()` and `kb_downloader.py`'s
  `_grab()` handle `asyncio.CancelledError` cleanly: child processes / streaming
  threads are signaled to stop, partial files are deleted.
- **Disk full**: `DiskFullError` is recognized in two places — KB streaming
  (errno `ENOSPC`) and 7-Zip stderr scraping (regex on common phrases). The
  extractor's worker pool sets `fatal_error` on the first hit, drains the queue
  via `task_done()`, and re-raises after `join()`.
- **LLM rate limits**: `tenacity` decorators on the most-frequent LLM calls
  (5 attempts, exponential backoff up to 60 s on `RateLimitError`). Other LLM
  failures bubble up.
- **Structured-output parse errors**: never swallowed. Every
  `with_structured_output(..., include_raw=True)` site checks `result["parsing_error"]`,
  logs `*_parse_error`, and either retries or returns nothing. The pipeline's
  `parse_errors` list collects these for postmortem.
- **BinDiff DB corruption**: one bounded retry with `override=True`, then `None`
  is returned. The RE node treats `None` as a soft-fail and drops the candidate.
- **Domain errors** (`DiskFullError` etc.) propagate out of `run_cve` and are
  caught in [`cli/commands/cve.py`](../src/patchdiff_ai/cli/commands/cve.py) /
  `month.py`, which print a single concise message and exit non-zero (no
  traceback), unless `--log-level trace/debug` was specified.

---

## On-disk layout

```
<repo or working dir>/
├── db/                                  # Chroma + patch-store
│   ├── chroma.sqlite3                   # Chroma index
│   ├── <collection-uuid>/...            # Chroma per-collection storage
│   ├── .patch_store_df                  # Polars-serialized PatchStoreEntry index
│   ├── winsxs.bin                       # cached winsxs DataFrame
│   ├── .os                              # JSON cache (OS detection)
│   └── patch_store/                     # extracted / patched binaries by uid
├── _temp/                               # downloaded .msu + extracted_<archive>/...
│   ├── windows*.msu                     # downloaded KBs
│   └── extracted_windows*.msu/          # 7-Zip + PSF + delta output
│       ├── report.txt                   # list of executables
│       ├── report.cache                 # Polars-cached update DataFrame
│       └── ...                          # nested cabs, manifests, executables
├── reports/                             # plain-text reports
│   └── <CVE>_<file>.txt
└── logs/                                # per-run JSON logs
    └── <unix>.<uuid>.log
```

Paths are configurable via `PATHS__<FIELD>` env vars. Defaults mirror the legacy
implicit layout.

Each binary in the patch store gets its own decompilation directory:

```
<patch_store>/<uid>/
├── <file>                                # PE binary
├── <file>.BinExport                      # produced by IDA + BinExport
├── <file>.<other-kb>.BinDiff             # produced by BinDiff
├── <file>.i64                            # IDA database
└── __funcs__/
    └── <addr>.c                          # decompiled C, one per changed function
```

---

## Walk-through: CVE-2025-29824

This is the canonical golden-reference run that every milestone validates against.

```text
$ patchdiff-ai cve CVE-2025-29824
```

1. **CLI** (typer) parses `cve_id`, builds `Settings` and an `AppContext`.
   `_bootstrap()` force-disables LangSmith / LangChain tracing before LangGraph
   is imported. `configure_logging` opens `logs/<unix>.<uuid>.log`.
2. **Orchestrator** binds the trace context (`bind_cve("CVE-2025-29824", run_id)`),
   builds the pipeline graph, and starts the interrupt loop.
3. **`cve_info_node`** detects the host OS (e.g. `Windows 11 Version 24H2 for
   x64-based Systems`, productId `12390`), fetches MSRC's SUG report, picks the
   product-specific entry, and resolves the `(current=KB5055523,
   previous=KB5053598)` pair (illustrative).
4. **`gather_info`**:
   - Downloads both `.msu`s into `_temp/`.
   - Extracts each into `_temp/extracted_<msu>/`. Nested archives (`.cab`, `.psf`)
     are unpacked. Forward / reverse deltas are applied through `DeltaApi`.
   - Builds `prev`, `curr`, and `winsxs` Polars DataFrames; computes their
     filtered intersections.
   - For every unseen `(name, package)`, calls `MODELS_GATHER_INFO` to produce an
     80-token description and embeds it into `windows.exe.desc`.
5. **`platform_internals`**:
   - Asks `MODELS_PLATFORM_INTERNALS` to derive a similarity-search query from CVE
     metadata.
   - Pulls the top-10 candidates from `windows.exe.desc`.
   - Asks `MODELS_DEFAULT` to rescore them; the patched binary `clfs.sys` typically
     ranks at the top for CVE-2025-29824.
6. **Routing** filters candidates above `thresholds.candidates` (default 7.5),
   patches their entries through `delta_apply.patch_entry` to materialize all three
   KB versions on disk, and `Send`s one RE job per `(primary, secondary)` pair to
   the RE subgraph.
7. **`reverse_engineering`** (per pair):
   - IDA produces `clfs.sys.BinExport` for each side.
   - BinDiff diffs them into `clfs.sys.<KB>.BinDiff`.
   - For each function with `similarity < 1.0`, IDA decompiles the address into
     `__funcs__/<addr>.c` (batched 500 funcs per IDA invocation per `.i64`).
   - Emits an `Artifact` with the diff and the changed `FunctionMatch` list.
8. **`vulnerability_research`** (per Artifact):
   - Reads each function's before / after `.c` files; computes a unified diff.
   - `MODELS_REVERSE_ENGINEERING` scores each function's security relevancy.
   - Functions above `thresholds.security_modification` go into the
     report-generation prompt; `MODELS_RESEARCHER` produces a structured
     `VulnReport(found, confidence, report)`.
   - If the report's confidence > `thresholds.report` → `generate`; else loop
     up to `iter_remaining` times on the remainder.
   - `generate` persists the `Report` into `windows.exe.rca.reports`.
9. **`finalize`** logs `cve_run_complete`. The orchestrator returns the final state.
10. **CLI** has previously installed a Rich progress reporter; its context manager
    exits and `ctx.close()` releases the `DeltaApi` handle.

A subsequent `patchdiff-ai cve CVE-2025-29824` run finds the report in Chroma and
short-circuits at step 3, returning immediately.

---

## Extending the system

### Add a new platform (distro / vendor / OS)

The full step-by-step lives at
[`src/patchdiff_ai/platforms/add_platform.md`](../src/patchdiff_ai/platforms/add_platform.md).
Short version:

1. Create a package `platforms/<name>/` with `provider.py`,
   `<thing>.py` (the per-version `Platform`), `cli.py`, and
   `__init__.py`. Use [`platforms/linux/`](../src/patchdiff_ai/platforms/linux/)
   as the template — it's the canonical skeleton.
2. Implement the `Platform` protocol's four pipeline-facing methods on
   the per-version class: `enrich_cve`, `gather_packages`,
   `candidate_prompts`, `candidate_metadata`.
3. Implement the `PlatformProvider` protocol on the group-level class:
   `cli_group`, `health_check`, `install`, `matches_native`,
   `matches_nvd`, `resolve`. Wrap any sync HTTP calls inside
   `matches_native` with `asyncio.to_thread` so the parallel native
   round stays parallel.
4. Build the Click sub-group with `cve` (using `@cve_options` from
   [`cli/options.py`](../src/patchdiff_ai/cli/options.py) and delegating
   to [`cli/runner.run_single_cve`](../src/patchdiff_ai/cli/runner.py)),
   `health-check`, `install`. Add provider-specific commands as needed.
5. Register `MyProvider()` in
   [`platforms/__init__.py`](../src/patchdiff_ai/platforms/__init__.py)'s
   `providers()` tuple.
6. If your platform needs new advisory fields, add them to
   [`schemas/cve.py`](../src/patchdiff_ai/schemas/cve.py) as optional
   fields so the existing Windows path keeps working unchanged.
7. If your platform's candidate prompts need a different shape, add new
   `PromptId` entries in
   [`prompts/registry.py`](../src/patchdiff_ai/prompts/registry.py) and
   return them from `candidate_prompts()`.

[`platforms/windows/`](../src/patchdiff_ai/platforms/windows/) is the
real reference (provider + versioned plugin + Click group + cycle
helpers).

### Add an analysis stage to an existing subgraph

1. Add a node function in `graphs/<name>/nodes.py`'s `make_nodes(ctx)` factory.
2. Register the node in `graphs/<name>/graph.py`'s `build_<name>_graph(ctx)`.
3. Wire its edges. Use `add_conditional_edges(...)` for branching, `add_edge(...)`
   for fixed transitions.
4. Extend the subgraph's `state.py` with whatever fields the new node reads / writes.
   For collection-style fields, use `Annotated[list[T], append_list]`.

### Add a new subgraph

1. Create `graphs/<new>/{state.py, nodes.py, graph.py}`.
2. Register the compiled graph in `graphs/pipeline/graph.py` as a node.
3. Add a new `Stage` value and a new `PipelineRouter.from_<previous>` method
   wiring the transition.

### Add a new LLM provider

1. Drop a `build_<name>_chat(spec, creds)` factory under
   [`llm/providers/`](../src/patchdiff_ai/llm/providers/).
2. Add a `Provider` enum value and a credentials class in
   [`config/credentials.py`](../src/patchdiff_ai/config/credentials.py).
3. Extend `MODEL_CATALOG` in [`llm/catalog.py`](../src/patchdiff_ai/llm/catalog.py).
4. Wire `Provider.<NEW>` into `ModelRegistry._provider_available` and `_build`.

### Add a new external tool

1. Drop the wrapper under [`tools/`](../src/patchdiff_ai/tools/), built on
   `tools/process.py`'s `run()`.
2. Expose its executable path through `ToolPaths` in
   [`config/tools.py`](../src/patchdiff_ai/config/tools.py).
3. Inject it via `AppContext.tools` in [`runtime/app_context.py`](../src/patchdiff_ai/runtime/app_context.py).
4. Use the injected instance from nodes — never reach for a module-level singleton.

### Switch an existing node to a different model

Set `MODELS_<PURPOSE>=<catalog-name>` in `.env`, or pass a `--model` flag through
the CLI command and into the run config; nodes call
`ctx.registry.for_purpose(ModelPurpose.<X>)`, so the override is honored as long as
the model exists in the catalog and its provider has credentials.

---

For the higher-level summary, see [readme.md](../readme.md). For the rationale
behind specific decisions, see [.plan/refactor-plan.md](../.plan/refactor-plan.md).
