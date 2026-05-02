# PatchDiff-AI

> LangGraph-driven multi-agent system that turns a Microsoft CVE ID into a fully-fledged
> root-cause-analysis report — by downloading the relevant Windows Update, diffing the
> patched and unpatched binaries with IDA Pro + BinDiff, decompiling what changed, and
> letting an LLM ensemble explain *why* the change is a security fix.

Feed it `CVE-2025-29824`. Get back a markdown report that names the buggy function,
shows the pre/post-patch decompilation diff, and walks the trigger flow.

---

## Table of Contents

1. [Status](#status)
2. [What it does](#what-it-does)
3. [High-level architecture](#high-level-architecture)
4. [Prerequisites](#prerequisites)
5. [Installation](#installation)
6. [Configuration](#configuration)
7. [Usage](#usage)
8. [Output](#output)
9. [Logging & observability](#logging--observability)
10. [Extending](#extending)
11. [Project layout](#project-layout)
12. [License](#license)

---

## Status

The greenfield rewrite is the active codebase.

- The active package is [src/patchdiff_ai/](src/patchdiff_ai/) — Pydantic v2 +
  dependency-injected `AppContext` + structured observability + a `Platform`
  plugin protocol so non-Windows targets can be added without touching the
  pipeline graph.
- The original implementation lives at [patchdiff-ai-wip-models_config/](patchdiff-ai-wip-models_config/)
  (gitignored, kept only as a parity reference).
- Architecture details are in [docs/Architecture.md](docs/Architecture.md);
  the original M1→M6 plan that drove the rewrite is at
  [.plan/refactor-plan.md](.plan/refactor-plan.md).

The user-visible workflow (`patchdiff-ai cve <id>` produces an RCA report) and
the on-disk layout (`db/`, `reports/`, `_temp/`, `logs/`) match the legacy
implementation.

---

## What it does

Given a single CVE identifier (e.g. `CVE-2025-29824`) or a whole Patch Tuesday cycle
(e.g. `2025-Apr`), PatchDiff-AI:

1. **Resolves the CVE** against MSRC's CVRF feed, picks the right Windows OS / KB pair
   (current vs. superseded), and decides whether the host platform is even affected.
2. **Downloads** the relevant `.msu` packages from the Microsoft Update Catalog.
3. **Extracts** them — handling nested `.cab` / `.psf` archives and applying forward /
   reverse delta patches via `UpdateCompression.dll`.
4. **Builds an executable index** of every binary that meaningfully differs between the
   two updates, embedding short LLM-written descriptions into a Chroma collection.
5. **Picks candidates** — a platform-internals agent uses CVE metadata + vector search
   to rank the top suspects (similarity × LLM relevancy score).
6. **Reverse engineers** each candidate pair: IDA Pro + BinExport produce comparable
   exports, BinDiff diffs them, and changed functions are decompiled.
7. **Generates the report** — a vulnerability-research agent scores each changed
   function for security impact, picks the top changes, and asks an LLM (or several,
   in `--eval` mode) to write a root-cause analysis.
8. **Persists the report** in the Chroma `reports` collection and prints / saves it
   under `reports/`.

Each CVE runs in its own LangGraph instance. Fan-out (CVE → multiple candidate binaries
→ multiple RE/VR agents) uses LangGraph's `Send` primitive. The pipeline graph
sequences stages via an explicit `Stage` enum — it's a deterministic state machine,
not an LLM-driven supervisor.

> **Supported targets**: Microsoft Patch Tuesday updates on Windows. Tested on
> Windows 11 24H2 x64. Other Windows versions should work; non-Windows targets are
> not currently supported.

---

## High-level architecture

```
   patchdiff-ai cve CVE-YYYY-NNNNN
              │
              ▼
   ┌──────────────────────┐
   │         CLI          │   click + .env loader; per-platform sub-groups
   └──────────┬───────────┘   (windows / linux / ...); resolves CVE→Platform
              │               via parallel native (MSRC/USN/...) + NVD fallback
              │ AppContext (DI bundle) + resolved Platform
              ▼
   ┌──────────────────────┐
   │     Orchestrator     │   stashes Platform on ctx, runs the
   │     run_cve(...)     │   pipeline, resumes on interrupt()
   └──────────┬───────────┘
              ▼
   ╔══════════════════════════════════════════════════════════════════════╗
   ║      Pipeline graph (LangGraph state machine — deterministic)        ║
   ║                                                                      ║
   ║   CVE_INFO ─► GATHER ─► PI_AGENT ─► RE_AGENT ─► VR_AGENT ─► FINALIZE ║
   ║   (advisory  (download  (rank        (per-cand    (per-art    ─► END ║
   ║    + cache    + extract  candidates   IDA +        scoring +         ║
   ║    short-     packages   via vector   BinDiff +    structured        ║
   ║    circuit)   per        search +     decomp)      report)           ║
   ║               platform)  refine)                                     ║
   ║                                                                      ║
   ║                          ═══►          ═══►                          ║
   ║                          Send fan-out  Send fan-out                  ║
   ║                          (per cand.)   (per artifact)                ║
   ║                                                                      ║
   ║   Cache hit on CVE_INFO, or empty fan-outs at PI / RE,               ║
   ║   short-circuit straight to FINALIZE.                                ║
   ╚══════════════════════════════════════════════════════════════════════╝
              │                                            │
              │ enrich_cve / gather_packages /             │ AppContext
              │ candidate_prompts / candidate_metadata     │ read by every
              ▼                                            ▼ node
   ┌──────────────────────┐                ┌──────────────────────────┐
   │  Platform plugin     │                │ Tools · LLM Registry     │
   │  windows / debian /  │                │ Vector stores · Logging  │
   │  android / ...       │                │ Prompts · Progress       │
   └──────────────────────┘                └──────────────────────────┘
   (consulted by CVE_INFO,
    GATHER, PI_AGENT)
```

For the full breakdown, see [docs/Architecture.md](docs/Architecture.md).

---

## Prerequisites

| Tool          | Version            | Why                                       |
|---------------|--------------------|-------------------------------------------|
| **Python**    | 3.11 x64           | Required (the project pins `>=3.11`)      |
| **IDA Pro**   | 8.x (≥ 8.0, < 9.0) | Required by BinDiff 8                     |
| **BinDiff**   | 8.0                | Binary diffing engine                     |
| **BinExport** | ≥ 12               | IDA plugin that produces `.BinExport`     |
| **7-Zip**     | ≥ 22               | Used to extract update archives           |

> **Licensing**: IDA Pro is commercial. Either bring a legal license or fork the
> project to use Ghidra (PRs welcome).

LLM access: Azure OpenAI is the primary provider. Anthropic and Gemini are supported
as eval / fallback providers. See [Configuration](#configuration).

---

## Installation

```powershell
git clone <this repo>
cd patchdiff-ai

# Create and activate a virtual env
python -m venv .venv
.venv\Scripts\activate

# Install the package (editable) and its dependencies
pip install -e .
```

The package exposes a console entry point:

```powershell
patchdiff-ai --help
# or, equivalently:
python -m patchdiff_ai --help
```

Verify external tools and credentials end-to-end:

```powershell
patchdiff-ai health-check
```

`health-check` validates `.env`, prints the resolved model catalog, and smoke-tests the
external tool wrappers.

---

## Configuration

Everything is read from `.env` (or process env vars) via `pydantic-settings`. Nested
fields use `__` as the delimiter — e.g. `PATHS__DB_DIR=/data/patchdiff/db`.

**Azure OpenAI** (primary):

```env
AZURE_ENDPOINT=https://<resource>.openai.azure.com
AZURE_TENANT_ID=...
AZURE_CLIENT_ID=...
AZURE_CLIENT_SECRET=...
```

If the service-principal trio is absent, the registry falls back to
`DefaultAzureCredential` (e.g. `az login`).

**Anthropic** (eval / fallback):

```env
ANTHROPIC_API_KEY=...
```

**Gemini** (eval / fallback):

```env
GOOGLE_API_KEY=...
```

**Per-purpose model overrides** (optional — defaults are in
[src/patchdiff_ai/llm/catalog.py](src/patchdiff_ai/llm/catalog.py)):

```env
MODELS_DEFAULT=azure.o4-mini
MODELS_GATHER_INFO=azure.gpt-4.1-nano
MODELS_PLATFORM_INTERNALS=azure.gpt-4.1-mini
MODELS_REVERSE_ENGINEERING=azure.o3-mini
MODELS_RESEARCHER=azure.o3
MODELS_EMBEDDING=azure.text-embedding-3-small
```

**Tool paths** (override only if non-default):

```env
TOOLS__SEVEN_ZIP=C:/Program Files/7-Zip/7z.exe
TOOLS__IDA=C:/Program Files/IDA Pro 8.0/idat64.exe
```

**Filesystem layout** (defaults shown):

```env
PATHS__DB_DIR=db
PATHS__REPORTS_DIR=reports
PATHS__TEMP_DIR=_temp
PATHS__LOGS_DIR=logs
```

**Telemetry**:

LangSmith / LangChain tracing is force-disabled at startup, and Chroma's
anonymous telemetry is disabled before the client is imported. No
observability data leaves the machine — everything goes to structlog and
the per-run log file under `logs/`.

---

## Usage

### Single CVE

```powershell
patchdiff-ai cve CVE-2025-29824
```

Useful flags:

- `--interrupt` — pause for interactive candidate refinement before the RE
  pipeline. The CLI prompts twice per refinement round: first for kind +
  query (`semantic` / `filename`), then for which entries from the search
  results to add. Refinement is constrained to files that actually changed
  in this KB.
- `--chat` — drop into an interactive chat REPL after the run completes.
  Built-in commands (`help`, `reports`, `save reports`, `delete all reports`,
  `reanalyze`, `change assistant`, `exit`) are dispatched directly;
  anything else routes through a ReAct agent with tool-calling that gates
  every tool call behind a `[y/N]` approval prompt.
- `--chat-permissive` — same REPL as `--chat` but the ReAct agent skips the
  `[y/N]` prompt and runs every tool call automatically. Implies `--chat`.
  Use it when you trust the agent (e.g. read-only tool set on your own
  machine) and don't want to babysit each call.
- `--eval` — run the report-generation step against multiple LLMs in parallel
  (useful for benchmarking or for picking the most confident output).
- `--platform windows` — explicit platform-plugin override. Default is
  auto-detect: every registered provider's native advisory source
  (Windows: MSRC; Linux: USN/DSA, when wired) is queried in parallel,
  with NVD CPE matching as the fallback if all native checks miss.
  Today: `windows` (real) and `linux` (skeleton) are registered.

For Windows-specific knobs (pinning a specific MSRC product ID,
running a Patch Tuesday cycle), use the `windows` sub-group:

```powershell
patchdiff-ai windows cve CVE-2025-29824 --platform-id 12390
patchdiff-ai windows month 2025-Apr --platform-id 12390
patchdiff-ai windows health-check
patchdiff-ai windows install
```

### Chat tools

The ReAct agent under `--chat` / `--chat-permissive` has access to two tool
families. **Native tools** are implemented in this repo and always available.
**IDA / idalib MCP tools** come from the bundled `ida-pro-mcp` server
(lazy-spawned on first call, requires IDA 9.x with idalib activated) and are
sandboxed to binaries under `db/patch_store/` — start a session with
`list_patch_store` → `idalib_open <abs-path>` before calling any analysis
tool. Tools that mutate the IDB (`patch*`), execute Python (`py_eval`,
`py_exec`, `py_run_file`), or drive the debugger (`dbg_*`) are stripped from
the catalogue.

#### Native

| Tool             | Description                                                                                |
|------------------|--------------------------------------------------------------------------------------------|
| `show_report`    | Show cached RCA report(s) for the current CVE. Optional `model_name` filters by exact match. |
| `search_reports` | Semantic search over RCA reports across all cached CVEs.                                   |
| `list_patch_store` | List binaries under `db/patch_store/` — pass an absolute path to `idalib_open`.          |
| `reanalyze`      | Re-run the full pipeline graph for the current CVE.                                        |

The chat REPL also accepts the slash-style hardcoded commands listed in
[`chat.py`](src/patchdiff_ai/cli/chat.py)'s `HELP_TEXT` (`reports`,
`save reports`, `delete all reports`, `reanalyze`, `change assistant`,
`exit`) — these short-circuit before the agent runs.

#### IDA / idalib MCP

**Server & instance management**

| Tool             | Description                                                                |
|------------------|----------------------------------------------------------------------------|
| `server_health`  | Health/ready probe for the MCP server and current IDB state.               |
| `server_warmup`  | Warm up IDA subsystems to reduce first-call latency and transient failures.|
| `list_instances` | List discovered IDA Pro instances with binary, port, and reachability.     |
| `select_instance`| Switch to a different IDA Pro instance for subsequent calls.               |
| `open_file`      | Open a file in a new IDA Pro instance.                                     |
| `idb_save`       | Save the active IDB to disk, optionally to a provided path.                |

**Listing & queries**

| Tool           | Description                                                                |
|----------------|----------------------------------------------------------------------------|
| `lookup_funcs` | Get functions by address or name (auto-detects).                           |
| `list_funcs`   | List functions with optional filtering and offset/count pagination.        |
| `func_query`   | Query functions with richer filtering than `list_funcs`.                   |
| `list_globals` | List globals with optional filtering and offset/count pagination.          |
| `entity_query` | Query IDB entities with typed filters, projection, and pagination.         |
| `imports`      | List imports with module names using offset/count pagination.              |
| `imports_query`| Query imports with richer filtering than `imports(offset,count)`.          |
| `insn_query`   | Query instructions with mnemonic/operand filters and scoped scans.         |
| `int_convert`  | Convert numbers to different formats.                                      |

**Disassembly & decompilation**

| Tool            | Description                                                                |
|-----------------|----------------------------------------------------------------------------|
| `decompile`     | Decompile function(s) at address(es); returns pseudocode and per-item errors. |
| `disasm`        | Disassemble function with offset/`max_instructions` pagination and optional total count. |
| `basic_blocks`  | Return function CFG blocks with offset/`max_blocks` pagination.            |
| `export_funcs`  | Export function data for addresses in `json` / `c_header` / `prototypes` formats. |

**Search**

| Tool          | Description                                                                |
|---------------|----------------------------------------------------------------------------|
| `find_regex`  | Search strings by case-insensitive regex with offset/limit pagination.     |
| `search_text` | Search the rendered listing using IDA's native text search (fast C++ scan).|
| `find_bytes`  | Search byte patterns (supports `??`) with offset/limit pagination.         |
| `find`        | Search strings/immediates/refs for targets with offset/limit pagination.   |

**Cross-references & call graph**

| Tool             | Description                                                                |
|------------------|----------------------------------------------------------------------------|
| `xrefs_to`       | Return xrefs to address(es) or named symbols, capped per target with truncation flag. |
| `xref_query`     | Query xrefs with direction/type filters and pagination.                    |
| `xrefs_to_field` | Get cross-references to structure fields.                                  |
| `callees`        | Return unique callees per function, capped by limit.                       |
| `callgraph`      | Build a bounded callgraph from roots with depth/node/edge limits.          |

**Function & component analysis**

| Tool                | Description                                                             |
|---------------------|-------------------------------------------------------------------------|
| `func_profile`      | Profile functions with summary metrics and optional sampled details.    |
| `analyze_batch`     | Run comprehensive analysis over one or more target functions.           |
| `analyze_function`  | Compact single-function analysis: pseudocode, strings, constants, callers, callees, xrefs, blocks. |
| `analyze_component` | Analyze related functions as a group: per-function summaries, internal call graph, shared data. |
| `survey_binary`     | Get a compact overview of the binary in one call.                       |
| `trace_data_flow`   | Follow cross-references from or to an address, automatically traversing.|

**Memory I/O**

| Tool               | Description                                                              |
|--------------------|--------------------------------------------------------------------------|
| `get_bytes`        | Read bytes from memory addresses.                                        |
| `get_int`          | Read integer values from memory addresses.                               |
| `get_string`       | Read strings from memory addresses.                                      |
| `get_global_value` | Read global variable values by address or symbol name.                   |
| `put_int`          | Write integer values to memory addresses.                                |
| `read_struct`      | Read struct fields from memory at address; auto-detect type when possible.|

**Types**

| Tool                | Description                                                             |
|---------------------|-------------------------------------------------------------------------|
| `declare_type`      | Declare C type definitions in the local type library.                   |
| `enum_upsert`       | Create or extend local enums idempotently.                              |
| `search_structs`    | Search local structs/unions by name pattern.                            |
| `type_query`        | Query local types with structured filters/projection-friendly output.   |
| `type_inspect`      | Inspect named types (size/kind/declaration/members).                    |
| `set_type`          | Apply types (function/global/local/stack).                              |
| `type_apply_batch`  | Apply multiple type edits and return aggregate status.                  |
| `infer_types`       | Infer and apply likely types at target addresses.                       |

**Code editing**

| Tool              | Description                                                               |
|-------------------|---------------------------------------------------------------------------|
| `set_comments`    | Set comments at addresses (both disassembly and decompiler views).        |
| `append_comments` | Append comments at addresses, deduping exact text by default.             |
| `rename`          | Batch-rename funcs/globals/locals/stack vars with dry-run options.        |
| `define_func`     | Define functions; IDA infers bounds unless `end` is provided.             |
| `define_code`     | Convert bytes to code instruction(s) at address(es).                      |
| `undefine`        | Undefine item(s) at address(es), converting back to raw bytes.            |

**Stack frames**

| Tool             | Description                                                                |
|------------------|----------------------------------------------------------------------------|
| `stack_frame`    | Return stack variables for function address(es).                           |
| `declare_stack`  | Create stack variables from typed stack declarations.                      |
| `delete_stack`   | Delete stack variables by name or offset.                                  |

**Signatures**

| Tool                          | Description                                                  |
|-------------------------------|--------------------------------------------------------------|
| `make_signature`              | Create unique byte signatures for addresses (shortest pattern). |
| `make_signature_for_function` | Create unique byte signatures for function entry points.     |
| `make_signature_for_range`    | Create a byte signature for a specific address range.        |
| `find_xref_signatures`        | Find signatures for code locations that reference an address.|

### A whole Patch Tuesday

```powershell
patchdiff-ai windows month 2025-Apr --platform-id 12390
```

The `month` command lives under the `windows` sub-group (Patch Tuesday
is an MSRC concept). Filters by `--platform-id` (single MSRC product
ID) and `--platform-name` (substring match). Runs every matching CVE
end-to-end, sequentially.

### Cached reports

```powershell
patchdiff-ai cached --cve CVE-2025-29824
patchdiff-ai cached --month 2025-Apr --platform-ids 12390
```

Reads back any reports already persisted to the `reports` Chroma collection and
saves them under `reports/`.

### Verbosity

```powershell
patchdiff-ai -L debug cve CVE-2025-29824
patchdiff-ai -L trace cve CVE-2025-29824   # full crash tracebacks to log file
```

Logs are JSON by default and tee'd to both stderr and `logs/<unix>.<uuid>.log`.

---

## Output

Reports are written to:

- **Vector store**: `db/` Chroma — three collections persist analysis state:
  `windows.exe.desc` (file descriptions for candidate retrieval),
  `windows.exe.functions.logic` (per-function summaries), and
  `windows.exe.rca.reports` (the final RCA reports — used to short-circuit
  re-runs and serve `patchdiff-ai cached`).
- **Filesystem**: `reports/<CVE>_<file>.txt` — plain ASCII, human-readable.

Each report includes:

- The CVE ID and MSRC metadata
- The vulnerable file / function and its address
- Pre-patch and post-patch decompiled C
- Unified diff of the change
- A root-cause narrative (the LLM's analysis)
- A confidence score (0.0 - 1.0)
- The model that authored the report

In `--eval` mode, multiple reports are produced (one per model in
`EVAL_MODELS` — see [src/patchdiff_ai/llm/catalog.py](src/patchdiff_ai/llm/catalog.py)).

---

## Logging & observability

- **Dual-stream structlog**: terminal (stderr) gets the colorized console renderer for human reading; the per-run log file gets line-oriented JSON for grep/jq.
- Every event carries the bound `cve` and `run_id` (a 12-char hex) via contextvars.
- An `LLMMetricsHandler` callback emits one `llm_call` event per LangChain
  invocation with model name, latency, token counts, and computed cost (using
  `ModelSpec.cost_per_mtok`).
- `cve_run_complete` is logged once per CVE with the report count.
- LangSmith / LangChain tracing is force-disabled at startup; Chroma anonymous
  telemetry is disabled before import. No data leaves the machine.

---

## Extending

There are three places to add capabilities; pick the smallest one that fits.

**A new platform** (Linux distro / Android / macOS / packaged app): implement
the `Platform` protocol at
[src/patchdiff_ai/platforms/base.py](src/patchdiff_ai/platforms/base.py) and
register it in
[src/patchdiff_ai/platforms/__init__.py](src/patchdiff_ai/platforms/__init__.py).
Five methods to implement: `matches(cve_id)`, `enrich_cve(state, ctx)`,
`gather_packages(state, ctx)`, `candidate_prompts()`, `candidate_metadata(cve)`.
[`platforms/windows.py`](src/patchdiff_ai/platforms/windows.py) is the
reference implementation — it delegates to existing `patches/*` modules and
the Windows gather subgraph.

**A new analysis stage**:

- **A new node inside an existing subgraph** — e.g. a call-flow extraction step in
  the RE subgraph at [src/patchdiff_ai/graphs/reverse_engineering/](src/patchdiff_ai/graphs/reverse_engineering/).
- **A new subgraph** — define a `state.py` (Pydantic v2 BaseModel) + `nodes.py` +
  `graph.py`, register it on the pipeline at
  [src/patchdiff_ai/graphs/pipeline/graph.py](src/patchdiff_ai/graphs/pipeline/graph.py),
  and wire a stage transition in
  [src/patchdiff_ai/graphs/pipeline/routing.py](src/patchdiff_ai/graphs/pipeline/routing.py).

**A new LLM provider** is two files:

1. `src/patchdiff_ai/llm/providers/<name>.py` — a `build_<name>_chat(spec, creds)` factory.
2. Register the provider in `Provider`, the catalog, and `ModelRegistry._build`.

**A new external tool**: drop it under `src/patchdiff_ai/tools/`, build it on top
of [`tools/process.py`](src/patchdiff_ai/tools/process.py)'s `run()` (mandatory
timeout, no `shell=True`), expose its executable path through
[`config/tools.py`](src/patchdiff_ai/config/tools.py), and inject via
`AppContext.tools`.

---

## Project layout

```
patchdiff-ai/
├── pyproject.toml
├── readme.md                       # this file
├── CLAUDE.md                       # project instructions for Claude Code
├── docs/
│   └── Architecture.md             # full architecture write-up
├── .plan/
│   └── refactor-plan.md            # design + milestone plan
├── src/patchdiff_ai/
│   ├── __init__.py                 # exposes run_cve()
│   ├── __main__.py                 # python -m patchdiff_ai
│   ├── cli/                        # typer entry points + chat REPL
│   ├── config/                     # pydantic-settings models
│   ├── llm/                        # registry + provider factories
│   ├── observability/              # structlog + callbacks + progress
│   ├── persistence/                # Chroma + patch-store + disk caches
│   ├── platforms/                  # Platform protocol + windows plugin
│   ├── prompts/                    # system prompts (markdown)
│   ├── runtime/                    # AppContext + orchestrator + interactivity
│   ├── schemas/                    # Pydantic v2 cross-agent contracts
│   ├── tools/                      # 7-Zip, IDA, BinDiff, PSF, Delta, manifest
│   ├── patches/                    # CVE / KB / extraction pipeline
│   └── graphs/                     # pipeline + four subgraphs
├── db/                             # Chroma + patch-store on disk
├── reports/                        # human-readable reports
├── _temp/                          # downloaded + extracted KBs
├── logs/                           # per-run JSON logs
└── patchdiff-ai-wip-models_config/ # legacy reference (gitignored)
```

---

## License

Copyright 2025 Akamai Technologies Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
these files except in compliance with the License. You may obtain a copy of the
License at

> http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.

