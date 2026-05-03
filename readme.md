# PatchDiff-AI

> Turn a CVE ID into a binary-diff root-cause-analysis report. Fully automated:
> Microsoft Security Update Guide → Update Catalog download → 7-Zip / `.cab` /
> `.psf` extraction → forward / reverse delta apply → IDA Pro + BinDiff →
> per-function decompile → LLM-authored markdown RCA.

Feed it `CVE-2025-29824`. Get back a markdown report that names the buggy
function, shows the pre/post-patch decompiled C, walks the trigger flow, and
attaches a confidence score and per-call cost trace.

![Pipeline](docs/Pipeline.png)

---

## Contents

- [What it does](#what-it-does)
- [Quick start](#quick-start)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Chat REPL](#chat-repl)
- [Output](#output)
- [Concurrency & tuning](#concurrency--tuning)
- [Observability](#observability)
- [Architecture](#architecture)
- [Extending](#extending)
- [Project layout](#project-layout)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## What it does

Given a single CVE (e.g. `CVE-2025-29824`) or a whole Patch Tuesday cycle
(e.g. `2026-Apr`), PatchDiff-AI:

1. **Resolves the CVE** against MSRC's CVRF feed (or NVD, for non-Microsoft
   CVEs), picks the right Windows version + KB pair, and decides whether the
   target is affected.
2. **Downloads** both `.msu` packages from the Microsoft Update Catalog.
   Concurrent CVEs targeting the same KB coalesce on a per-path lock; the
   bandwidth slot is bounded by `CONCURRENCY__KB_DOWNLOADS`.
3. **Extracts** them — nested `.cab` / `.psf` archives, forward / reverse
   delta apply via a RAII-wrapped `UpdateCompression.dll`. Same per-key lock
   protects parallel CVEs from racing into the same `extracted_<msu>/` tree.
4. **Indexes** every binary that meaningfully differs between the two updates
   and embeds short LLM-written descriptions into a local Chroma collection.
5. **Picks candidates** — a platform-internals agent uses CVE metadata + vector
   search to rank the top suspects (similarity × LLM relevancy score). Optional
   interactive refinement via `--interrupt`.
6. **Reverse engineers** each candidate: IDA Pro produces comparable
   `.BinExport`s, BinDiff diffs them, changed functions are decompiled to C
   (in-process via `idalib` when available, falling back to a headless `idat`
   subprocess flow).
7. **Generates the report** — a vulnerability-research agent scores each
   changed function for security impact and asks an LLM (or a fan-out across
   eval models) to write the root-cause analysis.
8. **Persists** the report in Chroma's `windows.exe.rca.reports` collection
   and saves a copy under `reports/<CVE>_<file>.txt`.

The pipeline is a deterministic LangGraph state machine — *not* an
LLM-driven supervisor. Every routing decision is a pure function of state.

> **Targets supported today:** Microsoft Patch Tuesday updates on Windows 10
> 22H2, Windows 11 23H2 / 24H2, and Windows Server 2022 / 2025. Other Windows
> versions can be added by indexing your own WinSxS tree
> (see [Adding a Windows version](#adding-a-windows-version)). A Linux
> provider skeleton is registered but the gather flow is not yet wired up.

---

## Quick start

```powershell
# Install directly from GitHub (Windows PowerShell, Python 3.11+ x64)
pip install git+https://github.com/maor-da/patchdiff-ai

# Set up Azure OpenAI credentials in a .env file in your working dir,
# then validate the install end-to-end
patchdiff-ai health-check

# Install the bundled IDA 9.3 plugins + idalib (needs admin)
# Run from an elevated PowerShell prompt
patchdiff-ai windows install

# Run a single CVE
patchdiff-ai cve CVE-2025-29824

# Or drop into the chat REPL with no CVE bound
patchdiff-ai
```

Both entry points are equivalent:

```powershell
patchdiff-ai --help
python -m patchdiff_ai --help
```

---

## Prerequisites

| Component   | Version                | Notes                                                                                                  |
|-------------|------------------------|--------------------------------------------------------------------------------------------------------|
| **Python**  | 3.11 x64               | Pinned `>=3.11`; idalib requires CPython matching the IDA build's Python version (3.11 for IDA 9.x).   |
| **IDA Pro** | 8.0+ or 9.0+           | 9.3 is the preferred path — the bundled BinDiff/BinExport plugins are 9.3-pinned. 8.x works via the legacy `idat` subprocess flow. |
| **idalib**  | bundled with IDA 9.0+  | In-process IDA via the `idapro` Python wrapper. ~5–10× faster RE than the subprocess flow.             |
| **BinDiff** | 8.0                    | Bundled in `resources/bindiff_ida_9.3/` (ships in the wheel). Set `BINDIFF_PATH` to override.          |
| **BinExport** | ≥ 12                 | Same bundle. The `bindiff8_ida64.dll` + `binexport12_ida64.dll` plugins are copied into IDA's `plugins/` dir by `patchdiff-ai windows install`. |
| **7-Zip**   | ≥ 22                   | Used for KB extraction. Default path: `C:\Program Files\7-Zip\7z.exe`; override via `TOOLS__SEVEN_ZIP`. |

LLM access: **Azure OpenAI is the primary provider.** Anthropic and Gemini
are supported as eval / fallback. See [Configuration](#configuration).

> **Licensing.** IDA Pro is commercial. Bring a legal license or fork the
> project to use Ghidra (PRs welcome).

---

## Installation

### From GitHub (recommended for end users)

```powershell
pip install git+https://github.com/maor-da/patchdiff-ai
```

The wheel ships the bundled BinDiff/BinExport DLLs (~9.5 MB) under
`patchdiff_ai/_resources/bindiff_ida_9.3/` so `patchdiff-ai windows install`
can copy them into your IDA 9.3 `plugins/` folder without extra downloads.

### From source (for development)

```powershell
git clone https://github.com/maor-da/patchdiff-ai
cd patchdiff-ai

python -m venv .venv
.venv\Scripts\activate

pip install -e .
```

In editable mode the runtime resolver finds the bundled DLLs at
`<repo>/resources/bindiff_ida_9.3/` instead — same files, no copy needed.

### Bootstrapping IDA-side prerequisites

```powershell
# Run from an elevated PowerShell prompt — the steps below write into
# C:\Program Files\IDA *.
patchdiff-ai windows install
```

What it does:

1. Warns if the current shell isn't elevated.
2. Discovers every IDA install under `Program Files`.
3. Installs the `idapro` wheel from the **newest** install's
   `<ida_root>/idalib/python/` and runs `py-activate-idalib.py`.
4. Copies `bindiff.exe`, `bindiff8_ida64.dll`, `binexport12_ida64.dll` from
   the bundled `bindiff_ida_9.3/` into the **IDA 9.3** install's `plugins/`
   folder. Idempotent (skips files whose contents already match).

The bundled DLLs are pinned to IDA 9.3's SDK ABI; the install command
refuses to copy them into 8.x or 9.0 because they wouldn't load.

### Adding a Windows version

The 3 GB `windows_sxs/` archive tree is **not** bundled — too large for a
pip install. To analyse a Windows version that isn't already in
`resources/windows_sxs/platforms.json`, build your own:

```powershell
python resources/index_winsxs.py <path-to-WinSxS> ^
       --product-id <MSRC-product-id> ^
       --slug <slug-like-windows_11_24h2>
```

Then point at the directory containing `platforms.json`:

```env
PATHS__RESOURCES_DIR=path/to/resources
```

---

## Configuration

Everything is read from `.env` (or process env) via `pydantic-settings`.
Nested fields use `__` as the delimiter — e.g.
`PATHS__DB_DIR=/data/patchdiff/db`.

### Azure OpenAI (primary)

```env
AZURE_ENDPOINT=https://<resource>.openai.azure.com
AZURE_TENANT_ID=...
AZURE_CLIENT_ID=...
AZURE_CLIENT_SECRET=...
```

If the service-principal trio is absent, the registry falls back to
`DefaultAzureCredential` (e.g. `az login`).

### Anthropic / Gemini (eval / fallback)

```env
ANTHROPIC_API_KEY=...
GOOGLE_API_KEY=...
```

### Per-purpose model overrides (optional)

Defaults are in [src/patchdiff_ai/llm/catalog.py](src/patchdiff_ai/llm/catalog.py).

```env
MODELS_DEFAULT=azure.o4-mini
MODELS_GATHER_INFO=azure.gpt-4.1-nano
MODELS_PLATFORM_INTERNALS=azure.gpt-4.1-mini
MODELS_REVERSE_ENGINEERING=azure.o3-mini
MODELS_RESEARCHER=azure.o3
MODELS_EMBEDDING=azure.text-embedding-3-small
```

### Tool paths (override only if non-default)

```env
TOOLS__SEVEN_ZIP=C:/Program Files/7-Zip/7z.exe
TOOLS__IDA=C:/Program Files/IDA Professional 9.3/idat.exe
```

When `TOOLS__IDA` is unset the runtime auto-discovers installs and picks the
newest one with `idalib`.

### Filesystem layout

```env
PATHS__DB_DIR=db                 # Chroma + patch-store
PATHS__REPORTS_DIR=reports       # plain-text reports
PATHS__TEMP_DIR=_temp            # downloaded + extracted KBs
PATHS__LOGS_DIR=logs             # per-run JSON logs
PATHS__RESOURCES_DIR=resources   # WinSxS archives + manifests
```

### Concurrency

```env
CONCURRENCY__CVE_WORKERS=12         # parallel CVEs in a batch run
CONCURRENCY__KB_DOWNLOADS=6         # concurrent multi-GB MS Update streams
CONCURRENCY__RE_WORKERS=12          # idalib worker processes
CONCURRENCY__EXTRACTOR_WORKERS=5    # 7-Zip/PSF extraction workers per KB
CONCURRENCY__FILE_INFO_SEMAPHORE=500  # cap on concurrent gather-stage LLM calls
CONCURRENCY__LLM_EVAL_PARALLEL=4    # parallel report generation in --eval mode
```

See [Concurrency & tuning](#concurrency--tuning) below for guidance.

### Telemetry

LangSmith / LangChain tracing is force-disabled at startup, and Chroma's
anonymous telemetry is disabled before the client is imported. **No
observability data leaves the machine** — everything goes to structlog and
the per-run log file under `logs/`.

---

## Usage

### Single CVE

```powershell
patchdiff-ai cve CVE-2025-29824
```

Auto-detects the platform via NVD CPE data. To force a specific one:

```powershell
patchdiff-ai cve CVE-2025-29824 --platform windows
```

Common flags (every CVE-running command accepts these):

| Flag                  | Effect                                                                                  |
|-----------------------|-----------------------------------------------------------------------------------------|
| `--interrupt`         | Pause for interactive candidate refinement before the RE pipeline.                      |
| `--chat`              | Drop into the chat REPL after the run completes.                                        |
| `--chat-permissive`   | Same as `--chat` but the agent runs tools without `[y/N]` approval. Implies `--chat`.   |
| `--eval`              | Generate reports across the full eval-model set in parallel (benchmarking).             |

### Windows-specific entry points

```powershell
patchdiff-ai windows cve CVE-2025-29824 --platform-id 12390   # force a specific MSRC product ID
patchdiff-ai windows month 2026-Apr --platform-id 12390       # whole Patch Tuesday cycle, parallel
patchdiff-ai windows health-check                             # Windows-side prereq probe
patchdiff-ai windows install                                  # idalib + IDA 9.3 plugins (needs admin)
```

A `month` run executes every matching CVE in parallel inside one process —
sharing the idalib pool, model registry, and Chroma stores. Tune the fan-out
via `CONCURRENCY__CVE_WORKERS`.

### Cached reports

```powershell
patchdiff-ai cached --cve CVE-2025-29824
patchdiff-ai cached --month 2026-Apr --platform-ids 12390,12436
```

Reads back any reports already persisted to the `reports` Chroma collection
and saves them under `reports/`. No graph runs.

### Verbosity

```powershell
patchdiff-ai -L debug cve CVE-2025-29824
patchdiff-ai -L trace cve CVE-2025-29824   # full crash tracebacks to log file
```

JSON logs land in `logs/<unix>.<uuid>.log`; the console gets a colourised
renderer in TTYs.

### CVE-less chat

Bare `patchdiff-ai` (or `patchdiff-ai --chat` / `--chat-permissive`) drops
straight into the chat REPL with no CVE bound — useful for browsing cached
reports, querying Chroma, or driving the IDA tools directly.

---

## Chat REPL

![Chat agent](docs/ChatAgent.png)

The REPL has two surfaces:

**Hardcoded slash-style commands** dispatch directly without ever reaching
an LLM:

| Command              | Action                                                          |
|----------------------|-----------------------------------------------------------------|
| `help`               | Show this list.                                                 |
| `reports`            | Print every cached RCA report for the bound CVE.                |
| `save reports`       | Save them to `./` as `<CVE>_<file>.txt`.                        |
| `delete all reports` | Drop the bound CVE's entries from Chroma (with `[y/N]`).        |
| `reanalyze`          | Re-run the full pipeline (requires a bound CVE + platform).     |
| `change assistant`   | Pick a different chat model from the registry.                  |
| `exit`               | Leave.                                                          |

**Free-form input** routes to a LangGraph ReAct agent. The agent has a
hybrid catalogue:

- ~10 **native tools** in this repo: `show_report`, `search_reports`,
  `chroma_query`, `list_patch_store`, `read_dataframe`, BinDiff inspectors,
  Python sandbox, etc.
- ~80 **idalib tools** proxied through the bundled
  [`ida-pro-mcp`](https://github.com/mrexodia/ida-pro-mcp) — function
  listings, decompile, xrefs, callgraphs, byte search, type queries, etc.
  Mutating tools (`patch*`), Python execution (`py_eval`), and debugger
  control (`dbg_*`) are stripped from the catalogue. The IDA worker is
  lazy-spawned on first use.

The agent discovers tools via three meta-tools:

```python
list_tools()                         # tag overview
list_tools(tag="search")             # tools tagged "search"
describe_tool("decompile")           # JSON args schema + full description
call_tool("decompile", {"addr": ...}) # invoke
```

By default each `call_tool` invocation pauses with a `[y/N]` approval prompt
in the REPL. `--chat-permissive` skips the gate.

---

## Output

Two persistence layers, both local:

- **Chroma** at `db/`. Three collections back the analysis loop:
  - `windows.exe.desc` — file descriptions for candidate retrieval.
  - `windows.exe.functions.logic` — per-function summaries.
  - `windows.exe.rca.reports` — final RCA reports. Used to short-circuit
    re-runs and serve `patchdiff-ai cached`.
- **Filesystem** at `reports/<CVE>_<file>.txt` — plain ASCII, human-readable.

Each report carries:

- The CVE ID and MSRC metadata
- The vulnerable file / function and its address
- Pre-patch and post-patch decompiled C
- Unified diff of the change
- Root-cause narrative (the LLM's analysis)
- Confidence score (0.0–1.0)
- Authoring model + token / cost trace

In `--eval` mode, multiple reports are produced (one per model in
`EVAL_MODELS` — see [src/patchdiff_ai/llm/catalog.py](src/patchdiff_ai/llm/catalog.py)).

---

## Concurrency & tuning

A `windows month` run is the big lever. Key knobs:

| Knob                              | Default | Effect                                                                                       |
|-----------------------------------|--------:|----------------------------------------------------------------------------------------------|
| `CONCURRENCY__CVE_WORKERS`        |     12  | CVEs running in parallel inside one batch invocation. Each shares the idalib pool + LLM deployment. |
| `CONCURRENCY__KB_DOWNLOADS`       |      6  | Concurrent multi-GB streams from the MS Update Catalog. Same-KB CVEs already coalesce on a per-path lock — this only matters for cross-version batches. |
| `CONCURRENCY__RE_WORKERS`         |     12  | `idalib` worker processes in the pool. Sized for the IDA SDK + Hex-Rays GIL pinning.         |
| `CONCURRENCY__EXTRACTOR_WORKERS`  |      5  | Async workers per `extract_kb` invocation (7-Zip + PSF + delta apply).                       |
| `CONCURRENCY__FILE_INFO_SEMAPHORE`|    500  | Cap on concurrent gather-stage LLM calls (file descriptions). Tune below your Azure deployment's per-minute rate limit. |
| `CONCURRENCY__LLM_EVAL_PARALLEL`  |      4  | Parallel report generation in `--eval` mode.                                                 |

**Rule of thumb:** start with the defaults; if your Azure deployment is
hitting per-minute caps, lower `CVE_WORKERS` to 5–6 before lowering anything
else. The system retries on `RateLimitError` with exponential backoff, but
queueing builds up tail latency that dominates wall time.

The batch runner's behaviour:

- **Per-CVE failures are isolated.** One CVE crashing logs a warning and
  continues; the final `batch_run_complete` event lists the failed CVEs.
- **Ctrl-C cancels the whole batch.** Partial work isn't rolled back —
  cached reports stay in Chroma.
- **Race-safe on shared resources.** KB downloads and extractions both
  serialise on per-path async locks (multiple CVEs targeting the same KB
  trigger a single download + a single extraction).

---

## Observability

- **Dual-stream structlog.** Stderr gets a colourised console renderer for
  human reading; the per-run log file gets line-oriented JSON for `grep`/`jq`.
- **Auto-tagged events.** Every event carries the bound `cve` and `run_id`
  (12-char hex) via `contextvars`. `bind_cve(cve, run_id)` is set per CVE
  task — async-safe across the parallel batch.
- **LLM cost trace.** An `LLMMetricsHandler` callback emits one `llm_call`
  event per LangChain invocation: model name, latency, token counts, and
  computed cost (using `ModelSpec.cost_per_mtok`). Per-CVE rollups land in
  `cve_run_summary` and `run_perf_summary`.
- **No external telemetry.** LangSmith / LangChain tracing is force-disabled
  before any LangChain import; Chroma's anonymous telemetry is disabled
  before the client is imported.

Useful query shapes against the JSON log file:

```jsonc
// Per-CVE total cost
jq 'select(.event=="cve_run_summary") | {cve, cost_usd_total, llm_calls}'

// Slowest LLM calls in the run
jq 'select(.event=="llm_call") | {cve, model, elapsed_s}' | sort -k3 -n -r | head

// Failed CVEs in a batch
jq 'select(.event=="batch_run_complete") | .failed_cves'
```

---

## Architecture

```
   patchdiff-ai cve CVE-YYYY-NNNNN
              │
              ▼
   ┌──────────────────────┐
   │         CLI          │   click + .env loader; per-platform sub-groups
   └──────────┬───────────┘   (windows / linux / ...); resolves CVE→Platform
              │               via parallel native (MSRC) + NVD fallback
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
```

Locked-in technical decisions worth knowing about:

- **Pydantic v2** for all state + settings + cross-agent contracts. Cross-node
  merging via LangGraph reducers (`Annotated[list[T], append_list]`,
  `add_messages`).
- **`AppContext` for DI.** Built once in `cli/app.py`'s `main()`, threaded
  through every node / tool / command. No module-level singletons, no
  god-objects, no import-time `sys.exit(1)`.
- **No `input()` inside graph nodes.** Interactivity lives in the CLI via
  LangGraph `interrupt()` → `CliInteractor.handle(...)`.
- **Subprocess discipline.** Every external-tool wrapper goes through
  `tools/process.py`'s `run()`: mandatory timeout, `create_subprocess_exec`
  (no `shell=True`), `ToolError` / `ToolTimeout`, Ctrl-C-clean cleanup.
- **Dependency versions are frozen.** Bump deliberately, not casually.

For the deep dive — every layer, the state machine, caching strategy, and a
worked walk-through of CVE-2025-29824 — see
[docs/Architecture.md](docs/Architecture.md).

---

## Extending

Three places to add capabilities; pick the smallest one that fits.

**A new platform** (Linux distro / Android / macOS / packaged app):
implement the `Platform` protocol at
[src/patchdiff_ai/platforms/base.py](src/patchdiff_ai/platforms/base.py)
(`matches`, `enrich_cve`, `gather_packages`, `candidate_prompts`,
`candidate_metadata`) and register it in
[src/patchdiff_ai/platforms/__init__.py](src/patchdiff_ai/platforms/__init__.py).
[`platforms/windows/`](src/patchdiff_ai/platforms/windows/) is the reference.
Walkthrough: [src/patchdiff_ai/platforms/add_platform.md](src/patchdiff_ai/platforms/add_platform.md).

**A new analysis stage:**

- *A new node inside an existing subgraph* — drop a node in
  `graphs/<name>/nodes.py` and wire edges in `graph.py`.
- *A new subgraph* — `state.py` (Pydantic v2 BaseModel) + `nodes.py` +
  `graph.py`, register on the pipeline at
  [src/patchdiff_ai/graphs/pipeline/graph.py](src/patchdiff_ai/graphs/pipeline/graph.py),
  wire transition in
  [src/patchdiff_ai/graphs/pipeline/routing.py](src/patchdiff_ai/graphs/pipeline/routing.py).

**A new LLM provider**: factory under `llm/providers/<name>.py`, register
the `Provider` enum value, extend the catalog, wire `ModelRegistry._build`.

**A new external tool**: drop under
[`src/patchdiff_ai/tools/`](src/patchdiff_ai/tools/), build on
[`tools/process.py`](src/patchdiff_ai/tools/process.py)'s `run()`, expose
its path through
[`config/tools.py`](src/patchdiff_ai/config/tools.py)'s `ToolPaths`, inject
through `AppContext.tools`.

---

## Project layout

```
patchdiff-ai/
├── pyproject.toml
├── readme.md                             # this file
├── CLAUDE.md                             # contributor guide / project rules
├── docs/
│   ├── Architecture.md                   # full architecture write-up
│   ├── Pipeline.png
│   └── ChatAgent.png
├── resources/
│   ├── bindiff_ida_9.3/                  # bundled BinDiff + IDA 9.3 plugins
│   ├── windows_sxs/                      # per-platform WinSxS archives (gitignored, build locally)
│   └── index_winsxs.py                   # WinSxS indexer
├── src/patchdiff_ai/
│   ├── __init__.py                       # exposes run_cve()
│   ├── __main__.py                       # python -m patchdiff_ai
│   ├── cli/                              # click entry points + chat REPL
│   ├── config/                           # pydantic-settings models
│   ├── llm/                              # registry + provider factories
│   ├── observability/                    # structlog + callbacks + progress
│   ├── persistence/                      # Chroma + patch-store + disk caches
│   ├── platforms/                        # Platform protocol + windows / linux plugins
│   ├── prompts/                          # system prompts (markdown)
│   ├── runtime/                          # AppContext + orchestrator + interactivity
│   ├── schemas/                          # Pydantic v2 cross-agent contracts
│   ├── tools/                            # 7-Zip, IDA, BinDiff, PSF, Delta, manifest
│   ├── patches/                          # CVE / KB / extraction pipeline
│   └── graphs/                           # pipeline + four subgraphs
├── db/                                   # Chroma + patch-store on disk
├── reports/                              # human-readable reports
├── _temp/                                # downloaded + extracted KBs
└── logs/                                 # per-run JSON logs
```

---

## Troubleshooting

**`patchdiff-ai windows install` fails with permission errors.**
You're not running elevated. The wheel install + plugin copy both write
into `C:\Program Files\IDA *`. Re-run from an elevated PowerShell.

**`No IDA install discovered under Program Files`.**
Either install IDA Pro under one of `Program Files` / `Program Files (x86)`,
or set `TOOLS__IDA=C:/path/to/idat.exe` in `.env`.

**`No IDA 9.3 install found` — plugins skipped.**
The bundled BinDiff/BinExport DLLs are pinned to 9.3's SDK ABI and won't
load into 8.x or 9.0. Either install IDA 9.3, or bring your own
plugins built against your IDA version.

**Long tail latency on a `windows month` run.**
Almost always Azure OpenAI deployment throttling. The system retries with
backoff but queueing piles up. Lower `CONCURRENCY__CVE_WORKERS` to 5–6
before any other tuning.

**`No platforms configured` on first run.**
The `windows_sxs/` archive tree isn't bundled (3 GB). Either add a Windows
version via `python resources/index_winsxs.py ...`, or set
`PATHS__RESOURCES_DIR=` to a directory that already has one built.

**Azure auth errors with no `AZURE_CLIENT_SECRET`.**
The registry falls back to `DefaultAzureCredential`. Make sure `az login`
worked and your account has `Cognitive Services User` on the resource.

---

## License

Copyright 2025 Akamai Technologies Inc.

This software is distributed under the terms set out in the project's
LICENSE file. By using or distributing this software you agree to those
terms.
