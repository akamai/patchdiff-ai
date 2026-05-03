# Reverse Engineering Agent — Architecture

This document describes how the **RE agent** in PatchDiff-AI is built: how it
diffs and decompiles two versions of a binary using IDA Pro 9.x's `idalib`,
why it splits into two layers (a **direct in-process pool** for the pipeline
hot path and a **chat-MCP service** for the post-run REPL), and how the
data flows through it end-to-end.

If you only need a high-level view of where the RE agent sits in the larger
pipeline, see [Architecture.md § 9. Graphs](Architecture.md#9-graphs-srcpatchdiff_aigraphs).
This document is the deep dive: process model, lifecycle, IPC protocol,
caching, backpressure, and observability.

---

## Table of contents

1. [The job, in one sentence](#the-job-in-one-sentence)
2. [Why two layers](#why-two-layers)
3. [Process model](#process-model)
4. [Component map](#component-map)
5. [Layer A: `IdalibPool` — the RE workhorse](#layer-a-idalibpool--the-re-workhorse)
   1. [Worker process: `_idalib_pool_worker.py`](#worker-process-_idalib_pool_workerpy)
   2. [The five ops](#the-five-ops)
   3. [Pool lifecycle](#pool-lifecycle)
   4. [Worker assignment + backpressure](#worker-assignment--backpressure)
   5. [`.i64` cache discipline](#i64-cache-discipline)
   6. [Failure modes](#failure-modes)
6. [Layer B: `IdaMcpService` — chat tools](#layer-b-idamcpservice--chat-tools)
7. [The pipeline graph](#the-pipeline-graph)
8. [The `analyze` node](#the-analyze-node)
9. [The `diff_and_decompile` node](#the-diff_and_decompile-node)
10. [Lifecycle integration with `AppContext`](#lifecycle-integration-with-appcontext)
11. [Observability — what gets logged and why](#observability--what-gets-logged-and-why)
12. [Performance tuning](#performance-tuning)
13. [End-to-end walk-through](#end-to-end-walk-through)
14. [Why we don't ...](#why-we-dont-)

---

## The job, in one sentence

Given two builds of the same binary (pre-patch and post-patch), produce:

1. A `.BinExport` file per build (BinDiff's input format).
2. A `.BinDiff` file (sqlite database of function matches with similarity
   scores).
3. A `__funcs__/<ea>.c` file for each function whose similarity is `< 1.0`,
   for both builds.

Everything downstream — the vulnerability research (VR) agent that picks
which functions are interesting, the chat REPL that lets the user explore
diffs, the report writer — reads those three artefact families off disk.
The RE agent's job is to put them there.

---

## Why two layers

The RE agent has two very different consumers:

| Consumer | Pattern | What it cares about |
|---|---|---|
| Pipeline graph | Bulk, batch, internal | Throughput, parallel binaries, `.i64` reuse |
| Chat ReAct agent | Interactive, sparse, LLM-driven | Tool surface, on-demand queries, sandbox |

A single layer can't be optimal for both:

- The pipeline does internal Python-to-Python calls. Routing them through
  an MCP server (JSON-RPC + HTTP + `py_eval` round-trips for IDC plugins)
  is pure overhead. A 600-function batch decompile becomes 600 HTTP
  requests with `init_hexrays_plugin` paid each time, when the same
  worker could have done it in one in-process loop.
- The chat agent benefits enormously from MCP. `ida-pro-mcp` exposes ~80
  tools (`decompile`, `disasm`, `xrefs_to`, `lookup_funcs`, `func_query`,
  `callgraph`, `type_inspect`, …) with proper schemas. `langchain-mcp-adapters`
  turns those into LangChain `BaseTool`s automatically — no hand-rolled
  wrappers, no schema drift, no per-tool maintenance.

So the design splits responsibility:

- **`IdalibPool`** — direct in-process idalib in N worker processes.
  No MCP. Used by the pipeline `re_agent` graph during a CVE run.
- **`IdaMcpService`** — single ida-pro-mcp subprocess, lazy-spawned on
  the first chat tool call. Used by the post-run REPL only.

The two services share no runtime state. They're constructed independently
in `AppContext` and torn down independently. A CVE run that never enters
chat never spawns the MCP server; a chat session that never asks about a
binary never spawns idalib-mcp.

---

## Process model

```
                       patchdiff-ai (parent)
                              │
            ┌─────────────────┼─────────────────────┐
            ▼                 ▼                     ▼
┌────────────────────┐  ┌─────────────────┐  ┌─────────────────────┐
│ idalib worker 0    │  │ idalib worker 4 │  │  idalib-mcp.exe     │
│ (Python, idapro)   │  │ ...             │  │  (chat ONLY, lazy)  │
│ holds 1 IDB        │  │                 │  │  ida-pro-mcp + IDA  │
└────────────────────┘  └─────────────────┘  └─────────────────────┘
        ▲                       ▲                      ▲
        │                       │                      │
        └─── multiprocessing ───┘                      │
             Pipe (pickle)                             │
                                                       │
        ┌──────────────────────────────────────────────┘
        │
   streamable HTTP (MCP, langchain-mcp-adapters)
```

Three classes of subprocess:

1. **idalib worker** — spawned by `multiprocessing.get_context("spawn")`.
   Each runs `_idalib_pool_worker.worker_main(conn)` and is the parent of
   exactly one `idapro.open_database` call at a time. Sized by
   `settings.concurrency.re_workers` (default 5). Lives only as long as
   it's bound to a binary; killed by `release()` to reclaim 1-2 GB RSS.
2. **`idalib-mcp.exe`** — spawned by `subprocess.Popen` from a wrapper
   module ([`_idalib_mcp_worker.py`](../src/patchdiff_ai/tools/_idalib_mcp_worker.py))
   that monkey-patches `MCP_SERVER.serve` to use `ThreadingHTTPServer`
   (so concurrent MCP requests don't queue behind one request thread).
   Single instance, lazy. Lives for the duration of the chat session.
3. **`bindiff.exe`** — bundled at [resources/bindiff_ida_9.3/](../resources/bindiff_ida_9.3/),
   spawned via `python-bindiff` → `asyncio.to_thread` per pair. Multiple
   in flight is fine; bindiff is stateless.

`idapro` is **process-global** — only one binary can be open per Python
interpreter, and `idapro.open_database` for a new binary implicitly
closes the old one. Multiple binaries → multiple processes. That single
constraint dictates almost everything else in this document.

---

## Component map

```
src/patchdiff_ai/
├── tools/
│   ├── idalib_pool.py            ← Layer A: IdalibPool (this doc's main subject)
│   ├── _idalib_pool_worker.py    ← Worker entrypoint (child process)
│   ├── ida_mcp.py                ← Layer B: IdaMcpService (chat-only)
│   ├── _idalib_mcp_worker.py     ← idalib-mcp wrapper (ThreadingHTTPServer)
│   ├── _subprocess_lifecycle.py  ← Shared atexit/PID/port helpers
│   └── bindiff.py                ← BindiffTool (subprocess wrapper, unchanged)
├── graphs/
│   └── reverse_engineering/      ← single subgraph, two make_nodes implementations
│       ├── graph.py              ← picks idalib vs legacy via ctx.tools.idalib
│       ├── nodes.py              ← legacy idat-subprocess flow (fallback)
│       ├── nodes_idalib.py       ← idalib flow (preferred)
│       └── _shared.py            ← discover_parents, hexish, decompile_set_via_idalib
├── runtime/
│   ├── app_context.py            ← Tools(idalib=…, ida_chat=…)
│   ├── paths.py                  ← BUNDLED_BINDIFF_DIR
│   └── orchestrator.py           ← await ctx.tools.idalib.aclose() post-graph
├── cli/
│   ├── commands/cve.py           ← ctx.tools.idalib.attach_progress(progress)
│   ├── chat.py                   ← post-run REPL (await build_chat_agent)
│   └── chat_agent.py             ← _make_mcp_tools via ida_chat.get_langchain_tools
└── config/
    └── tools.py                  ← discover_ida_installs / select_ida_install
```

Reference materials kept under [`_temp/reference/`](../_temp/reference/) (gitignored,
read-only): [haruspex-master](../_temp/reference/haruspex-master/) (Rust template
for in-process idalib decompile) and [ida-pro-mcp-main](../_temp/reference/ida-pro-mcp-main/)
(the upstream MCP server source).

---

## Layer A: `IdalibPool` — the RE workhorse

Defined at [`tools/idalib_pool.py`](../src/patchdiff_ai/tools/idalib_pool.py).

The pool's contract is small and entirely binary-path-driven:

```python
class IdalibPool:
    def __init__(self, *, n_workers: int = 5, ida_install: IdaInstall | None) -> None: ...
    def attach_progress(self, reporter: ProgressReporter) -> None  # optional Rich spinner
    async def open(self, binary: Path) -> None                     # warm an IDB
    async def binexport(self, binary: Path, out: Path,
                        *, skip_if_exists: bool = True) -> Path
    async def decompile_many(self, binary: Path, addrs: list[int]
                             ) -> dict[int, str]
    async def release(self, binary: Path) -> None                  # close IDB, kill worker
    async def aclose(self) -> None                                 # graceful shutdown
    def shutdown(self) -> None                                     # sync emergency

    progress: ProgressReporter | None                              # optional Rich spinner
```

When idalib isn't available, `AppContext.build()` sets `ctx.tools.idalib = None`
and the pipeline's RE-graph picks the legacy idat-subprocess `make_nodes`
implementation instead.

### Worker process: `_idalib_pool_worker.py`

The child process is intentionally minimal. From
[`_idalib_pool_worker.py`](../src/patchdiff_ai/tools/_idalib_pool_worker.py):

```python
# CRITICAL: `import idapro` must be the very first import. It bootstraps
# IDA's bundled SDK (idaapi, ida_loader, ida_hexrays, …) into sys.path.
import idapro

_open_path: Path | None = None    # the one binary this worker holds


def worker_main(conn: Connection) -> None:
    """Dispatch loop.

    Reads `(op, kwargs)` tuples from the parent pipe and writes
    `("ok", payload)` or `("err", traceback_str)` back. Stays alive until
    the parent sends `("shutdown", {})` or the pipe EOFs.
    """
```

**Why a separate process per worker?**

- `idapro` is process-global — only one binary at a time.
- Auto-analysis pins the GIL for tens of seconds (sometimes minutes on
  mshtml/ieframe-class DLLs). Threads can't parallelise across that.
- Hex-Rays is also blocking. Multiple decompiles need separate processes.

**Why `spawn`, not `fork`?** Required on Windows. On POSIX we use spawn
anyway so each worker re-bootstraps idapro from a clean Python — no
inherited state from the parent, no surprises with fd inheritance of
loaded DLLs.

### The five ops

The worker speaks a tiny pickle protocol over `multiprocessing.Pipe`:

| Op | Args | Result | Notes |
|---|---|---|---|
| `open` | `path: str` | `{opened, cached_idb, saved_idb}` | Loads `<path>` (or `<path>.i64` if cached) into idalib. Idempotent for already-loaded paths. |
| `binexport` | `out: str` | `{out, save_warning?}` | Drives `BinExportBinary("<dst>")` via `idaapi.ida_expr.eval_idc_expr` (the plugin only exposes IDC). Saves the IDB after. |
| `decompile_many` | `addrs: list[int]` | `{ea: c_source}` | One round-trip Hex-Rays loop. Failures (no Hex-Rays unit, malformed CFG) silently absent from result. |
| `release` | — | `{released, path?}` | `idapro.close_database(save=False)`; worker stays alive for reuse on a different binary. |
| `ping` | — | `{open, pid}` | Liveness probe. |
| `shutdown` | — | (worker exits) | No reply. Pipe closes; parent observes EOF. |

Per-op exceptions are caught inside the dispatch loop and replied as
`("err", traceback)` — the worker stays alive. Only an unrecoverable
error (segfault, OOM, broken pipe) breaks the loop, at which point the
parent detects death via `proc.poll()` and recycles the slot.

### Pool lifecycle

```
__init__               workers list created (no procs spawned yet)
                                    │
                                    ▼
first  open / binexport / decompile_many on binary B
                                    │
                                    ▼
_assign(B)             pick free worker → mark binding → send `open`
                                    │
                                    ▼
worker N spawned       multiprocessing.spawn → idapro bootstrap → Pipe ready
                                    │
                                    ▼
op replies arrive      _send_recv awaits via run_in_executor + recv
                                    │
                                    ▼
release(B)             send `release` → send `shutdown` → await proc exit
                                    │
                                    ▼
worker slot free       bound_path = None → notify _assign waiters
                                    │
                                    ▼
… reused for binary C, eventually ─┘ (lazy respawn)
                                    │
                                    ▼
aclose() at end of graph     send shutdown to all live workers, await exit
                             (orchestrator does this in run_cve's finally)
```

**Lazy spawn** — `_start_worker(w)` is the only place a `Process` is
created. It runs from `_send_recv` on every op, but the idempotent
`is_alive and conn is not None` short-circuit makes it free after the
first call.

**Eager release** — `release(B)` doesn't just close the IDB; it
*kills the process*. Python and IDA both hold tenacious memory after
`close_database` and we measured 1-2 GB of RSS that never goes back to
the OS. Killing the process is the only reliable reclamation. The next
binary that needs that slot pays a fresh ~50ms `Popen` cost — negligible
compared to even a cached `.i64` load.

### Worker assignment + backpressure

The trickiest part of the pool. Three rules:

1. A binary path is **pinned** to a worker on first `_assign`. Subsequent
   ops on the same binary route to the same worker so the IDB stays warm.
2. Round-robin **across binaries** so two binaries-of-a-pair land on
   different workers and analyse in parallel.
3. When all workers are bound, `_assign` **waits** instead of failing.

The wait was the v3 fix. Earlier versions raised `IdalibUnavailable` if
the pool was saturated, which got silently swallowed by the eager-open's
`gather(return_exceptions=True)` in `diff_and_decompile`. The pipeline
then quietly fell back to a lazy open inside `decompile_many`, paying
the full auto-analysis cost *inside* the `decompile_diff` timer — which
showed up as a 275-second `decompile_diff` for 5 functions in the
CVE-2026-21513 run.

The wait/notify mechanism uses `asyncio.Event`:

```python
self._worker_freed: asyncio.Event   # lazy-init in _ensure_event

async def _assign(self, binary):
    while True:
        async with self._assign_lock:
            # 1. Existing binding? Return it.
            # 2. Free worker? Mark binding, break.
            # 3. No free worker → ev.clear(), log wait_for_free_worker
        # 4. Outside the lock, await Event.set() (with 30-min safety timeout)
        await asyncio.wait_for(ev.wait(), timeout=1800.0)

def _notify_worker_freed(self):
    self._worker_freed.set()           # sync-safe; called from release/_kill_worker
```

Three sites set the event:
- `release(B)` after `_await_proc_exit` finishes
- `_kill_worker(w)` (timeout / pipe broken in `_send_recv`)
- The open-retry-failure path in `_assign` itself, when it gives up

`Event.set()` wakes **all** waiters. They race on `_assign_lock`; the
first one finds a free slot, the others re-check, find no slot, clear
the event, and re-park. This causes a small thundering-herd in the log
(multiple `wait_for_free_worker` events for the same binary) but is
otherwise harmless. We deliberately picked `Event` over `Condition` so
the sync code paths in `_kill_worker` can call `set()` without
acquiring an async lock.

**Why the binding is cleared *after* `_await_proc_exit`** — clearing it
earlier would let `_assign` race onto a worker that's still draining
(proc alive, but `release` op pending). The next `_send_recv("open")`
would race the still-running shutdown sequence and either deadlock on
the pipe or get a half-baked open response.

### `.i64` cache discipline

The worker's `_op_open` has two paths, gated on whether `<binary>.i64`
already exists:

```python
have_cached_idb = idb_candidate.is_file()
rc = idapro.open_database(
    str(target),
    run_auto_analysis=not have_cached_idb,    # ← critical
)
ida_auto.auto_wait()                          # flush any straggler queue
if not have_cached_idb:
    ida_loader.save_database(idb_path_str, 0) # populate cache for next time
```

Why this matters — from
[idapro's own docstring](../.venv/Lib/site-packages/idapro/__init__.py):

> If run_auto_analysis is set to True, the auto-analysis will start and
> wait for its completion.

The SDK has no short-circuit for "already complete" — `True` always
runs a full analysis pass. On a 16k-function `combase.dll` that's ~110
seconds, even when the saved `.i64` already encodes the full analysis
state. With `False` and a cached `.i64`, the same load takes ~5s.

`_op_binexport` always saves the IDB after a successful BinExport, so
even when a cold-cache run only does `binexport` (not `open` directly),
the next run hits the warm path.

**Self-healing** — if a prior run did `binexport` but never persisted
the IDB (interrupted run, manual cleanup), the next call to `_op_open`
populates the cache via the cold-path branch.

### Failure modes

| Failure | Detection | Recovery |
|---|---|---|
| Worker process segfaults / OOM | `recv()` raises `EOFError` / `BrokenPipeError` in `_send_recv` | `_kill_worker` clears slot + notifies; caller re-attempts `_assign` |
| Worker hung on auto-analysis | `asyncio.wait_for` timeout (default 600s) on `_send_recv` | `_kill_worker`; surface `IdalibUnavailable` to caller |
| Stale `.i64` from prior crash | First `idapro.open_database` returns non-zero | `_assign` deletes `.i64` + sidecars (`.id0/.id1/.id2/.nam/.til`), retries once |
| BinExport plugin missing or fails silently | `out_path.exists()` check after `eval_idc_expr` | `RuntimeError` from worker; caller sees it via the `("err", ...)` reply |
| Ctrl-C in parent | `atexit` handler taskkills any PID in `_SPAWNED_PIDS` | Survives even when the normal shutdown chain is interrupted |
| Pool saturated (more binaries than workers) | `_assign` finds no free slot | Wait on `_worker_freed` event; resume when `release` notifies |

The atexit safety net (line 75-100 of `idalib_pool.py`) is critical on
Windows: `multiprocessing.spawn` workers get their own console process
group, so the user's Ctrl-C doesn't reach them. Without `atexit`, an
interrupted run leaves orphan worker processes holding the `.i64`
mmap'd, and the *next* run can't open them.

---

## Layer B: `IdaMcpService` — chat tools

Defined at [`tools/ida_mcp.py`](../src/patchdiff_ai/tools/ida_mcp.py).

A drastically simpler service than the pool — single worker, single
purpose, lazy spawn:

```python
class IdaMcpService:
    async def start(self) -> None
    async def get_langchain_tools(
        self, *, deny: set[str] | None = None,
        path_allowlist: set[str] | None = None,
    ) -> list[BaseTool]
    async def aclose(self) -> None
    def shutdown(self) -> None
```

`get_langchain_tools` is the only method the chat agent actually calls.
It:

1. Lazy-starts the underlying `_IdaMcpWorker` (spawns `idalib-mcp.exe`,
   waits for the port to come up, opens a persistent `mcp.ClientSession`
   over streamable HTTP).
2. Fetches the tool catalogue via `langchain_mcp_adapters.MultiServerMCPClient.get_tools()`.
3. Applies the deny-list (`py_eval`, `py_exec`, `patch_*`, `dbg_*`).
4. Wraps every tool that takes an `input_path` or `session_id` argument
   in a sandbox that rejects values outside `path_allowlist` (typically
   the absolute paths of binaries under `db/patch_store/`).

The chat ReAct agent then sees the full ida-pro-mcp catalogue
(~80 tools — `decompile`, `disasm`, `xrefs_to`, `lookup_funcs`,
`func_query`, `callgraph`, `type_inspect`, `rename`, etc.) as proper
LangChain tools with schemas. No hand-rolled wrappers.

### Why a wrapper script for the MCP server

`idalib-mcp` (the upstream console script) calls
`MCP_SERVER.serve(background=False)`, which uses single-threaded
`http.server.HTTPServer`. SSE streaming POST + GET over the same
connection then deadlocks the one request thread.

Our wrapper at [`_idalib_mcp_worker.py`](../src/patchdiff_ai/tools/_idalib_mcp_worker.py)
monkey-patches `serve` to default `background=True` (= `ThreadingHTTPServer`),
then delegates to `idalib_server.main()` so we inherit its argparse,
signal handlers, and session-manager wiring verbatim.

### Why MCP for chat at all

The pipeline doesn't need MCP — it does internal Python-to-Python
calls. But chat is fundamentally tool-driven: an LLM agent picks tools
based on schemas, and `ida-pro-mcp`'s schemas are already curated for
LLM consumption. Re-implementing 80 tool wrappers (with argument
schemas, output formatting, error handling) would be a maintenance
burden; surfacing them via langchain-mcp-adapters is one line of code
that updates automatically as the upstream evolves.

---

## The pipeline graph

The RE agent is a LangGraph subgraph with two nodes:

```
                   ┌──────────────┐
                   │   analyze    │   ← BinExport (skip_if_exists)
                   └──────┬───────┘
                          │
                          ▼
                ┌────────────────────┐
                │ diff_and_decompile │   ← BinDiff + decompile_many
                └────────┬───────────┘   + release()
                         │
                         ▼
                        END
```

Pair selection happens upstream in the platform-internals (PI) graph;
the RE subgraph is `Send()`-fanned out per pair, so multiple pairs run
in parallel. The pool's backpressure is what makes that fanout safe
when `n_pairs * 2 > re_workers`.

### Selector

[`graphs/pipeline/graph.py`](../src/patchdiff_ai/graphs/pipeline/graph.py)
mounts `build_re_router_graph(ctx)` (M3) as the RE_AGENT. The router
classifies each candidate via `Platform.classify_candidate` and
forwards into the matching backend subgraph:

```python
re_node = build_re_router_graph(ctx)
# Routes per Send to:
#   binary_graph.build_binary_re_graph(ctx)  — IDA + BinDiff
#   source_graph.build_source_re_graph(ctx)  — text udiff
```

Inside the binary backend, the idalib-vs-subprocess pick still happens
at build time: `build_binary_re_graph` imports `nodes_idalib.make_nodes`
when `ctx.tools.idalib is not None` and `nodes.make_nodes` otherwise
(IDA 8.x fallback). When idalib isn't available (no IDA install, IDA
8.x without idalib, broken `idapro` activation), `AppContext.build`
sets `ctx.tools.idalib = None`. Same node names, same artefact shape —
the substitution is invisible to everything downstream.

---

## The `analyze` node

[`graphs/reverse_engineering/nodes_idalib.py`](../src/patchdiff_ai/graphs/reverse_engineering/nodes_idalib.py):

```python
async def analyze(state):
    prim = Path(state.primary_file.path)     # post-patch
    sec  = Path(state.secondary_file.path)   # pre-patch
    async with Timer("ida_export"):
        await asyncio.gather(*(
            ctx.tools.idalib.binexport(
                src,
                src.with_name(src.name + ".BinExport"),
                skip_if_exists=True,
            )
            for src in (prim, sec)
        ))
    return {}
```

That's the whole node. Two binexport calls in `gather`, each landing on
a different worker (round-robin pinning), each producing one `.BinExport`
file on disk.

`skip_if_exists=True` is the cache shortcut: if the `.BinExport` file
already exists from a prior run, `binexport` returns immediately
without binding a worker. On a fully-cached pair, `analyze` is
essentially instant (`ida_export` timer ~0.1s).

---

## The `diff_and_decompile` node

The harder node. Three phases, each with its own timer:

```python
async def diff_and_decompile(state):
    prim, sec = state.primary_file.path, state.secondary_file.path

    # Phase 1: kick off eager IDB warm-up (in parallel with bindiff)
    warmup_tasks = []
    for binary in (prim, sec):
        if binary.with_name(binary.name + ".i64").is_file():
            warmup_tasks.append(asyncio.create_task(ctx.tools.idalib.open(binary)))

    # Phase 2: bindiff (subprocess, parallel-safe across pairs)
    async with Timer("bindiff"):
        bd = await ctx.tools.bindiff.diff(prim_be, sec_be, out_path)
        if bd is None:
            await asyncio.gather(*warmup_tasks, return_exceptions=True)
            for binary in (prim, sec):
                await ctx.tools.idalib.release(binary)
            return {"artifacts": []}

    # Phase 3: wait for warmup to finish, then decompile changed funcs
    await asyncio.gather(*warmup_tasks, return_exceptions=True)
    async with Timer("decompile_diff"):
        # changed = funcs with similarity < 1.0
        # primary_addrs = changed - already-cached .c files
        # secondary_addrs = same for secondary
        await asyncio.gather(
            _decompile_set(ctx, bd.primary, primary_funcs_dir, primary_addrs),
            _decompile_set(ctx, bd.secondary, secondary_funcs_dir, secondary_addrs),
        )
        # build Artifact with FunctionMatchRefs

    # Phase 4: release workers — drop 1-2 GB IDBs from RAM
    for finished in (prim, sec):
        await ctx.tools.idalib.release(finished)

    return {"artifacts": [artifact]}
```

### Phase 1: eager warm-up

The big perf trick. We **gate on `.i64` existence**: only kick off the
eager open if the saved IDB is already on disk, where the open is a
~5-second cached load. Skipping the gate would let the eager open
trigger a cold full-analysis pass (~100s on big DLLs) on every pair
where decompile turns out to be unnecessary (everything cached) — pure
waste.

The `asyncio.create_task` schedules the open coroutines without
awaiting them. Phase 2's bindiff then runs in parallel with the
warm-up.

### Phase 2: bindiff

Wraps the existing `BindiffTool` (which calls `python-bindiff` →
`bindiff.exe` via `asyncio.to_thread`). Independent of idalib —
bindiff only needs the two `.BinExport` files. Multiple bindiff
subprocesses across pairs run truly in parallel.

If bindiff fails (sqlite corruption, missing input, etc.), we drain
the warm-up tasks and call `release` on both binaries before bailing
out. The release path frees workers for other pairs and ensures we
don't leak 1-2 GB IDBs into the rest of the pipeline.

### Phase 3: decompile only what's not cached

```python
primary_addrs = {f.address1 for f in changed} - {
    int(i.stem, 16) for i in primary_funcs_dir.glob("*.c") if _hexish(i.stem)
}
```

For each binary, we compute the *uncached* changed set by subtracting
the existing `__funcs__/<ea>.c` filenames from the bindiff change list.
If the user has run this CVE before and only a few new functions
changed, only those new ones get sent to `decompile_many`.

`_decompile_set` short-circuits early when the address set is empty:

```python
if not addresses:
    return    # no _assign call, no worker bound for this binary
```

This is what makes a fully-cached pair (BinExport ✓, all `.c` files ✓)
take ~0.2s end-to-end — `decompile_many` returns instantly without
touching idalib.

`decompile_many` is the critical optimisation for the **uncached**
path. ida-pro-mcp's `decompile` tool is single-address; running 600
changed functions through it would cost 600 HTTP round-trips, 600
`init_hexrays_plugin` calls, 600 result encodings. We bypass that:
one pickle round-trip carrying a list of EAs, the worker loops
in-process, returns `dict[ea, c_source]`.

### Phase 4: release

Always releases both workers, regardless of how the decompile went. The
artefacts are on disk; we don't need the IDB any more. Releasing here
(rather than in `aclose`) is what keeps peak memory bounded when
multiple pairs run concurrently — finished pairs free their RAM while
later pairs are still analysing.

---

## Lifecycle integration with `AppContext`

[`runtime/app_context.py`](../src/patchdiff_ai/runtime/app_context.py):

```python
@dataclass
class Tools:
    seven_zip: SevenZipTool
    ida: IdaTool                          # legacy 8.x subprocess wrapper (always built)
    bindiff: BindiffTool
    delta: DeltaApi
    idalib:   IdalibPool   | None         # RE workhorse, None when idalib not activated
    ida_chat: IdaMcpService | None        # chat-only MCP, None when idalib not activated
    manifest: WcpManifestExtractor | None = None
```

Construction:

```python
idalib_pool: IdalibPool | None = None
ida_chat: IdaMcpService | None = None
if ida_install is not None and ida_install.has_idalib:
    os.environ.setdefault("IDADIR", str(ida_install.root))
    idalib_pool = IdalibPool(
        n_workers=settings.concurrency.re_workers,
        ida_install=ida_install,
    )
    ida_chat = IdaMcpService()
```

Setting `IDADIR` is what lets the worker's `import idapro` succeed via
the `spawn` start method (children inherit env). Without it the worker
would `ImportError` immediately.

### Three teardown paths, three reasons

```python
# 1. After-graph (in run_cve's finally, INSIDE the event loop):
await ctx.tools.idalib.aclose()
```

This is the **clean** path. Async, runs on the same event loop the
worker's `_io_executor` futures are bound to. Lets every worker get a
`shutdown` op via the pipe and exit cleanly within the timeout.

```python
# 2. AppContext.close() (sync, called by the CLI's `finally`):
self.tools.idalib.shutdown()
self.tools.ida_chat.shutdown()
```

The **emergency** path. Sync because `asyncio.run` has already returned
by the time `AppContext.close()` runs. Just `proc.terminate()` per
worker, no awaiting. Safe to call after `aclose` (idempotent — both
methods skip dead workers).

```python
# 3. Module-level atexit handler:
atexit.register(_kill_tracked_pids)
```

The **last-resort** path. Fires regardless of how Python exits — Ctrl-C,
uncaught exception, `os._exit` from a finalizer. Iterates `_SPAWNED_PIDS`
and `taskkill /F /PID` (Windows) or `SIGKILL` (POSIX) any survivor.
On the happy path this is a no-op because `shutdown()` discards the PID
from the set on clean termination.

---

## Observability — what gets logged and why

Every meaningful state transition emits a structlog event. The schema
is stable: operators can grep by `event` field or filter via
`-L info`/`-L debug`.

### Pool events

| Event | Level | Fields | Meaning |
|---|---|---|---|
| `idalib_pool_spawn` | info | worker, pid | Subprocess started |
| `idalib_pool_wait_for_free_worker` | info | binary, pool_size | Backpressure parked a waiter |
| `idalib_pool_wait_resolved` | info | binary, worker, **wait_s** | Waiter got a slot; cumulative queue time |
| `idalib_pool_open_done` | info | binary, worker, **open_s** | `_op_open` returned |
| `idalib_pool_binexport_done` | info | binary, worker, **elapsed_s** | BinExport plugin finished |
| `idalib_pool_decompile_done` | info | binary, worker, n, **elapsed_s** | Hex-Rays loop finished |
| `idalib_pool_release` | info | worker, binary | Worker shut down after pair |
| `idalib_pool_kill` | warning | worker, pid, reason | `_kill_worker` (timeout/pipe failure) |
| `idalib_pool_open_failed` | warning | worker, binary, attempt, error | Open failed; auto-retry after sidecar cleanup |
| `idalib_pool_force_terminate` | warning | worker, pid | `_await_proc_exit` had to fall back to terminate |

The three `*_s` fields (`wait_s`, `open_s`, `elapsed_s`) split a single
`ida_export` outer timer into its components, so an operator can tell
"54s ida_export = 46s queue + 8s open" without counting events
manually.

### Node-level timers (unchanged from legacy)

| Timer | Wraps |
|---|---|
| `ida_export` | `analyze` node's `gather(binexport(prim, sec))` |
| `bindiff` | `bindiff.diff(...)` call inside `diff_and_decompile` |
| `decompile_diff` | `gather(_decompile_set, _decompile_set)` after warm-up wait |

These are pair-level totals. The pool events are per-binary breakdowns.
Cross-reference them when investigating a slow run.

### Progress UX

When the CVE CLI command runs with a TTY (`make_reporter()` returns
`RichProgressReporter`), [`cli/commands/cve.py`](../src/patchdiff_ai/cli/commands/cve.py)
sets `ctx.tools.idalib.progress = progress`. The pool's `_send_recv`
then surfaces a per-call spinner:

```python
spinner = self._spinner(f"worker {w.idx}: {op} {_short_kwargs(kwargs)}")
try:
    ...
finally:
    spinner.complete()
```

Non-TTY runs get `NullProgressReporter` and the spinner becomes a
no-op. Logs alone are still complete.

---

## Performance tuning

### `concurrency.re_workers`

Default 5. Override via `CONCURRENCY__RE_WORKERS=N` env var or
`config/concurrency.py`. Each worker holds one IDB at a time — sized
appropriately for the CVE's biggest DLL, that's typically 1-4 GB RSS.

Rule of thumb: **`re_workers ≈ available_RAM_GB / 4`** for mshtml-class
workloads. Lower if you're memory-constrained; higher if you have RAM
to spare and want to fan out more pairs in parallel.

The pool's backpressure means oversizing isn't catastrophic — extra
binaries just queue. But undersizing means peak parallelism is capped
(8 binaries on 5 workers spends part of its wall time queueing).

### `.i64` cache hygiene

The `.i64` files live next to the binary inside `db/patch_store/<pkg>/<bin>/<KB>/`.
They're **not** garbage-collected by patchdiff-ai. Disk usage grows
linearly with the number of distinct binary versions analysed.

If you delete `.i64` files (manually or via `git clean`), the next run
on those binaries pays the cold-cache penalty (~110s for big DLLs)
and re-saves them.

### Skipping pairs you don't care about

The pipeline's `relevancy_threshold` (default 7.5, in
`config/thresholds.py`) gates which candidate binaries get dispatched
to RE at all. Lower it to analyse more pairs per CVE; raise it to
narrow focus.

---

## End-to-end walk-through

Tracing a single CVE run, taken from a real log
([CVE-2026-20806](../logs/1777476741.979c6492-4377-4fa6-a55e-ff8e959fab1e.log)):

**1. Setup (T = 0–25s).** CLI parses args. AppContext built.
   `discover_ida_installs()` finds IDA 9.3, idalib activated.
   `IdalibPool(n_workers=5, ida_install=ida_9_3)` constructed (no procs
   yet). MSRC + KB download/extract/index. PI agent ranks candidates.

**2. RE fanout (T = 25s).** PI's router fires `Send(re_agent, ...)` for
   each candidate above the relevancy threshold — 4 pairs in this run
   (combase, rpcss, actxprxy, rpcrt4).

**3. Analyze starts in parallel for all 4 pairs (T = 25s).** Each pair's
   `analyze` node gathers `binexport(prim, sec)`. 4 pairs × 2 binaries
   = 8 `_assign` calls hitting `_assign_lock` in some order.

   First 5 `_assign` calls win:
   ```
   T=25.06  worker 0 spawn  (combase prim)
   T=25.07  worker 1 spawn  (combase sec)
   T=25.08  worker 2 spawn  (rpcss prim)
   T=25.08  worker 3 spawn  (rpcss sec)
   T=25.09  worker 4 spawn  (actxprxy prim)
   ```
   Last 3 park on the event:
   ```
   T=25.09  idalib_pool_wait_for_free_worker  binary=actxprxy.dll
   T=25.09  idalib_pool_wait_for_free_worker  binary=rpcrt4.dll
   T=25.09  idalib_pool_wait_for_free_worker  binary=rpcrt4.dll
   ```

**4. First pair finishes (T = 25–55s).** rpcss is small (~4.7k funcs);
   its `analyze` (cold cache, ~30s) finishes first. Its
   `diff_and_decompile`:
   - eager-open both rpcss binaries — already bound to W2/W3, no-op
   - bindiff (~3s)
   - decompile 58 changed funcs (~12s)
   - release(W2), release(W3) → notify backpressure

**5. Backpressure cascades (T = 55–80s).** As W2/W3 release, the queued
   binaries claim them:
   ```
   T=55.08  worker 2 release  → ev.set()
   T=55.08  worker 2 spawn    (actxprxy sec, claimed by waiter)
   T=55.71  worker 3 release  → ev.set()
   T=55.81  worker 3 spawn    (rpcrt4 prim, claimed by waiter)
   T=64.03  worker 4 release  (actxprxy done) → ev.set()
   T=64.03  worker 4 spawn    (rpcrt4 sec, last waiter)
   ```

**6. Big binary finishes last (T = 25–134s).** combase (~16k funcs)
   needs full cold-cache analysis on both versions. Its `ida_export`
   timer reads 112s. Its `decompile_diff` reads 3.7s for 75 functions —
   because both eager-opens succeeded (workers W0, W1 already had the
   IDBs open from analyze, so eager-open is a fast `_bindings.get`
   hit), and `decompile_many` is just Hex-Rays time.

**7. RE phase ends (T = 134s).** `await ctx.tools.idalib.aclose()` in
   `run_cve`'s `finally` sends shutdown to any still-alive worker.
   None remain — every pair released its workers as part of phase 4.
   `_SPAWNED_PIDS` is empty.

**8. VR + reports + chat (T = 134s+).** VR agent ranks changed funcs,
   LLM writes per-pair RCA reports. If chat was requested
   (`--chat-permissive`), `ida_chat.get_langchain_tools` is called on
   first chat turn — only then does `idalib-mcp.exe` spawn (one
   instance, lives until chat exits).

Wall time: 3m 57s. RE phase: 2m 4s. The fixes from this conversation
took the comparable mshtml/ieframe/browserbroker run from ~5min to
~2min for the same shape of work.

---

## Why we don't ...

**... use `concurrent.futures.ProcessPoolExecutor`.** It's optimised for
stateless work-units. Our workers are *stateful* — each holds an
expensive IDB for the duration of a binary. Pinning a binary to a
specific worker isn't expressible in the executor API; we'd lose the
warm-IDB optimisation.

**... open multiple binaries in one worker.** `idapro` is process-global
— `idapro.open_database` for a new path implicitly closes the old one,
losing the analysis. Switching costs more than parallelising.

**... use `multiprocessing.Queue` or `JoinableQueue` instead of a Pipe.**
We never need fan-out (one parent → many workers, one message → many
consumers). Pipes are simpler and faster for the 1:1 case.

**... use SSE for the chat MCP transport.** Tried it. ida-pro-mcp's
`zeromcp` SSE implementation has a thread-safety race in
`_McpSseConnection.send_event` — initialise works, first `tools/call`
deadlocks. Streamable HTTP avoids the issue (every request is short
and self-contained).

**... use `langchain-mcp-adapters` for the pipeline path too.** We did
in v1. Encoding internal Python calls as JSON-RPC `py_eval` strings
(`idaapi.ida_expr.eval_idc_expr(None, BADADDR, 'BinExportBinary("...");')`)
was pure overhead and a debugging tax. The pipeline talks Python; it
should *speak* Python.

**... save the `.i64` after every op.** `_op_open` saves only on the
cold path (when `.i64` didn't exist). Re-saving on every load would
add ~5s of disk I/O per call with zero benefit — the in-memory state
matches the on-disk state, by definition.

**... share workers between the pipeline and the chat session.** The
pipeline runs to completion, releases every worker, then the chat
session starts in a *different event loop* (`asyncio.run` in `run_chat`).
Worker `_io_executor` futures are loop-bound; carrying a worker across
loops is a lifetime-bug magnet. Easier and cleaner to spawn fresh on
demand — and the chat almost never needs the bulk-decompile op pattern
the pool optimises for.

---

For higher-level questions about how the RE agent fits into the rest of
the pipeline, jump to [Architecture.md § The CVE → report lifecycle](Architecture.md#the-cve--report-lifecycle).
For how to extend it (e.g. a Linux/Android RE backend), see
[Architecture.md § Extending the system](Architecture.md#extending-the-system).
