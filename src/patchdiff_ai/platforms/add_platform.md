# Adding a new platform

A "platform" in patchdiff-ai is a vendor / OS / distro family. It contributes:

- One **CLI sub-group** (`patchdiff-ai <name> ...`).
- A way to **auto-detect** whether a CVE belongs to it (advisory source first; NVD CPE list as fallback).
- The **pipeline-facing methods** (`enrich_cve`, `gather_packages`, `candidate_prompts`, `candidate_metadata`) — the stages of the pipeline read these via `ctx.platform`.

**Reference implementations** (read these first):
- Windows (real): [`platforms/windows/`](windows/) — `provider.py`, `versioned.py`, `cli.py`, `cycle.py`.
- Linux (skeleton): [`platforms/linux/`](linux/) — same shape, methods stubbed out.

The Linux package is the cleanest template. Copy it, rename, replace stubs.

---

## Step 1 — Create the package

```
src/patchdiff_ai/platforms/<name>/
├── __init__.py        # exports Provider + concrete Platform class
├── provider.py        # PlatformProvider — group-level, owns CLI + auto-detect
├── <thing>.py         # Platform — per-version concrete plugin
└── cli.py             # the Click group
```

Use `<name>` lower-case, no spaces (`linux`, `android`, `macos`). It becomes the CLI sub-group name.

---

## Step 2 — Implement the per-version `Platform`

A `Platform` instance represents one concrete target (one Windows SKU, one Ubuntu release, one Android security bulletin window). Implement the protocol from [`base.py`](base.py):

```python
class Platform(Protocol):
    name: str

    async def enrich_cve(self, state, ctx) -> dict[str, Any]: ...
    async def gather_packages(self, state, ctx) -> dict[str, Any]: ...
    def candidate_prompts(self) -> tuple[PromptId, PromptId]: ...
    def candidate_metadata(self, cve) -> dict[str, Any]: ...
```

**Method contracts:**

| Method | Returns | Reads from state |
|---|---|---|
| `enrich_cve` | `{stage, os, KB, cve_details}` — fetch advisory, choose `(current, previous)` package pair | `state.cve_details.cve` |
| `gather_packages` | `{extracted, dataframes, filtered_dataframes}` — download + extract + index | `state.os`, `state.KB` |
| `candidate_prompts` | `(collect_prompt_id, rank_prompt_id)` from `prompts.registry.PromptId` | — |
| `candidate_metadata` | JSON-able dict that gets fed to the candidate-ranking LLM | `cve.advisory_report` (or whatever you stash there) |

For real implementations the concrete class typically holds an external resource (an archive handle, a tracker client, etc.) — see `WindowsVersionedPlatform` for a real example.

---

## Step 3 — Implement the `PlatformProvider`

The provider is the group-level thing the CLI mounts. One provider can manage N `Platform` versions.

```python
class PlatformProvider(Protocol):
    name: str

    def cli_group(self) -> click.Group: ...
    def health_check(self) -> bool: ...
    def install(self) -> None: ...
    async def matches_native(self, cve_id: str) -> Platform | None: ...
    def matches_nvd(self, cpes: list[str]) -> Platform | None: ...
    def resolve(self, **overrides: Any) -> Platform: ...
```

**Method contracts:**

| Method | What it does |
|---|---|
| `cli_group()` | Build the `click.Group` mounted at `patchdiff-ai <name> ...`. Always include `cve`, `health-check`, `install`. Add provider-specific commands as needed (Windows: `month`). |
| `health_check()` | Provider-specific checks (advisory API reachable, archives present, ...). Return `False` on failure. The core checks (Azure creds, IDA paths) live in [`cli/commands/health_check.py`](../cli/commands/health_check.py) — don't duplicate. |
| `install()` | Download / unpack any provider-specific assets (caches, mirrors, ...). |
| `matches_native(cve_id)` | **Primary auto-detect.** Hit your own advisory source (Windows: MSRC; Linux: USN/DSA). Return the matching `Platform` or `None`. Runs in parallel with every other provider's `matches_native` — wrap any sync `requests` calls in `asyncio.to_thread` so the parallelism is real. |
| `matches_nvd(cpes)` | **Fallback.** Called only if every provider's `matches_native` missed. Match `cpes` (a flat list of `cpe:2.3:o:...` strings from NVD) against the versions you know about; return one or `None`. |
| `resolve(**overrides)` | Pick a concrete `Platform` from CLI overrides (Windows: `platform_id=int`; Linux: `distro=str, release=str`). Empty overrides → pick a sensible default (e.g. newest release). Unknown kwargs raise. |

**The two-phase resolution flow** is owned by [`platforms/__init__.py`](__init__.py)'s `resolve_for_cve` — you don't need to touch it. Just make sure your `matches_native` returns `None` when uncertain (so other providers get a chance), and your `matches_nvd` is strict (returns `None` if not your CVE).

---

## Step 4 — Build the Click group

[`platforms/linux/cli.py`](linux/cli.py) is the canonical template. Required commands:

```python
@grp.command("health-check")
def _hc(): ...                # calls provider.health_check()

@grp.command("install")
def _install(): ...           # calls provider.install()

@grp.command("cve")
@click.argument("cve_id", metavar="CVE-YYYY-NNNNN")
@click.option("--<provider-flag>", ...)   # whatever overrides resolve() takes
@cve_options                              # adds --eval/--interrupt/--chat/--chat-permissive
@click.pass_context
def _cve(ctx, cve_id, ..., eval_mode, interrupt, chat, chat_permissive):
    from patchdiff_ai.cli.runner import run_single_cve
    platform = provider.resolve(...)
    run_single_cve(ctx, cve_id=cve_id, platform=platform,
                   eval_mode=eval_mode, interactive=interrupt,
                   chat=chat, chat_permissive=chat_permissive)
```

**Always use `@cve_options`** (from [`cli/options.py`](../cli/options.py)) on any `cve`-style command so the shared flag set stays consistent across providers.

**Always delegate to `cli/runner.run_single_cve`** — that's where AppContext is built and the orchestrator is invoked. Don't replicate it.

---

## Step 5 — Register the provider

In [`platforms/__init__.py`](__init__.py), add your provider to the `providers()` tuple:

```python
@lru_cache(maxsize=1)
def providers() -> tuple[PlatformProvider, ...]:
    return (WindowsProvider(), LinuxProvider(), MyNewProvider())
```

That's it. The CLI root iterates providers and mounts each one's `cli_group()` automatically.

---

## Step 6 — Verify

Run these in order — each one should pass before moving to the next:

```bash
# 1. Imports clean.
python -c "import patchdiff_ai.platforms.<name>"

# 2. Sub-group shows up.
patchdiff-ai --help               # → lists <name>
patchdiff-ai <name> --help        # → lists cve, health-check, install

# 3. Health-check runs.
patchdiff-ai <name> health-check
patchdiff-ai health-check         # → also includes your provider's section

# 4. Install runs.
patchdiff-ai <name> install
patchdiff-ai install              # → aggregator runs your provider's install

# 5. Resolution: native + NVD fallback.
python -c "
from patchdiff_ai.platforms import resolve_for_cve
provider, platform = resolve_for_cve('CVE-YYYY-NNNNN-known-to-affect-your-platform')
print(provider.name, platform.name)
"

# 6. End-to-end on a real CVE you know your platform handles.
patchdiff-ai cve CVE-YYYY-NNNNN
patchdiff-ai <name> cve CVE-YYYY-NNNNN [--your-flag VALUE]
```

The pipeline parity smoke run for Windows is `CVE-2025-29824`. Pick an analogous canonical CVE for your platform and document it in your provider's module docstring.

---

## Common pitfalls

- **Don't put `input()` in pipeline nodes.** The `enrich_cve` and `gather_packages` methods run inside the LangGraph pipeline; interactive prompts live only in the CLI side via `runtime/interactive.py`.
- **Don't use `requests.get(...)` synchronously inside `matches_native`** without `asyncio.to_thread`. Without it the `asyncio.gather` in `_native_round` collapses back to serial.
- **Don't return a "best guess" from `matches_native` when you're not sure.** Return `None` instead. The orchestrator falls back to NVD and then to other providers — being too eager defeats the auto-detect chain.
- **Don't skip `@cve_options`.** Users expect `--eval / --interrupt / --chat / --chat-permissive` on every `cve`-style command.
- **Don't replicate `AppContext.build` / `run_cve` in your CLI.** Always go through `cli.runner.run_single_cve`.
- **Don't add module-level network calls or `sys.exit` calls.** The provider is constructed at CLI import time; an outbound call there blocks `--help`.
- **Don't read `ctx.platform_*_hint` style fields.** The pre-M1 `platform_ids_hint` is gone — overrides flow through `provider.resolve(...)` only.
