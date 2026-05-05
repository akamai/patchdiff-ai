# Slack bot

A standalone Slack sidecar that exposes `patchdiff-ai` over slash commands. Kick off CVE / Patch Tuesday analyses, fetch cached reports, and pull cycle-level stats — all from Slack.

The bot lives at [../resources/slackbot/](../resources/slackbot/). It runs as a separate Python process with its own dependencies and shells out to the `patchdiff-ai` CLI for every operation, so the main package's dependency tree stays untouched.

---

## Commands

| Slash command | What it does | Latency |
|---|---|---|
| `/health-check` | Run `patchdiff-ai health-check`, post the output. | ~10 s |
| `/get-report <CVE>` | Fetch a previously cached RCA from the vector store and upload as a `.md` file. | seconds |
| `/analyze-cve <CVE>` | Run a fresh single-CVE analysis. Posts the report when done. | 5–30 min |
| `/analyze-month <YYYY-MMM>` | Run the entire Patch Tuesday cycle. | hours |
| `/month-stats <YYYY-MMM>` | Aggregate per-cycle results — totals, high-confidence findings, incomplete-patch flags. | seconds |

---

## Installation

### 1. Prerequisites

Before installing the bot, make sure `patchdiff-ai` itself is set up and working:

```powershell
pip install -e .
patchdiff-ai health-check
```

The bot shells out to the `patchdiff-ai` console script, so it must be on `PATH`. Use the **same venv** for both — the bot's `pip install` step assumes that venv.

### 2. Create the Slack app

1. Go to https://api.slack.com/apps and click **Create New App** → **From an app manifest**.
2. Pick the workspace you want the bot to live in.
3. Paste the contents of [../resources/slackbot/manifest.json](../resources/slackbot/manifest.json) and confirm.

The manifest declares all five slash commands, requests the `chat:write` / `commands` / `files:write` scopes, and enables socket mode (no public HTTP endpoint required).

### 3. Generate tokens

From the app's settings page, you need two tokens:

**Bot token (`xoxb-…`)**
- Go to **OAuth & Permissions** → **Install to Workspace** → approve.
- Copy the **Bot User OAuth Token** (starts with `xoxb-`).

**App-level token (`xapp-…`)**
- Go to **Basic Information** → **App-Level Tokens** → **Generate Token and Scopes**.
- Give it a name, add the `connections:write` scope, click **Generate**.
- Copy the token (starts with `xapp-`).

### 4. Configure `.env`

```powershell
cp resources/slackbot/.env.example resources/slackbot/.env
```

Edit `resources/slackbot/.env` and paste both tokens:

```
SLACK_BOT_TOKEN=xoxb-...
SLACK_APP_TOKEN=xapp-...
```

The `.env` file is gitignored.

### 5. Install bot dependencies

```powershell
pip install -r resources/slackbot/requirements.txt
```

Pinned to:

- `slack-bolt==1.21.2`
- `python-dotenv==1.2.2`

(`slack-sdk` and `aiohttp` are pulled transitively.)

### 6. Run

```powershell
python resources/slackbot/main.py
```

You should see:

```
slackbot starting (socket mode)
slackbot connected
```

Invite the bot to a channel (`/invite @patchdiff-ai`) and try `/health-check`.

---

## Usage

### `/health-check`

```
/health-check
```

Runs `patchdiff-ai health-check` and posts the captured stdout as a code block. If any provider check fails, the message is prepended with `:x: provider failures detected`.

### `/get-report <CVE>`

```
/get-report CVE-2025-29824
```

Looks up cached RCA reports for the given CVE in the vector store. Posts a summary message (model, confidence, file) and uploads each report's body as a `.md` file. If there's no cached report, you'll see `:grey_question: No cached reports found for CVE-...`.

To populate the cache, run `/analyze-cve` first.

### `/analyze-cve <CVE>`

```
/analyze-cve CVE-2025-29824
```

Kicks off a fresh analysis pipeline. The bot acks immediately with a "starting" message, then runs `patchdiff-ai cve <CVE>` in the background. When it finishes, the bot posts the resulting report (same format as `/get-report`).

If the same CVE is already being analyzed, the bot rejects the second request with an ephemeral message saying who started it and when. Different CVEs run in parallel.

### `/analyze-month <YYYY-MMM>`

```
/analyze-month 2025-Apr
```

Runs the full Patch Tuesday cycle (every CVE in the cycle that affects any of the bundled Windows versions). Takes hours. The bot posts a starting message, runs `patchdiff-ai windows month <cycle>` in the background, and on completion posts:

> :white_check_mark: Patch Tuesday *2025-Apr* analysis complete. Run `/month-stats 2025-Apr` for results.

Same dedup as `/analyze-cve`: a second trigger for the same cycle is rejected with an ephemeral.

### `/month-stats <YYYY-MMM>`

```
/month-stats 2025-Apr
```

Aggregates the cycle's analyzed reports into a glanceable summary:

- **Totals** — total CVEs in the cycle, how many have at least one cached report, how many are missing.
- **High-confidence findings** — every report with `confidence >= 0.75`, sorted by confidence.
- **Incomplete-patch flags** — every report whose body matches an incomplete-patch heuristic (see below), with a snippet.

Safe to call mid-run on `/analyze-month` — you'll see partial coverage (`analyzed < total`).

You can also call this directly on the CLI:

```powershell
patchdiff-ai windows month-stats 2025-Apr
patchdiff-ai windows month-stats 2025-Apr --json
```

---

## How it works

```
Slack workspace
     │
     │  socket-mode (xapp- token)
     ▼
resources/slackbot/main.py        ← long-running Python process
     │
     │  asyncio.create_subprocess_exec
     ▼
patchdiff-ai <cmd>                 ← fresh CLI process per command
     │
     ▼
AppContext + LangGraph + IDA + Chroma   (the existing pipeline)
```

Every slash command spawns a fresh `patchdiff-ai` process. The bot itself does not import any patchdiff-ai code — it only parses the CLI's stdout and uploads the report files the CLI writes to `<data_root>/reports/`.

For long-running commands (`/analyze-cve`, `/analyze-month`), the slash handler acks within Slack's 3-second window and then dispatches the subprocess as a background asyncio task. An in-memory `JobRegistry` deduplicates by `cve:<CVE>` / `month:<YYYY-MMM>` so the same job can't be triggered twice in parallel.

### Files

| File | Purpose |
|---|---|
| [main.py](../resources/slackbot/main.py) | Entrypoint — dotenv + `AsyncApp` + `AsyncSocketModeHandler`. |
| [handlers.py](../resources/slackbot/handlers.py) | One async handler per slash command. |
| [runner.py](../resources/slackbot/runner.py) | `asyncio` subprocess wrapper around `patchdiff-ai`. |
| [jobs.py](../resources/slackbot/jobs.py) | In-memory `JobRegistry` for analyze dedup. |
| [formatting.py](../resources/slackbot/formatting.py) | Block Kit helpers. |
| [validators.py](../resources/slackbot/validators.py) | Local CVE + cycle regex (no cross-package import). |
| [manifest.json](../resources/slackbot/manifest.json) | The Slack app manifest. |

### Incomplete-patch detection

The bot flags reports whose body contains any of these patterns (case-insensitive):

```
\bincomplete\s+(patch|fix)\b
\bpartially?\s+(patched|fixed|mitigat)
\bstill\s+(vulnerable|exploitable)\b
\bbypass(es|able)?\b.*\bpatch\b
```

This is a heuristic over the RCA text — patchdiff-ai has no structured "incomplete patch" field today. False positives are expected when reports merely *discuss* the concept without claiming the patch is incomplete. Tune the patterns in [src/patchdiff_ai/platforms/windows/month_stats.py](../src/patchdiff_ai/platforms/windows/month_stats.py) (`INCOMPLETE_PATCH_PATTERNS`) as needed.

---

## Troubleshooting

### The bot exits immediately with "Missing SLACK_BOT_TOKEN or SLACK_APP_TOKEN"

The `.env` file isn't where the bot expects it (`resources/slackbot/.env`) or one of the variables is empty. Re-check `cp resources/slackbot/.env.example resources/slackbot/.env` and that you pasted both tokens.

### `/analyze-cve` returns "command not found" or similar in the failure block

The bot couldn't find `patchdiff-ai` on `PATH`. Make sure the bot is launched from the same venv where `pip install -e .` was run. The runner does fall back to `python -m patchdiff_ai.cli.app`, but only if `python` itself resolves to that venv's interpreter.

### `/month-stats` fails with "No matching ProductIDs"

The local Windows platforms manifest is empty — you haven't indexed any WinSxS dump yet. Run `patchdiff-ai windows index <winsxs_dir> --product-name '...' --slug <slug>` first, then retry.

### The bot reconnects in a loop

Usually a token problem. Re-issue the bot token (Install to Workspace → reinstall) and the app-level token (regenerate with `connections:write`). Update `.env` and restart the bot.

### `/analyze-cve` finished but I never got the completion message

If the bot was restarted while the subprocess was still running, the `JobRegistry` lost track of the task. The `patchdiff-ai cve` subprocess keeps running independently — when it eventually finishes, the report is in the cache. Run `/get-report <CVE>` to fetch it.

### Slash command times out in Slack

Slack requires an ack within 3 seconds. All the bot's handlers ack first thing. If you see a Slack-side timeout, the bot process is probably wedged or disconnected — check the bot's stdout for `slackbot connected`.

### File upload fails with `not_in_channel`

Invite the bot to the channel: `/invite @patchdiff-ai`.

---

## Known limitations

- **No per-user authorization.** Anyone in the Slack workspace who can see the bot can trigger analyses. If that becomes a concern, gate the handlers in [handlers.py](../resources/slackbot/handlers.py) on a `SLACK_ALLOWED_USERS` env var.
- **In-memory job registry.** Bot restart loses dedup state — a second `/analyze-cve <CVE>` after a restart, while the original subprocess is still running, will spawn a duplicate.
- **No mid-run progress.** `/analyze-cve` and `/analyze-month` post only "starting" and "done" — there's no intermediate progress (the CLI's progress reporter is terminal-only).
- **Subprocess startup cost.** Every command (even fast ones) pays the ~few-second cost of building a fresh `AppContext`. Acceptable for the requested isolation.
- **`patchdiff-ai` must be on `PATH`.** Run the bot from the same venv where `patchdiff-ai` is installed.
- **`/analyze-month` runs in a single subprocess.** Killing the bot mid-run does **not** cancel the subprocess — it'll keep running to completion. To actually stop a month run, kill the `patchdiff-ai` process directly.
