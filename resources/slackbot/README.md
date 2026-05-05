# patchdiff-ai Slack bot

Standalone sidecar that exposes `patchdiff-ai` over Slack slash commands. Shells out to the `patchdiff-ai` CLI for every operation; ships its own deps so it doesn't bloat the main package.

See [../../docs/slack.md](../../docs/slack.md) for the full design (architecture, output formatting, known limitations).

## Setup

1. Create the Slack app at https://api.slack.com/apps → "Create New App" → "From an app manifest" → pick your workspace → paste [manifest.json](manifest.json).
2. Generate tokens:
   - **Bot token** (`xoxb-...`): "OAuth & Permissions" → "Install to Workspace" → copy.
   - **App token** (`xapp-...`): "Basic Information" → "App-Level Tokens" → "Generate" → add `connections:write` scope → copy.
3. Copy the env template and fill in the tokens:
   ```
   cp .env.example .env
   # then edit .env
   ```
4. Install bot deps **into the same venv where `patchdiff-ai` is installed** (the bot shells out to the `patchdiff-ai` console script):
   ```
   pip install -r requirements.txt
   ```
5. Run:
   ```
   python main.py
   ```
   The bot logs `slackbot connected` once it joins Slack's socket-mode endpoint.

## Commands

| Slash | What it does |
|---|---|
| `/health-check` | Run `patchdiff-ai health-check`, post the output. |
| `/get-report <CVE>` | Fetch a previously cached RCA from the vector store and upload as a `.md` file. |
| `/analyze-cve <CVE>` | Run a fresh single-CVE analysis (5–30 min). Posts the result when done. |
| `/analyze-month <YYYY-MMM>` | Run the entire Patch Tuesday cycle (hours). |
| `/month-stats <YYYY-MMM>` | Aggregate per-cycle results: total, analyzed, failed, high-confidence, incomplete-patch flags. |

## Files

- [main.py](main.py) — entrypoint: dotenv + AsyncApp + AsyncSocketModeHandler.
- [handlers.py](handlers.py) — slash-command handlers (one per command).
- [runner.py](runner.py) — `asyncio.create_subprocess_exec` wrapper around `patchdiff-ai`.
- [jobs.py](jobs.py) — in-memory `JobRegistry` for analyze dedup.
- [formatting.py](formatting.py) — Block Kit + file-upload helpers.
- [validators.py](validators.py) — CVE + cycle-id regex.
- [manifest.json](manifest.json) — Slack app manifest (paste into api.slack.com).
