"""Entrypoint for the patchdiff-ai Slack sidecar.

Loads tokens from .env, builds an AsyncApp + AsyncSocketModeHandler,
attaches the slash-command handlers, and runs forever.

Usage:
    python resources/slackbot/main.py

Requires the same venv to also have `patchdiff-ai` installed (the
sidecar shells out to the `patchdiff-ai` console script).
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from slack_bolt.adapter.socket_mode.async_handler import AsyncSocketModeHandler
from slack_bolt.async_app import AsyncApp

from handlers import register_handlers
from jobs import JobRegistry

HERE = Path(__file__).resolve().parent


def _load_env() -> tuple[str, str]:
    load_dotenv(HERE / ".env")
    bot_token = os.environ.get("SLACK_BOT_TOKEN", "").strip()
    app_token = os.environ.get("SLACK_APP_TOKEN", "").strip()
    if not bot_token or not app_token:
        sys.stderr.write(
            "[!] Missing SLACK_BOT_TOKEN or SLACK_APP_TOKEN.\n"
            f"    Copy {HERE / '.env.example'} -> {HERE / '.env'} "
            "and fill in the tokens from api.slack.com/apps.\n"
        )
        sys.exit(2)
    return bot_token, app_token


async def _main_async() -> None:
    bot_token, app_token = _load_env()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    log = logging.getLogger("slackbot")

    app = AsyncApp(token=bot_token)
    jobs = JobRegistry()
    register_handlers(app, jobs)

    handler = AsyncSocketModeHandler(app, app_token)
    log.info("slackbot starting (socket mode)")
    await handler.start_async()
    log.info("slackbot connected")
    # `start_async()` blocks until the socket-mode connection ends.


def main() -> None:
    try:
        asyncio.run(_main_async())
    except KeyboardInterrupt:
        sys.stderr.write("\n[+] slackbot shutting down\n")


if __name__ == "__main__":
    main()
