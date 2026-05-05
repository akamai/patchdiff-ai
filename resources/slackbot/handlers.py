"""Slash-command handlers — one per supported command.

Sync commands (health-check, get-report, month-stats) run inline after
ack(). Long-running commands (analyze-cve, analyze-month) ack
immediately and dispatch a background asyncio task; on completion the
task posts to the same channel.

`patchdiff-ai cached --cve <CVE>` writes report files to the configured
reports_dir and prints a `[+] Saved cached reports for ... -> <path>`
line; we parse that to locate the files for upload.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import io
import json
import logging
import re
from pathlib import Path

from slack_bolt.async_app import AsyncApp

from formatting import (
    already_running_text,
    failure_blocks,
    health_blocks,
    month_done_blocks,
    month_stats_blocks,
    report_summary_blocks,
    section,
    starting_blocks,
)
from jobs import JobRegistry
from runner import run_patchdiff, tail
from validators import normalize_cve, normalize_month

log = logging.getLogger("slackbot.handlers")

# Match the `[+] Saved cached reports for <CVE> -> <path>` line from cached.py.
_SAVED_LINE_RE = re.compile(r"->\s*(.+?)\s*$", re.MULTILINE)

# Slash-command body field used by Slack — channel sometimes arrives as
# `channel_id` and sometimes as `channel`.
def _channel(body: dict) -> str:
    return body.get("channel_id") or body.get("channel", {}).get("id") or ""


def _user(body: dict) -> str:
    return body.get("user_id") or body.get("user", {}).get("id") or ""


def _split_meta_and_body(text: str) -> tuple[dict, str]:
    """`patchdiff-ai cached` writes `{json metadata}\n\n{report body}`.

    Returns (metadata, body). On parse failure returns ({}, full_text).
    """
    if "\n\n" not in text:
        return {}, text
    head, body = text.split("\n\n", 1)
    try:
        meta = json.loads(head)
        if isinstance(meta, dict):
            return meta, body
    except (ValueError, TypeError):
        pass
    return {}, text


def _resolve_reports_dir(stdout: str) -> Path | None:
    """Pull the reports dir out of the `cached` command's success line."""
    match = None
    for line in stdout.splitlines():
        if line.startswith("[+] Saved cached reports"):
            m = _SAVED_LINE_RE.search(line)
            if m:
                match = m.group(1)
    if not match:
        return None
    p = Path(match.strip())
    return p if p.exists() else None


async def _upload_reports_for_cve(client, channel: str, cve: str) -> bool:
    """Run `patchdiff-ai cached --cve <CVE>`, upload the resulting files.

    Returns True if at least one file was uploaded.
    """
    res = await run_patchdiff("cached", "--cve", cve)
    if not res.ok:
        await client.chat_postMessage(
            channel=channel,
            blocks=failure_blocks(f"cached --cve {cve}", res.returncode, tail(res.stderr)),
        )
        return False

    reports_dir = _resolve_reports_dir(res.stdout)
    if reports_dir is None:
        await client.chat_postMessage(
            channel=channel,
            text=f":grey_question: No cached reports found for `{cve}`.",
        )
        return False

    files = sorted(reports_dir.glob(f"{cve}_*.txt"))
    if not files:
        await client.chat_postMessage(
            channel=channel,
            text=f":grey_question: No cached reports found for `{cve}`.",
        )
        return False

    summaries = []
    for f in files:
        meta, body = _split_meta_and_body(f.read_text(encoding="utf-8", errors="replace"))
        summaries.append(
            {
                "model": meta.get("model_name", "?"),
                "confidence": float(meta.get("confidence", 0.0)),
                "file": meta.get("file", f.name),
            }
        )

    await client.chat_postMessage(
        channel=channel,
        text=f"Reports for {cve}",
        blocks=report_summary_blocks(cve, summaries),
    )

    # files_upload_v2 accepts a list under `file_uploads`. Upload each
    # report as a .md so Slack renders the body inline.
    file_uploads = []
    for f in files:
        _, body = _split_meta_and_body(f.read_text(encoding="utf-8", errors="replace"))
        file_uploads.append(
            {
                "file": io.BytesIO(body.encode("utf-8")),
                "filename": f.with_suffix(".md").name,
                "title": f.with_suffix(".md").name,
            }
        )
    try:
        await client.files_upload_v2(
            channel=channel,
            file_uploads=file_uploads,
            initial_comment=f"Reports for `{cve}` ({len(file_uploads)})",
        )
    except Exception as exc:
        log.exception("files_upload failed")
        await client.chat_postMessage(
            channel=channel,
            text=f":warning: Failed to upload report files: `{exc}`",
        )
        return False
    return True


def register_handlers(app: AsyncApp, jobs: JobRegistry) -> None:
    @app.command("/health-check")
    async def _health_check(ack, body, client):
        await ack()
        channel = _channel(body)
        await client.chat_postMessage(
            channel=channel,
            text=":hospital: Running `patchdiff-ai health-check`…",
        )
        res = await run_patchdiff("health-check")
        await client.chat_postMessage(
            channel=channel,
            text="patchdiff-ai health-check result",
            blocks=health_blocks(res.stdout, ok=res.ok),
        )

    @app.command("/get-report")
    async def _get_report(ack, body, client, respond):
        await ack()
        raw = (body.get("text") or "").strip()
        try:
            cve = normalize_cve(raw)
        except ValueError as exc:
            await respond(text=f":warning: {exc}")
            return
        channel = _channel(body)
        await _upload_reports_for_cve(client, channel, cve)

    @app.command("/analyze-cve")
    async def _analyze_cve(ack, body, client, respond):
        await ack()
        raw = (body.get("text") or "").strip()
        try:
            cve = normalize_cve(raw)
        except ValueError as exc:
            await respond(text=f":warning: {exc}")
            return

        channel = _channel(body)
        user = _user(body)
        job_id = f"cve:{cve}"

        existing = await jobs.existing(job_id)
        if existing is not None:
            started = dt.datetime.fromtimestamp(existing.started_at).isoformat(
                timespec="seconds"
            )
            await respond(
                text=already_running_text(f"analyze-cve {cve}", existing.user_id, started),
                response_type="ephemeral",
            )
            return

        info = await jobs.try_register(job_id, user)
        if info is None:
            return  # raced with another caller; treat as duplicate

        await client.chat_postMessage(
            channel=channel,
            text=f"Analyzing {cve}",
            blocks=starting_blocks(f"Analyzing *{cve}*", user),
        )

        async def _run() -> None:
            try:
                res = await run_patchdiff("cve", cve)
                if not res.ok:
                    await client.chat_postMessage(
                        channel=channel,
                        text=f"analyze-cve {cve} failed",
                        blocks=failure_blocks(f"analyze-cve {cve}", res.returncode, tail(res.stderr)),
                    )
                    return
                await _upload_reports_for_cve(client, channel, cve)
            except Exception as exc:
                log.exception("analyze-cve task crashed")
                await client.chat_postMessage(
                    channel=channel,
                    text=f":x: analyze-cve `{cve}` crashed: `{exc}`",
                )
            finally:
                await jobs.release(job_id)

        asyncio.create_task(_run())

    @app.command("/analyze-month")
    async def _analyze_month(ack, body, client, respond):
        await ack()
        raw = (body.get("text") or "").strip()
        try:
            cycle = normalize_month(raw)
        except ValueError as exc:
            await respond(text=f":warning: {exc}")
            return

        channel = _channel(body)
        user = _user(body)
        job_id = f"month:{cycle}"

        existing = await jobs.existing(job_id)
        if existing is not None:
            started = dt.datetime.fromtimestamp(existing.started_at).isoformat(
                timespec="seconds"
            )
            await respond(
                text=already_running_text(f"analyze-month {cycle}", existing.user_id, started),
                response_type="ephemeral",
            )
            return

        info = await jobs.try_register(job_id, user)
        if info is None:
            return

        await client.chat_postMessage(
            channel=channel,
            text=f"Running Patch Tuesday {cycle}",
            blocks=starting_blocks(
                f"Running Patch Tuesday *{cycle}* — this will take a while",
                user,
            ),
        )

        async def _run() -> None:
            try:
                res = await run_patchdiff("windows", "month", cycle)
                if not res.ok:
                    await client.chat_postMessage(
                        channel=channel,
                        text=f"analyze-month {cycle} failed",
                        blocks=failure_blocks(
                            f"analyze-month {cycle}", res.returncode, tail(res.stderr)
                        ),
                    )
                    return
                await client.chat_postMessage(
                    channel=channel,
                    text=f"Patch Tuesday {cycle} analysis complete",
                    blocks=month_done_blocks(cycle),
                )
            except Exception as exc:
                log.exception("analyze-month task crashed")
                await client.chat_postMessage(
                    channel=channel,
                    text=f":x: analyze-month `{cycle}` crashed: `{exc}`",
                )
            finally:
                await jobs.release(job_id)

        asyncio.create_task(_run())

    @app.command("/month-stats")
    async def _month_stats(ack, body, client, respond):
        await ack()
        raw = (body.get("text") or "").strip()
        try:
            cycle = normalize_month(raw)
        except ValueError as exc:
            await respond(text=f":warning: {exc}")
            return

        channel = _channel(body)
        await client.chat_postMessage(
            channel=channel,
            text=f":bar_chart: Computing stats for `{cycle}`…",
        )
        res = await run_patchdiff("windows", "month-stats", cycle, "--json")
        if not res.ok:
            await client.chat_postMessage(
                channel=channel,
                text=f"month-stats {cycle} failed",
                blocks=failure_blocks(
                    f"month-stats {cycle}", res.returncode, tail(res.stderr)
                ),
            )
            return
        try:
            stats = json.loads(res.stdout)
        except json.JSONDecodeError as exc:
            await client.chat_postMessage(
                channel=channel,
                text=f":x: Could not parse month-stats output: `{exc}`",
            )
            return
        await client.chat_postMessage(
            channel=channel,
            text=f"Patch Tuesday {cycle} stats",
            blocks=month_stats_blocks(stats),
        )
