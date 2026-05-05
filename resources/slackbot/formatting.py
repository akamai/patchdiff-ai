"""Block Kit + plain-text formatters for slash-command responses."""

from __future__ import annotations

from typing import Any

MAX_BLOCK_TEXT = 3000  # Slack's per-section text limit


def code_block(text: str, lang: str = "") -> str:
    """mrkdwn-fenced code block. Truncated to fit a single section."""
    fence_overhead = len(f"```{lang}\n\n```")
    body = text or "(empty)"
    if len(body) > MAX_BLOCK_TEXT - fence_overhead:
        cut = MAX_BLOCK_TEXT - fence_overhead - len("\n... [truncated]")
        body = body[:cut] + "\n... [truncated]"
    return f"```{lang}\n{body}\n```"


def section(text: str) -> dict:
    return {"type": "section", "text": {"type": "mrkdwn", "text": text}}


def header(text: str) -> dict:
    return {"type": "header", "text": {"type": "plain_text", "text": text}}


def divider() -> dict:
    return {"type": "divider"}


def health_blocks(stdout: str, ok: bool) -> list[dict]:
    icon = ":hospital:" if ok else ":x:"
    title = "patchdiff-ai health" if ok else "patchdiff-ai health (failures)"
    return [
        header(f"{icon} {title}"),
        section(code_block(stdout)),
    ]


def report_summary_blocks(cve: str, summaries: list[dict]) -> list[dict]:
    """Top-level message body posted before the .md file uploads.

    `summaries` is a list of dicts with keys: model, confidence, file, found.
    """
    if not summaries:
        return [
            header(f":page_facing_up: {cve}"),
            section("_No cached reports for this CVE._"),
        ]

    lines = []
    for s in summaries:
        conf = s.get("confidence", 0.0)
        model = s.get("model") or "?"
        fname = s.get("file") or "?"
        lines.append(f"• `{model}` — confidence *{conf:.2f}* — `{fname}`")

    return [
        header(f":page_facing_up: {cve}"),
        section("\n".join(lines)),
    ]


def starting_blocks(label: str, user_id: str) -> list[dict]:
    return [section(f":hourglass_flowing_sand: {label} — started by <@{user_id}>")]


def already_running_text(label: str, user_id: str, started_iso: str) -> str:
    return (
        f":no_entry: *{label}* is already in progress "
        f"(started {started_iso} by <@{user_id}>)."
    )


def failure_blocks(label: str, returncode: int, stderr_tail: str) -> list[dict]:
    return [
        header(f":x: {label} failed (exit {returncode})"),
        section(code_block(stderr_tail)),
    ]


def month_done_blocks(cycle: str) -> list[dict]:
    return [
        section(
            f":white_check_mark: Patch Tuesday *{cycle}* analysis complete. "
            f"Run `/month-stats {cycle}` for results."
        )
    ]


def _summary_line(cve_summary: dict) -> str:
    return (
        f"• `{cve_summary['cve']}` "
        f"_{cve_summary.get('model', '?')}_ "
        f"conf *{cve_summary.get('confidence', 0):.2f}*"
    )


def month_stats_blocks(stats: dict[str, Any]) -> list[dict]:
    cycle = stats["cycle"]
    blocks: list[dict] = [
        header(f"Patch Tuesday {cycle}"),
        section(
            f"*Total CVEs*: {stats['total_cves']}   "
            f"*Analyzed*: {stats['analyzed']}   "
            f"*Failed/Missing*: {stats['failed_or_missing']}"
        ),
        divider(),
    ]

    high = stats.get("high_confidence") or []
    if high:
        body = "\n".join(_summary_line(h) for h in high[:25])
        if len(high) > 25:
            body += f"\n_…and {len(high) - 25} more (see CLI for full list)._"
        blocks.append(section(f":star: *High-confidence findings* ({len(high)})\n{body}"))
    else:
        blocks.append(section(":star: *High-confidence findings*\n_none_"))

    blocks.append(divider())

    incomplete = stats.get("incomplete_patches") or []
    if incomplete:
        lines = []
        for h in incomplete[:15]:
            snippet = (h.get("snippet") or "").replace("\n", " ")[:160]
            lines.append(f"• `{h['cve']}` — _{h.get('model', '?')}_\n  > {snippet}")
        body = "\n".join(lines)
        if len(incomplete) > 15:
            body += f"\n_…and {len(incomplete) - 15} more (see CLI for full list)._"
        blocks.append(
            section(f":warning: *Incomplete-patch flags* ({len(incomplete)})\n{body}")
        )
    else:
        blocks.append(section(":warning: *Incomplete-patch flags*\n_none_"))

    return blocks
