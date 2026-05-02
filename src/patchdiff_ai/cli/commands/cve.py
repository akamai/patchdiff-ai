"""`patchdiff-ai cve <CVE>` — single-CVE end-to-end run with NVD auto-detect.

Resolves a `(provider, concrete Platform)` pair via NVD (or `--platform`
override), then forwards to `cli.runner.run_single_cve`. Provider-specific
flags (e.g. `--platform-id`, `--distro`) live on the provider's own
`<provider> cve` sub-command — this top-level shortcut runs with sane
defaults only.
"""

from __future__ import annotations

import re

import click

from patchdiff_ai.cli.options import cve_options
from patchdiff_ai.cli.runner import run_single_cve
from patchdiff_ai.platforms import (
    UnknownPlatform,
    UnsupportedPlatform,
    providers,
    resolve_for_cve,
)

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)


def _validate_cve(ctx: click.Context, param: click.Parameter, value: str) -> str:
    if not CVE_RE.match(value):
        raise click.BadParameter(
            "Invalid CVE format; expected CVE-YYYY-NNNN[...] (e.g. CVE-2025-29824)"
        )
    return value.upper()


@click.command(
    "cve",
    help="Run RCA on a single CVE. Auto-detects the platform via NVD CPE data.",
)
@click.argument(
    "cve_id",
    metavar="CVE-YYYY-NNNNN",
    callback=_validate_cve,
)
@click.option(
    "--platform",
    "platform_override",
    type=click.Choice([p.name for p in providers()], case_sensitive=False),
    default=None,
    help="Override the platform plugin (e.g. windows). Default: auto-detect via NVD.",
)
@cve_options
@click.pass_context
def cve_command(
    ctx: click.Context,
    cve_id: str,
    platform_override: str | None,
    eval_mode: bool,
    interrupt: bool,
    chat: bool,
    chat_permissive: bool,
) -> None:
    try:
        provider, platform = resolve_for_cve(cve_id, platform_override=platform_override)
    except (UnsupportedPlatform, UnknownPlatform) as exc:
        raise click.UsageError(str(exc))

    click.echo(f"[*] Resolved platform: {provider.name} → {platform.name}")
    run_single_cve(
        ctx,
        cve_id=cve_id,
        platform=platform,
        eval_mode=eval_mode,
        interactive=interrupt,
        chat=chat,
        chat_permissive=chat_permissive,
    )
