"""Shared CLI option decorators.

`@cve_options` factors the four flags that every CVE-running command
takes (root `cve`, `windows cve`, future `linux cve`, ...) so the help
output stays consistent and the wiring lives in one place.
"""

from __future__ import annotations

from typing import Callable, TypeVar

import click

F = TypeVar("F", bound=Callable[..., object])


def cve_options(f: F) -> F:
    """Apply the four shared CVE-running flags.

    The decorated function's signature must accept (in any order):
        eval_mode: bool, interrupt: bool, chat: bool, chat_permissive: bool

    Click resolves them by name (the option's `dest`).
    """
    f = click.option(
        "--chat-permissive",
        "chat_permissive",
        is_flag=True,
        help="Like --chat but the ReAct agent runs tools without asking for y/N approval.",
    )(f)
    f = click.option(
        "--chat",
        is_flag=True,
        help="Drop into an interactive chat after the run completes.",
    )(f)
    f = click.option(
        "--interrupt",
        is_flag=True,
        help="Allow interactive refinement.",
    )(f)
    f = click.option(
        "--eval",
        "eval_mode",
        is_flag=True,
        help="Generate reports across multiple models.",
    )(f)
    return f
