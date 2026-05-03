"""`patchdiff-ai init` — write a starter ``config.json`` to the app data root.

Idempotent in spirit: refuses to overwrite an existing config without
``--force``. Called explicitly by the user after a fresh ``pip install``,
or implicitly by ``AppContext.build()`` on the first run that finds no
config file.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import click

from patchdiff_ai.runtime.app_dirs import app_data_root, config_json_path

_TEMPLATE_PATH = Path(__file__).resolve().parent / "_config_template.json"


def write_default_config(target: Path, *, overwrite: bool = False) -> bool:
    """Copy the bundled template to ``target``. Returns True if written.

    Returns False (no error) when ``target`` already exists and
    ``overwrite`` is False — the auto-create path on every CLI invocation
    relies on this no-op-on-existing behaviour.
    """
    if target.exists() and not overwrite:
        return False
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(_TEMPLATE_PATH, target)
    return True


@click.command("init", help="Write a starter config.json into the app data root.")
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Overwrite the existing config.json (default: refuse).",
)
def init_command(force: bool) -> None:
    target = config_json_path()
    if target.exists() and not force:
        click.echo(f"[=] config.json already exists at {target}")
        click.echo("    pass --force to overwrite, or edit it directly.")
        raise click.exceptions.Exit(code=0)
    write_default_config(target, overwrite=True)
    click.echo(f"[+] wrote starter config -> {target}")
    click.echo(f"    data_root resolves to {app_data_root()}")
    click.echo("    edit credentials + tool paths, then run `patchdiff-ai health-check`.")
