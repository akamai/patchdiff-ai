"""`list_patch_store` — discoverable handle for binaries available to idalib_open."""

from __future__ import annotations

from pathlib import Path

from patchdiff_ai.runtime.app_context import AppContext

from ..catalogue import ToolCatalogue


def _enumerate_patch_store(ctx: AppContext) -> dict[str, Path]:
    """Return {filename: absolute_path} for binaries under `patch_store_dir`."""
    root = Path(ctx.settings.paths.patch_store_dir)
    if not root.is_dir():
        return {}
    by_name: dict[str, list[Path]] = {}
    for child in root.rglob("*"):
        if child.is_file() and child.suffix.lower() in (".dll", ".exe", ".sys"):
            by_name.setdefault(child.name, []).append(child)
    out: dict[str, Path] = {}
    for name, paths in by_name.items():
        if len(paths) == 1:
            out[name] = paths[0].resolve()
        else:
            for p in paths:
                out[f"{p.parent.name}/{p.name}"] = p.resolve()
    return out


def register(cat: ToolCatalogue, ctx: AppContext) -> None:
    """Register `list_patch_store` against `cat`."""

    allowed = _enumerate_patch_store(ctx)

    def list_patch_store() -> str:
        """List binaries available for live idalib analysis."""
        if not allowed:
            return (
                "patch_store is empty. Run `patchdiff-ai cve <CVE>` first "
                "to extract binaries."
            )
        return "\n".join(
            f"{name}\t{path}" for name, path in sorted(allowed.items())
        )

    cat.register_native(
        "list_patch_store",
        "List binaries under db/patch_store/ — pass an absolute path to idalib_open.",
        {"type": "object", "properties": {}, "required": []},
        list_patch_store,
    )
