"""AppContext: the only DI bundle. Built once in cli/app.py, passed everywhere."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from patchdiff_ai.config.settings import Settings
from patchdiff_ai.config.tools import IdaInstall, discover_ida_installs, select_ida_install
from patchdiff_ai.llm.catalog import ModelPurpose
from patchdiff_ai.llm.registry import ModelRegistry
from patchdiff_ai.observability.progress import NullProgressReporter, ProgressReporter
from patchdiff_ai.persistence.vector_store import VectorStores
from patchdiff_ai.runtime.paths import BUNDLED_BINDIFF_DIR
from patchdiff_ai.tools.bindiff import BindiffTool
from patchdiff_ai.tools.delta import DeltaApi
from patchdiff_ai.tools.ida import IdaTool
from patchdiff_ai.tools.ida_mcp import IdaMcpService
from patchdiff_ai.tools.idalib_pool import IdalibPool
from patchdiff_ai.tools.manifest import WcpManifestExtractor
from patchdiff_ai.tools.seven_zip import SevenZipTool

if TYPE_CHECKING:
    from patchdiff_ai.platforms.base import Platform
    from patchdiff_ai.prompts.registry import PromptRegistry


@dataclass
class Tools:
    seven_zip: SevenZipTool
    # Legacy 8.x subprocess wrapper; used by RE when idalib is unavailable.
    # Always constructed so health-check can report on it.
    ida: IdaTool
    bindiff: BindiffTool
    delta: DeltaApi
    # In-process idalib in N worker processes; None falls back to the
    # legacy subprocess RE flow.
    idalib: IdalibPool | None
    # Chat-only ida-pro-mcp wrapper; None when idalib isn't activated.
    ida_chat: IdaMcpService | None
    manifest: WcpManifestExtractor | None = None


@dataclass
class AppContext:
    """Top-level DI bundle. Holds everything any node, tool, or CLI command needs."""

    settings: Settings
    registry: ModelRegistry
    tools: Tools
    log: structlog.stdlib.BoundLogger
    ida_install: IdaInstall | None = None
    vector_stores: VectorStores | None = None
    prompts: "PromptRegistry | None" = field(default=None)
    progress: ProgressReporter = field(default_factory=NullProgressReporter)
    # Set by the orchestrator at run_cve entry from the CLI-resolved
    # provider/Platform; nodes route per-OS work (advisory fetch,
    # package gather, ranking prompts) through it.
    platform: "Platform | None" = field(default=None)

    @classmethod
    def build(cls, settings: Settings) -> "AppContext":
        """Construct the context; vector stores stay lazy."""
        registry = ModelRegistry.from_settings(settings)

        # `setdefault` so explicit user BINDIFF_PATH wins. python-bindiff
        # resolves the binary lazily on first diff.
        if BUNDLED_BINDIFF_DIR.is_dir() and (BUNDLED_BINDIFF_DIR / "bindiff.exe").is_file():
            os.environ.setdefault("BINDIFF_PATH", str(BUNDLED_BINDIFF_DIR))

        # IDA exe: explicit setting → discovered install → 8.0 default.
        # The default keeps health-check's "missing" message clear rather
        # than crashing on None elsewhere.
        ida_install = select_ida_install(discover_ida_installs())
        if settings.tools.ida is not None:
            ida_exe = settings.tools.ida
        elif ida_install is not None:
            ida_exe = ida_install.executable
        else:
            ida_exe = Path(r"C:\Program Files\IDA Pro 8.0\idat64.exe")

        # idapro (PyPI) loads `idalib.dll` from %IDADIR%/idalib.dll;
        # spawned workers inherit this env via multiprocessing `spawn`.
        if ida_install is not None and ida_install.has_idalib:
            os.environ.setdefault("IDADIR", str(ida_install.root))

        # idalib optional: present → preferred RE path; absent → legacy
        # idat-subprocess flow (same artefacts, slower).
        idalib_pool: IdalibPool | None = None
        ida_chat: IdaMcpService | None = None
        if ida_install is not None and ida_install.has_idalib:
            idalib_pool = IdalibPool(
                n_workers=settings.concurrency.re_workers,
                ida_install=ida_install,
            )
            ida_chat = IdaMcpService()

        tools = Tools(
            seven_zip=SevenZipTool(
                settings.tools.seven_zip,
                timeout=settings.tools.process_timeout_seconds,
            ),
            ida=IdaTool(
                ida_exe,
                timeout=settings.tools.process_timeout_seconds,
            ),
            bindiff=BindiffTool(),
            delta=DeltaApi(
                modules=[settings.tools.update_compression_dll]
                if settings.tools.update_compression_dll.exists()
                else []
            ),
            idalib=idalib_pool,
            ida_chat=ida_chat,
            manifest=None,
        )
        log = structlog.get_logger("patchdiff_ai")
        ctx = cls(
            settings=settings,
            registry=registry,
            tools=tools,
            log=log,
            ida_install=ida_install,
        )

        try:
            from patchdiff_ai.prompts.registry import PromptRegistry

            ctx.prompts = PromptRegistry.default()
        except Exception as exc:
            log.warning("prompts_unavailable", error=str(exc))

        return ctx

    def open_vector_stores(self) -> VectorStores:
        if self.vector_stores is not None:
            return self.vector_stores
        embedding = self.registry.for_purpose(ModelPurpose.EMBEDDING).model
        self.vector_stores = VectorStores.open(self.settings.paths.db_dir, embedding)
        return self.vector_stores

    def close(self) -> None:
        try:
            self.tools.delta.close()
        except Exception:
            pass
        # idalib / ida_chat subprocess cleanup runs in the orchestrator's
        # `finally:` and the shared `_subprocess_lifecycle` atexit.
