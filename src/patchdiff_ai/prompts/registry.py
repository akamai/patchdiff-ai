"""PromptRegistry: file-backed system prompts."""

from __future__ import annotations

from enum import Enum
from functools import lru_cache
from pathlib import Path

_PROMPTS_DIR = Path(__file__).resolve().parent


class PromptId(str, Enum):
    PI_COLLECT = "platform_internals/collect.system.md"
    PI_RANK = "platform_internals/rank.system.md"
    GATHER_FILE_DESC = "gather_info/file_description.system.md"
    VR_SCORE_FUNCTIONS = "vulnerability_research/score_functions.system.md"
    VR_GENERATE_REPORT = "vulnerability_research/generate_report.system.md"
    CHAT_SYSTEM = "chat/system.md"


class PromptRegistry:
    def __init__(self, root: Path) -> None:
        self.root = root

    @classmethod
    def default(cls) -> "PromptRegistry":
        return cls(_PROMPTS_DIR)

    @lru_cache(maxsize=64)
    def get(self, prompt_id: PromptId) -> str:
        path = self.root / prompt_id.value
        return path.read_text(encoding="utf-8")
