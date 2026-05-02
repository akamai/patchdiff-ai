"""Tiny disk-pickle cache for things like CVRF os data and report listings."""

from __future__ import annotations

import pickle
from pathlib import Path
from typing import Any


class DiskCache:
    """Minimal pickle-on-disk get-or-fill helper."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def exists(self) -> bool:
        return self.path.exists()

    def load(self) -> Any:
        return pickle.loads(self.path.read_bytes())

    def store(self, value: Any) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_bytes(pickle.dumps(value))

    def get_or_fill(self, fill):
        if self.exists():
            return self.load()
        value = fill()
        self.store(value)
        return value
