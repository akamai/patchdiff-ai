"""Windows platform package.

`WindowsProvider` (group-level, contributes the `windows` Click group)
owns N `WindowsVersionedPlatform` instances, one per Windows release/SKU
declared in `resources/windows_sxs/platforms.json`.

Public API: just `WindowsProvider`. Everything else is internal.
"""

from __future__ import annotations

from patchdiff_ai.platforms.windows.provider import WindowsProvider
from patchdiff_ai.platforms.windows.versioned import WindowsVersionedPlatform

__all__ = ["WindowsProvider", "WindowsVersionedPlatform"]
