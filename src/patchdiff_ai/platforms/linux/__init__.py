"""Linux platform package — skeleton, not a real implementation.

`LinuxProvider` is registered in `platforms/__init__.py` so the `linux`
group shows up in `patchdiff-ai --help`. Every advisory-fetching method
raises `NotImplementedError` until someone wires real data sources
(Ubuntu USNs, Debian DSAs, distro source-package mirrors, debdiff, ...).

Use this package as the template for any future provider. See
`platforms/add_platform.md` for the step-by-step.
"""

from __future__ import annotations

from patchdiff_ai.platforms.linux.distro import LinuxDistroPlatform
from patchdiff_ai.platforms.linux.provider import LinuxProvider

__all__ = ["LinuxProvider", "LinuxDistroPlatform"]
