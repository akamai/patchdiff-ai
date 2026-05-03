"""Windows-internal gather subgraph.

Lives inside the `windows` plugin because everything it does is
Windows-specific (KB downloader, MSU 7-Zip + PSF + delta extraction,
WinSxS dedupe, PE executable filter, "Windows executable" file-description
prompt). The shared pipeline only ever sees this subgraph indirectly via
`WindowsVersionedPlatform.gather_packages` returning
`{extracted, dataframes, filtered_dataframes}`.

Adding a new platform never imports from here — see
`platforms/add_platform.md` for the contract.
"""

from patchdiff_ai.platforms.windows.gather_info.graph import build_gather_graph
from patchdiff_ai.platforms.windows.gather_info.state import GatherInfoState

__all__ = ["GatherInfoState", "build_gather_graph"]
