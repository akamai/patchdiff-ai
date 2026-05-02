from patchdiff_ai.schemas.analysis import Artifact, DecompiledFunction, DecompiledFunctionMetadata
from patchdiff_ai.schemas.candidate import Candidate, Candidates, RankedCandidate
from patchdiff_ai.schemas.core import CveId, KbId
from patchdiff_ai.schemas.cve import CveDetails, CveMetadata
from patchdiff_ai.schemas.patch_store import OsDetails, PatchSources, PatchStoreEntry
from patchdiff_ai.schemas.reducers import append_list, replace
from patchdiff_ai.schemas.report import FunctionRelevancy, Report, VulnReport

__all__ = [
    "Artifact",
    "Candidate",
    "Candidates",
    "CveDetails",
    "CveId",
    "CveMetadata",
    "DecompiledFunction",
    "DecompiledFunctionMetadata",
    "FunctionRelevancy",
    "KbId",
    "OsDetails",
    "PatchSources",
    "PatchStoreEntry",
    "RankedCandidate",
    "Report",
    "VulnReport",
    "append_list",
    "replace",
]
