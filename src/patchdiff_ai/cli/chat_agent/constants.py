"""Package-internal constants shared between the agent build and tool registrations."""

from __future__ import annotations


# Surfaced when a CVE_INFO cache hit dispatched no artifacts so binary-level
# tools have nothing to read; routes the agent to live-IDA instead.
_NO_ARTIFACTS_HINT = (
    "No patch-diff artifacts in this chat session (the run was "
    "served from the report cache, so no per-function diff state "
    "was produced). For binary-level questions, use the live-IDA "
    "tools instead: call_tool(\"list_patch_store\", {}) to find the "
    "binary path, call_tool(\"idalib_open\", {\"input_path\": <path>}) "
    "to load it, then list_funcs / lookup_funcs / decompile / "
    "xrefs_to / survey_binary as needed."
)


# IDA tools that mutate state or arbitrary-execute — never registered.
_DENY_IDA_TOOLS = {
    "py_eval", "py_exec", "py_run_file", "patch", "patch_asm",
    "dbg_start", "dbg_continue", "dbg_step_into", "dbg_step_over",
    "dbg_add_bp", "dbg_bps", "dbg_regs", "dbg_read", "dbg_write",
}
