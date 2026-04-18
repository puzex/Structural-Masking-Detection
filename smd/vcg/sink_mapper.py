# Pre-to-post-patch sink block mapping.
# Maps the pre-patch vulnerability sink line number to its post-patch equivalent
# by parsing the LLM-generated patch diff hunks and computing cumulative offsets.
# Three states: mapped, removed, unmappable.

import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)

# Import the diff parser from codeql_vcg (same module for consistency)
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from smd.vcg.codeql_vcg import parse_unified_diff


def _normalize_file(path: Optional[str]) -> str:
    """Strip leading a/ b/ and return basename for comparison."""
    if not path:
        return ""
    p = path.strip()
    if p.startswith("a/") or p.startswith("b/"):
        p = p[2:]
    return p


def map_sink_to_post_patch(
    sink_info: dict,
    llm_patch_diff: str,
) -> dict:
    """
    Map the pre-patch sink block to its post-patch location in the LLM diff.

    Args:
        sink_info: VCG extraction result dict (from codeql_vcg.extract_sink_from_diff).
                   Must contain 'file', 'function', 'sink_line_pre'.
        llm_patch_diff: Unified diff text of the LLM-generated patch.

    Returns:
        {
            "state": "mapped" | "removed" | "unmappable",
            "sink_line_post": int | None,   # adjusted post-patch line number
            "offset_delta": int,            # net +/- offset applied
            "reason": str,                  # short explanation
        }
    """
    NOT_FOUND = {"state": "unmappable", "sink_line_post": None, "offset_delta": 0, "reason": ""}

    if not sink_info.get("success", False):
        return {**NOT_FOUND, "reason": "vcg_extraction_failed"}

    sink_line_pre = sink_info.get("sink_line_pre")
    if sink_line_pre is None:
        return {**NOT_FOUND, "reason": "no_sink_line_pre"}

    ref_file = _normalize_file(sink_info.get("file", ""))
    ref_func = sink_info.get("function", "")

    if not llm_patch_diff or not llm_patch_diff.strip():
        return {**NOT_FOUND, "reason": "empty_llm_diff"}

    try:
        hunks = parse_unified_diff(llm_patch_diff)
    except Exception as e:
        return {**NOT_FOUND, "reason": f"parse_error:{e}"}

    if not hunks:
        return {**NOT_FOUND, "reason": "no_hunks_in_llm_diff"}

    # ── Find all hunks that cover the sink file ─────────────────────────────
    matching_hunks = []
    for h in hunks:
        hunk_file = _normalize_file(h.get("file_old") or h.get("file_new") or "")
        # Match by filename (basename comparison, allow partial path suffix match)
        if ref_file and hunk_file:
            rf_base = Path(ref_file).name
            hf_base = Path(hunk_file).name
            if rf_base != hf_base:
                # Also try suffix match for full path context
                if not (ref_file.endswith(hunk_file) or hunk_file.endswith(ref_file)):
                    continue
        matching_hunks.append(h)

    if not matching_hunks:
        # No LLM changes in the same file: sink line is unchanged → mapped
        return {
            "state": "mapped",
            "sink_line_post": sink_line_pre,
            "offset_delta": 0,
            "reason": "same_file_not_patched",
        }

    # ── Walk hunks in order to compute cumulative offset and check removal ──
    cumulative_offset = 0

    for h in sorted(matching_hunks, key=lambda x: x["old_start"]):
        hunk_old_start = h["old_start"]
        hunk_old_end = hunk_old_start + h["old_count"] - 1

        # If the sink is BEFORE this hunk, it's not affected by later hunks
        if sink_line_pre < hunk_old_start:
            break

        # Check if the sink line was deleted in this hunk
        deleted_lines = {
            l["old_lineno"]
            for l in h["lines"]
            if l["type"] == "-" and l["old_lineno"] is not None
        }
        if sink_line_pre in deleted_lines:
            return {
                "state": "removed",
                "sink_line_post": None,
                "offset_delta": cumulative_offset,
                "reason": "sink_line_on_deletion_line",
            }

        # Accumulate offset from this hunk (adds and deletes)
        if hunk_old_end < sink_line_pre:
            # Entire hunk is before the sink: accumulate offset
            n_added = sum(1 for l in h["lines"] if l["type"] == "+")
            n_removed = sum(1 for l in h["lines"] if l["type"] == "-")
            cumulative_offset += n_added - n_removed

    # Sink not deleted — compute adjusted post-patch line
    sink_line_post = sink_line_pre + cumulative_offset

    return {
        "state": "mapped",
        "sink_line_post": max(1, sink_line_post),
        "offset_delta": cumulative_offset,
        "reason": "offset_adjusted",
    }


def bulk_map_sinks(
    vcg_results: dict,
    attempts: list[dict],
) -> dict:
    """
    Map sinks for a batch of LLM patch attempts.

    Args:
        vcg_results: dict {vuln_id -> vcg_result} from load_vcg_results()
        attempts: list of dicts with keys vuln_id, tool, model, attempt, patch_diff

    Returns:
        dict {(vuln_id, tool, model, attempt) -> mapping_result}
    """
    mappings = {}
    for row in attempts:
        vuln_id = row["vuln_id"]
        key = (vuln_id, row["tool"], row["model"], row["attempt"])
        vcg = vcg_results.get(vuln_id, {"success": False, "error": "no_vcg"})
        mapping = map_sink_to_post_patch(vcg, row.get("patch_diff", ""))
        mappings[key] = mapping
    return mappings
