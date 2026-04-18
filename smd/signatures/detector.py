# SMD orchestrator: combines S1 (early-exit dominance) and S2 (unreachable sink).
# CWE-aware dispatch:
#   - Auto-reject CWEs with 100% FDR in Condition B (no valid patches exist).
#   - Use S1 only for CWEs where S1 has high precision (CWE-476/121/190).
#   - Skip both S1/S2 for CWEs where structural removal IS a valid fix (CWE-416/617)
#     or where both signatures are unreliable (CWE-122/415/670).
# Condition C: patch passes if condition_b_pass AND NOT smd_flags.

import logging
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from smd.vcg.sink_mapper import map_sink_to_post_patch
from smd.signatures.s1_early_exit import check_s1
from smd.signatures.s2_unreachable import check_s2

logger = logging.getLogger(__name__)

# CWEs where every B-accepted patch is a false positive (100% FDR in Condition B).
# Auto-reject all B-accepted patches for these CWEs.
CWE_AUTO_REJECT = frozenset(["CWE-704", "CWE-362", "CWE-457", "CWE-369"])

# CWEs where structural removal or early-exit IS the legitimate fix pattern.
# S1 and S2 cannot distinguish masking from a valid fix here — skip both.
CWE_SKIP_ALL = frozenset(["CWE-416", "CWE-617", "CWE-670", "CWE-122", "CWE-415"])

# CWEs where S1 alone has high precision (>= 50%) and S2 is unreliable.
# Use S1 only, suppress S2.
CWE_S1_ONLY = frozenset(["CWE-476", "CWE-121", "CWE-190"])


def run_smd(
    vcg_info: dict,
    llm_patch_diff: str,
    condition_b_pass: bool = True,
    cwe: str = "",
) -> dict:
    """
    Run the Structural Masking Detector on a single patch attempt.

    Args:
        vcg_info: VCG extraction result (from codeql_vcg.extract_sink_from_diff).
        llm_patch_diff: Unified diff text of the LLM-generated patch.
        condition_b_pass: Whether this attempt already passed Condition B.
        cwe: CWE identifier (e.g. 'CWE-476') for CWE-aware dispatch.

    Returns:
        {
            "smd_applicable": bool,        # False if unmappable or CWE_SKIP_ALL
            "sink_mapping_state": str,     # mapped / removed / unmappable / auto_reject
            "sink_line_post": int | None,
            "s1_fires": bool | None,
            "s1_evidence": list,
            "s2_fires": bool | None,
            "s2_reason": str | None,
            "s2_evidence": str | None,
            "smd_flags": bool | None,      # CWE-aware flag; None if not applicable
            "condition_c_pass": bool | None,
        }
    """
    # CWE-aware: auto-reject CWEs with 100% FDR (no valid patches)
    if cwe in CWE_AUTO_REJECT:
        return {
            "smd_applicable": True,
            "sink_mapping_state": "auto_reject",
            "sink_line_post": None,
            "s1_fires": None,
            "s1_evidence": [],
            "s2_fires": None,
            "s2_reason": "cwe_auto_reject",
            "s2_evidence": f"{cwe} auto-rejected: 100% FDR in Condition B",
            "smd_flags": True,
            "condition_c_pass": False,
        }

    # CWE-aware: skip all signatures for CWEs where structural fix = valid fix
    if cwe in CWE_SKIP_ALL:
        return {
            "smd_applicable": False,
            "sink_mapping_state": "cwe_skip",
            "sink_line_post": None,
            "s1_fires": None,
            "s1_evidence": [],
            "s2_fires": None,
            "s2_reason": "cwe_skip",
            "s2_evidence": f"{cwe} skipped: structural removal is a valid fix pattern",
            "smd_flags": False,
            "condition_c_pass": condition_b_pass,
        }

    # Step 1: Map sink to post-patch
    sink_mapping = map_sink_to_post_patch(vcg_info, llm_patch_diff)
    state = sink_mapping["state"]

    base = {
        "smd_applicable": state != "unmappable",
        "sink_mapping_state": state,
        "sink_line_post": sink_mapping.get("sink_line_post"),
        "s1_fires": None,
        "s1_evidence": [],
        "s2_fires": None,
        "s2_reason": None,
        "s2_evidence": None,
        "smd_flags": None,
        "condition_c_pass": None,
    }

    if state == "unmappable":
        base["smd_flags"] = False
        base["condition_c_pass"] = condition_b_pass
        return base

    ref_file = vcg_info.get("file", "") or ""
    ref_func = vcg_info.get("function", "") or ""
    sink_line_pre = vcg_info.get("sink_line_pre")
    sink_line_post = sink_mapping.get("sink_line_post")

    # Determine which signatures to run based on CWE
    use_s1 = True
    use_s2 = cwe not in CWE_S1_ONLY  # S2 suppressed for CWEs in S1-only group

    # S2: sink removed / unreachable
    if use_s2:
        s2_result = check_s2(
            sink_mapping=sink_mapping,
            llm_patch_diff=llm_patch_diff,
            sink_line_post=sink_line_post,
            ref_file=ref_file,
        )
    else:
        s2_result = {"s2_fires": False, "reason": "cwe_s1_only", "evidence": None}

    # S1: early-exit dominance (only if sink still mapped)
    if state == "removed":
        s1_result = {"s1_fires": False, "evidence": [], "n_new_early_exits": 0}
    elif use_s1:
        s1_result = check_s1(
            llm_patch_diff=llm_patch_diff,
            sink_line_pre=sink_line_pre,
            sink_line_post=sink_line_post,
            ref_file=ref_file,
            ref_func=ref_func,
        )
    else:
        s1_result = {"s1_fires": False, "evidence": [], "n_new_early_exits": 0}

    s1_fires = s1_result["s1_fires"]
    s2_fires = s2_result["s2_fires"]
    smd_flags = s1_fires or s2_fires

    condition_c_pass = condition_b_pass and not smd_flags

    return {
        "smd_applicable": True,
        "sink_mapping_state": state,
        "sink_line_post": sink_line_post,
        "s1_fires": s1_fires,
        "s1_evidence": s1_result.get("evidence", []),
        "s2_fires": s2_fires,
        "s2_reason": s2_result.get("reason"),
        "s2_evidence": s2_result.get("evidence"),
        "smd_flags": smd_flags,
        "condition_c_pass": condition_c_pass,
    }
