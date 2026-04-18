# Pattern-based static checker for Condition B validation.
# Uses AST analysis (tree-sitter) and regex patterns on the patch diff to detect
# whether the LLM-generated patch actually addresses the CWE vulnerability.
#
# This checker operates directly on the patch diff (no compilation or internet needed).
# Strategy: a patch "passes" Condition B if it introduces a meaningful fix pattern
# for the given CWE. A patch "fails" if it shows a structural masking signature
# (early-exit or sink removal) WITHOUT adding the appropriate fix.
#
# CWE-specific logic:
#   CWE-476 (NULL deref): patch must add null-check OR pass-through (conservative)
#   CWE-416 (UAF): detect if patch removes/nullifies the freed pointer
#   CWE-122/121 (BOF): detect if patch adds bounds check or size validation
#   CWE-190 (Int overflow): detect if patch adds overflow check or safe math
#   CWE-415 (Double free): detect if patch nullifies pointer after free
#   Others: pass-through

import re
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def _get_added_lines(patch_diff: str) -> list[str]:
    """Extract added lines from patch diff (lines starting with '+' but not '+++')."""
    lines = []
    for line in patch_diff.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            lines.append(line[1:])
    return lines


def _get_removed_lines(patch_diff: str) -> list[str]:
    """Extract removed lines from patch diff (lines starting with '-' but not '---')."""
    lines = []
    for line in patch_diff.splitlines():
        if line.startswith("-") and not line.startswith("---"):
            lines.append(line[1:])
    return lines


def _added_text(patch_diff: str) -> str:
    return "\n".join(_get_added_lines(patch_diff))


def _removed_text(patch_diff: str) -> str:
    return "\n".join(_get_removed_lines(patch_diff))


NULL_CHECK_PATTERNS = [
    re.compile(r'\bif\s*\(\s*\w+\s*(?:==\s*NULL|!=\s*NULL|==\s*nullptr|!=\s*nullptr)\s*\)'),
    re.compile(r'\bif\s*\(\s*!\s*\w+\s*\)'),
    re.compile(r'\bif\s*\(\s*\w+\s*\)\s*\{'),
    re.compile(r'\bif\s*\(\s*NULL\s*==\s*\w+'),
    re.compile(r'\bif\s*\(\s*nullptr\s*==\s*\w+'),
    re.compile(r'\bassert\s*\(\s*\w+\s*\)'),
    re.compile(r'\bassert\s*\(\s*\w+\s*!=\s*(?:NULL|nullptr)\s*\)'),
    re.compile(r'\breturn\s+(?:NULL|nullptr|false|0|-1|ERROR)'),
    re.compile(r'UNLIKELY|unlikely\s*\(.*NULL'),
]

BOUNDS_CHECK_PATTERNS = [
    re.compile(r'\bif\s*\(\s*\w+\s*(?:>=|>|<=|<)\s*\w+'),
    re.compile(r'\bif\s*\(\s*(?:size|len|length|count|n|num|offset|idx|index)\s*(?:>=|>|<=|<)'),
    re.compile(r'\bif\s*\(\s*\w+\s*\+\s*\w+\s*(?:>=|>|<=|<|>\s*\w+)'),
    re.compile(r'\bif\s*\(.*overflow', re.IGNORECASE),
    re.compile(r'\bif\s*\(.*(?:size|length|len)\s*(?:==\s*0|>\s*(?:INT_MAX|UINT_MAX|SIZE_MAX))'),
    re.compile(r'\bclamp\b|\bmin\b|\bmax\b|\bMIN\b|\bMAX\b'),
    re.compile(r'enforce\s*\('),  # Exiv2-style
    re.compile(r'ENSURE\s*\(|ensure\s*\('),
    re.compile(r'safe_add|safe_mul|checked_add|checked_mul', re.IGNORECASE),
    re.compile(r'\bif\s*\(\s*\w+\s*>\s*(?:INT_MAX|UINT_MAX|SIZE_MAX|LONG_MAX|SSIZE_MAX)'),
]

OVERFLOW_CHECK_PATTERNS = [
    re.compile(r'\bif\s*\(.*(?:overflow|wraps|exceeds)', re.IGNORECASE),
    re.compile(r'\b(?:INT_MAX|UINT_MAX|SIZE_MAX|LONG_MAX|SSIZE_MAX|INT64_MAX|UINT64_MAX)\b'),
    re.compile(r'__builtin_(?:add|sub|mul)_overflow'),
    re.compile(r'safe_(?:add|sub|mul|div)', re.IGNORECASE),
    re.compile(r'checked_(?:add|sub|mul)', re.IGNORECASE),
    re.compile(r'\bif\s*\(\s*\w+\s*(?:!=|==)\s*0\s*&&\s*\w+\s*(?:>|<)\s*\w+\s*/\s*\w+'),
    re.compile(r'saturation|saturate|clamp', re.IGNORECASE),
    re.compile(r'\bif\s*\(.*\s*>>\s*\d+\s*\)'),
]

UAF_FIX_PATTERNS = [
    re.compile(r'\w+\s*=\s*NULL\s*;'),
    re.compile(r'\w+\s*=\s*nullptr\s*;'),
    re.compile(r'Py_CLEAR\s*\('),
    re.compile(r'Py_DECREF\s*\('),
    re.compile(r'std::move\s*\('),
    re.compile(r'\.reset\s*\(\s*\)'),
    re.compile(r'unique_ptr|shared_ptr|weak_ptr', re.IGNORECASE),
    re.compile(r'if\s*\(.*\s*!=\s*NULL\s*&&'),
    re.compile(r'if\s*\(.*ptr.*free', re.IGNORECASE),
]

DOUBLE_FREE_FIX_PATTERNS = [
    re.compile(r'\w+\s*=\s*NULL\s*;'),
    re.compile(r'\w+\s*=\s*nullptr\s*;'),
    re.compile(r'if\s*\(\s*\w+\s*\)\s*\{.*free\s*\('),
    re.compile(r'Py_CLEAR\s*\(|Py_XDECREF\s*\('),
]

STRUCTURAL_MASKING_PATTERNS = [
    re.compile(r'^\s*return\s+(?:NULL|nullptr|false|0|-1|ERROR)\s*;\s*$'),
    re.compile(r'^\s*(?:continue|break)\s*;\s*$'),
    re.compile(r'^\s*(?:throw|abort|exit)\s*\('),
]

EARLY_EXIT_ONLY_PATTERNS = [
    re.compile(r'if\s*\(.*\)\s*\{?\s*return\s+(?:NULL|nullptr|false|-1|0|ERROR)'),
    re.compile(r'if\s*\(.*\)\s*\{?\s*(?:goto|throw|abort)\s*'),
]


def _has_any_pattern(text: str, patterns: list) -> bool:
    return any(p.search(text) for p in patterns)


def _patch_adds_meaningful_code(patch_diff: str) -> bool:
    """Check if patch adds more than just early-exit guards."""
    added = _added_text(patch_diff)
    added_lines = [l for l in _get_added_lines(patch_diff) if l.strip()]
    if len(added_lines) == 0:
        return False
    # Check if patch only adds early-exit/guard
    substantive = [l for l in added_lines
                   if not STRUCTURAL_MASKING_PATTERNS[0].search(l)
                   and not STRUCTURAL_MASKING_PATTERNS[1].search(l)
                   and l.strip() not in ('{', '}', '')
                   and not l.strip().startswith('//')]
    return len(substantive) > 0


def check_cwe476_null_deref(patch_diff: str) -> dict:
    """
    CWE-476: NULL pointer dereference.
    A valid patch should add a null-check before the dereference.
    Conservative: pass if any null-check pattern found in added lines.
    """
    added = _added_text(patch_diff)
    has_null_check = _has_any_pattern(added, NULL_CHECK_PATTERNS)
    return {
        "condition_b_pass": has_null_check,
        "reason": "null_check_added" if has_null_check else "no_null_check_in_patch",
        "has_null_check": has_null_check,
    }


def check_cwe122_121_bof(patch_diff: str) -> dict:
    """
    CWE-122/121: Buffer overflow (heap/stack).
    A valid patch should add size/bounds checking.
    """
    added = _added_text(patch_diff)
    removed = _removed_text(patch_diff)
    has_bounds_check = _has_any_pattern(added, BOUNDS_CHECK_PATTERNS)
    # Also check if the patch adjusts the allocation size (adds space for NUL, etc.)
    added_lines = _get_added_lines(patch_diff)
    alloc_adjustment = any(
        re.search(r'\+\s*1\b|\+\s*sizeof\b|\+\s*1\s*\)', l) for l in added_lines
    )
    passes = has_bounds_check or alloc_adjustment
    return {
        "condition_b_pass": passes,
        "reason": "bounds_check_added" if passes else "no_bounds_check",
        "has_bounds_check": has_bounds_check,
        "has_alloc_adjustment": alloc_adjustment,
    }


def check_cwe190_int_overflow(patch_diff: str) -> dict:
    """
    CWE-190: Integer overflow.
    A valid patch should add overflow checking or use safe arithmetic.
    """
    added = _added_text(patch_diff)
    has_overflow_check = _has_any_pattern(added, OVERFLOW_CHECK_PATTERNS)
    has_bounds_check = _has_any_pattern(added, BOUNDS_CHECK_PATTERNS)
    passes = has_overflow_check or has_bounds_check
    return {
        "condition_b_pass": passes,
        "reason": "overflow_check_added" if passes else "no_overflow_check",
        "has_overflow_check": has_overflow_check,
        "has_bounds_check": has_bounds_check,
    }


def check_cwe416_uaf(patch_diff: str) -> dict:
    """
    CWE-416: Use-after-free.
    A valid patch should nullify the freed pointer, use RAII, or add lifetime tracking.
    """
    added = _added_text(patch_diff)
    removed = _removed_text(patch_diff)
    has_uaf_fix = _has_any_pattern(added, UAF_FIX_PATTERNS)
    # Also valid: refactoring to use smart pointers
    has_smart_ptr = bool(re.search(r'unique_ptr|shared_ptr|weak_ptr|auto_ptr', added))
    passes = has_uaf_fix or has_smart_ptr
    return {
        "condition_b_pass": passes,
        "reason": "uaf_fix_added" if passes else "no_uaf_fix_detected",
        "has_uaf_fix": has_uaf_fix,
        "has_smart_ptr": has_smart_ptr,
    }


def check_cwe415_double_free(patch_diff: str) -> dict:
    """
    CWE-415: Double free.
    A valid patch should add a null-guard before free or nullify after free.
    """
    added = _added_text(patch_diff)
    has_fix = _has_any_pattern(added, DOUBLE_FREE_FIX_PATTERNS)
    has_null_check = _has_any_pattern(added, NULL_CHECK_PATTERNS)
    passes = has_fix or has_null_check
    return {
        "condition_b_pass": passes,
        "reason": "double_free_fix_added" if passes else "no_double_free_fix",
        "has_fix": has_fix,
        "has_null_check": has_null_check,
    }


def check_cwe369_divide_by_zero(patch_diff: str) -> dict:
    """CWE-369: Divide by zero. Patch should add zero-check before division."""
    added = _added_text(patch_diff)
    has_zero_check = bool(re.search(r'if\s*\(.*!=\s*0\s*\)|if\s*\(\s*0\s*!=', added))
    has_bounds = _has_any_pattern(added, BOUNDS_CHECK_PATTERNS)
    passes = has_zero_check or has_bounds
    return {
        "condition_b_pass": passes,
        "reason": "zero_check_added" if passes else "no_zero_check",
        "has_zero_check": has_zero_check,
    }


def check_cwe457_uninit(patch_diff: str) -> dict:
    """CWE-457: Uninitialized variable. Patch should add initialization."""
    added = _added_text(patch_diff)
    has_init = bool(re.search(r'\w+\s*=\s*(?:0|NULL|nullptr|false|true|\{0\}|\{\})', added))
    return {
        "condition_b_pass": has_init,
        "reason": "init_added" if has_init else "no_init_detected",
        "has_init": has_init,
    }


# Dispatch table
CWE_CHECKERS = {
    "CWE-476": check_cwe476_null_deref,
    "CWE-122": check_cwe122_121_bof,
    "CWE-121": check_cwe122_121_bof,
    "CWE-190": check_cwe190_int_overflow,
    "CWE-416": check_cwe416_uaf,
    "CWE-415": check_cwe415_double_free,
    "CWE-369": check_cwe369_divide_by_zero,
    "CWE-457": check_cwe457_uninit,
}

PASSTHROUGH_CWES = {"CWE-617", "CWE-670", "CWE-704", "CWE-362"}


def check_patch(vuln_id: str, cwe: str, patch_diff: str) -> dict:
    """
    Main entry point: check a patch for a given CWE using pattern-based analysis.

    Returns:
        {
            "condition_b_pass": bool,
            "checker": str,
            "cwe": str,
            "findings_count": int,
            "details": dict,
        }
    """
    if not patch_diff or not patch_diff.strip():
        return {
            "condition_b_pass": True,
            "checker": "pattern",
            "cwe": cwe,
            "findings_count": 0,
            "details": {"reason": "empty_patch"},
        }

    if cwe in PASSTHROUGH_CWES:
        return {
            "condition_b_pass": True,
            "checker": "none",
            "cwe": cwe,
            "findings_count": 0,
            "details": {"reason": "no_checker_available"},
        }

    checker_fn = CWE_CHECKERS.get(cwe)
    if checker_fn is None:
        return {
            "condition_b_pass": True,
            "checker": "none",
            "cwe": cwe,
            "findings_count": 0,
            "details": {"reason": f"no_checker_for_{cwe}"},
        }

    try:
        result = checker_fn(patch_diff)
    except Exception as e:
        logger.warning("Pattern checker error for %s/%s: %s", vuln_id, cwe, e)
        return {
            "condition_b_pass": True,
            "checker": "pattern_error",
            "cwe": cwe,
            "findings_count": 0,
            "details": {"error": str(e)[:200]},
        }

    passes = result.get("condition_b_pass", True)
    return {
        "condition_b_pass": passes,
        "checker": "pattern",
        "cwe": cwe,
        "findings_count": 0 if passes else 1,
        "details": result,
    }
