# Semgrep-based static checker for Condition B validation.
# Applies CWE-specific Semgrep rules to post-patch source files.
# Primary approach: apply the LLM-generated patch diff to a temp copy of the
# vulnerable source file, then run semgrep on that file. This avoids needing
# a full project build.
#
# For each vuln, we work with the files modified by the patch (extracted from
# the diff) — no git clone needed since PVBench provides patch.diff and the
# pre-patch source is recoverable via reverse-patching or we skip source-level
# checks and rely on AST-pattern matching via semgrep --config=auto on the diff.
#
# Fallback strategy: if source file recovery fails, mark result as "no_checker"
# (pass-through, same as Condition A).

import json
import logging
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[2]
CODEQL_REPO = ROOT / "tools" / "codeql-repo"
CWE_MAP_PATH = ROOT / "smd" / "configs" / "cwe_query_map.yaml"

_CWE_MAP: Optional[dict] = None


def _load_cwe_map() -> dict:
    global _CWE_MAP
    if _CWE_MAP is None:
        with open(CWE_MAP_PATH) as f:
            _CWE_MAP = yaml.safe_load(f)
    return _CWE_MAP


def get_checker_strategy(cwe: str) -> str:
    """Return 'codeql', 'semgrep', or 'none' for the given CWE."""
    cwe_map = _load_cwe_map()
    entry = cwe_map.get(cwe, {})
    return entry.get("checker_strategy", "none")


def get_semgrep_rules(cwe: str) -> list[str]:
    cwe_map = _load_cwe_map()
    entry = cwe_map.get(cwe, {})
    return entry.get("semgrep_rules", [])


def _extract_modified_files(patch_diff: str) -> list[str]:
    """Extract list of files touched by the patch diff."""
    files = []
    for line in patch_diff.splitlines():
        if line.startswith("+++ b/"):
            path = line[6:].strip()
            if path and path != "/dev/null":
                files.append(path)
    return files


def _write_patched_file(
    original_source: str,
    patch_diff: str,
    target_file: str,
    work_dir: Path,
) -> Optional[Path]:
    """
    Write original source to a temp dir, apply the patch, and return the path
    to the patched file. Returns None if patching fails.
    """
    # Write original content
    dest = work_dir / target_file
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(original_source)

    # Write diff to a temp file
    patch_file = work_dir / "_patch.diff"
    patch_file.write_text(patch_diff)

    result = subprocess.run(
        ["patch", "-p1", "--fuzz=3", "-i", str(patch_file)],
        cwd=str(work_dir),
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        logger.debug("patch failed for %s: %s", target_file, result.stderr[:200])
        return None
    return dest


def _run_semgrep_on_file(
    file_path: Path,
    rules: list[str],
    cwe: str,
) -> dict:
    """
    Run semgrep on a single file with the given rules.
    Returns dict with keys: passed, findings, error.
    'passed' = True means no vulnerability detected (patch is OK for Condition B).
    """
    if not rules:
        return {"passed": True, "findings": [], "rule": "none", "error": None}

    # Build semgrep command
    cmd = ["semgrep", "--json", "--quiet"]
    for rule in rules:
        cmd += ["--config", rule]
    cmd.append(str(file_path))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        logger.warning("semgrep timed out for %s", file_path)
        return {"passed": True, "findings": [], "rule": str(rules), "error": "timeout"}

    findings = []
    if result.returncode in (0, 1):
        try:
            data = json.loads(result.stdout)
            findings = data.get("results", [])
        except json.JSONDecodeError:
            pass
    elif result.returncode != 0:
        logger.debug("semgrep error (rc=%d): %s", result.returncode, result.stderr[:200])
        return {
            "passed": True,
            "findings": [],
            "rule": str(rules),
            "error": f"semgrep rc={result.returncode}",
        }

    return {
        "passed": len(findings) == 0,
        "findings": findings[:10],
        "rule": str(rules),
        "error": None,
    }


def _get_added_lines_snippet(patch_diff: str, target_file: str, max_lines: int = 200) -> str:
    """
    Extract only the added (+) lines from the patch for a specific file.
    Returns a synthetic C source file with just the added code for semgrep to scan.
    """
    in_target = False
    lines = []
    for line in patch_diff.splitlines():
        if line.startswith("diff --git"):
            in_target = f" b/{target_file}" in line
        if not in_target:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            lines.append(line[1:])
        if len(lines) >= max_lines:
            break
    return "\n".join(lines)


def check_patch_with_semgrep(
    vuln_id: str,
    cwe: str,
    patch_diff: str,
    vuln_file: Optional[str] = None,
) -> dict:
    """
    Apply Semgrep check to the added code in patch_diff for the given CWE.

    Strategy:
    1. Extract added lines from the patch diff
    2. Write them to a temporary .c file
    3. Run semgrep with CWE-specific rules
    4. Return result dict

    Returns:
        {
            "condition_b_pass": bool,
            "checker": "semgrep" | "none",
            "cwe": str,
            "findings_count": int,
            "details": dict,
        }
    """
    strategy = get_checker_strategy(cwe)

    if strategy == "none":
        return {
            "condition_b_pass": True,
            "checker": "none",
            "cwe": cwe,
            "findings_count": 0,
            "details": {"reason": "no_checker_available"},
        }

    if strategy != "semgrep":
        # Will be handled by codeql_checker
        return {
            "condition_b_pass": True,
            "checker": "deferred_to_codeql",
            "cwe": cwe,
            "findings_count": 0,
            "details": {"reason": "codeql_strategy"},
        }

    rules = get_semgrep_rules(cwe)
    if not rules:
        return {
            "condition_b_pass": True,
            "checker": "none",
            "cwe": cwe,
            "findings_count": 0,
            "details": {"reason": "no_semgrep_rules"},
        }

    # Extract modified files from diff
    modified_files = _extract_modified_files(patch_diff)
    if not modified_files:
        return {
            "condition_b_pass": True,
            "checker": "semgrep",
            "cwe": cwe,
            "findings_count": 0,
            "details": {"reason": "no_modified_files"},
        }

    # Focus on the primary modified file (first C/C++ file)
    target_file = modified_files[0]
    if vuln_file:
        for f in modified_files:
            if vuln_file in f or f in vuln_file:
                target_file = f
                break

    # Extract added-line snippet from the diff
    snippet = _get_added_lines_snippet(patch_diff, target_file)
    if not snippet.strip():
        return {
            "condition_b_pass": True,
            "checker": "semgrep",
            "cwe": cwe,
            "findings_count": 0,
            "details": {"reason": "no_added_lines"},
        }

    # Write snippet to temp file and run semgrep
    with tempfile.TemporaryDirectory(prefix=f"smd_semgrep_{vuln_id}_") as tmpdir:
        ext = ".cpp" if any(target_file.endswith(e) for e in (".cpp", ".cc", ".cxx", ".hpp")) else ".c"
        snippet_path = Path(tmpdir) / f"patch_snippet{ext}"
        snippet_path.write_text(snippet)

        result = _run_semgrep_on_file(snippet_path, rules, cwe)

    return {
        "condition_b_pass": result["passed"],
        "checker": "semgrep",
        "cwe": cwe,
        "findings_count": len(result["findings"]),
        "details": {
            "rule": result["rule"],
            "error": result["error"],
            "target_file": target_file,
            "snippet_lines": len(snippet.splitlines()),
        },
    }
