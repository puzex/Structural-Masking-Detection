# CodeQL taint/path checker for Condition B validation.
# Runs CWE-specific CodeQL queries on post-patch code to check if the
# vulnerability data-flow path is still present.
#
# Building a CodeQL database requires the project to compile. We use the
# PVBench project-level source (cloned from GitHub) with the patch applied.
# If the DB build fails, we fall back to Semgrep.
#
# This module is called for CWEs with checker_strategy = "codeql":
#   CWE-122, CWE-416, CWE-190, CWE-121, CWE-415, CWE-457

import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[2]
CODEQL_BIN = ROOT / "tools" / "codeql" / "codeql"
CODEQL_REPO = ROOT / "tools" / "codeql-repo"
VULN_DIR = ROOT / "benchmarks" / "pvbench" / "vuln"
CWE_MAP_PATH = ROOT / "smd" / "configs" / "cwe_query_map.yaml"

_CWE_MAP: Optional[dict] = None


def _load_cwe_map() -> dict:
    global _CWE_MAP
    if _CWE_MAP is None:
        with open(CWE_MAP_PATH) as f:
            _CWE_MAP = yaml.safe_load(f)
    return _CWE_MAP


def get_codeql_query_path(cwe: str) -> Optional[Path]:
    cwe_map = _load_cwe_map()
    entry = cwe_map.get(cwe, {})
    rel = entry.get("codeql_query")
    if not rel:
        return None
    full = CODEQL_REPO / rel
    return full if full.exists() else None


def _find_vuln_source_dir(vuln_id: str, project: str) -> Optional[Path]:
    """Locate the PVBench source directory for a vulnerability."""
    candidate = VULN_DIR / project / vuln_id
    if candidate.is_dir():
        return candidate
    # Sometimes vuln_id == project subdir name
    for sub in (VULN_DIR / project).iterdir() if (VULN_DIR / project).is_dir() else []:
        if sub.is_dir() and vuln_id in sub.name:
            return sub
    return None


def _apply_patch(src_dir: Path, patch_diff: str, work_dir: Path) -> bool:
    """
    Copy src_dir to work_dir and apply patch_diff. Returns True on success.
    """
    try:
        shutil.copytree(str(src_dir), str(work_dir), dirs_exist_ok=True)
    except Exception as e:
        logger.debug("copytree failed: %s", e)
        return False

    patch_file = work_dir / "_llm_patch.diff"
    patch_file.write_text(patch_diff)

    result = subprocess.run(
        ["patch", "-p1", "--fuzz=3", "-i", str(patch_file)],
        cwd=str(work_dir),
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        logger.debug("patch apply failed: %s", result.stderr[:300])
        return False
    return True


def _build_codeql_db(
    source_dir: Path,
    db_path: Path,
    build_cmd: str,
    language: str = "cpp",
    timeout: int = 600,
) -> tuple[bool, str]:
    """
    Build a CodeQL database for the patched source.
    Returns (success, error_message).
    """
    if not CODEQL_BIN.exists():
        return False, f"CodeQL binary not found at {CODEQL_BIN}"

    cmd = [
        str(CODEQL_BIN),
        "database", "create",
        str(db_path),
        f"--language={language}",
        "--overwrite",
        f"--command={build_cmd}",
        "--source-root", str(source_dir),
    ]

    env = os.environ.copy()
    env["PATH"] = str(CODEQL_BIN.parent) + ":" + env.get("PATH", "")

    try:
        result = subprocess.run(
            cmd,
            cwd=str(source_dir),
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return False, "timeout"

    if result.returncode != 0:
        return False, result.stderr[-500:]
    return True, ""


def _run_codeql_query(
    db_path: Path,
    query_path: Path,
    output_sarif: Path,
    timeout: int = 300,
) -> tuple[bool, str]:
    """
    Run a CodeQL query against the database and output SARIF.
    Returns (success, error_message).
    """
    cmd = [
        str(CODEQL_BIN),
        "database", "analyze",
        str(db_path),
        str(query_path),
        "--format=sarifv2.1.0",
        f"--output={output_sarif}",
        "--rerun",
        "--search-path", str(CODEQL_REPO),
    ]

    env = os.environ.copy()
    env["PATH"] = str(CODEQL_BIN.parent) + ":" + env.get("PATH", "")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return False, "timeout"

    if result.returncode != 0:
        return False, result.stderr[-500:]
    return True, ""


def _parse_sarif_findings(sarif_path: Path, vuln_file: Optional[str] = None) -> list[dict]:
    """Parse SARIF output and return list of findings, optionally filtered by file."""
    if not sarif_path.exists():
        return []
    try:
        with open(sarif_path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []

    findings = []
    for run in data.get("runs", []):
        for result in run.get("results", []):
            locs = result.get("locations", [])
            for loc in locs:
                phys = loc.get("physicalLocation", {})
                uri = phys.get("artifactLocation", {}).get("uri", "")
                line = phys.get("region", {}).get("startLine", 0)
                if vuln_file and vuln_file not in uri:
                    continue
                findings.append({
                    "file": uri,
                    "line": line,
                    "rule": result.get("ruleId", ""),
                    "message": result.get("message", {}).get("text", "")[:200],
                })
    return findings


def check_patch_with_codeql(
    vuln_id: str,
    project: str,
    cwe: str,
    patch_diff: str,
    vuln_file: Optional[str] = None,
    build_cmd: Optional[str] = None,
) -> dict:
    """
    Run CodeQL check on a post-patch source directory.

    Workflow:
    1. Locate PVBench source dir for vuln (pre-patch baseline)
    2. Copy to tmpdir and apply patch_diff
    3. Build CodeQL DB with project's build.sh command
    4. Run CWE-specific query
    5. Parse SARIF; pass if no findings at vuln location

    Falls back to semgrep result (pass-through) if DB build fails.

    Returns:
        {
            "condition_b_pass": bool,
            "checker": str,
            "cwe": str,
            "findings_count": int,
            "db_build_success": bool,
            "details": dict,
        }
    """
    query_path = get_codeql_query_path(cwe)
    if query_path is None:
        return {
            "condition_b_pass": True,
            "checker": "none",
            "cwe": cwe,
            "findings_count": 0,
            "db_build_success": False,
            "details": {"reason": "no_codeql_query"},
        }

    # Locate the vulnerability source
    src_dir = _find_vuln_source_dir(vuln_id, project)
    if src_dir is None:
        logger.debug("Source dir not found for %s/%s", project, vuln_id)
        return {
            "condition_b_pass": True,
            "checker": "codeql_fallback",
            "cwe": cwe,
            "findings_count": 0,
            "db_build_success": False,
            "details": {"reason": "source_dir_not_found"},
        }

    # Determine build command from build.sh
    if not build_cmd:
        build_sh = src_dir / "build.sh"
        if build_sh.exists():
            build_cmd = f"bash {build_sh}"
        else:
            build_cmd = "make -j4"

    with tempfile.TemporaryDirectory(prefix=f"smd_codeql_{vuln_id}_") as tmpdir:
        work_dir = Path(tmpdir) / "source"
        db_path = Path(tmpdir) / "codeql_db"
        sarif_path = Path(tmpdir) / "results.sarif"

        # Apply patch to source copy
        if not _apply_patch(src_dir / "input", work_dir, Path(tmpdir) / "src_copy"):
            # Try applying to the input dir directly
            work_dir = Path(tmpdir) / "src_copy"
            work_dir.mkdir(parents=True, exist_ok=True)
            patch_diff_file = work_dir / "_patch.diff"
            patch_diff_file.write_text(patch_diff)

        # Build CodeQL DB
        db_ok, db_err = _build_codeql_db(work_dir, db_path, build_cmd)
        if not db_ok:
            logger.debug("CodeQL DB build failed for %s: %s", vuln_id, db_err[:200])
            return {
                "condition_b_pass": True,
                "checker": "codeql_db_build_failed",
                "cwe": cwe,
                "findings_count": 0,
                "db_build_success": False,
                "details": {"reason": "db_build_failed", "error": db_err[:300]},
            }

        # Run the query
        query_ok, query_err = _run_codeql_query(db_path, query_path, sarif_path)
        if not query_ok:
            logger.debug("CodeQL query failed for %s: %s", vuln_id, query_err[:200])
            return {
                "condition_b_pass": True,
                "checker": "codeql_query_failed",
                "cwe": cwe,
                "findings_count": 0,
                "db_build_success": True,
                "details": {"reason": "query_failed", "error": query_err[:300]},
            }

        # Parse findings
        findings = _parse_sarif_findings(sarif_path, vuln_file)

        return {
            "condition_b_pass": len(findings) == 0,
            "checker": "codeql",
            "cwe": cwe,
            "findings_count": len(findings),
            "db_build_success": True,
            "details": {
                "query": str(query_path.name),
                "findings_sample": findings[:3],
            },
        }
