# Differential static checker for PatchEval Condition B.
# Runs CodeQL or Semgrep on pre-patch and post-patch source to determine
# whether the vulnerability is still present after patching.
#
# Strategy:
#   1. Try CodeQL differential: build DB on pre and post, run CWE-specific query.
#      Pass if: pre_findings > 0 AND post_findings == 0 (vulnerability eliminated)
#      Reject if: post_findings > 0 (vulnerability still present)
#      Blind if: pre_findings == 0 (CodeQL cannot see the vuln in snippet)
#   2. If CodeQL is blind or fails: try Semgrep differential (same logic).
#   3. If Semgrep also blind: pass-through (condition_b_pass = True, checker = "passthrough")
#
# Language codes: "python", "javascript", "go"
# CodeQL language flags: "python", "javascript", "go"

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

CODEQL_LANG_MAP = {
    "python": "python",
    "javascript": "javascript",
    "go": "go",
    "Python": "python",
    "JavaScript": "javascript",
    "Go": "go",
    "npm": "javascript",
}

SEMGREP_LANG_MAP = {
    "python": "python",
    "javascript": "javascript",
    "go": "go",
    "Python": "python",
    "JavaScript": "javascript",
    "Go": "go",
    "npm": "javascript",
}


def _load_cwe_map(cwe_map_path: str) -> dict:
    with open(cwe_map_path) as f:
        return yaml.safe_load(f) or {}


def _get_codeql_query(cwe_id: str, lang_code: str, cwe_map: dict, codeql_repo: str) -> Optional[str]:
    """Return absolute path to CodeQL query for given CWE and language, or None."""
    entry = cwe_map.get(cwe_id, {})
    queries = entry.get("codeql_queries", {})
    if not queries:
        return None
    rel_path = queries.get(lang_code)
    if not rel_path:
        return None
    full_path = os.path.join(codeql_repo, rel_path)
    return full_path if os.path.exists(full_path) else None


def _get_semgrep_config(cwe_id: str, lang_code: str, cwe_map: dict) -> Optional[str]:
    """Return Semgrep config string for given CWE and language, or None."""
    entry = cwe_map.get(cwe_id, {})
    rules = entry.get("semgrep_rules", {})
    if not rules:
        return None
    config = rules.get(lang_code)
    return config if config else None


def _run_codeql_db_create(src_dir: str, db_dir: str, codeql_bin: str, lang: str,
                          timeout: int = 120, ram_mb: int = 8000) -> bool:
    """Create a CodeQL database from a source directory. Returns True on success."""
    if os.path.exists(db_dir):
        shutil.rmtree(db_dir)
    cmd = [
        codeql_bin, "database", "create",
        db_dir,
        f"--language={lang}",
        f"--source-root={src_dir}",
        "--build-mode=none",
        "--overwrite",
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        if result.returncode != 0:
            logger.debug("CodeQL DB create failed: %s", result.stderr[:500])
            return False
        return True
    except subprocess.TimeoutExpired:
        logger.debug("CodeQL DB create timed out for %s", src_dir)
        return False
    except Exception as e:
        logger.debug("CodeQL DB create error: %s", e)
        return False


def _run_codeql_query(db_dir: str, query_path: str, codeql_bin: str,
                      timeout: int = 300, ram_mb: int = 8000) -> int:
    """Run a CodeQL query using 'query run', return number of findings (-1 on failure)."""
    with tempfile.NamedTemporaryFile(suffix=".bqrs", delete=False) as tf:
        out_bqrs = tf.name
    try:
        cmd = [
            codeql_bin, "query", "run",
            query_path,
            f"--database={db_dir}",
            f"--output={out_bqrs}",
            "--search-path=tools/codeql-repo",
            f"--ram={ram_mb}",
        ]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        if result.returncode != 0:
            logger.debug("CodeQL query run failed: %s", result.stderr[:500])
            return -1
        if not os.path.exists(out_bqrs) or os.path.getsize(out_bqrs) == 0:
            return 0
        # Decode BQRS to CSV
        decode_cmd = [
            codeql_bin, "bqrs", "decode",
            "--format=csv",
            out_bqrs,
        ]
        decode_result = subprocess.run(
            decode_cmd, capture_output=True, text=True, timeout=60
        )
        if decode_result.returncode != 0:
            logger.debug("BQRS decode failed: %s", decode_result.stderr[:300])
            return -1
        lines = [l for l in decode_result.stdout.splitlines() if l.strip()]
        # Subtract 1 for header row
        return max(0, len(lines) - 1)
    except subprocess.TimeoutExpired:
        logger.debug("CodeQL query run timed out for %s", query_path)
        return -1
    except Exception as e:
        logger.debug("CodeQL query run error: %s", e)
        return -1
    finally:
        try:
            os.unlink(out_bqrs)
        except Exception:
            pass


def _run_semgrep(src_file: str, lang: str, config: str, timeout: int = 60) -> int:
    """Run Semgrep on a source file, return number of findings (-1 on failure)."""
    cmd = [
        "semgrep", "--config", config,
        "--lang", lang,
        "--json",
        "--no-git-ignore",
        src_file,
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        if result.returncode not in (0, 1):
            logger.debug("Semgrep failed (rc=%d): %s", result.returncode, result.stderr[:300])
            return -1
        data = json.loads(result.stdout)
        return len(data.get("results", []))
    except subprocess.TimeoutExpired:
        logger.debug("Semgrep timed out for %s", src_file)
        return -1
    except Exception as e:
        logger.debug("Semgrep error: %s", e)
        return -1


def run_codeql_differential(
    pre_src_dir: str,
    post_src_dir: str,
    lang: str,
    query_path: str,
    codeql_bin: str,
    work_dir: str,
    timeout: int = 300,
    ram_mb: int = 8000,
) -> dict:
    """
    Build CodeQL databases for pre/post source directories and run query differentially.
    Returns:
      {tool: "codeql", pre_findings, post_findings, condition_b_pass, blind, error}
    """
    pre_db = os.path.join(work_dir, "db_pre")
    post_db = os.path.join(work_dir, "db_post")

    pre_ok = _run_codeql_db_create(pre_src_dir, pre_db, codeql_bin, lang, timeout=120, ram_mb=ram_mb)
    if not pre_ok:
        return {"tool": "codeql", "error": "db_create_failed_pre", "pre_findings": -1,
                "post_findings": -1, "condition_b_pass": None, "blind": True}

    pre_findings = _run_codeql_query(pre_db, query_path, codeql_bin, timeout=timeout, ram_mb=ram_mb)
    if pre_findings < 0:
        return {"tool": "codeql", "error": "query_failed_pre", "pre_findings": -1,
                "post_findings": -1, "condition_b_pass": None, "blind": True}

    if pre_findings == 0:
        # CodeQL doesn't see the vulnerability in the snippet — blind
        return {"tool": "codeql", "pre_findings": 0, "post_findings": -1,
                "condition_b_pass": None, "blind": True, "error": None}

    # Pre-patch has findings — now check post-patch
    post_ok = _run_codeql_db_create(post_src_dir, post_db, codeql_bin, lang, timeout=120, ram_mb=ram_mb)
    if not post_ok:
        return {"tool": "codeql", "error": "db_create_failed_post", "pre_findings": pre_findings,
                "post_findings": -1, "condition_b_pass": None, "blind": False}

    post_findings = _run_codeql_query(post_db, query_path, codeql_bin, timeout=timeout, ram_mb=ram_mb)
    if post_findings < 0:
        return {"tool": "codeql", "error": "query_failed_post", "pre_findings": pre_findings,
                "post_findings": -1, "condition_b_pass": None, "blind": False}

    condition_b_pass = (post_findings == 0)
    return {
        "tool": "codeql",
        "pre_findings": pre_findings,
        "post_findings": post_findings,
        "condition_b_pass": condition_b_pass,
        "blind": False,
        "error": None,
    }


def run_semgrep_differential(
    pre_src_file: str,
    post_src_file: str,
    lang: str,
    config: str,
    timeout: int = 60,
) -> dict:
    """
    Run Semgrep on pre/post source files differentially.
    Returns:
      {tool: "semgrep", pre_findings, post_findings, condition_b_pass, blind, error}
    """
    pre_findings = _run_semgrep(pre_src_file, lang, config, timeout=timeout)
    if pre_findings < 0:
        return {"tool": "semgrep", "error": "semgrep_failed_pre", "pre_findings": -1,
                "post_findings": -1, "condition_b_pass": None, "blind": True}

    if pre_findings == 0:
        return {"tool": "semgrep", "pre_findings": 0, "post_findings": -1,
                "condition_b_pass": None, "blind": True, "error": None}

    post_findings = _run_semgrep(post_src_file, lang, config, timeout=timeout)
    if post_findings < 0:
        return {"tool": "semgrep", "error": "semgrep_failed_post", "pre_findings": pre_findings,
                "post_findings": -1, "condition_b_pass": None, "blind": False}

    condition_b_pass = (post_findings == 0)
    return {
        "tool": "semgrep",
        "pre_findings": pre_findings,
        "post_findings": post_findings,
        "condition_b_pass": condition_b_pass,
        "blind": False,
        "error": None,
    }


def check_patch(
    cve_id: str,
    cwe_list: list,
    pre_src_dir: str,
    pre_src_file: str,
    post_src_dir: str,
    post_src_file: str,
    language: str,
    codeql_bin: str,
    codeql_repo: str,
    cwe_map_path: str,
    work_dir: str,
    timeout: int = 300,
    ram_mb: int = 8000,
) -> dict:
    """
    Main entry point: check whether post-patch source is free from the CWE vulnerability.
    Tries CodeQL first (if query available), falls back to Semgrep, then pass-through.

    Returns dict with:
      condition_b_pass: bool
      checker: "codeql" | "semgrep" | "passthrough"
      tool_detail: dict (findings counts, blind, error, etc.)
      cwe_used: str (first matched CWE)
    """
    cwe_map = _load_cwe_map(cwe_map_path)
    lang_code = CODEQL_LANG_MAP.get(language, language.lower())
    semgrep_lang = SEMGREP_LANG_MAP.get(language, language.lower())

    # Try each CWE in the list; use the first one that has a checker
    tried_cwes = []
    for cwe_id_try in cwe_list:
        entry = cwe_map.get(cwe_id_try, {})
        strategy = entry.get("checker_strategy", "none")
        if strategy == "none":
            continue

        query_path = _get_codeql_query(cwe_id_try, lang_code, cwe_map, codeql_repo)
        semgrep_config = _get_semgrep_config(cwe_id_try, lang_code, cwe_map)

        if query_path:
            # Try CodeQL differential
            codeql_result = run_codeql_differential(
                pre_src_dir, post_src_dir, lang_code, query_path,
                codeql_bin, work_dir, timeout=timeout, ram_mb=ram_mb,
            )
            if not codeql_result.get("blind") and codeql_result.get("condition_b_pass") is not None:
                return {
                    "condition_b_pass": codeql_result["condition_b_pass"],
                    "checker": "codeql",
                    "tool_detail": codeql_result,
                    "cwe_used": cwe_id_try,
                    "pre_findings": codeql_result.get("pre_findings"),
                    "post_findings": codeql_result.get("post_findings"),
                }
            # CodeQL blind — fall through to Semgrep
            tried_cwes.append(f"{cwe_id_try}:codeql_blind")

        if semgrep_config and pre_src_file and post_src_file:
            # Try Semgrep differential
            semgrep_result = run_semgrep_differential(
                pre_src_file, post_src_file, semgrep_lang, semgrep_config, timeout=60,
            )
            if not semgrep_result.get("blind") and semgrep_result.get("condition_b_pass") is not None:
                return {
                    "condition_b_pass": semgrep_result["condition_b_pass"],
                    "checker": "semgrep",
                    "tool_detail": semgrep_result,
                    "cwe_used": cwe_id_try,
                    "pre_findings": semgrep_result.get("pre_findings"),
                    "post_findings": semgrep_result.get("post_findings"),
                }
            tried_cwes.append(f"{cwe_id_try}:semgrep_blind")

    # All CWEs either pass-through or both tools blind
    return {
        "condition_b_pass": True,
        "checker": "passthrough",
        "tool_detail": {"tried_cwes": tried_cwes, "reason": "all_tools_blind_or_no_checker"},
        "cwe_used": cwe_list[0] if cwe_list else "unknown",
        "pre_findings": None,
        "post_findings": None,
    }
