# VCG extraction using diff-context analysis for C/C++ vulnerabilities.
# Identifies the vulnerability sink block from the reference patch.diff using
# CWE-specific heuristics on the unified diff context (no compilation needed).
# Primary output: sink block identifier stored in pvbench_vcg.json.

import json
import logging
import re
import sys
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# CWE-specific sink patterns (pre-registered in signature_spec.yaml)
# ─────────────────────────────────────────────────────────────────────────────
CWE_SINK_PATTERNS = {
    "CWE-476": re.compile(r"(?:->|\*\s*\w+|\w+\s*\[)"),
    "CWE-416": re.compile(r"(?:free\s*\(|->|\*\s*\w+)"),
    "CWE-122": re.compile(r"(?:memcpy|memmove|strcpy|strcat|sprintf|\w+\s*\[)"),
    "CWE-121": re.compile(r"(?:memcpy|memmove|strcpy|strcat|sprintf|\w+\s*\[)"),
    "CWE-617": re.compile(r"(?:\bassert\s*\(|\bxmlAssert\s*\(|\bASSERT\s*\()"),
    "CWE-190": re.compile(r"(?:\w+\s*\+\s*\w+|\w+\s*\*\s*\w+|\w+\s*<<\s*\w+)"),
    "CWE-415": re.compile(r"\bfree\s*\("),
    "CWE-369": re.compile(r"(?:/\s*\w+|\bfmod\s*\()"),
    "CWE-457": re.compile(r"\w+\s*[=;]"),
}

# Early-exit patterns (for context — also used by S1)
EARLY_EXIT_RE = re.compile(
    r"(?:\breturn\b|\bthrow\b|(?:std::)?abort\s*\(\s*\)|"
    r"_?exit\s*\(|"
    r"goto\s+\w*(err|fail|error|bail|cleanup|out)\w*|"
    r"xmlHaltParser\s*\()"
)


def parse_unified_diff(diff_text: str) -> list[dict]:
    """
    Parse a unified diff into a list of hunk records.

    Each record:
      {
        "file_old": str, "file_new": str,
        "func_name": str | None,
        "old_start": int, "old_count": int,
        "new_start": int, "new_count": int,
        "lines": [{"type": "+"/"-"/" ", "content": str, "old_lineno": int|None, "new_lineno": int|None}]
      }
    """
    hunks = []
    current_file_old = None
    current_file_new = None
    current_hunk = None
    old_lineno = 0
    new_lineno = 0

    hunk_header_re = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)")
    file_old_re = re.compile(r"^--- (.+)")
    file_new_re = re.compile(r"^\+\+\+ (.+)")

    for raw_line in diff_text.splitlines():
        m_old = file_old_re.match(raw_line)
        if m_old:
            current_file_old = m_old.group(1).strip()
            if current_file_old.startswith("a/"):
                current_file_old = current_file_old[2:]
            continue

        m_new = file_new_re.match(raw_line)
        if m_new:
            current_file_new = m_new.group(1).strip()
            if current_file_new.startswith("b/"):
                current_file_new = current_file_new[2:]
            continue

        m_hunk = hunk_header_re.match(raw_line)
        if m_hunk:
            if current_hunk is not None:
                hunks.append(current_hunk)
            old_start = int(m_hunk.group(1))
            old_count = int(m_hunk.group(2)) if m_hunk.group(2) else 1
            new_start = int(m_hunk.group(3))
            new_count = int(m_hunk.group(4)) if m_hunk.group(4) else 1
            func_ctx = m_hunk.group(5).strip()
            func_name = None
            m_func = re.search(r"(\w+)\s*\(", func_ctx)
            if m_func:
                func_name = m_func.group(1)
            current_hunk = {
                "file_old": current_file_old,
                "file_new": current_file_new,
                "func_name": func_name,
                "old_start": old_start,
                "old_count": old_count,
                "new_start": new_start,
                "new_count": new_count,
                "lines": [],
            }
            old_lineno = old_start
            new_lineno = new_start
            continue

        if current_hunk is None:
            continue

        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            current_hunk["lines"].append({
                "type": "+", "content": raw_line[1:],
                "old_lineno": None, "new_lineno": new_lineno,
            })
            new_lineno += 1
        elif raw_line.startswith("-") and not raw_line.startswith("---"):
            current_hunk["lines"].append({
                "type": "-", "content": raw_line[1:],
                "old_lineno": old_lineno, "new_lineno": None,
            })
            old_lineno += 1
        else:
            content = raw_line[1:] if raw_line.startswith(" ") else raw_line
            current_hunk["lines"].append({
                "type": " ", "content": content,
                "old_lineno": old_lineno, "new_lineno": new_lineno,
            })
            old_lineno += 1
            new_lineno += 1

    if current_hunk is not None:
        hunks.append(current_hunk)

    return hunks


def _find_sink_in_pre_patch_context(hunk: dict, cwe: str) -> Optional[dict]:
    """
    Given a diff hunk, identify the sink line in the pre-patch code.

    Strategy:
    1. Try CWE-specific regex on context lines + deletion lines (pre-patch visible code).
    2. Prefer lines that are adjacent to (just before) the first '+' line (the fix site).
    3. Fall back to the last context line before the first '+' line.

    Returns dict with sink_line (pre-patch lineno), sink_content, sink_pattern, method.
    """
    pattern = CWE_SINK_PATTERNS.get(cwe)
    pre_patch_lines = [
        l for l in hunk["lines"] if l["type"] in ("-", " ")
    ]
    added_lines = [l for l in hunk["lines"] if l["type"] == "+"]

    if not pre_patch_lines:
        return None

    first_add_old_lineno = None
    if added_lines:
        idx_first_add = hunk["lines"].index(added_lines[0])
        preceding_context = [
            l for l in hunk["lines"][:idx_first_add] if l["type"] in ("-", " ")
        ]
        if preceding_context:
            first_add_old_lineno = preceding_context[-1]["old_lineno"]

    candidate = None
    candidate_method = "fallback"

    if pattern:
        # Search pre-patch lines around the fix site
        search_window = pre_patch_lines
        for line in reversed(search_window):
            if line["old_lineno"] is None:
                continue
            if pattern.search(line["content"]):
                # Prefer lines at or near the fix site
                candidate = line
                candidate_method = f"cwe_pattern:{cwe}"
                break

    if candidate is None and pre_patch_lines:
        # Fallback: use the pre-patch line closest to the first '+' line
        if first_add_old_lineno is not None:
            dists = [
                (abs((l["old_lineno"] or 0) - first_add_old_lineno), l)
                for l in pre_patch_lines if l["old_lineno"] is not None
            ]
            if dists:
                dists.sort(key=lambda x: x[0])
                candidate = dists[0][1]
                candidate_method = "fallback_proximity"

    if candidate is None and pre_patch_lines:
        for l in reversed(pre_patch_lines):
            if l["old_lineno"] is not None:
                candidate = l
                candidate_method = "fallback_last_context"
                break

    if candidate is None:
        return None

    return {
        "sink_line_pre": candidate["old_lineno"],
        "sink_content": candidate["content"].strip(),
        "sink_pattern": cwe,
        "vcg_method": candidate_method,
        "hunk_func": hunk.get("func_name"),
        "hunk_file": hunk.get("file_old"),
    }


def extract_sink_from_diff(
    vuln_id: str,
    cwe: str,
    ref_patch_diff: str,
    vuln_dir: Optional[Path] = None,
) -> dict:
    """
    Extract the vulnerability sink block from the reference patch.diff.

    Returns:
    {
      "vuln_id": str,
      "cwe": str,
      "file": str,
      "function": str,
      "sink_line_pre": int,
      "sink_content": str,
      "sink_pattern": str,
      "vcg_method": str,
      "success": bool,
      "error": str (if success=False),
    }
    """
    result = {
        "vuln_id": vuln_id,
        "cwe": cwe,
        "file": None,
        "function": None,
        "sink_line_pre": None,
        "sink_content": None,
        "sink_pattern": None,
        "vcg_method": None,
        "success": False,
        "error": None,
    }

    if not ref_patch_diff or not ref_patch_diff.strip():
        result["error"] = "empty_diff"
        return result

    try:
        hunks = parse_unified_diff(ref_patch_diff)
    except Exception as e:
        result["error"] = f"parse_error:{e}"
        return result

    if not hunks:
        result["error"] = "no_hunks"
        return result

    # Try each hunk, prefer the one that yields a CWE-pattern match
    best = None
    for hunk in hunks:
        sink_info = _find_sink_in_pre_patch_context(hunk, cwe)
        if sink_info is None:
            continue
        if best is None:
            best = sink_info
        elif "cwe_pattern" in sink_info.get("vcg_method", "") and "cwe_pattern" not in best.get("vcg_method", ""):
            best = sink_info

    if best is None:
        result["error"] = "no_sink_found"
        return result

    result["file"] = best.get("hunk_file") or (hunks[0]["file_old"] if hunks else None)
    result["function"] = best.get("hunk_func")
    result["sink_line_pre"] = best["sink_line_pre"]
    result["sink_content"] = best["sink_content"]
    result["sink_pattern"] = best["sink_pattern"]
    result["vcg_method"] = best["vcg_method"]
    result["success"] = True
    return result


def run_vcg_extraction(vuln_dir: Path, output_path: Path) -> dict:
    """
    Run VCG extraction for all PVBench vulnerabilities found under vuln_dir.

    Args:
        vuln_dir: Path to benchmarks/pvbench/vuln/
        output_path: Path to write pvbench_vcg.json

    Returns: summary dict
    """
    import yaml

    results = []
    success_count = 0
    fail_count = 0

    for project_dir in sorted(vuln_dir.iterdir()):
        if not project_dir.is_dir():
            continue
        for vuln_subdir in sorted(project_dir.iterdir()):
            if not vuln_subdir.is_dir():
                continue
            vuln_id = vuln_subdir.name
            config_path = vuln_subdir / "config.yaml"
            diff_path = vuln_subdir / "patch.diff"

            if not config_path.exists() or not diff_path.exists():
                continue

            try:
                with open(config_path) as f:
                    cfg = yaml.safe_load(f) or {}
                with open(diff_path) as f:
                    diff_text = f.read()
            except Exception as e:
                results.append({
                    "vuln_id": vuln_id, "cwe": None,
                    "success": False, "error": f"io_error:{e}",
                })
                fail_count += 1
                continue

            raw_type = cfg.get("type", "")
            cwe = _normalize_cwe(raw_type)

            r = extract_sink_from_diff(
                vuln_id=vuln_id,
                cwe=cwe,
                ref_patch_diff=diff_text,
                vuln_dir=vuln_subdir,
            )
            r["project"] = project_dir.name
            r["raw_type"] = raw_type
            results.append(r)

            if r["success"]:
                success_count += 1
            else:
                fail_count += 1

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)

    logger.info(
        "VCG extraction: %d success, %d fail, total %d",
        success_count, fail_count, len(results),
    )
    return {
        "total": len(results),
        "success": success_count,
        "fail": fail_count,
        "success_rate": round(success_count / max(len(results), 1), 4),
    }


def _normalize_cwe(raw_type: str) -> str:
    """Map PVBench 'type' string to a canonical CWE tag."""
    mapping = {
        "heap buffer overflow": "CWE-122",
        "stack buffer overflow": "CWE-121",
        "null pointer dereference": "CWE-476",
        "use after free": "CWE-416",
        "double free": "CWE-415",
        "reachable assertion": "CWE-617",
        "integer overflow": "CWE-190",
        "divide by zero": "CWE-369",
        "uninitialized variable": "CWE-457",
        "race condition": "CWE-362",
        "incorrect type conversion": "CWE-704",
        "type conversion": "CWE-704",
        "always-incorrect control flow": "CWE-670",
    }
    lower = raw_type.lower().strip()
    for key, cwe in mapping.items():
        if key in lower:
            return cwe
    # Try direct CWE-NNN pattern
    m = re.search(r"CWE-\d+", raw_type)
    if m:
        return m.group(0)
    return "CWE-UNKNOWN"


def load_vcg_results(vcg_json_path: Path) -> dict:
    """Load VCG results as a dict keyed by vuln_id."""
    with open(vcg_json_path) as f:
        data = json.load(f)
    return {r["vuln_id"]: r for r in data}


if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    parser = argparse.ArgumentParser(description="Run VCG extraction on all PVBench vulnerabilities")
    parser.add_argument("--vuln-dir", default="benchmarks/pvbench/vuln")
    parser.add_argument("--output", default="smd/results/pvbench_vcg.json")
    args = parser.parse_args()

    ROOT = Path(__file__).resolve().parents[2]
    summary = run_vcg_extraction(
        vuln_dir=ROOT / args.vuln_dir,
        output_path=ROOT / args.output,
    )
    print(json.dumps(summary, indent=2))
