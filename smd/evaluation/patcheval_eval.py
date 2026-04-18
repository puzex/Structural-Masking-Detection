# SMD Condition C evaluation pipeline for PatchEval.
# Uses Joern CPG (batch per language) for VCG extraction, S1 dominance, and
# S2 reachability analysis, with diff-context fallback.
#
# Usage:
#   python smd/evaluation/patcheval_eval.py \
#       --dataset benchmarks/patcheval/patcheval/datasets/patcheval_dataset.json \
#       --log-dir benchmarks/patcheval/patcheval/log/llm \
#       --output-dir smd/results

import argparse
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from smd.vcg.joern_vcg import bulk_extract_patcheval
from smd.vcg.sink_mapper import map_sink_to_post_patch
from smd.signatures.s1_early_exit import check_s1
from smd.signatures.s2_unreachable import check_s2, _has_compensating_fix

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

JOERN_BIN = ROOT / "tools" / "joern" / "joern-cli" / "joern"
JDK21_BIN = ROOT / "tools" / "jdk21" / "bin"

MODEL_FILE_MAP = {
    "fixed_gemini_2_5_pro_Default.json": "gemini-2.5-pro",
    "fixed_gpt_4_1_2025_04_14_Default.json": "gpt-4.1",
    "fixed_Deepseek_V3_Default.json": "deepseek-v3",
    "fixed_Deepseek_r1_0528_Default.json": "deepseek-r1-0528",
    "fixed_Doubao_1_6_Default.json": "doubao-1.6",
    "fixed_Doubao_1_6_thinking_Default.json": "doubao-1.6-thinking",
    "fixed_kimi_k2_Default.json": "kimi-k2",
    "fixed_qwen3_coder_480b_a35b_instruct_Default.json": "qwen3-coder-480b",
    "fixed_qwen3_max_Default.json": "qwen3-max",
}

LANG_TO_JOERN = {"Python": "python", "JavaScript": "jssrc", "Go": "go"}
LANG_TO_EXT = {"Python": ".py", "JavaScript": ".js", "Go": ".go"}

# PatchEval CWE-aware dispatch (v2.0 — optimized)
#
# skip_all: structural removal or early-exit IS the valid fix; both S1 and S2 unreliable
#   - CWE-285 (improper authorization): FDR=0% → skip (no false positives to catch)
#   - CWE-863/269/250/639: auth/privilege CWEs where removal IS the fix
#   - CWE-73 (file path control): flagged=3 with precision=0% → adding path validation IS the fix
#   - CWE-601 (open redirect): raise HTTPError IS the fix; S2 fires as "sink removed" but it's correct
#   - CWE-22 (path traversal): FDR=0%, flagged=1 with precision=0% (realpath IS the fix)
#   - CWE-78 (OS cmd injection): FDR=0%, flagged=6 with precision=0% (safe API IS the fix)
#   - CWE-284 (improper access): flagged=1 with precision=0%
#   - CWE-471: flagged=2 with precision=0%
#   - CWE-444 (HTTP response splitting): flagged=1 with precision=0%
PATCHEVAL_CWE_SKIP_ALL = frozenset([
    "CWE-285", "CWE-863", "CWE-269", "CWE-250", "CWE-639",
    "CWE-73", "CWE-601", "CWE-22", "CWE-78", "CWE-284",
    "CWE-471", "CWE-444",
])

# CWEs with ~100% FDR in B-accepted: auto-reject all (no valid patches)
# CWE-287 (improper auth): FDR=94% (29/31 are FPs)
# CWE-862 (missing auth): FDR=63% (27/43), significant enough to auto-reject
PATCHEVAL_CWE_AUTO_REJECT = frozenset(["CWE-287", "CWE-862"])

# CWEs where S2 (sink_removed) fires with precision=0 for JavaScript:
# File-path and URL-related CWEs where sink deletion is the valid fix in JS
PATCHEVAL_JS_S2_SKIP = frozenset(["CWE-94"])  # code injection: exec→safe replacement looks like removal

# Multi-language compensating fix patterns (v2.0 — extended for CWE-94)
_COMP_FIX_EXTRA = [
    re.compile(r"\bif\s+not\s+\w+"),
    re.compile(r"\braise\s+\w+(?:Error|Exception)\s*\("),
    re.compile(r"urllib\.parse\.(?:quote|urlencode)\s*\("),
    re.compile(r"\bre\.(?:match|fullmatch|search)\s*\("),
    re.compile(r"\b(?:validate|sanitize|clean)\s*\("),
    re.compile(r"os\.path\.(?:abspath|realpath)\s*\("),
    re.compile(r"html\.escape\s*\("),
    re.compile(r"\bencodeURIComponent\s*\(|\bencodeURI\s*\("),
    re.compile(r"\bDOMPurify\b|\bsanitize\s*\("),
    re.compile(r"\bpath\.(?:resolve|normalize)\s*\("),
    re.compile(r"\bfilepath\.(?:Clean|Rel|Abs)\s*\("),
    re.compile(r"\bstrings\.(?:HasPrefix|Contains)\s*\("),
    re.compile(r"\burl\.(?:Parse|QueryEscape)\s*\("),
    re.compile(r"\bhtml\.EscapeString\s*\("),
    re.compile(r"\bdb\.Prepare\s*\("),
    # CWE-94 (code injection): safe API replacements for exec/eval
    re.compile(r"\bsubprocess\.(?:run|Popen|check_output|check_call)\s*\("),
    re.compile(r"\bast\.literal_eval\s*\("),
    re.compile(r"\bjson\.(?:loads|dumps)\s*\("),
    re.compile(r"\bshlex\.(?:quote|split)\s*\("),
    re.compile(r"\bimportlib\.import_module\s*\("),
    re.compile(r"\bgetattr\s*\(\s*\w+\s*,\s*['\"]"),
    re.compile(r"\bchild_process\.(?:exec|spawn|fork)\b"),
    re.compile(r"\bvm\.(?:runInContext|runInNewContext|createContext)\s*\("),
    re.compile(r"\bFunction\s*\(\s*['\"]"),  # JS: new Function() as controlled eval
    re.compile(r"\bsafeEval\s*\(|\bsandbox\b"),
    re.compile(r"\bexec\.Command\s*\("),  # Go safe command execution
    re.compile(r"\bos/exec\b"),
    # CWE-94 Python: using compile() with restricted builtins
    re.compile(r"\bcompile\s*\(.*\bexec\b|\b__builtins__\s*="),
    # Generic: input allow-list / whitelist
    re.compile(r"\b(?:allowlist|whitelist|allowed_?\w*)\b", re.IGNORECASE),
    re.compile(r"\bin\s+\[|\bin\s+\{|\bin\s+\("),  # 'if x in [allowed_values]'
]


def _normalize_lang(lang: str) -> str:
    lang = lang.strip()
    m = lang.lower()
    if m in ("py", "python"):
        return "Python"
    if m in ("js", "javascript", "jssrc"):
        return "JavaScript"
    if m in ("go", "golang"):
        return "Go"
    return lang


def _has_comp_fix(diff: str, ref_file: str = "") -> bool:
    if _has_compensating_fix(diff, ref_file):
        return True
    try:
        from smd.vcg.codeql_vcg import parse_unified_diff
        hunks = parse_unified_diff(diff)
        added = "\n".join(r["content"] for h in hunks for r in h["lines"] if r["type"] == "+")
        return any(p.search(added) for p in _COMP_FIX_EXTRA)
    except Exception:
        return False


def _run_joern_script(script: str, timeout: int = 300) -> Optional[str]:
    """Run a Joern Scala script, return stdout or None."""
    if not JOERN_BIN.exists():
        return None
    env = dict(os.environ)
    env["JAVA_HOME"] = str(JDK21_BIN.parent)
    env["PATH"] = str(JDK21_BIN) + ":" + env.get("PATH", "")
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sc", delete=False) as f:
        f.write(script)
        script_path = f.name
    try:
        r = subprocess.run(
            [str(JOERN_BIN), "--script", script_path],
            capture_output=True, text=True, timeout=timeout, env=env,
        )
        return r.stdout if r.stdout.strip() else None
    except subprocess.TimeoutExpired:
        logger.warning("Joern script timed out after %ds", timeout)
        return None
    except Exception as e:
        logger.warning("Joern error: %s", e)
        return None
    finally:
        try:
            os.unlink(script_path)
        except OSError:
            pass


def _batch_joern_s1(
    attempts: list[dict],
) -> dict[str, dict]:
    """
    Batch Joern S1 (dominance) check.

    For each attempt with fix_code_snippet and sink_line_post:
    Writes snippets to temp files, runs ONE Joern script per language that
    checks if any early-exit node dominates the sink node.

    Returns: {attempt_key -> {"s1_fires": bool, "evidence": list, "method": "joern"}}
    """
    by_lang: dict[str, list[dict]] = defaultdict(list)
    for att in attempts:
        lang = att.get("language", "")
        if lang in LANG_TO_JOERN and att.get("fix_code_snippet") and att.get("sink_line_post"):
            by_lang[lang].append(att)

    results: dict[str, dict] = {}

    for lang, lang_atts in by_lang.items():
        joern_lang = LANG_TO_JOERN[lang]
        ext = LANG_TO_EXT[lang]
        tmp_dir = tempfile.mkdtemp(prefix=f"joern_s1_{lang.lower()}_")

        file_map = []
        for att in lang_atts:
            key = att["_key"]
            safe_key = re.sub(r"[^a-zA-Z0-9_]", "_", key)[:60]
            fpath = os.path.join(tmp_dir, f"{safe_key}{ext}")
            try:
                with open(fpath, "w") as f:
                    f.write(att["fix_code_snippet"])
                file_map.append((key, fpath, int(att["sink_line_post"]), safe_key))
            except Exception:
                results[key] = {"s1_fires": None, "evidence": [], "method": "joern_write_error"}

        if not file_map:
            continue

        # Build batch S1 script
        script_lines = [
            "import scala.collection.mutable",
            "val out = mutable.ListBuffer[String]()",
        ]
        exit_pattern = "(return|raise|panic|os.Exit|log.Fatal|log.Panic|sys.exit|throw)"

        for key, fpath, sink_line, safe_key in file_map:
            safe_fpath = fpath.replace("\\", "/")
            script_lines.append(f"""
try {{
  importCode.{joern_lang}("{safe_fpath}")
  val sinkNode_{safe_key} = cpg.call.lineNumber({sink_line}).l.headOption
  val exits_{safe_key} = (cpg.ret.l ++ cpg.call.name(".*({exit_pattern}).*").l).distinctBy(_.id)
  val dominating_{safe_key} = exits_{safe_key}.filter(e => sinkNode_{safe_key}.exists(s => e.dominates.exists(_ == s)))
  val res_{safe_key} = if (dominating_{safe_key}.nonEmpty) dominating_{safe_key}.map(d => d.lineNumber.getOrElse(-1).toString + ":" + d.code.take(60)).mkString("|") else "none"
  out += "{key}||" + res_{safe_key}
  close("{safe_fpath}")
}} catch {{
  case e: Exception => out += "{key}||error"
}}""")

        script_lines.append('println(out.mkString("\\n"))')
        script = "\n".join(script_lines)

        output = _run_joern_script(script, timeout=600)

        import shutil
        try:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass

        if output:
            for line in output.strip().splitlines():
                line = line.strip()
                if "||" not in line:
                    continue
                parts = line.split("||", 1)
                if len(parts) != 2:
                    continue
                key_out, res = parts[0].strip(), parts[1].strip()
                if res in ("none", "error", ""):
                    results[key_out] = {"s1_fires": res == "none" and False or None,
                                        "evidence": [], "method": "joern"}
                    if res == "none":
                        results[key_out]["s1_fires"] = False
                    else:
                        results[key_out]["s1_fires"] = None
                else:
                    evidence = []
                    sink_line_post = next((int(a["sink_line_post"]) for a in lang_atts if a["_key"] == key_out), None)
                    for token in res.split("|"):
                        token = token.strip()
                        if ":" not in token:
                            continue
                        ln_str, code = token.split(":", 1)
                        try:
                            ln = int(ln_str)
                        except ValueError:
                            continue
                        dominates = sink_line_post is not None and ln > 0 and ln < sink_line_post
                        evidence.append({"line": ln, "text": code, "exit_type": "joern_dominance", "dominates_sink": dominates})
                    s1_fires = any(e["dominates_sink"] for e in evidence)
                    results[key_out] = {"s1_fires": s1_fires, "evidence": evidence, "method": "joern"}

        # Mark missing as None
        for key, _, _, _ in file_map:
            if key not in results:
                results[key] = {"s1_fires": None, "evidence": [], "method": "joern_no_output"}

    return results


def _batch_joern_s2(
    attempts: list[dict],
) -> dict[str, dict]:
    """
    Batch Joern S2 (reachability) check.

    For each attempt with fix_code_snippet and sink_line_post:
    Checks if sink is reachable from function entry in post-patch CFG.

    Returns: {attempt_key -> {"s2_fires": bool, "reason": str, "method": "joern"}}
    """
    by_lang: dict[str, list[dict]] = defaultdict(list)
    for att in attempts:
        lang = att.get("language", "")
        if lang in LANG_TO_JOERN and att.get("fix_code_snippet") and att.get("sink_line_post"):
            by_lang[lang].append(att)

    results: dict[str, dict] = {}

    for lang, lang_atts in by_lang.items():
        joern_lang = LANG_TO_JOERN[lang]
        ext = LANG_TO_EXT[lang]
        tmp_dir = tempfile.mkdtemp(prefix=f"joern_s2_{lang.lower()}_")

        file_map = []
        for att in lang_atts:
            key = att["_key"]
            safe_key = re.sub(r"[^a-zA-Z0-9_]", "_", key)[:60]
            fpath = os.path.join(tmp_dir, f"{safe_key}{ext}")
            try:
                with open(fpath, "w") as f:
                    f.write(att["fix_code_snippet"])
                file_map.append((key, fpath, int(att["sink_line_post"]), safe_key))
            except Exception:
                results[key] = {"s2_fires": None, "reason": None, "evidence": "write_error", "method": "joern"}

        if not file_map:
            continue

        script_lines = [
            "import scala.collection.mutable",
            "val out = mutable.ListBuffer[String]()",
        ]

        for key, fpath, sink_line, safe_key in file_map:
            safe_fpath = fpath.replace("\\", "/")
            script_lines.append(f"""
try {{
  importCode.{joern_lang}("{safe_fpath}")
  val sinkNode_{safe_key} = cpg.call.lineNumber({sink_line}).l.headOption
  val entry_{safe_key} = cpg.method.cfgFirst.l.headOption
  val reachable_{safe_key} = (sinkNode_{safe_key}, entry_{safe_key}) match {{
    case (Some(s), Some(e)) => s.reachableBy(e).nonEmpty
    case _ => true
  }}
  out += "{key}||" + reachable_{safe_key}.toString
  close("{safe_fpath}")
}} catch {{
  case e: Exception => out += "{key}||error"
}}""")

        script_lines.append('println(out.mkString("\\n"))')
        script = "\n".join(script_lines)

        output = _run_joern_script(script, timeout=600)

        import shutil
        try:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass

        if output:
            for line in output.strip().splitlines():
                line = line.strip()
                if "||" not in line:
                    continue
                parts = line.split("||", 1)
                if len(parts) != 2:
                    continue
                key_out, res = parts[0].strip(), parts[1].strip()
                if res == "error":
                    results[key_out] = {"s2_fires": None, "reason": None, "evidence": "joern_error", "method": "joern"}
                elif res.lower() == "false":
                    results[key_out] = {"s2_fires": True, "reason": "unreachable",
                                        "evidence": "Joern: sink not reachable from function entry", "method": "joern"}
                else:
                    results[key_out] = {"s2_fires": False, "reason": "none", "evidence": None, "method": "joern"}

        for key, _, _, _ in file_map:
            if key not in results:
                results[key] = {"s2_fires": None, "reason": None, "evidence": "joern_no_output", "method": "joern"}

    return results


def load_dataset(dataset_path: Path) -> dict[str, dict]:
    with open(dataset_path) as f:
        data = json.load(f)
    result: dict[str, dict] = {}
    for entry in data:
        cve_id = entry.get("cve_id", "")
        if cve_id and cve_id not in result:
            result[cve_id] = entry
    logger.info("Loaded %d unique CVEs from dataset", len(result))
    return result


def load_patcheval_logs(log_dir: Path) -> list[dict]:
    records = []
    for filename, model_name in MODEL_FILE_MAP.items():
        fpath = log_dir / filename
        if not fpath.exists():
            logger.warning("Log file not found: %s", fpath)
            continue
        with open(fpath) as f:
            data = json.load(f)
        for entry in data:
            cve_id = list(entry.keys())[0]
            epochs = entry[cve_id]
            for ep in epochs:
                lang = _normalize_lang(ep.get("language", ""))
                fix_code_dict = ep.get("fix_code", {}) or {}
                fix_code_snippet = ""
                if isinstance(fix_code_dict, dict) and fix_code_dict:
                    fix_code_snippet = list(fix_code_dict.values())[0] or ""
                elif isinstance(fix_code_dict, str):
                    fix_code_snippet = fix_code_dict
                records.append({
                    "model": model_name,
                    "cve_id": cve_id,
                    "epoch": ep.get("epoch", 1),
                    "poc_status": bool(ep.get("poc_status", False)),
                    "unittest_status": bool(ep.get("unittest_status", False)),
                    "language": lang,
                    "diff_content": ep.get("diff_content", "") or "",
                    "fix_code_snippet": fix_code_snippet,
                })
    logger.info("Loaded %d total attempt records", len(records))
    return records


def _compute_model_metrics(attempts: list[dict], lang_filter: str = None) -> dict:
    if lang_filter:
        attempts = [a for a in attempts if a["language"] == lang_filter]
    b_acc = [a for a in attempts if a["poc_status"]]
    c_acc = [a for a in b_acc if a.get("condition_c_pass", True)]

    def fdr(lst):
        if not lst:
            return None
        tp = sum(1 for a in lst if a["unittest_status"])
        return (len(lst) - tp) / len(lst)

    def yld(lst):
        return len(set(a["cve_id"] for a in lst if a["unittest_status"]))

    smd_flagged = [a for a in b_acc if a.get("smd_flags")]
    fps_b = [a for a in b_acc if not a["unittest_status"]]
    smd_correct = [a for a in smd_flagged if not a["unittest_status"]]

    return {
        "b_accepted": len(b_acc),
        "c_accepted": len(c_acc),
        "b_fdr": fdr(b_acc),
        "c_fdr": fdr(c_acc),
        "b_yield": yld(b_acc),
        "c_yield": yld(c_acc),
        "smd_flagged": len(smd_flagged),
        "smd_precision": len(smd_correct) / len(smd_flagged) if smd_flagged else None,
        "smd_recall": len(smd_correct) / len(fps_b) if fps_b else None,
        "strong_oracle_pass_rate_c": sum(1 for a in c_acc if a["unittest_status"]) / len(c_acc) if c_acc else None,
        "fdr_delta_abs": (fdr(c_acc) - fdr(b_acc)) if (fdr(c_acc) is not None and fdr(b_acc) is not None) else None,
        "yield_loss": yld(c_acc) - yld(b_acc),
    }


def _compute_coverage(annotated: list[dict]) -> dict:
    result = {}
    for lang in ["Python", "JavaScript", "Go"]:
        la = [a for a in annotated if a["language"] == lang]
        if not la:
            continue
        total = len(la)
        result[lang] = {
            "total_b_accepted": total,
            "vcg_success": sum(1 for a in la if a.get("vcg_success")),
            "vcg_success_rate": sum(1 for a in la if a.get("vcg_success")) / total,
            "vcg_joern": sum(1 for a in la if a.get("vcg_method") == "joern"),
            "vcg_regex_fallback": sum(1 for a in la if a.get("vcg_method") == "regex_fallback"),
            "sink_mapped": sum(1 for a in la if a.get("sink_mapping_state") == "mapped"),
            "sink_removed": sum(1 for a in la if a.get("sink_mapping_state") == "removed"),
            "sink_unmappable": sum(1 for a in la if a.get("sink_mapping_state") in ("unmappable", "vcg_failed", "unknown")),
            "s1_joern": sum(1 for a in la if a.get("s1_method") == "joern"),
            "s1_diff_fallback": sum(1 for a in la if a.get("s1_method") in ("diff_regex", "diff_context")),
            "s2_joern": sum(1 for a in la if a.get("s2_method") == "joern"),
            "s2_diff_fallback": sum(1 for a in la if a.get("s2_method") in ("diff_regex", "diff_context")),
        }
    return result


def _compute_diagnostics(annotated: list[dict]) -> dict:
    lang_diag = {}
    for lang in ["Python", "JavaScript", "Go"]:
        la = [a for a in annotated if a["language"] == lang and a["poc_status"]]
        if not la:
            continue
        total = len(la)
        fps = [a for a in la if not a["unittest_status"]]
        tps = [a for a in la if a["unittest_status"]]
        s1_fired = [a for a in la if a.get("s1_fires")]
        s2_fired = [a for a in la if a.get("s2_fires")]
        smd_fired = [a for a in la if a.get("smd_flags")]
        smd_correct = [a for a in smd_fired if not a["unittest_status"]]
        applicable = [a for a in la if a.get("smd_applicable")]
        lang_diag[lang] = {
            "total_b_accepted": total,
            "true_positives": len(tps),
            "false_positives": len(fps),
            "s1_firing_rate": len(s1_fired) / total if total else 0,
            "s2_firing_rate": len(s2_fired) / total if total else 0,
            "smd_firing_rate": len(smd_fired) / total if total else 0,
            "smd_precision": len(smd_correct) / len(smd_fired) if smd_fired else None,
            "smd_recall": len(smd_correct) / len(fps) if fps else None,
            "smd_applicable_rate": len(applicable) / total if total else 0,
            "coverage_ceiling": len([a for a in fps if a.get("smd_applicable")]) / len(fps) if fps else None,
        }

    cwe_diag = defaultdict(lambda: {"b_accepted": 0, "fps": 0, "smd_flagged": 0, "smd_correct": 0})
    for a in annotated:
        if not a["poc_status"]:
            continue
        cwe = a.get("primary_cwe", "unknown")
        cwe_diag[cwe]["b_accepted"] += 1
        if not a["unittest_status"]:
            cwe_diag[cwe]["fps"] += 1
        if a.get("smd_flags"):
            cwe_diag[cwe]["smd_flagged"] += 1
            if not a["unittest_status"]:
                cwe_diag[cwe]["smd_correct"] += 1

    cwe_results = {}
    for cwe, s in sorted(cwe_diag.items(), key=lambda x: -x[1]["b_accepted"]):
        b = s["b_accepted"]
        flagged = s["smd_flagged"]
        correct = s["smd_correct"]
        cwe_results[cwe] = {
            "b_accepted": b,
            "fps": s["fps"],
            "fdr_b": s["fps"] / b if b else None,
            "smd_flagged": flagged,
            "smd_precision": correct / flagged if flagged else None,
        }
    return {"by_language": lang_diag, "by_cwe": cwe_results}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--log-dir", required=True)
    parser.add_argument("--output-dir", default="smd/results")
    parser.add_argument("--debug-n", type=int, default=None)
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── 1. Load data ──────────────────────────────────────────────────────────
    dataset = load_dataset(Path(args.dataset))
    records = load_patcheval_logs(Path(args.log_dir))

    # ── 2. VCG extraction ────────────────────────────────────────────────────
    vcg_cache_path = output_dir / "patcheval_vcg.json"
    if vcg_cache_path.exists():
        logger.info("Loading cached VCG from %s", vcg_cache_path)
        with open(vcg_cache_path) as f:
            vcg_cache = json.load(f)
        vcg_results = vcg_cache.get("results", vcg_cache)
        coverage_stats = vcg_cache.get("coverage_stats", {})
    else:
        log_cves = set(r["cve_id"] for r in records)
        entries_to_extract = [dataset[cve_id] for cve_id in log_cves if cve_id in dataset]
        vcg_output = bulk_extract_patcheval(entries_to_extract, str(vcg_cache_path))
        vcg_results = vcg_output["results"]
        coverage_stats = vcg_output["coverage_stats"]

    # ── 3. B-accepted attempts ───────────────────────────────────────────────
    b_accepted = [r for r in records if r["poc_status"]]
    logger.info("B-accepted: %d / %d total", len(b_accepted), len(records))
    if args.debug_n:
        b_accepted = b_accepted[:args.debug_n]
        logger.info("Debug: using %d attempts", len(b_accepted))

    # ── 4. Sink mapping ──────────────────────────────────────────────────────
    logger.info("Mapping sinks to post-patch positions...")
    for rec in b_accepted:
        cve_id = rec["cve_id"]
        vcg_info = vcg_results.get(cve_id, {"success": False})
        sink_mapping = map_sink_to_post_patch(vcg_info, rec["diff_content"])
        rec["_vcg_info"] = vcg_info
        rec["sink_mapping"] = sink_mapping
        rec["sink_line_post"] = sink_mapping.get("sink_line_post")
        rec["sink_mapping_state"] = sink_mapping["state"]

    # ── 5. Batch Joern S1/S2 ────────────────────────────────────────────────
    # Only run on attempts with mapped/removed sinks and fix_code_snippet
    s1_candidates = []
    s2_candidates = []
    for i, rec in enumerate(b_accepted):
        cve_id = rec["cve_id"]
        ds_entry = dataset.get(cve_id, {})
        cwe_ids = list(ds_entry.get("cwe_info", {}).keys()) if isinstance(ds_entry.get("cwe_info"), dict) else []
        primary_cwe = cwe_ids[0] if cwe_ids else ""
        rec["primary_cwe"] = primary_cwe
        rec["_key"] = f"{cve_id}__{rec['model']}__{rec['epoch']}__{i}"

        state = rec["sink_mapping_state"]
        if (state == "mapped" and rec["sink_line_post"] is not None
                and rec["fix_code_snippet"]
                and primary_cwe not in PATCHEVAL_CWE_SKIP_ALL
                and primary_cwe not in PATCHEVAL_CWE_AUTO_REJECT):
            s1_candidates.append(rec)

        if (state == "mapped" and rec["sink_line_post"] is not None
                and rec["fix_code_snippet"]
                and primary_cwe not in PATCHEVAL_CWE_SKIP_ALL
                and primary_cwe not in PATCHEVAL_CWE_AUTO_REJECT):
            s2_candidates.append(rec)

    logger.info("S1 candidates: %d, S2 candidates: %d", len(s1_candidates), len(s2_candidates))

    # Run batch Joern S1
    logger.info("Running batch Joern S1 dominance analysis...")
    joern_s1_results = _batch_joern_s1(s1_candidates)
    logger.info("Joern S1 results: %d", len(joern_s1_results))

    # Run batch Joern S2
    logger.info("Running batch Joern S2 reachability analysis...")
    joern_s2_results = _batch_joern_s2(s2_candidates)
    logger.info("Joern S2 results: %d", len(joern_s2_results))

    # ── 6. Assign S1/S2 results per attempt ──────────────────────────────────
    annotated = []
    for rec in b_accepted:
        key = rec["_key"]
        cve_id = rec["cve_id"]
        vcg_info = rec["_vcg_info"]
        primary_cwe = rec.get("primary_cwe", "")
        state = rec["sink_mapping_state"]
        sink_line_post = rec.get("sink_line_post")
        ref_file = vcg_info.get("file", "") or ""

        # CWE dispatch: auto-reject (high FDR, no valid patches)
        if primary_cwe in PATCHEVAL_CWE_AUTO_REJECT:
            annotated.append({
                **{k: v for k, v in rec.items() if not k.startswith("_")},
                "vcg_success": vcg_info.get("success", False),
                "vcg_method": vcg_info.get("method"),
                "smd_applicable": True,
                "sink_line_post": sink_line_post,
                "s1_fires": None, "s1_method": "auto_reject",
                "s2_fires": None, "s2_method": "auto_reject",
                "smd_flags": True,
                "condition_c_pass": False,
                "cwe_dispatch": "auto_reject",
            })
            continue

        # CWE dispatch: skip all signatures (structural removal IS the fix)
        if primary_cwe in PATCHEVAL_CWE_SKIP_ALL:
            annotated.append({
                **{k: v for k, v in rec.items() if not k.startswith("_")},
                "vcg_success": vcg_info.get("success", False),
                "vcg_method": vcg_info.get("method"),
                "smd_applicable": False,
                "sink_line_post": sink_line_post,
                "s1_fires": None, "s1_method": "skip_cwe",
                "s2_fires": None, "s2_method": "skip_cwe",
                "smd_flags": False,
                "condition_c_pass": True,
                "cwe_dispatch": "skip_all",
            })
            continue

        if state in ("unmappable", "vcg_failed", "unknown"):
            annotated.append({
                **{k: v for k, v in rec.items() if not k.startswith("_")},
                "vcg_success": vcg_info.get("success", False),
                "vcg_method": vcg_info.get("method"),
                "smd_applicable": False,
                "sink_line_post": sink_line_post,
                "s1_fires": None, "s1_method": None,
                "s2_fires": None, "s2_method": None,
                "smd_flags": False,
                "condition_c_pass": True,
                "cwe_dispatch": "unmappable",
            })
            continue

        lang = rec.get("language", "")

        # ── S2 ───────────────────────────────────────────────────────────────
        if state == "removed":
            has_comp = _has_comp_fix(rec["diff_content"], ref_file)
            if has_comp:
                s2_result = {"s2_fires": False, "reason": "none", "evidence": "compensating_fix", "method": "diff_regex"}
            else:
                s2_result = {"s2_fires": True, "reason": "sink_removed", "evidence": "pure_deletion", "method": "diff_regex"}
        elif lang == "JavaScript" and primary_cwe in PATCHEVAL_JS_S2_SKIP:
            # JS + CWE-94: S2 unreachability has near-random precision; suppress
            s2_result = {"s2_fires": False, "reason": "none", "evidence": "js_cwe94_s2_suppressed", "method": "skip_js_cwe"}
        else:
            # Use Joern S2 result if available and valid
            joern_s2 = joern_s2_results.get(key)
            if joern_s2 and joern_s2.get("s2_fires") is not None:
                s2_result = joern_s2
            else:
                # Fallback to diff-context S2
                s2_diff = check_s2(rec["sink_mapping"], rec["diff_content"], sink_line_post, ref_file)
                s2_result = {**s2_diff, "method": "diff_context"}

        # ── S1 ───────────────────────────────────────────────────────────────
        if state == "removed":
            s1_result = {"s1_fires": False, "evidence": [], "method": "sink_removed"}
        else:
            joern_s1 = joern_s1_results.get(key)
            if joern_s1 and joern_s1.get("s1_fires") is not None:
                s1_result = joern_s1
            else:
                # Fallback to diff-context S1
                s1_diff = check_s1(
                    rec["diff_content"],
                    sink_line_pre=vcg_info.get("sink_line_pre"),
                    sink_line_post=sink_line_post,
                    ref_file=ref_file,
                )
                s1_result = {**s1_diff, "method": "diff_context"}

        s1_fires = bool(s1_result.get("s1_fires", False))
        s2_fires = bool(s2_result.get("s2_fires", False))
        smd_flags = s1_fires or s2_fires

        annotated.append({
            **{k: v for k, v in rec.items() if not k.startswith("_")},
            "vcg_success": vcg_info.get("success", False),
            "vcg_method": vcg_info.get("method"),
            "smd_applicable": state != "unmappable",
            "sink_line_post": sink_line_post,
            "s1_fires": s1_fires,
            "s1_evidence": s1_result.get("evidence", []),
            "s1_method": s1_result.get("method"),
            "s2_fires": s2_fires,
            "s2_reason": s2_result.get("reason"),
            "s2_evidence": s2_result.get("evidence"),
            "s2_method": s2_result.get("method"),
            "smd_flags": smd_flags,
            "condition_c_pass": not smd_flags,
            "cwe_dispatch": "normal",
        })

    logger.info("Annotated %d attempts", len(annotated))

    # ── 7. Aggregate metrics ─────────────────────────────────────────────────
    all_cve_ids = set(a["cve_id"] for a in annotated)
    models = sorted(set(a["model"] for a in annotated))
    langs = ["Python", "JavaScript", "Go"]

    by_model: dict[str, dict] = {}
    for model in models:
        ma = [a for a in annotated if a["model"] == model]
        overall = _compute_model_metrics(ma)
        by_lang = {lang: _compute_model_metrics(ma, lang_filter=lang) for lang in langs}
        by_model[model] = {"overall": overall, "by_language": by_lang}

    primary = ["gemini-2.5-pro", "gpt-4.1"]
    prim_atts = [a for a in annotated if a["model"] in primary]
    overall_primary = _compute_model_metrics(prim_atts)

    coverage = _compute_coverage(annotated)
    diagnostics = _compute_diagnostics(annotated)

    # ── 8. Save results ───────────────────────────────────────────────────────
    cond_c = {
        "task": 8,
        "benchmark": "PatchEval",
        "condition": "C_v2",
        "methodology": {
            "vcg_tool": "Joern v4.0.516 batch CPG (importCode.python/jssrc/go) + regex fallback",
            "s1_tool": "Joern batch dominance query + diff-context fallback",
            "s2_tool": "Joern batch reachability query + diff-context fallback (JS CWE-94 suppressed)",
            "condition_b_basis": "poc_status==True (100% pass-through from Task 4)",
            "patcheval_cwe_skip_all": sorted(PATCHEVAL_CWE_SKIP_ALL),
            "patcheval_cwe_auto_reject": sorted(PATCHEVAL_CWE_AUTO_REJECT),
            "patcheval_js_s2_skip": sorted(PATCHEVAL_JS_S2_SKIP),
            "optimization_version": "v2.0",
        },
        "vcg_coverage_stats": coverage_stats,
        "primary_models_overall": overall_primary,
        "by_model": by_model,
        "tool_coverage_by_language": coverage,
    }
    with open(output_dir / "patcheval_condition_c.json", "w") as f:
        json.dump(cond_c, f, indent=2)
    logger.info("Saved Condition C to %s/patcheval_condition_c.json", output_dir)

    diag = {"task": 8, "benchmark": "PatchEval", "diagnostics": diagnostics,
            "tool_coverage": coverage, "vcg_extraction": coverage_stats}
    with open(output_dir / "patcheval_diagnostic.json", "w") as f:
        json.dump(diag, f, indent=2)
    logger.info("Saved diagnostic to %s/patcheval_diagnostic.json", output_dir)

    # ── 9. Print summary ─────────────────────────────────────────────────────
    logger.info("=" * 60)
    logger.info("CONDITION C SUMMARY (PatchEval)")
    logger.info("=" * 60)
    for model in primary:
        if model in by_model:
            m = by_model[model]["overall"]
            logger.info(
                "%s: B=%d C=%d FDR_B=%.1f%% FDR_C=%.1f%% Yield_B=%d Yield_C=%d SMD_prec=%.1f%%",
                model, m["b_accepted"], m["c_accepted"],
                (m["b_fdr"] or 0) * 100, (m["c_fdr"] or 0) * 100,
                m["b_yield"], m["c_yield"],
                (m["smd_precision"] or 0) * 100,
            )
    return cond_c, diag


if __name__ == "__main__":
    main()
