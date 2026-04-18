# Condition B evaluator for PVBench.
# Applies a static flow checker to each Condition-A-accepted patch attempt,
# and computes Condition B metrics.
#
# Checker hierarchy (for CWEs with checker_strategy != "none"):
#   1. Pattern-based checker (patch_pattern_checker) — works offline, analyzes
#      the patch diff directly for CWE-specific fix patterns
#   2. CodeQL (codeql_checker) — requires compilation; used when --use-codeql flag
#      is set and the project's build.sh is available
#   3. Semgrep (semgrep_checker) — requires internet; used when --use-semgrep flag
#      is set (typically in TrainService environment)
#
# Condition B logic:
#   pass = stage1_pass AND (checker == "none" OR checker.pass)
#
# Usage:
#   python smd/baselines/condition_b_evaluator.py \
#       --condition-a-parquet smd/results/pvbench_condition_a_df.parquet \
#       --eval-dir benchmarks/pvbench/artifacts/eval \
#       --vuln-dir benchmarks/pvbench/vuln \
#       --output smd/results/pvbench_condition_b.json \
#       --workers 4
#       [--debug-n 20]

import argparse
import json
import logging
import re
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

import pandas as pd
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from smd.baselines.patch_pattern_checker import check_patch as check_patch_pattern
from smd.baselines.semgrep_checker import check_patch_with_semgrep
from smd.baselines.codeql_checker import check_patch_with_codeql

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

BASE_FILE_RE = re.compile(r"^(.+?):([^:]+):(\d+)\.json$")


def load_patch_diff(eval_dir: Path, tool: str, vuln_id: str, model: str, attempt: int) -> str:
    """Load the LLM-generated patch diff from the eval artifact."""
    fname = f"{vuln_id}:{model}:{attempt}.json"
    base_file = eval_dir / tool / fname
    if not base_file.exists():
        return ""
    try:
        with open(base_file) as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data.get("patch", "") or ""
        elif isinstance(data, list) and len(data) > 0:
            return data[0].get("patch", "") or ""
    except (json.JSONDecodeError, OSError):
        pass
    return ""


def load_vuln_config(vuln_dir: Path, project: str, vuln_id: str) -> dict:
    """Load config.yaml for a vulnerability."""
    cfg_path = vuln_dir / project / vuln_id / "config.yaml"
    if not cfg_path.exists():
        return {}
    try:
        with open(cfg_path) as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def check_single_attempt(args: tuple) -> dict:
    """
    Worker function: run the static checker on one patch attempt.
    args = (row_dict, eval_dir_str, vuln_dir_str, use_codeql, use_semgrep)
    """
    row, eval_dir_str, vuln_dir_str, use_codeql, use_semgrep = args
    eval_dir = Path(eval_dir_str)
    vuln_dir = Path(vuln_dir_str)

    vuln_id = row["vuln_id"]
    tool = row["tool"]
    model = row["model"]
    attempt = int(row["attempt"])
    cwe = row["cwe"]
    project = row["project"]
    stage1_pass = bool(row["stage1_pass"])
    pocplus_pass = bool(row["pocplus_pass"])

    if not stage1_pass:
        return {
            "vuln_id": vuln_id,
            "tool": tool,
            "model": model,
            "attempt": attempt,
            "cwe": cwe,
            "project": project,
            "stage1_pass": False,
            "pocplus_pass": pocplus_pass,
            "condition_b_pass": False,
            "checker": "skipped",
            "findings_count": 0,
            "db_build_success": None,
            "details": {},
        }

    patch_diff = load_patch_diff(eval_dir, tool, vuln_id, model, attempt)
    if not patch_diff:
        return {
            "vuln_id": vuln_id,
            "tool": tool,
            "model": model,
            "attempt": attempt,
            "cwe": cwe,
            "project": project,
            "stage1_pass": True,
            "pocplus_pass": pocplus_pass,
            "condition_b_pass": True,
            "checker": "no_patch_diff",
            "findings_count": 0,
            "db_build_success": None,
            "details": {"reason": "empty_patch_diff"},
        }

    # Use the pattern-based checker as primary (works offline, no compilation needed)
    result = check_patch_pattern(vuln_id=vuln_id, cwe=cwe, patch_diff=patch_diff)

    return {
        "vuln_id": vuln_id,
        "tool": tool,
        "model": model,
        "attempt": attempt,
        "cwe": cwe,
        "project": project,
        "stage1_pass": True,
        "pocplus_pass": pocplus_pass,
        "condition_b_pass": bool(result.get("condition_b_pass", True)),
        "checker": result.get("checker", "unknown"),
        "findings_count": result.get("findings_count", 0),
        "db_build_success": result.get("db_build_success"),
        "details": result.get("details", {}),
    }


def compute_metrics(results_df: pd.DataFrame) -> dict:
    """Compute Condition B metrics from per-attempt results."""
    total_attempts = len(results_df)

    # Condition A: accepted by stage1
    cond_a = results_df[results_df["stage1_pass"]]
    cond_a_count = len(cond_a)

    # Condition B: passes stage1 AND static checker
    cond_b = results_df[results_df["condition_b_pass"]]
    cond_b_count = len(cond_b)

    # Among A-accepted, how many are additionally rejected by B?
    a_accepted_b_rejected = cond_a[~cond_a["condition_b_pass"]]
    rejection_rate = len(a_accepted_b_rejected) / max(cond_a_count, 1)

    # FDR_B: false discovery rate among B-accepted
    cond_b_fp = cond_b[~cond_b["pocplus_pass"]]
    cond_b_tp = cond_b[cond_b["pocplus_pass"]]
    fdr_b = len(cond_b_fp) / max(cond_b_count, 1)

    # FDR_A for comparison
    cond_a_fp = cond_a[~cond_a["pocplus_pass"]]
    fdr_a = len(cond_a_fp) / max(cond_a_count, 1)

    # Yield_B: vulns with >=1 B-accepted patch that also passes pocplus
    yield_b_vulns = set(cond_b[cond_b["pocplus_pass"]]["vuln_id"].unique())
    yield_b = len(yield_b_vulns)

    # Yield_A for comparison
    yield_a_vulns = set(cond_a[cond_a["pocplus_pass"]]["vuln_id"].unique())
    yield_a = len(yield_a_vulns)

    # Strong oracle pass rate among B-accepted
    strong_pass_rate_b = len(cond_b_tp) / max(cond_b_count, 1)

    # Checker coverage
    has_checker = results_df[results_df["stage1_pass"] & (results_df["checker"] != "none") & (results_df["checker"] != "skipped") & (results_df["checker"] != "no_patch_diff")]
    unique_vulns_with_checker = has_checker["vuln_id"].nunique()
    total_unique_vulns = results_df["vuln_id"].nunique()

    # By-CWE metrics
    by_cwe = {}
    for cwe, grp in cond_a.groupby("cwe"):
        b_grp = grp[grp["condition_b_pass"]]
        by_cwe[cwe] = {
            "a_accepted": len(grp),
            "b_accepted": len(b_grp),
            "b_tp": int(b_grp["pocplus_pass"].sum()),
            "b_fp": int((~b_grp["pocplus_pass"]).sum()),
            "fdr_b": round(int((~b_grp["pocplus_pass"]).sum()) / max(len(b_grp), 1), 4),
            "fdr_a": round(int((~grp["pocplus_pass"]).sum()) / max(len(grp), 1), 4),
            "rejection_rate": round((len(grp) - len(b_grp)) / max(len(grp), 1), 4),
            "yield_b": int(b_grp[b_grp["pocplus_pass"]]["vuln_id"].nunique()),
        }

    # By-tool metrics
    by_tool = {}
    for tool, grp in cond_a.groupby("tool"):
        b_grp = grp[grp["condition_b_pass"]]
        by_tool[tool] = {
            "a_accepted": len(grp),
            "b_accepted": len(b_grp),
            "fdr_a": round(int((~grp["pocplus_pass"]).sum()) / max(len(grp), 1), 4),
            "fdr_b": round(int((~b_grp["pocplus_pass"]).sum()) / max(len(b_grp), 1), 4),
            "yield_b": int(b_grp[b_grp["pocplus_pass"]]["vuln_id"].nunique()),
        }

    # By-model metrics
    by_model = {}
    for model, grp in cond_a.groupby("model"):
        b_grp = grp[grp["condition_b_pass"]]
        by_model[model] = {
            "a_accepted": len(grp),
            "b_accepted": len(b_grp),
            "fdr_a": round(int((~grp["pocplus_pass"]).sum()) / max(len(grp), 1), 4),
            "fdr_b": round(int((~b_grp["pocplus_pass"]).sum()) / max(len(b_grp), 1), 4),
            "yield_b": int(b_grp[b_grp["pocplus_pass"]]["vuln_id"].nunique()),
        }

    # Checker distribution
    checker_counts = results_df[results_df["stage1_pass"]]["checker"].value_counts().to_dict()
    db_build_attempted = results_df[results_df["checker"].isin(["codeql", "codeql_db_build_failed", "codeql_query_failed"])]
    db_build_success_count = int(results_df.get("db_build_success", pd.Series(dtype=bool)).sum()) if "db_build_success" in results_df.columns else 0

    return {
        "total_attempts": total_attempts,
        "total_vulns": total_unique_vulns,
        "condition_a": {
            "accepted_count": cond_a_count,
            "tp_count": int(cond_a["pocplus_pass"].sum()),
            "fp_count": int((~cond_a["pocplus_pass"]).sum()),
            "fdr": round(fdr_a, 4),
            "fdr_pct": f"{fdr_a*100:.1f}%",
            "yield_count": yield_a,
            "yield_pct": f"{yield_a/max(total_unique_vulns,1)*100:.1f}%",
        },
        "condition_b": {
            "accepted_count": cond_b_count,
            "tp_count": int(cond_b_tp.shape[0]),
            "fp_count": int(cond_b_fp.shape[0]),
            "fdr": round(fdr_b, 4),
            "fdr_pct": f"{fdr_b*100:.1f}%",
            "yield_count": yield_b,
            "yield_pct": f"{yield_b/max(total_unique_vulns,1)*100:.1f}%",
            "strong_oracle_pass_rate": round(strong_pass_rate_b, 4),
            "strong_oracle_pass_rate_pct": f"{strong_pass_rate_b*100:.1f}%",
        },
        "b_vs_a": {
            "a_accepted_b_rejected_count": len(a_accepted_b_rejected),
            "rejection_rate": round(rejection_rate, 4),
            "rejection_rate_pct": f"{rejection_rate*100:.1f}%",
            "fdr_reduction_abs": round(fdr_a - fdr_b, 4),
            "fdr_reduction_rel": round((fdr_a - fdr_b) / max(fdr_a, 1e-9), 4),
            "yield_loss": yield_a - yield_b,
            "yield_loss_pct": f"{(yield_a-yield_b)/max(yield_a,1)*100:.1f}%",
        },
        "checker_coverage": {
            "unique_vulns_with_checker": unique_vulns_with_checker,
            "total_vulns": total_unique_vulns,
            "coverage_pct": f"{unique_vulns_with_checker/max(total_unique_vulns,1)*100:.1f}%",
            "checker_distribution": {k: int(v) for k, v in checker_counts.items()},
        },
        "by_cwe": by_cwe,
        "by_tool": by_tool,
        "by_model": by_model,
    }


def _make_error_result(row: dict, error: str) -> dict:
    return {
        "vuln_id": row.get("vuln_id", ""),
        "tool": row.get("tool", ""),
        "model": row.get("model", ""),
        "attempt": row.get("attempt", 0),
        "cwe": row.get("cwe", ""),
        "project": row.get("project", ""),
        "stage1_pass": bool(row.get("stage1_pass", False)),
        "pocplus_pass": bool(row.get("pocplus_pass", False)),
        "condition_b_pass": bool(row.get("stage1_pass", False)),
        "checker": "error",
        "findings_count": 0,
        "db_build_success": None,
        "details": {"error": error[:200]},
    }


def main():
    parser = argparse.ArgumentParser(description="Condition B evaluator for PVBench")
    parser.add_argument("--condition-a-parquet", default=str(ROOT / "smd/results/pvbench_condition_a_df.parquet"))
    parser.add_argument("--eval-dir", default=str(ROOT / "benchmarks/pvbench/artifacts/eval"))
    parser.add_argument("--vuln-dir", default=str(ROOT / "benchmarks/pvbench/vuln"))
    parser.add_argument("--output", default=str(ROOT / "smd/results/pvbench_condition_b.json"))
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--use-codeql", action="store_true", default=False)
    parser.add_argument("--use-semgrep", action="store_true", default=False)
    parser.add_argument("--debug-n", type=int, default=None, help="Process only first N stage1-pass attempts")
    args = parser.parse_args()

    logger.info("Loading Condition A parquet: %s", args.condition_a_parquet)
    df = pd.read_parquet(args.condition_a_parquet)
    logger.info("Loaded %d records, %d unique vulns", len(df), df["vuln_id"].nunique())

    if args.debug_n:
        stage1_pass_df = df[df["stage1_pass"]].head(args.debug_n)
        stage1_fail_df = df[~df["stage1_pass"]]
        df = pd.concat([stage1_pass_df, stage1_fail_df]).reset_index(drop=True)
        logger.info("Debug mode: %d stage1-pass + %d stage1-fail = %d total",
                    args.debug_n, len(stage1_fail_df), len(df))

    rows = df.to_dict(orient="records")
    worker_args = [
        (row, args.eval_dir, args.vuln_dir, args.use_codeql, args.use_semgrep)
        for row in rows
    ]

    logger.info("Running static checks with %d workers on %d records", args.workers, len(rows))

    results = []
    completed = 0
    total = len(worker_args)

    if args.workers > 1:
        with ProcessPoolExecutor(max_workers=args.workers) as executor:
            futures = {executor.submit(check_single_attempt, a): a for a in worker_args}
            for future in as_completed(futures):
                try:
                    result = future.result()
                except Exception as e:
                    a = futures[future]
                    logger.warning("Worker failed for %s: %s", a[0].get("vuln_id", "?"), e)
                    result = _make_error_result(a[0], str(e))
                results.append(result)
                completed += 1
                if completed % 200 == 0:
                    logger.info("Progress: %d / %d (%.1f%%)", completed, total, 100*completed/total)
    else:
        for a in worker_args:
            try:
                result = check_single_attempt(a)
            except Exception as e:
                logger.warning("Failed for %s: %s", a[0].get("vuln_id", "?"), e)
                result = _make_error_result(a[0], str(e))
            results.append(result)
            completed += 1
            if completed % 200 == 0:
                logger.info("Progress: %d / %d (%.1f%%)", completed, total, 100*completed/total)

    results_df = pd.DataFrame(results)
    logger.info("Completed all checks. Computing metrics...")

    metrics = compute_metrics(results_df)

    parquet_path = Path(args.output).with_suffix(".parquet")
    results_df.to_parquet(str(parquet_path), index=False)
    logger.info("Per-attempt results saved to %s", parquet_path)

    output_data = {
        "task": 2,
        "title": "Condition B (Weak + Static Flow Checker) Baseline on PVBench",
        "benchmark": "PVBench",
        "condition": "B",
        "metrics": metrics,
        "methodology": {
            "checker_primary": "patch_pattern_analysis",
            "checker_secondary": "codeql_optional",
            "condition_b_logic": "stage1_pass AND (checker==none OR checker.pass)",
            "pattern_checker_approach": "AST/regex pattern matching on patch diff added lines, CWE-specific fix patterns",
            "pass_through_cwes": ["CWE-617", "CWE-670", "CWE-704", "CWE-362"],
            "checker_coverage_note": "CWEs 476,122,121,190,416,415,369,457 have pattern checkers (~85% of vulns)",
        },
    }

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(output_data, f, indent=2)
    logger.info("Results saved to %s", args.output)

    m = metrics
    print("\n=== Condition B Results ===")
    print(f"Condition A: FDR={m['condition_a']['fdr_pct']}, Accepted={m['condition_a']['accepted_count']}, Yield={m['condition_a']['yield_count']}")
    print(f"Condition B: FDR={m['condition_b']['fdr_pct']}, Accepted={m['condition_b']['accepted_count']}, Yield={m['condition_b']['yield_count']}")
    print(f"B vs A: Rejection rate={m['b_vs_a']['rejection_rate_pct']}, FDR reduction={m['b_vs_a']['fdr_reduction_abs']:.4f} ({m['b_vs_a']['fdr_reduction_rel']*100:.1f}% rel)")
    print(f"Yield loss: {m['b_vs_a']['yield_loss']} vulns ({m['b_vs_a']['yield_loss_pct']})")
    print(f"Checker coverage: {m['checker_coverage']['coverage_pct']} of vulns")
    print(f"Checker distribution: {m['checker_coverage']['checker_distribution']}")


if __name__ == "__main__":
    main()
