# Condition C (SMD) evaluation pipeline for PVBench.
# Inputs: Condition B parquet + reference patch diffs + LLM-generated patch diffs.
# Outputs: pvbench_condition_c.json, pvbench_condition_c.parquet,
#          pvbench_sink_mapping.json, pvbench_vcg.json, pvbench_diagnostic.json.
#
# Usage:
#   python smd/evaluation/pvbench_eval.py \
#       --condition-b-parquet smd/results/pvbench_condition_b.parquet \
#       --eval-dir benchmarks/pvbench/artifacts/eval \
#       --vuln-dir benchmarks/pvbench/vuln \
#       --output-dir smd/results \
#       [--workers 4] [--debug-n 50]

import argparse
import json
import logging
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

import pandas as pd
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from smd.vcg.codeql_vcg import extract_sink_from_diff
from smd.vcg.sink_mapper import map_sink_to_post_patch
from smd.signatures.detector import run_smd

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def load_patch_diff(eval_dir: Path, tool: str, vuln_id: str, model: str, attempt: int) -> str:
    """Load LLM-generated patch diff from the eval artifact directory."""
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


def load_ref_diff(vuln_dir: Path, project: str, vuln_id: str) -> str:
    """Load the reference (ground-truth) patch.diff for a vulnerability."""
    diff_path = vuln_dir / project / vuln_id / "patch.diff"
    if not diff_path.exists():
        return ""
    try:
        with open(diff_path) as f:
            return f.read()
    except OSError:
        return ""


def _run_single_attempt(args: tuple) -> dict:
    """Worker: run SMD on one B-accepted patch attempt."""
    (
        row, eval_dir_str, vuln_dir_str,
        vcg_cache_json_str,
    ) = args
    eval_dir = Path(eval_dir_str)
    vuln_dir = Path(vuln_dir_str)

    vuln_id = row["vuln_id"]
    tool = row["tool"]
    model = row["model"]
    attempt = int(row["attempt"])
    cwe = row.get("cwe", "")
    project = row.get("project", "")
    pocplus_pass = bool(row.get("pocplus_pass", False))
    condition_b_pass = bool(row.get("condition_b_pass", True))

    vcg_cache = {}
    if vcg_cache_json_str:
        try:
            vcg_list = json.loads(vcg_cache_json_str)
            vcg_cache = {r["vuln_id"]: r for r in vcg_list}
        except Exception:
            pass

    vcg_info = vcg_cache.get(vuln_id)
    if vcg_info is None:
        ref_diff = load_ref_diff(vuln_dir, project, vuln_id)
        vcg_info = extract_sink_from_diff(vuln_id=vuln_id, cwe=cwe, ref_patch_diff=ref_diff)

    llm_patch_diff = load_patch_diff(eval_dir, tool, vuln_id, model, attempt)

    smd_result = run_smd(
        vcg_info=vcg_info,
        llm_patch_diff=llm_patch_diff,
        condition_b_pass=condition_b_pass,
        cwe=cwe,
    )

    return {
        "vuln_id": vuln_id,
        "tool": tool,
        "model": model,
        "attempt": attempt,
        "cwe": cwe,
        "project": project,
        "pocplus_pass": pocplus_pass,
        "condition_b_pass": condition_b_pass,
        "vcg_success": vcg_info.get("success", False),
        "vcg_method": vcg_info.get("vcg_method"),
        "sink_mapping_state": smd_result["sink_mapping_state"],
        "smd_applicable": smd_result["smd_applicable"],
        "s1_fires": smd_result["s1_fires"],
        "s2_fires": smd_result["s2_fires"],
        "s2_reason": smd_result["s2_reason"],
        "smd_flags": smd_result["smd_flags"],
        "condition_c_pass": smd_result["condition_c_pass"],
    }


def compute_condition_c_metrics(smd_df: pd.DataFrame) -> dict:
    """Compute Condition C metrics from the per-attempt SMD results."""
    total_b_accepted = len(smd_df)
    total_vulns = smd_df["vuln_id"].nunique()

    vcg_success = int(smd_df["vcg_success"].sum())
    vcg_success_rate = vcg_success / max(total_b_accepted, 1)

    state_counts = smd_df["sink_mapping_state"].value_counts().to_dict()
    mapped_count = int(state_counts.get("mapped", 0))
    removed_count = int(state_counts.get("removed", 0))
    unmappable_count = int(state_counts.get("unmappable", 0))
    applicable_count = mapped_count + removed_count

    smd_applicable_rate = applicable_count / max(total_b_accepted, 1)

    applicable_df = smd_df[smd_df["smd_applicable"] == True]
    s1_fires_count = int(applicable_df["s1_fires"].fillna(False).sum())
    s2_fires_count = int(applicable_df["s2_fires"].fillna(False).sum())
    smd_flags_count = int(applicable_df["smd_flags"].fillna(False).sum())

    s1_rate = s1_fires_count / max(len(applicable_df), 1)
    s2_rate = s2_fires_count / max(len(applicable_df), 1)
    smd_flag_rate = smd_flags_count / max(len(applicable_df), 1)

    cond_c_df = smd_df[smd_df["condition_c_pass"] == True]
    cond_c_count = len(cond_c_df)
    cond_c_tp = int(cond_c_df["pocplus_pass"].sum())
    cond_c_fp = cond_c_count - cond_c_tp
    fdr_c = cond_c_fp / max(cond_c_count, 1)

    yield_c_vulns = set(cond_c_df[cond_c_df["pocplus_pass"]]["vuln_id"].unique())
    yield_c = len(yield_c_vulns)
    strong_pass_rate_c = cond_c_tp / max(cond_c_count, 1)

    cond_b_pass_df = smd_df[smd_df["condition_b_pass"] == True]
    cond_b_count = len(cond_b_pass_df)
    cond_b_tp = int(cond_b_pass_df["pocplus_pass"].sum())
    cond_b_fp = cond_b_count - cond_b_tp
    fdr_b = cond_b_fp / max(cond_b_count, 1)
    yield_b_vulns = set(cond_b_pass_df[cond_b_pass_df["pocplus_pass"]]["vuln_id"].unique())
    yield_b = len(yield_b_vulns)

    fdr_reduction_abs = fdr_b - fdr_c
    fdr_reduction_rel = fdr_reduction_abs / max(fdr_b, 1e-9)
    yield_loss = yield_b - yield_c
    yield_loss_pct_val = yield_loss / max(yield_b, 1)

    by_cwe = {}
    for cwe, grp in cond_b_pass_df.groupby("cwe"):
        c_grp = grp[grp["condition_c_pass"] == True]
        by_cwe[cwe] = {
            "b_accepted": len(grp),
            "c_accepted": len(c_grp),
            "c_tp": int(c_grp["pocplus_pass"].sum()),
            "c_fp": int((~c_grp["pocplus_pass"]).sum()),
            "fdr_c": round(int((~c_grp["pocplus_pass"]).sum()) / max(len(c_grp), 1), 4),
            "fdr_b": round(int((~grp["pocplus_pass"]).sum()) / max(len(grp), 1), 4),
            "rejection_rate_c": round((len(grp) - len(c_grp)) / max(len(grp), 1), 4),
            "yield_c": int(c_grp[c_grp["pocplus_pass"]]["vuln_id"].nunique()),
        }

    by_tool = {}
    for tool, grp in cond_b_pass_df.groupby("tool"):
        c_grp = grp[grp["condition_c_pass"] == True]
        by_tool[tool] = {
            "b_accepted": len(grp),
            "c_accepted": len(c_grp),
            "fdr_b": round(int((~grp["pocplus_pass"]).sum()) / max(len(grp), 1), 4),
            "fdr_c": round(int((~c_grp["pocplus_pass"]).sum()) / max(len(c_grp), 1), 4),
            "yield_c": int(c_grp[c_grp["pocplus_pass"]]["vuln_id"].nunique()),
        }

    return {
        "total_b_accepted": total_b_accepted,
        "total_vulns": total_vulns,
        "vcg_coverage": {
            "vcg_success": vcg_success,
            "vcg_success_rate": round(vcg_success_rate, 4),
            "vcg_success_rate_pct": f"{vcg_success_rate*100:.1f}%",
        },
        "sink_mapping": {
            "mapped": mapped_count,
            "removed": removed_count,
            "unmappable": unmappable_count,
            "applicable": applicable_count,
            "smd_applicable_rate": round(smd_applicable_rate, 4),
            "smd_applicable_rate_pct": f"{smd_applicable_rate*100:.1f}%",
        },
        "smd_firing": {
            "s1_fires": s1_fires_count,
            "s2_fires": s2_fires_count,
            "smd_flags": smd_flags_count,
            "s1_rate": round(s1_rate, 4),
            "s2_rate": round(s2_rate, 4),
            "smd_flag_rate": round(smd_flag_rate, 4),
            "s1_rate_pct": f"{s1_rate*100:.1f}%",
            "s2_rate_pct": f"{s2_rate*100:.1f}%",
            "smd_flag_rate_pct": f"{smd_flag_rate*100:.1f}%",
        },
        "condition_b": {
            "accepted_count": cond_b_count,
            "tp_count": cond_b_tp,
            "fp_count": cond_b_fp,
            "fdr": round(fdr_b, 4),
            "fdr_pct": f"{fdr_b*100:.1f}%",
            "yield_count": yield_b,
            "yield_pct": f"{yield_b/max(total_vulns,1)*100:.1f}%",
        },
        "condition_c": {
            "accepted_count": cond_c_count,
            "tp_count": cond_c_tp,
            "fp_count": cond_c_fp,
            "fdr": round(fdr_c, 4),
            "fdr_pct": f"{fdr_c*100:.1f}%",
            "yield_count": yield_c,
            "yield_pct": f"{yield_c/max(total_vulns,1)*100:.1f}%",
            "strong_oracle_pass_rate": round(strong_pass_rate_c, 4),
            "strong_oracle_pass_rate_pct": f"{strong_pass_rate_c*100:.1f}%",
        },
        "c_vs_b": {
            "b_accepted_c_rejected": cond_b_count - cond_c_count,
            "rejection_rate": round((cond_b_count - cond_c_count) / max(cond_b_count, 1), 4),
            "rejection_rate_pct": f"{(cond_b_count - cond_c_count)/max(cond_b_count,1)*100:.1f}%",
            "fdr_reduction_abs": round(fdr_reduction_abs, 4),
            "fdr_reduction_rel": round(fdr_reduction_rel, 4),
            "fdr_reduction_rel_pct": f"{fdr_reduction_rel*100:.1f}%",
            "yield_loss": yield_loss,
            "yield_loss_pct": f"{yield_loss_pct_val*100:.1f}%",
        },
        "by_cwe": by_cwe,
        "by_tool": by_tool,
    }


def compute_diagnostic_metrics(smd_df: pd.DataFrame) -> dict:
    """Compute SMD diagnostic breakdown (step 6)."""
    applicable_df = smd_df[smd_df["smd_applicable"] == True].copy()
    applicable_df["s1_fires"] = applicable_df["s1_fires"].fillna(False).astype(bool)
    applicable_df["s2_fires"] = applicable_df["s2_fires"].fillna(False).astype(bool)
    applicable_df["smd_flags"] = applicable_df["smd_flags"].fillna(False).astype(bool)

    n_applicable = len(applicable_df)
    if n_applicable == 0:
        return {"error": "no_applicable_cases"}

    s1_rate = float(applicable_df["s1_fires"].mean())
    s2_rate = float(applicable_df["s2_fires"].mean())
    smd_flag_rate = float(applicable_df["smd_flags"].mean())

    flagged_df = applicable_df[applicable_df["smd_flags"]]
    n_flagged = len(flagged_df)
    n_flagged_strong_fail = int((~flagged_df["pocplus_pass"]).sum())
    smd_precision = n_flagged_strong_fail / max(n_flagged, 1)

    b_strong_fail = applicable_df[~applicable_df["pocplus_pass"]]
    n_b_strong_fail = len(b_strong_fail)
    n_caught = int(b_strong_fail["smd_flags"].sum())
    smd_recall = n_caught / max(n_b_strong_fail, 1)
    coverage_ceiling = smd_recall

    s2_removed = int((applicable_df["s2_reason"] == "sink_removed").sum())
    s2_unreachable = int((applicable_df["s2_reason"] == "unreachable").sum())

    only_s1 = int((applicable_df["s1_fires"] & ~applicable_df["s2_fires"]).sum())
    only_s2 = int((~applicable_df["s1_fires"] & applicable_df["s2_fires"]).sum())
    both = int((applicable_df["s1_fires"] & applicable_df["s2_fires"]).sum())

    state_dist = applicable_df["sink_mapping_state"].value_counts().to_dict()

    return {
        "n_applicable": n_applicable,
        "n_flagged_by_smd": n_flagged,
        "s1_rate": round(s1_rate, 4),
        "s2_rate": round(s2_rate, 4),
        "smd_flag_rate": round(smd_flag_rate, 4),
        "s1_rate_pct": f"{s1_rate*100:.1f}%",
        "s2_rate_pct": f"{s2_rate*100:.1f}%",
        "smd_flag_rate_pct": f"{smd_flag_rate*100:.1f}%",
        "smd_precision": round(smd_precision, 4),
        "smd_precision_pct": f"{smd_precision*100:.1f}%",
        "smd_recall": round(smd_recall, 4),
        "smd_recall_pct": f"{smd_recall*100:.1f}%",
        "coverage_ceiling": round(coverage_ceiling, 4),
        "coverage_ceiling_pct": f"{coverage_ceiling*100:.1f}%",
        "n_b_accepted_strong_oracle_fail": n_b_strong_fail,
        "n_caught_by_smd": n_caught,
        "s2_breakdown": {"sink_removed": s2_removed, "unreachable": s2_unreachable},
        "signature_overlap": {"only_s1": only_s1, "only_s2": only_s2, "both_s1_and_s2": both},
        "sink_mapping_state_dist": {k: int(v) for k, v in state_dist.items()},
    }


def main():
    parser = argparse.ArgumentParser(description="Condition C (SMD) evaluator for PVBench")
    parser.add_argument("--condition-b-parquet",
                        default=str(ROOT / "smd/results/pvbench_condition_b.parquet"))
    parser.add_argument("--eval-dir",
                        default=str(ROOT / "benchmarks/pvbench/artifacts/eval"))
    parser.add_argument("--vuln-dir",
                        default=str(ROOT / "benchmarks/pvbench/vuln"))
    parser.add_argument("--output-dir",
                        default=str(ROOT / "smd/results"))
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--debug-n", type=int, default=None)
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    vuln_dir = Path(args.vuln_dir)
    eval_dir = Path(args.eval_dir)

    logger.info("Loading Condition B parquet: %s", args.condition_b_parquet)
    b_df = pd.read_parquet(args.condition_b_parquet)
    logger.info("Loaded %d records (%d B-accepted)", len(b_df), b_df["condition_b_pass"].sum())

    if args.debug_n:
        b_df_pass = b_df[b_df["condition_b_pass"]].head(args.debug_n)
        b_df_fail = b_df[~b_df["condition_b_pass"]]
        b_df = pd.concat([b_df_pass, b_df_fail]).reset_index(drop=True)
        logger.info("Debug mode: %d B-pass + %d B-fail = %d total",
                    len(b_df_pass), len(b_df_fail), len(b_df))

    # ── VCG extraction ───────────────────────────────────────────────────────
    vcg_output = output_dir / "pvbench_vcg.json"
    logger.info("Running VCG extraction for all unique vulns...")

    vcg_results = {}
    unique_vulns = b_df[["vuln_id", "project", "cwe"]].drop_duplicates(subset=["vuln_id"])
    for _, row in unique_vulns.iterrows():
        vuln_id = row["vuln_id"]
        project = row["project"]
        cwe = row["cwe"]
        ref_diff = load_ref_diff(vuln_dir, project, vuln_id)
        vcg = extract_sink_from_diff(vuln_id=vuln_id, cwe=cwe, ref_patch_diff=ref_diff)
        vcg["project"] = project
        vcg_results[vuln_id] = vcg

    vcg_list = list(vcg_results.values())
    with open(vcg_output, "w") as f:
        json.dump(vcg_list, f, indent=2)
    vcg_success = sum(1 for v in vcg_list if v.get("success", False))
    logger.info("VCG extraction: %d/%d success (%.1f%%)",
                vcg_success, len(vcg_list), 100*vcg_success/max(len(vcg_list), 1))

    vcg_cache_json = json.dumps(vcg_list)

    # ── SMD on B-accepted patches ────────────────────────────────────────────
    b_accepted_df = b_df[b_df["condition_b_pass"] == True]
    rows = b_accepted_df.to_dict(orient="records")
    logger.info("Running SMD on %d B-accepted attempts...", len(rows))

    worker_args = [
        (row, str(eval_dir), str(vuln_dir), vcg_cache_json)
        for row in rows
    ]

    smd_results = []
    completed = 0
    total = len(worker_args)

    if args.workers > 1:
        with ProcessPoolExecutor(max_workers=args.workers) as executor:
            futures = {executor.submit(_run_single_attempt, a): a for a in worker_args}
            for future in as_completed(futures):
                try:
                    r = future.result()
                except Exception as e:
                    a = futures[future]
                    row = a[0]
                    logger.warning("Worker failed for %s: %s", row.get("vuln_id", "?"), e)
                    r = {k: None for k in ["vuln_id", "tool", "model", "attempt", "cwe",
                                           "project", "pocplus_pass", "condition_b_pass",
                                           "vcg_success", "vcg_method", "sink_mapping_state",
                                           "smd_applicable", "s1_fires", "s2_fires",
                                           "s2_reason", "smd_flags", "condition_c_pass"]}
                    r.update({"vuln_id": row.get("vuln_id", ""), "tool": row.get("tool", ""),
                               "model": row.get("model", ""), "attempt": row.get("attempt", 0),
                               "cwe": row.get("cwe", ""), "project": row.get("project", ""),
                               "pocplus_pass": bool(row.get("pocplus_pass", False)),
                               "condition_b_pass": True, "vcg_success": False,
                               "sink_mapping_state": "unmappable", "smd_applicable": False})
                smd_results.append(r)
                completed += 1
                if completed % 200 == 0:
                    logger.info("Progress: %d/%d (%.1f%%)", completed, total, 100*completed/total)
    else:
        for a in worker_args:
            try:
                r = _run_single_attempt(a)
            except Exception as e:
                row = a[0]
                logger.warning("Worker failed for %s: %s", row.get("vuln_id", "?"), e)
                r = {k: None for k in ["vuln_id", "tool", "model", "attempt", "cwe",
                                       "project", "pocplus_pass", "condition_b_pass",
                                       "vcg_success", "vcg_method", "sink_mapping_state",
                                       "smd_applicable", "s1_fires", "s2_fires",
                                       "s2_reason", "smd_flags", "condition_c_pass"]}
                r.update({"vuln_id": row.get("vuln_id", ""), "tool": row.get("tool", ""),
                           "model": row.get("model", ""), "attempt": row.get("attempt", 0),
                           "cwe": row.get("cwe", ""), "project": row.get("project", ""),
                           "pocplus_pass": bool(row.get("pocplus_pass", False)),
                           "condition_b_pass": True, "vcg_success": False,
                           "sink_mapping_state": "unmappable", "smd_applicable": False})
            smd_results.append(r)
            completed += 1
            if completed % 200 == 0:
                logger.info("Progress: %d/%d (%.1f%%)", completed, total, 100*completed/total)

    smd_df = pd.DataFrame(smd_results)

    sink_mapping_records = smd_df[
        ["vuln_id", "tool", "model", "attempt", "sink_mapping_state"]
    ].to_dict(orient="records")
    with open(output_dir / "pvbench_sink_mapping.json", "w") as f:
        json.dump(sink_mapping_records, f, indent=2)

    smd_parquet = output_dir / "pvbench_condition_c.parquet"
    smd_df.to_parquet(str(smd_parquet), index=False)
    logger.info("Per-attempt SMD results saved to %s", smd_parquet)

    # ── Condition C metrics ──────────────────────────────────────────────────
    logger.info("Computing Condition C metrics...")
    metrics = compute_condition_c_metrics(smd_df)

    output_data = {
        "task": 6,
        "title": "Condition C (SMD Validator Add-On) on PVBench — Optimized",
        "benchmark": "PVBench",
        "condition": "C",
        "methodology": {
            "vcg_extraction": "CWE-specific diff-context heuristics (no compilation needed)",
            "sink_mapping": "Unified diff offset adjustment + deletion detection",
            "s1_dominance": "Positional early-exit dominance; full brace-depth conditional check",
            "s2_unreachability": "Sink deletion check + unconditional early-exit (suppressed for CWE_S1_ONLY)",
            "smd_logic": "CWE-aware: auto-reject 100%-FDR CWEs; S1-only for CWE-476/121/190; skip CWE-416/617/670/122/415",
            "signature_spec": "smd/configs/signature_spec.yaml (pre-registered)",
        },
        "metrics": metrics,
    }

    c_json_path = output_dir / "pvbench_condition_c.json"
    with open(c_json_path, "w") as f:
        json.dump(output_data, f, indent=2)
    logger.info("Condition C results saved to %s", c_json_path)

    # ── Diagnostic breakdown ─────────────────────────────────────────────────
    logger.info("Computing diagnostic metrics...")
    diagnostic = compute_diagnostic_metrics(smd_df)

    diag_data = {
        "task": 6,
        "title": "SMD Diagnostic Breakdown on PVBench — Optimized",
        "diagnostic": diagnostic,
        "by_cwe_diagnostic": {},
    }

    applicable_df = smd_df[smd_df["smd_applicable"] == True].copy()
    applicable_df["s1_fires"] = applicable_df["s1_fires"].fillna(False).astype(bool)
    applicable_df["s2_fires"] = applicable_df["s2_fires"].fillna(False).astype(bool)
    applicable_df["smd_flags"] = applicable_df["smd_flags"].fillna(False).astype(bool)

    for cwe, grp in applicable_df.groupby("cwe"):
        n = len(grp)
        if n == 0:
            continue
        n_flagged = int(grp["smd_flags"].sum())
        b_fail = grp[~grp["pocplus_pass"]]
        n_b_fail = len(b_fail)
        n_caught = int(b_fail["smd_flags"].sum())
        flagged = grp[grp["smd_flags"]]
        n_flagged_fail = int((~flagged["pocplus_pass"]).sum()) if len(flagged) else 0
        diag_data["by_cwe_diagnostic"][str(cwe)] = {
            "n_applicable": n,
            "smd_flag_rate": round(n_flagged / max(n, 1), 4),
            "precision": round(n_flagged_fail / max(n_flagged, 1), 4),
            "recall": round(n_caught / max(n_b_fail, 1), 4),
        }

    diag_path = output_dir / "pvbench_diagnostic.json"
    with open(diag_path, "w") as f:
        json.dump(diag_data, f, indent=2)
    logger.info("Diagnostic results saved to %s", diag_path)

    m = metrics
    print("\n=== Condition C (SMD) Results ===")
    print(f"VCG coverage: {m['vcg_coverage']['vcg_success_rate_pct']}")
    print(f"SMD applicable: {m['sink_mapping']['smd_applicable_rate_pct']}")
    print(f"  Mapped={m['sink_mapping']['mapped']}, Removed={m['sink_mapping']['removed']}, Unmappable={m['sink_mapping']['unmappable']}")
    print(f"S1 fires: {m['smd_firing']['s1_rate_pct']}, S2 fires: {m['smd_firing']['s2_rate_pct']}, SMD flags: {m['smd_firing']['smd_flag_rate_pct']}")
    print(f"Condition B: FDR={m['condition_b']['fdr_pct']}, Accepted={m['condition_b']['accepted_count']}, Yield={m['condition_b']['yield_count']}")
    print(f"Condition C: FDR={m['condition_c']['fdr_pct']}, Accepted={m['condition_c']['accepted_count']}, Yield={m['condition_c']['yield_count']}")
    print(f"C vs B: FDR change={m['c_vs_b']['fdr_reduction_abs']:.4f} ({m['c_vs_b']['fdr_reduction_rel_pct']} rel), Yield loss={m['c_vs_b']['yield_loss']}")
    d = diagnostic
    if "error" not in d:
        print(f"\nSMD Diagnostic:")
        print(f"  Precision={d['smd_precision_pct']}, Recall={d['smd_recall_pct']}, Coverage ceiling={d['coverage_ceiling_pct']}")
        print(f"  S1 only={d['signature_overlap']['only_s1']}, S2 only={d['signature_overlap']['only_s2']}, Both={d['signature_overlap']['both_s1_and_s2']}")


if __name__ == "__main__":
    main()
