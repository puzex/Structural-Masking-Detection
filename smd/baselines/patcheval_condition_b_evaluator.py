# Condition B evaluator for PatchEval.
# Applies differential CodeQL/Semgrep analysis to Condition-A-accepted patches.
#
# For each patch where poc_status is True (Condition A accepted):
#   1. Reconstruct pre-patch source (vul_func snippet) and post-patch source (fix_code snippet)
#   2. Run CodeQL differential analysis using the CWE-specific query
#   3. Fall back to Semgrep differential if CodeQL is blind or fails
#   4. condition_b_pass = True if post-patch source is free of the vulnerability
#
# Usage:
#   python smd/baselines/patcheval_condition_b_evaluator.py \
#       --log-dir benchmarks/patcheval/patcheval/log/llm \
#       --input-json benchmarks/patcheval/patcheval/datasets/input.json \
#       --codeql-dir tools/codeql \
#       --codeql-repo tools/codeql-repo \
#       --workers 16 \
#       --output smd/results/patcheval_condition_b.json

import argparse
import json
import logging
import os
import shutil
import statistics
import sys
import tempfile
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from smd.baselines.patcheval_source_extractor import (
    load_input_metadata,
    write_pre_patch_source,
    write_post_patch_source,
    make_temp_pair_dirs,
    LANG_CODE,
)
from smd.baselines.patcheval_static_checker import check_patch, CODEQL_LANG_MAP

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

LANG_NORM = {
    "py": "Python",
    "Python": "Python",
    "go": "Go",
    "Go": "Go",
    "JavaScript": "JavaScript",
    "npm": "JavaScript",
    "javascript": "JavaScript",
}

MODEL_DISPLAY = {
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


def normalize_lang(lang: str) -> str:
    return LANG_NORM.get(lang, lang)


def load_model_data(fpath: str) -> list:
    """Load a PatchEval log file and return flat list of records."""
    with open(fpath) as f:
        data = json.load(f)
    records = []
    for item_dict in data:
        for cve, items in item_dict.items():
            for item in items:
                lang = normalize_lang(item.get("language", "unknown"))
                cwe = item.get("cwe", [])
                if isinstance(cwe, str):
                    cwe = [cwe]
                poc = item.get("poc_status")
                ut = item.get("unittest_status")
                epoch = item.get("epoch")
                fix_code = item.get("fix_code", {})
                diff_content = item.get("diff_content")
                records.append({
                    "cve": cve,
                    "epoch": epoch,
                    "language": lang,
                    "poc_status": poc,
                    "unittest_status": ut,
                    "cwe": cwe,
                    "fix_code": fix_code,
                    "diff_content": diff_content,
                })
    return records


def _check_single(args: tuple) -> dict:
    """Worker: run static checker on one Condition-A-accepted patch."""
    (rec, meta_entry, codeql_bin, codeql_repo, cwe_map_path, tmpdir_base) = args

    cve = rec["cve"]
    cwe_list = rec["cwe"]
    language = rec["language"]
    fix_code = rec.get("fix_code", {})
    poc_status = rec["poc_status"]
    unittest_status = rec["unittest_status"]
    epoch = rec["epoch"]

    base_result = {
        "cve": cve,
        "epoch": epoch,
        "language": language,
        "cwe": cwe_list,
        "poc_status": poc_status,
        "unittest_status": unittest_status,
        "condition_b_pass": True,
        "checker": "passthrough",
        "pre_findings": None,
        "post_findings": None,
        "cwe_used": cwe_list[0] if cwe_list else "unknown",
        "error": None,
    }

    if not poc_status:
        base_result["checker"] = "skipped"
        base_result["condition_b_pass"] = False
        return base_result

    if not meta_entry:
        base_result["checker"] = "no_metadata"
        return base_result

    if not fix_code:
        base_result["checker"] = "no_fix_code"
        return base_result

    parent_dir = None
    try:
        parent_dir, pre_dir, post_dir = make_temp_pair_dirs(tmpdir_base)
        work_dir = os.path.join(parent_dir, "work")
        os.makedirs(work_dir, exist_ok=True)

        # Write pre-patch source
        vul_funcs = meta_entry.get("vul_funcs", [])
        snippet_pre = "\n\n".join(vf.get("snippet", "") for vf in vul_funcs if vf.get("snippet"))
        lang_prog = meta_entry.get("programming_language", language)

        from smd.baselines.patcheval_source_extractor import _write_source
        pre_src_file = _write_source(snippet_pre, lang_prog, pre_dir, prefix="pre_")
        post_snippet = "\n\n".join(str(v) for v in fix_code.values() if v)
        post_src_file = _write_source(post_snippet, lang_prog, post_dir, prefix="post_")

        if not pre_src_file or not post_src_file:
            base_result["checker"] = "source_write_failed"
            return base_result

        result = check_patch(
            cve_id=cve,
            cwe_list=cwe_list,
            pre_src_dir=pre_dir,
            pre_src_file=pre_src_file,
            post_src_dir=post_dir,
            post_src_file=post_src_file,
            language=lang_prog,
            codeql_bin=codeql_bin,
            codeql_repo=codeql_repo,
            cwe_map_path=cwe_map_path,
            work_dir=work_dir,
            timeout=300,
            ram_mb=8000,
        )

        base_result.update({
            "condition_b_pass": result.get("condition_b_pass", True),
            "checker": result.get("checker", "passthrough"),
            "pre_findings": result.get("pre_findings"),
            "post_findings": result.get("post_findings"),
            "cwe_used": result.get("cwe_used", cwe_list[0] if cwe_list else "unknown"),
            "error": result.get("tool_detail", {}).get("error"),
        })
        return base_result

    except Exception as e:
        base_result["error"] = str(e)[:200]
        base_result["checker"] = "exception"
        return base_result
    finally:
        if parent_dir and os.path.exists(parent_dir):
            try:
                shutil.rmtree(parent_dir)
            except Exception:
                pass


def compute_condition_b_metrics(records: list) -> dict:
    """Compute Condition B metrics from per-attempt records."""
    total_attempts = len(records)

    cond_a = [r for r in records if r.get("poc_status") is True]
    cond_b = [r for r in cond_a if r.get("condition_b_pass")]

    cond_a_strong = [r for r in cond_a if r.get("unittest_status") is True]
    cond_b_strong = [r for r in cond_b if r.get("unittest_status") is True]

    cond_a_fp = [r for r in cond_a if not r.get("unittest_status")]
    cond_b_fp = [r for r in cond_b if not r.get("unittest_status")]

    fdr_a = len(cond_a_fp) / max(len(cond_a), 1)
    fdr_b = len(cond_b_fp) / max(len(cond_b), 1)

    # Yield: CVEs with >=1 strong-oracle-passing accepted patch
    yield_a = len(set(r["cve"] for r in cond_a_strong))
    yield_b = len(set(r["cve"] for r in cond_b_strong))
    total_cves = len(set(r["cve"] for r in records))

    rejection_rate = (len(cond_a) - len(cond_b)) / max(len(cond_a), 1)
    strong_rate_b = len(cond_b_strong) / max(len(cond_b), 1)

    # Checker distribution
    checker_dist = defaultdict(int)
    for r in cond_a:
        checker_dist[r.get("checker", "unknown")] += 1

    # By language
    by_language = {}
    all_langs = set(r["language"] for r in records)
    for lang in all_langs:
        la = [r for r in cond_a if r["language"] == lang]
        lb = [r for r in cond_b if r["language"] == lang]
        la_strong = [r for r in la if r.get("unittest_status") is True]
        lb_strong = [r for r in lb if r.get("unittest_status") is True]
        la_fp = [r for r in la if not r.get("unittest_status")]
        lb_fp = [r for r in lb if not r.get("unittest_status")]
        lang_total_cves = len(set(r["cve"] for r in records if r["language"] == lang))
        by_language[lang] = {
            "a_accepted": len(la),
            "b_accepted": len(lb),
            "fdr_a": round(len(la_fp) / max(len(la), 1), 4),
            "fdr_b": round(len(lb_fp) / max(len(lb), 1), 4),
            "yield_a": len(set(r["cve"] for r in la_strong)),
            "yield_b": len(set(r["cve"] for r in lb_strong)),
            "total_cves": lang_total_cves,
        }

    # By CWE
    by_cwe = {}
    cwe_map_flat = defaultdict(list)
    for r in cond_a:
        for cw in r.get("cwe", []):
            cwe_map_flat[cw].append(r)
    for cw, la in cwe_map_flat.items():
        lb = [r for r in la if r.get("condition_b_pass")]
        la_fp = [r for r in la if not r.get("unittest_status")]
        lb_fp = [r for r in lb if not r.get("unittest_status")]
        by_cwe[cw] = {
            "a_accepted": len(la),
            "b_accepted": len(lb),
            "fdr_a": round(len(la_fp) / max(len(la), 1), 4),
            "fdr_b": round(len(lb_fp) / max(len(lb), 1), 4),
            "rejection_rate": round((len(la) - len(lb)) / max(len(la), 1), 4),
            "yield_b": len(set(r["cve"] for r in lb if r.get("unittest_status") is True)),
        }

    return {
        "total_attempts": total_attempts,
        "total_cves": total_cves,
        "condition_a": {
            "accepted_count": len(cond_a),
            "fp_count": len(cond_a_fp),
            "tp_count": len(cond_a_strong),
            "fdr": round(fdr_a, 4),
            "fdr_pct": f"{fdr_a * 100:.1f}%",
            "yield_count": yield_a,
            "yield_rate": round(yield_a / max(total_cves, 1), 4),
        },
        "condition_b": {
            "accepted_count": len(cond_b),
            "fp_count": len(cond_b_fp),
            "tp_count": len(cond_b_strong),
            "fdr": round(fdr_b, 4),
            "fdr_pct": f"{fdr_b * 100:.1f}%",
            "yield_count": yield_b,
            "yield_rate": round(yield_b / max(total_cves, 1), 4),
            "strong_oracle_pass_rate": round(strong_rate_b, 4),
        },
        "b_vs_a": {
            "rejection_count": len(cond_a) - len(cond_b),
            "rejection_rate": round(rejection_rate, 4),
            "rejection_rate_pct": f"{rejection_rate * 100:.1f}%",
            "fdr_delta_abs": round(fdr_a - fdr_b, 4),
            "fdr_delta_rel": round((fdr_a - fdr_b) / max(fdr_a, 1e-9), 4),
            "yield_loss": yield_a - yield_b,
            "yield_loss_pct": f"{(yield_a - yield_b) / max(yield_a, 1) * 100:.1f}%",
        },
        "checker_distribution": dict(checker_dist),
        "by_language": by_language,
        "by_cwe": by_cwe,
    }


def compute_epoch_stats(records: list) -> dict:
    """Compute mean ± std metrics across epochs."""
    epochs = defaultdict(list)
    for r in records:
        if r.get("epoch") is not None:
            epochs[r["epoch"]].append(r)

    epoch_fdrs_a, epoch_fdrs_b, epoch_rejections = [], [], []
    for epoch, epoch_recs in sorted(epochs.items()):
        cond_a = [r for r in epoch_recs if r.get("poc_status") is True]
        cond_b = [r for r in cond_a if r.get("condition_b_pass")]
        if not cond_a:
            continue
        cond_a_fp = [r for r in cond_a if not r.get("unittest_status")]
        cond_b_fp = [r for r in cond_b if not r.get("unittest_status")]
        fdr_a_ep = len(cond_a_fp) / max(len(cond_a), 1)
        fdr_b_ep = len(cond_b_fp) / max(len(cond_b), 1) if cond_b else 0.0
        rej_rate = (len(cond_a) - len(cond_b)) / max(len(cond_a), 1)
        epoch_fdrs_a.append(fdr_a_ep)
        epoch_fdrs_b.append(fdr_b_ep)
        epoch_rejections.append(rej_rate)

    def stats(vals):
        if not vals:
            return {"mean": None, "std": None}
        return {
            "mean": round(statistics.mean(vals), 4),
            "std": round(statistics.stdev(vals) if len(vals) > 1 else 0.0, 4),
        }

    return {
        "fdr_a_across_epochs": stats(epoch_fdrs_a),
        "fdr_b_across_epochs": stats(epoch_fdrs_b),
        "rejection_rate_across_epochs": stats(epoch_rejections),
        "n_epochs": len(epoch_fdrs_a),
    }


def process_model(
    log_file: str,
    model_name: str,
    meta: dict,
    codeql_bin: str,
    codeql_repo: str,
    cwe_map_path: str,
    workers: int,
    tmpdir_base: str,
) -> dict:
    """Process a single model's log file and return all per-record results."""
    logger.info("Processing model: %s", model_name)
    records = load_model_data(log_file)
    logger.info("  Loaded %d records, %d Condition-A accepted",
                len(records), sum(1 for r in records if r.get("poc_status") is True))

    # Prepare worker args for Condition-A-accepted records only
    work_args = []
    passthrough_records = []
    for rec in records:
        if not rec.get("poc_status"):
            # Not Condition-A accepted — mark B as failed
            passthrough_records.append({
                **rec,
                "condition_b_pass": False,
                "checker": "skipped",
                "pre_findings": None,
                "post_findings": None,
                "cwe_used": rec["cwe"][0] if rec.get("cwe") else "unknown",
                "error": None,
            })
            continue
        cve = rec["cve"]
        meta_entry = meta.get(cve)
        work_args.append((rec, meta_entry, codeql_bin, codeql_repo, cwe_map_path, tmpdir_base))

    logger.info("  Dispatching %d checker jobs with %d workers", len(work_args), workers)
    checked_records = []
    if workers > 1 and work_args:
        with ProcessPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(_check_single, args): args for args in work_args}
            for i, future in enumerate(as_completed(futures)):
                try:
                    result = future.result(timeout=300)
                    checked_records.append(result)
                except Exception as e:
                    logger.warning("Worker exception: %s", e)
                    orig_args = futures[future]
                    rec = orig_args[0]
                    checked_records.append({
                        "cve": rec["cve"],
                        "epoch": rec["epoch"],
                        "language": rec["language"],
                        "cwe": rec["cwe"],
                        "poc_status": rec["poc_status"],
                        "unittest_status": rec["unittest_status"],
                        "condition_b_pass": True,
                        "checker": "exception",
                        "pre_findings": None,
                        "post_findings": None,
                        "cwe_used": rec["cwe"][0] if rec.get("cwe") else "unknown",
                        "error": str(e)[:200],
                    })
                if (i + 1) % 50 == 0:
                    logger.info("  %d/%d done", i + 1, len(work_args))
    else:
        for args in work_args:
            checked_records.append(_check_single(args))

    all_records = passthrough_records + checked_records
    return all_records


def main():
    parser = argparse.ArgumentParser(description="PatchEval Condition B evaluator")
    parser.add_argument("--log-dir", required=True,
                        help="Directory with LLM log files")
    parser.add_argument("--input-json", required=True,
                        help="Path to PatchEval input.json")
    parser.add_argument("--codeql-dir", required=True,
                        help="Path to CodeQL CLI directory (contains codeql binary)")
    parser.add_argument("--codeql-repo", required=True,
                        help="Path to CodeQL standard library repo")
    parser.add_argument("--cwe-map", default=None,
                        help="Path to cwe_query_map.yaml (default: smd/configs/cwe_query_map.yaml)")
    parser.add_argument("--workers", type=int, default=8,
                        help="Number of parallel worker processes")
    parser.add_argument("--output", required=True,
                        help="Output JSON file path")
    parser.add_argument("--tmpdir", default=None,
                        help="Base temp directory for CodeQL work (default: system temp)")
    parser.add_argument("--models", nargs="*", default=None,
                        help="Specific model files to process (default: all)")
    args = parser.parse_args()

    # Resolve paths
    codeql_bin = os.path.join(args.codeql_dir, "codeql")
    if not os.path.exists(codeql_bin):
        codeql_bin = args.codeql_dir  # might be direct path
    codeql_repo = os.path.abspath(args.codeql_repo)
    cwe_map_path = args.cwe_map or str(ROOT / "smd" / "configs" / "cwe_query_map.yaml")

    # Verify codeql binary
    if not os.path.exists(codeql_bin):
        logger.error("CodeQL binary not found at %s", codeql_bin)
        sys.exit(1)

    logger.info("Loading input metadata from %s", args.input_json)
    meta = load_input_metadata(args.input_json)
    logger.info("Loaded metadata for %d CVEs", len(meta))

    # Find log files
    log_dir = Path(args.log_dir)
    if args.models:
        log_files = [(log_dir / f, MODEL_DISPLAY.get(f, f)) for f in args.models]
    else:
        log_files = [(f, MODEL_DISPLAY.get(f.name, f.name)) for f in sorted(log_dir.glob("*.json"))]

    tmpdir_base = args.tmpdir or tempfile.gettempdir()
    os.makedirs(tmpdir_base, exist_ok=True)

    all_results = {}

    for log_file, model_name in log_files:
        if not log_file.exists():
            logger.warning("Log file not found: %s", log_file)
            continue
        logger.info("=" * 60)
        logger.info("Model: %s", model_name)

        records = process_model(
            str(log_file), model_name, meta,
            codeql_bin, codeql_repo, cwe_map_path,
            workers=args.workers,
            tmpdir_base=tmpdir_base,
        )

        metrics = compute_condition_b_metrics(records)
        epoch_stats = compute_epoch_stats(records)
        metrics["epoch_stats"] = epoch_stats
        metrics["model"] = model_name
        metrics["log_file"] = log_file.name

        all_results[model_name] = metrics

        # Log summary
        cond_b = metrics["condition_b"]
        logger.info("  FDR_A=%.1f%% -> FDR_B=%.1f%% | Yield_B=%d | Rejection=%.1f%%",
                    metrics["condition_a"]["fdr"] * 100,
                    cond_b["fdr"] * 100,
                    cond_b["yield_count"],
                    metrics["b_vs_a"]["rejection_rate"] * 100)

    # Save results
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(all_results, f, indent=2)
    logger.info("Results written to %s", output_path)


if __name__ == "__main__":
    main()
