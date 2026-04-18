# Parse PVBench released evaluation artifacts into a structured DataFrame.
# Determines stage1_pass (weak oracle) and pocplus_pass (strong oracle) for each
# patch attempt across PatchAgent and San2Patch under gpt-4.1 and claude-4-sonnet.
# Writes aggregated Condition A metrics to smd/results/pvbench_condition_a.json.

import json
import re
import sys
from pathlib import Path

import pandas as pd
import yaml

ROOT = Path(__file__).resolve().parents[2]
PVBENCH = ROOT / "benchmarks" / "pvbench"
EVAL_DIR = PVBENCH / "artifacts" / "eval"
VULN_DIR = PVBENCH / "vuln"
RESULTS_DIR = ROOT / "smd" / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

sys.path.insert(0, str(ROOT))
from smd.evaluation.metrics import compute_condition_a_metrics, compute_cwe_catalog, map_type_to_cwe


def load_vuln_metadata() -> dict[str, dict]:
    meta = {}
    for cfg_path in VULN_DIR.rglob("config.yaml"):
        dir_id = cfg_path.parent.name
        with open(cfg_path) as f:
            cfg = yaml.safe_load(f)
        meta[dir_id] = {
            "vuln_id": dir_id,
            "project": cfg.get("project", ""),
            "type": cfg.get("type", ""),
            "sanitizer": cfg.get("sanitizer", ""),
            "patch_commit": cfg.get("patch", {}).get("commit", "") if isinstance(cfg.get("patch"), dict) else "",
        }
    return meta


BASE_FILE_RE = re.compile(r"^(.+?):([^:]+):(\d+)\.json$")


def scan_tool_dir(tool_dir: Path, tool_name: str) -> list[dict]:
    records = []
    base_files = [f for f in tool_dir.iterdir() if BASE_FILE_RE.match(f.name)]
    for base_file in base_files:
        m = BASE_FILE_RE.match(base_file.name)
        if not m:
            continue
        vuln_id, model, attempt = m.group(1), m.group(2), m.group(3)
        post_file = tool_dir / f"{vuln_id}:{model}:{attempt}:post.json"
        stage1_pass = post_file.exists()
        pocplus_pass = False
        if stage1_pass:
            try:
                with open(post_file) as f:
                    post_data = json.load(f)
                if isinstance(post_data, dict):
                    pocplus_pass = bool(post_data.get("result", False))
                elif isinstance(post_data, list) and len(post_data) > 0:
                    pocplus_pass = bool(post_data[0].get("result", False))
            except (json.JSONDecodeError, KeyError, IndexError):
                pocplus_pass = False
        patch_diff = ""
        try:
            with open(base_file) as f:
                base_data = json.load(f)
            if isinstance(base_data, dict):
                patch_diff = base_data.get("patch", "")
            elif isinstance(base_data, list) and len(base_data) > 0:
                patch_diff = base_data[0].get("patch", "")
        except (json.JSONDecodeError, KeyError):
            patch_diff = ""
        records.append({
            "vuln_id": vuln_id,
            "tool": tool_name,
            "model": model,
            "attempt": int(attempt),
            "patch_diff": patch_diff,
            "stage1_pass": stage1_pass,
            "pocplus_pass": pocplus_pass,
        })
    return records


def build_dataframe(vuln_meta: dict[str, dict]) -> pd.DataFrame:
    records = []
    for tool_name in ("patchagent", "san2patch"):
        tool_dir = EVAL_DIR / tool_name
        if not tool_dir.exists():
            print(f"Warning: {tool_dir} not found, skipping")
            continue
        tool_records = scan_tool_dir(tool_dir, tool_name)
        records.extend(tool_records)

    df = pd.DataFrame(records)
    if df.empty:
        raise RuntimeError("No records found — check eval directory structure")

    meta_df = pd.DataFrame(list(vuln_meta.values()))
    meta_df["cwe"] = meta_df["type"].apply(map_type_to_cwe)
    meta_df["vcg_feasible"] = meta_df["patch_commit"].apply(lambda x: bool(x))

    df = df.merge(
        meta_df[["vuln_id", "project", "type", "sanitizer", "cwe", "vcg_feasible"]],
        on="vuln_id",
        how="left",
    )
    df["type"] = df["type"].fillna("Unknown")
    df["cwe"] = df["cwe"].fillna("CWE-UNKNOWN")
    df["vcg_feasible"] = df["vcg_feasible"].fillna(False)
    return df


def verify_against_reference(metrics: dict) -> None:
    """Check computed FDR against PVBench paper-reported 42.3% (1250/2952)."""
    ref_fp = 1250
    ref_accepted = 2952
    ref_fdr = ref_fp / ref_accepted
    computed_fdr = metrics["fdr"]
    computed_fp = metrics["fp_count"]
    computed_accepted = metrics["accepted_count"]
    print(f"\nReference (PVBench paper): FP={ref_fp}, Accepted={ref_accepted}, FDR={ref_fdr:.4f} (42.3%)")
    print(f"Computed:                  FP={computed_fp}, Accepted={computed_accepted}, FDR={computed_fdr:.4f} ({computed_fdr*100:.1f}%)")
    diff = abs(computed_fdr - ref_fdr)
    if diff < 0.05:
        print(f"MATCH: FDR within 5pp of reference (diff={diff:.4f})")
    else:
        print(f"MISMATCH: FDR differs by {diff:.4f} from reference — investigate")


def main():
    print("Loading vulnerability metadata...")
    vuln_meta = load_vuln_metadata()
    print(f"  Found {len(vuln_meta)} vulnerabilities")

    print("Building patch attempt DataFrame...")
    df = build_dataframe(vuln_meta)
    print(f"  Total records: {len(df)}")
    print(f"  Tools: {sorted(df['tool'].unique())}")
    print(f"  Models: {sorted(df['model'].unique())}")
    print(f"  Unique vulns in eval: {df['vuln_id'].nunique()}")
    print(f"  Stage1 pass: {df['stage1_pass'].sum()} / {len(df)}")
    print(f"  PoCplus pass: {df['pocplus_pass'].sum()} / {len(df)}")

    print("\nComputing Condition A metrics...")
    metrics = compute_condition_a_metrics(df)
    verify_against_reference(metrics)

    print("\nBuilding CWE catalog...")
    catalog = compute_cwe_catalog(df)
    print(f"  CWE categories found: {len(catalog)}")
    for entry in catalog:
        print(f"    {entry['cwe']:12s}  {entry['vuln_count']:3d} vulns  "
              f"VCG-feasible: {entry['vcg_feasible_count']}/{entry['vuln_count']}")

    output = {
        "condition_a_metrics": metrics,
        "cwe_catalog": catalog,
        "raw_counts": {
            "total_records": len(df),
            "unique_vulns_in_eval": int(df["vuln_id"].nunique()),
            "total_vulns_in_benchmark": len(vuln_meta),
        },
    }

    out_path = RESULTS_DIR / "pvbench_condition_a.json"
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults written to {out_path}")

    df_path = RESULTS_DIR / "pvbench_condition_a_df.parquet"
    df_no_patch = df.drop(columns=["patch_diff"])
    df_no_patch.to_parquet(df_path, index=False)
    print(f"DataFrame (no patch text) written to {df_path}")

    return output


if __name__ == "__main__":
    main()
