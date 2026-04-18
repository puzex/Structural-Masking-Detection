# Metrics computation: FDR (false discovery rate), yield, precision, recall.
# Computes per-condition and per-CWE stratified metrics for PVBench and PatchEval.
# Also computes diagnostic coverage ceiling metrics.

import pandas as pd
from typing import Any

TYPE_TO_CWE = {
    "NULL Pointer Dereference": "CWE-476",
    "Heap Buffer Overflow": "CWE-122",
    "Stack Buffer Overflow": "CWE-121",
    "Use After Free": "CWE-416",
    "Double Free": "CWE-415",
    "Integer Overflow": "CWE-190",
    "Reachable Assertion": "CWE-617",
    "Incorrect Type Conversion or Cast": "CWE-704",
    "Always-Incorrect Control Flow": "CWE-670",
    "Use of Uninitialized Variable": "CWE-457",
    "Race Condition": "CWE-362",
    "Divide by Zero": "CWE-369",
}


def map_type_to_cwe(vuln_type: str) -> str:
    return TYPE_TO_CWE.get(vuln_type, "CWE-UNKNOWN")


def _safe_fdr(fp: int, accepted: int) -> float:
    return fp / accepted if accepted > 0 else 0.0


def compute_condition_a_metrics(df: pd.DataFrame) -> dict[str, Any]:
    """Compute Condition A metrics: accepted = stage1_pass == True.

    Returns a dict with overall metrics and breakdowns by tool, model, cwe.
    """
    total_attempts = len(df)
    accepted = df[df["stage1_pass"] == True]
    accepted_count = len(accepted)

    tp = accepted[accepted["pocplus_pass"] == True]
    fp = accepted[accepted["pocplus_pass"] == False]
    tp_count = len(tp)
    fp_count = len(fp)

    overall_fdr = _safe_fdr(fp_count, accepted_count)
    strong_oracle_pass_rate = tp_count / total_attempts if total_attempts > 0 else 0.0

    # Yield: unique vuln_ids with at least one accepted AND pocplus_pass patch
    yield_vulns = tp["vuln_id"].nunique()
    total_vulns = df["vuln_id"].nunique()

    def breakdown(group_col: str) -> dict[str, dict]:
        result = {}
        for grp, sub in accepted.groupby(group_col):
            grp_tp = int((sub["pocplus_pass"] == True).sum())
            grp_fp = int((sub["pocplus_pass"] == False).sum())
            grp_accepted = len(sub)
            grp_fdr = _safe_fdr(grp_fp, grp_accepted)
            grp_yield = sub[sub["pocplus_pass"] == True]["vuln_id"].nunique()
            result[str(grp)] = {
                "accepted": grp_accepted,
                "tp": grp_tp,
                "fp": grp_fp,
                "fdr": round(grp_fdr, 4),
                "yield": int(grp_yield),
            }
        return result

    by_tool = breakdown("tool")
    by_model = breakdown("model")
    by_cwe = breakdown("cwe")

    return {
        "condition": "A",
        "total_attempts": total_attempts,
        "total_vulns": total_vulns,
        "accepted_count": accepted_count,
        "tp_count": tp_count,
        "fp_count": fp_count,
        "fdr": round(overall_fdr, 4),
        "yield_count": int(yield_vulns),
        "strong_oracle_pass_rate": round(strong_oracle_pass_rate, 4),
        "by_tool": by_tool,
        "by_model": by_model,
        "by_cwe": by_cwe,
    }


def compute_cwe_catalog(df: pd.DataFrame) -> list[dict[str, Any]]:
    """Per-CWE summary with VCG feasibility flags.

    VCG feasibility is flagged True for all vulns where patch_commit is available
    (passed in as 'vcg_feasible' column). If column absent, defaults to True.
    """
    catalog = []
    vuln_meta = df.drop_duplicates("vuln_id")[
        ["vuln_id", "project", "type", "cwe", "vcg_feasible"]
    ]
    for cwe, group in vuln_meta.groupby("cwe"):
        vcg_feasible_count = int(group["vcg_feasible"].sum())
        projects = sorted([p for p in group["project"].dropna().unique().tolist() if p])
        catalog.append(
            {
                "cwe": str(cwe),
                "type": group["type"].iloc[0],
                "vuln_count": len(group),
                "vcg_feasible_count": vcg_feasible_count,
                "projects": projects,
            }
        )
    return sorted(catalog, key=lambda x: -x["vuln_count"])
