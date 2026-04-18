#!/bin/bash
# Full Condition B evaluation on PVBench
set -eu
cd /mnt/fars_task/7445860835987065088/7445862364995390976/agents/experiment/exp
source .venv/bin/activate
export PATH="$PWD/tools/codeql:$PATH"

echo "=== Condition B Full Run ==="
python smd/baselines/condition_b_evaluator.py \
    --condition-a-parquet smd/results/pvbench_condition_a_df.parquet \
    --eval-dir benchmarks/pvbench/artifacts/eval \
    --vuln-dir benchmarks/pvbench/vuln \
    --output smd/results/pvbench_condition_b.json \
    --workers 8

echo "=== Full run complete ==="
