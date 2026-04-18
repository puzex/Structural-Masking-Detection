#!/bin/bash
# Debug run: process only first 50 stage1-pass attempts to verify correctness
set -eu
cd /mnt/fars_task/7445860835987065088/7445862364995390976/agents/experiment/exp
source .venv/bin/activate
export PATH="$PWD/tools/codeql:$PATH"

echo "=== Condition B Debug Run (50 stage1-pass attempts) ==="
python smd/baselines/condition_b_evaluator.py \
    --condition-a-parquet smd/results/pvbench_condition_a_df.parquet \
    --eval-dir benchmarks/pvbench/artifacts/eval \
    --vuln-dir benchmarks/pvbench/vuln \
    --output smd/results/pvbench_condition_b_debug.json \
    --workers 4 \
    --debug-n 50

echo "=== Debug run complete ==="
cat smd/results/pvbench_condition_b_debug.json
