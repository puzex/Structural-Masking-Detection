#!/bin/bash
# Run PatchEval Condition B evaluation using CodeQL + Semgrep differential analysis.
# Designed to run in TrainService with 32+ CPU cores and 64GB+ RAM.

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKDIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$WORKDIR"

source .venv/bin/activate

export PATH="$WORKDIR/tools/codeql:$PATH"
export JAVA_HOME="$WORKDIR/tools/jdk21"
export PATH="$JAVA_HOME/bin:$PATH"

WORKERS=${WORKERS:-16}
OUTPUT="smd/results/patcheval_condition_b.json"
TMPDIR_BASE="/tmp/patcheval_codeql_work"

mkdir -p "$TMPDIR_BASE"
mkdir -p smd/results

echo "PatchEval Condition B Evaluation"
echo "  WorkDir: $WORKDIR"
echo "  Workers: $WORKERS"
echo "  Output: $OUTPUT"
echo "  CodeQL: $(tools/codeql/codeql version 2>/dev/null | head -1)"
echo "  Python: $(python --version)"
echo "  Semgrep: $(semgrep --version 2>/dev/null || echo 'not found')"

python smd/baselines/patcheval_condition_b_evaluator.py \
    --log-dir benchmarks/patcheval/patcheval/log/llm \
    --input-json benchmarks/patcheval/patcheval/datasets/input.json \
    --codeql-dir tools/codeql \
    --codeql-repo tools/codeql-repo \
    --workers "$WORKERS" \
    --output "$OUTPUT" \
    --tmpdir "$TMPDIR_BASE"

echo "Done. Results at $OUTPUT"
