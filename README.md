# Structural Masking Detection for Reference-Free Validation of LLM-Generated Security Patches

## Project Overview

This project implements the **Structural Masking Detector (SMD)** — a reference-free patch validator that detects structurally-masking patches by analyzing vulnerability causal graphs (VCG). SMD uses two signatures:
- **S1**: Early-exit dominance (patch inserts a dominating early-exit before the vulnerability sink)
- **S2**: Sink removed/unreachable (vulnerability sink is deleted or unreachable in post-patch CFG)

Evaluated on two benchmarks: **PVBench** (209 C/C++ vulnerabilities) and **PatchEval** (230 CVEs, Python/JS/Go).

## Environment Setup

### Activate Virtual Environment
```bash
source .venv/bin/activate
```

### Tool Paths
```bash
# CodeQL CLI (v2.25.1)
export PATH="$PWD/tools/codeql:$PATH"

# JDK 21 (required for Joern)
export JAVA_HOME="$PWD/tools/jdk21"
export PATH="$JAVA_HOME/bin:$PATH"

# Joern (installed at /opt/joern/joern-cli/, symlinked in /usr/local/bin/)
# Already on PATH after Joern install
```

### Key Tool Locations
| Tool | Location |
|------|----------|
| CodeQL CLI v2.25.1 | `./tools/codeql/` |
| CodeQL standard library | `./tools/codeql-repo/` |
| JDK 21 (Temurin) | `./tools/jdk21/` |
| Joern v4.0.516 | `./tools/joern/joern-cli/joern` |
| PVBench | `./benchmarks/pvbench/` |
| PatchEval | `./benchmarks/patcheval/` |

## Project Structure

```
smd/                  # Main SMD codebase
  vcg/                # VCG extraction (codeql_vcg.py for C/C++, joern_vcg.py for Python/JS/Go)
  signatures/         # S1/S2 structural masking signature detectors
  baselines/          # Condition B static flow checker implementations
  evaluation/         # PVBench and PatchEval evaluation pipelines
  analysis/           # Ablation studies and diagnostic analysis
  configs/            # CWE-to-query mappings (cwe_query_map.yaml)
  results/            # Evaluation results output (gitignored)
benchmarks/
  pvbench/            # PVBench: 209 C/C++ vulnerabilities
  patcheval/          # PatchEval: 230 CVEs (Python/JS/Go)
tools/
  codeql/             # CodeQL CLI bundle
  codeql-repo/        # CodeQL standard library (C/C++ dominance queries)
  jdk21/              # OpenJDK 21 for Joern
  joern/              # Joern v4.0.516 (joern-cli/) — multi-language CPG
```

## Configuration

- CWE-to-query mappings: `smd/configs/cwe_query_map.yaml`

## Key Dependencies (in .venv)

- `tree-sitter`, `tree-sitter-c/cpp/python/javascript/go` — AST parsing and sink mapping
- `docker` — Python Docker SDK for sandbox evaluation
- `networkx` — Graph analysis for VCG
- `semgrep` — Fallback static analyzer for CWEs without CodeQL support
- `openai`, `anthropic`, `google-generativeai` — LLM APIs for PatchEval generation

## Development Notes

- Docker CLI is not available in the local container; Docker-based evaluations run via TrainService
- Joern binary: `tools/joern/joern-cli/joern`. Requires `JAVA_HOME=tools/jdk21` and `PATH=$JAVA_HOME/bin:$PATH`
- Joern workspace directory (CPG artifacts) is gitignored; set `JAVA_HOME` before running Joern scripts
- `git commit` is slow due to pre-commit hook traversing large tool directories; temporarily move them outside `experiment/` before committing (see FARS_MEMO)
- `google-generativeai` shows a deprecation warning; it still works but may need migration to `google-genai`
- PatchEval installed with `pip install -r benchmarks/patcheval/requirements.txt`

## SMD v2.0 (Task 6 Optimization)

Key changes to the SMD pipeline:
- `smd/signatures/detector.py`: CWE-aware dispatch (`cwe` param added to `run_smd()`). Auto-rejects CWE-704/362/457/369; skips all signatures for CWE-416/617/670/122/415; uses S1-only for CWE-476/121/190.
- `smd/signatures/s1_early_exit.py`: `_is_inside_conditional` now uses full brace-depth tracking from hunk start (not just 8-line lookback).
- `smd/evaluation/pvbench_eval.py`: Passes `cwe` to `run_smd()`.
- `smd/configs/signature_spec.yaml`: Updated to v2.0 with CWE dispatch table.



## SMD v2.0 PatchEval (Task 8 Optimization)

Key changes to `smd/evaluation/patcheval_eval.py`:
- `PATCHEVAL_CWE_AUTO_REJECT`: Added CWE-287, CWE-862 (high FDR, no valid patches).
- `PATCHEVAL_CWE_SKIP_ALL`: Expanded to include CWE-73/601/22/78/284/471/444 (precision=0%).
- `PATCHEVAL_JS_S2_SKIP`: Added CWE-94 for JavaScript (S2 unreachable has near-random precision).
- `_COMP_FIX_EXTRA`: Extended from 15 to 30 patterns (subprocess.run, ast.literal_eval, shlex, exec.Command, allow-list patterns).
=======
# Structural-Masking-Detection
This project implements the **Structural Masking Detector (SMD)** — a reference-free patch validator that detects structurally-masking patches by analyzing vulnerability causal graphs (VCG).
>>>>>>> 34b2350b4f35257db17e6179c00c2595532779e0
