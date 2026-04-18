# S1: Early-exit dominance signature.
# Detects patches that insert a dominating early-exit (return/throw/exit/abort)
# strictly BEFORE the vulnerability sink block, masking the sink without fixing
# the root cause.  Dominance is approximated by positional order in the post-patch
# diff: an early-exit at post-patch line L_exit dominates sink at L_sink if
# L_exit < L_sink and both are in the same function hunk.

import logging
import re
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from smd.vcg.codeql_vcg import parse_unified_diff

logger = logging.getLogger(__name__)

# Pre-registered early-exit patterns (signature_spec.yaml S1)
# Extended to cover Python/Go/JS language-specific exits in addition to C/C++.
EARLY_EXIT_PATTERNS = [
    ("return_statement",  re.compile(r"\breturn\b")),
    ("throw_statement",   re.compile(r"\bthrow\b")),
    ("exit_call",         re.compile(r"(?:^|[^_\w])_?exit\s*\(")),
    ("abort_call",        re.compile(r"(?:std::)?abort\s*\(\s*\)")),
    ("error_goto",        re.compile(r"\bgoto\s+\w*(err|fail|error|bail|cleanup|out)\w*\b", re.IGNORECASE)),
    ("halt_call",         re.compile(r"xmlHaltParser\s*\(")),
    # Python
    ("raise_statement",   re.compile(r"\braise\b")),
    ("sys_exit",          re.compile(r"\bsys\.exit\s*\(")),
    # Go
    ("panic_call",        re.compile(r"\bpanic\s*\(")),
    ("os_exit",           re.compile(r"\bos\.Exit\s*\(")),
    ("log_fatal",         re.compile(r"\blog\.(?:Fatal|Fatalf|Fatalln|Panic|Panicf|Panicln)\s*\(")),
]

# Conditional keyword — exit inside these scopes is NOT an unconditional dominator
CONDITIONAL_SCOPE_RE = re.compile(r"^\s*(if|else\s*if|else|switch)\b")
# Open brace on same line as conditional => next lines are inside conditional scope
CONDITIONAL_OPEN_BRACE_RE = re.compile(r"^\s*(if|else\s*if|else|switch)\b.*\{")


def _classify_early_exit(line_content: str) -> str | None:
    """Return the exit type label if this line is an early-exit, else None."""
    stripped = line_content.strip()
    if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("#"):
        return None
    for label, pat in EARLY_EXIT_PATTERNS:
        if pat.search(stripped):
            return label
    return None


def _is_inside_conditional(hunk_lines: list, exit_idx: int) -> bool:
    """
    Check if the early-exit at hunk_lines[exit_idx] is inside a conditional block.

    Uses full brace-depth tracking from the start of the hunk to the exit line.
    An early-exit is considered conditional if:
    - The net brace depth at the exit line is > 1 (inside a nested scope beyond function body), OR
    - The immediately preceding non-blank, non-comment line is a conditional statement (if/else/switch/for/while).
    """
    brace_depth = 0
    prev_meaningful_content = ""

    for i in range(exit_idx):
        rec = hunk_lines[i]
        if rec["type"] == "-":
            continue
        content = rec["content"]
        stripped = content.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("*"):
            continue

        opens = content.count("{")
        closes = content.count("}")
        brace_depth += opens - closes

        prev_meaningful_content = content

    # If brace depth > 1, we are inside a conditional/loop scope
    # (depth 1 = function body open brace, depth 2+ = nested block)
    if brace_depth > 1:
        return True

    # Also check if the immediately preceding meaningful line is a conditional
    stripped_prev = prev_meaningful_content.strip()
    if CONDITIONAL_SCOPE_RE.match(prev_meaningful_content):
        return True
    if CONDITIONAL_OPEN_BRACE_RE.match(prev_meaningful_content):
        return True
    # Standalone open brace after a conditional keyword
    if stripped_prev == "{":
        return True

    return False


def _normalize_file(path: str | None) -> str:
    if not path:
        return ""
    p = path.strip()
    if p.startswith("a/") or p.startswith("b/"):
        p = p[2:]
    return p


def check_s1(
    llm_patch_diff: str,
    sink_line_pre: int | None,
    sink_line_post: int | None,
    ref_file: str = "",
    ref_func: str = "",
) -> dict:
    """
    Check S1: Early-Exit Dominance.

    A patch is flagged by S1 if ANY newly introduced early-exit statement has
    a post-patch line number strictly less than the mapped sink post-patch line.

    Args:
        llm_patch_diff: Unified diff text of the LLM-generated patch.
        sink_line_pre: Pre-patch sink line (used for fallback comparison).
        sink_line_post: Post-patch sink line (primary comparison).
        ref_file: Reference file path (to restrict analysis to same file).
        ref_func: Reference function name (to restrict to same function hunk).

    Returns:
        {
            "s1_fires": bool,
            "evidence": list of {line, text, exit_type, dominates_sink},
            "n_new_early_exits": int,
            "sink_line_post": int | None,
        }
    """
    result = {
        "s1_fires": False,
        "evidence": [],
        "n_new_early_exits": 0,
        "sink_line_post": sink_line_post,
    }

    if sink_line_post is None and sink_line_pre is None:
        return result

    effective_sink = sink_line_post if sink_line_post is not None else sink_line_pre

    if not llm_patch_diff or not llm_patch_diff.strip():
        return result

    try:
        hunks = parse_unified_diff(llm_patch_diff)
    except Exception:
        return result

    ref_file_base = Path(_normalize_file(ref_file)).name if ref_file else ""

    for h in hunks:
        hunk_file = _normalize_file(h.get("file_old") or h.get("file_new") or "")
        hunk_file_base = Path(hunk_file).name if hunk_file else ""

        # Filter to same file if ref_file provided
        if ref_file_base and hunk_file_base and ref_file_base != hunk_file_base:
            # Allow suffix match
            if not (
                _normalize_file(ref_file).endswith(hunk_file)
                or hunk_file.endswith(_normalize_file(ref_file))
            ):
                continue

        # Scan '+' lines for newly introduced early-exits
        hunk_lines = h["lines"]
        for idx, line_rec in enumerate(hunk_lines):
            if line_rec["type"] != "+":
                continue
            content = line_rec["content"]
            exit_type = _classify_early_exit(content)
            if exit_type is None:
                continue

            # Skip if this exit is inside a conditional block (it's a guarded early-exit, not masking)
            if _is_inside_conditional(hunk_lines, idx):
                continue

            new_lineno = line_rec.get("new_lineno")
            dominates = (
                new_lineno is not None
                and effective_sink is not None
                and new_lineno < effective_sink
            )
            evidence_item = {
                "line": new_lineno,
                "text": content.strip(),
                "exit_type": exit_type,
                "dominates_sink": dominates,
            }
            result["evidence"].append(evidence_item)
            result["n_new_early_exits"] += 1

            if dominates:
                result["s1_fires"] = True

    return result


# ── Joern-based S1 (dominance query via CPG) ────────────────────────────────

_S1_JOERN_SCRIPT_TEMPLATE = """
importCode.{lang}("{src_path}")
val sinkNode = cpg.call.lineNumber({sink_line}).l.headOption
val exits = (cpg.ret.l ++ cpg.call.name("(raise|sys\\\\.exit|panic|os\\\\.Exit|log\\\\.Fatal|log\\\\.Fatalf|log\\\\.Fatalln|log\\\\.Panic|log\\\\.Panicf|log\\\\.Panicln|throw)").l).distinctBy(_.id)
val dominating = exits.filter(e => sinkNode.exists(s => e.dominates.exists(_ == s)))
println(dominating.map(d => s"${{d.lineNumber.getOrElse(-1)}}:${{d.code.take(80)}}").mkString("|"))
"""

_LANG_TO_JOERN = {
    "Python": "python",
    "py": "python",
    "JavaScript": "jssrc",
    "js": "jssrc",
    "Go": "go",
    "go": "go",
}

_LANG_TO_EXT = {
    "Python": ".py",
    "py": ".py",
    "JavaScript": ".js",
    "js": ".js",
    "Go": ".go",
    "go": ".go",
}


def check_s1_joern(
    fix_code_snippet: str,
    sink_line_post: int,
    language: str,
) -> dict:
    """
    S1 via Joern dominance query on post-patch fix_code snippet.

    Writes fix_code to a temp file, builds CPG via Joern, and queries whether
    any newly-introduced early-exit dominates the sink node.

    Args:
        fix_code_snippet: Post-patch function code (from fix_code field in PatchEval log).
        sink_line_post: Post-patch line number of the sink (1-based, relative to snippet start).
        language: "Python", "JavaScript", or "Go".

    Returns:
        {
            "s1_fires": bool | None,   # None if Joern failed
            "evidence": list,
            "method": "joern",
            "error": str | None,
        }
    """
    import os
    import subprocess
    import tempfile

    joern_lang = _LANG_TO_JOERN.get(language)
    ext = _LANG_TO_EXT.get(language, ".py")

    if not joern_lang or not fix_code_snippet or sink_line_post is None:
        return {"s1_fires": None, "evidence": [], "method": "joern", "error": "missing_input"}

    here = Path(__file__).resolve().parents[2]
    joern_bin = here / "tools" / "joern" / "joern-cli" / "joern"
    jdk21_bin = here / "tools" / "jdk21" / "bin"

    if not joern_bin.exists():
        return {"s1_fires": None, "evidence": [], "method": "joern", "error": "joern_not_found"}

    with tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False) as sf:
        sf.write(fix_code_snippet)
        src_path = sf.name

    script_content = _S1_JOERN_SCRIPT_TEMPLATE.format(
        lang=joern_lang,
        src_path=src_path.replace("\\", "/"),
        sink_line=sink_line_post,
    )
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sc", delete=False) as scf:
        scf.write(script_content)
        script_path = scf.name

    env = dict(os.environ)
    env["JAVA_HOME"] = str(jdk21_bin.parent)
    env["PATH"] = str(jdk21_bin) + ":" + env.get("PATH", "")

    try:
        result = subprocess.run(
            [str(joern_bin), "--script", script_path],
            capture_output=True, text=True, timeout=90, env=env,
        )
        output = result.stdout.strip()
    except subprocess.TimeoutExpired:
        return {"s1_fires": None, "evidence": [], "method": "joern", "error": "timeout"}
    except Exception as e:
        return {"s1_fires": None, "evidence": [], "method": "joern", "error": str(e)}
    finally:
        for p in (src_path, script_path):
            try:
                os.unlink(p)
            except OSError:
                pass

    if not output:
        return {"s1_fires": False, "evidence": [], "method": "joern", "error": None}

    evidence = []
    s1_fires = False
    for token in output.split("|"):
        token = token.strip()
        if not token or token == "null":
            continue
        parts = token.split(":", 1)
        try:
            lineno = int(parts[0])
        except (ValueError, IndexError):
            continue
        code_text = parts[1] if len(parts) > 1 else ""
        if lineno > 0 and lineno < sink_line_post:
            s1_fires = True
            evidence.append({"line": lineno, "text": code_text, "exit_type": "joern_dominance", "dominates_sink": True})

    return {"s1_fires": s1_fires, "evidence": evidence, "method": "joern", "error": None}
