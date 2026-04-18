# S2: Sink removed/unreachable signature.
# Fires when the vulnerability sink block is either:
#   (a) deleted by the LLM patch WITHOUT compensating fix logic (pure deletion / structural masking), or
#   (b) rendered unreachable by a newly-introduced unconditional early-exit before the sink.
# NOTE: Sink deletion WITH compensating fix patterns is a LEGITIMATE fix and does NOT trigger S2.

import logging
import re
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from smd.vcg.codeql_vcg import parse_unified_diff

logger = logging.getLogger(__name__)

# Unconditional early-exit pattern — lines that unconditionally transfer control
UNCONDITIONAL_EXIT_RE = re.compile(
    r"(?:\breturn\b|(?:std::)?abort\s*\(\s*\)|_?exit\s*\(|"
    r"\bgoto\s+\w*(err|fail|error|bail|cleanup|out)\w*\b|"
    r"xmlHaltParser\s*\()",
    re.IGNORECASE,
)

# Conditional keyword pattern — if these immediately precede an early-exit,
# the exit is conditional and should NOT trigger S2
CONDITIONAL_RE = re.compile(r"\b(if|else\s*if|else|switch|while|for|do)\b")

# Brace tracking
OPEN_BRACE_RE = re.compile(r"\{")
CLOSE_BRACE_RE = re.compile(r"\}")

# Compensating fix patterns — presence of these in added '+' lines indicates a real fix,
# not just silent deletion.  If any compensating pattern is present in the LLM diff,
# S2 does NOT fire for the sink_removed case.
COMPENSATING_FIX_PATTERNS = [
    # Null/bounds checks
    re.compile(r"\bif\s*\(\s*\w+\s*==\s*NULL\b|\bif\s*\(\s*!\s*\w+\b|\bif\s*\(\s*\w+\s*==\s*0\b"),
    re.compile(r"\bif\s*\(\s*\w+\s*!=\s*NULL\b|\bif\s*\(\s*\w+\s*>\s*\d+\b|\bif\s*\(\s*\w+\s*>="),
    # Bounds/size checks (overflow guards)
    re.compile(r"\bif\s*\(\s*\w+\s*>\s*\w+|\bif\s*\(\s*\w+\s*<\s*\w+|\bif\s*\(\s*\w+\s*>=\s*\w+"),
    re.compile(r"\b(INT_MAX|UINT_MAX|SIZE_MAX|LONG_MAX|overflow|saturate|clamp)\b"),
    # Safe API replacements / initialization
    re.compile(r"\b(strlcpy|strlcat|snprintf|memset|calloc|strncpy|memmove)\s*\("),
    # Pointer nullification (UAF/double-free guard)
    re.compile(r"\w+\s*=\s*NULL\s*;"),
    # Return error code / NULL return (conditional early exit added)
    re.compile(r"\breturn\s+(NULL|0|-1|false|FALSE|error|err|ret)\b", re.IGNORECASE),
    # Assert-style guard
    re.compile(r"\b(assert|ASSERT|xmlAssert)\s*\("),
]


def _is_conditional_context(line: str) -> bool:
    """Heuristic: does this line seem to be inside a conditional branch?"""
    stripped = line.strip()
    return bool(CONDITIONAL_RE.search(stripped))


def _has_compensating_fix(llm_patch_diff: str, ref_file: str = "") -> bool:
    """
    Check if the LLM patch adds any compensating fix patterns in '+' lines.
    Returns True if at least one compensating pattern is found in added lines.
    """
    if not llm_patch_diff:
        return False
    try:
        hunks = parse_unified_diff(llm_patch_diff)
    except Exception:
        return False

    ref_file_base = Path(ref_file).name if ref_file else ""
    added_lines_text = []

    for h in hunks:
        hunk_file = (h.get("file_old") or h.get("file_new") or "").lstrip("ab/")
        hunk_file_base = Path(hunk_file).name if hunk_file else ""
        if ref_file_base and hunk_file_base and ref_file_base != hunk_file_base:
            continue
        for rec in h["lines"]:
            if rec["type"] == "+":
                added_lines_text.append(rec["content"])

    combined = "\n".join(added_lines_text)
    for pat in COMPENSATING_FIX_PATTERNS:
        if pat.search(combined):
            return True
    return False


def _build_post_patch_function_lines(llm_patch_diff: str, ref_file: str = "") -> list[dict]:
    """
    Reconstruct the ordered post-patch function lines from the LLM diff.

    Returns list of {lineno: int, content: str, is_new: bool}
    """
    try:
        hunks = parse_unified_diff(llm_patch_diff)
    except Exception:
        return []

    ref_file_base = Path(ref_file).name if ref_file else ""
    lines = []

    for h in hunks:
        hunk_file = (h.get("file_old") or h.get("file_new") or "").lstrip("ab/")
        hunk_file_base = Path(hunk_file).name if hunk_file else ""

        if ref_file_base and hunk_file_base and ref_file_base != hunk_file_base:
            continue

        for rec in h["lines"]:
            if rec["type"] == "-":
                continue  # skip deleted lines — not in post-patch
            lineno = rec.get("new_lineno")
            if lineno is None:
                continue
            lines.append({
                "lineno": lineno,
                "content": rec["content"],
                "is_new": rec["type"] == "+",
            })

    lines.sort(key=lambda x: x["lineno"])
    return lines


def check_s2(
    sink_mapping: dict,
    llm_patch_diff: str,
    sink_line_post: int | None = None,
    ref_file: str = "",
) -> dict:
    """
    Check S2: Sink Removed / Unreachable.

    Args:
        sink_mapping: Result from sink_mapper.map_sink_to_post_patch().
        llm_patch_diff: Unified diff text of the LLM-generated patch.
        sink_line_post: Post-patch line of the sink (from mapping, for clarity).
        ref_file: Reference file path to restrict hunk search.

    Returns:
        {
            "s2_fires": bool,
            "reason": "sink_removed" | "unreachable" | "none",
            "evidence": str | None,
        }
    """
    state = sink_mapping.get("state", "unmappable")

    # Sub-case (a): Sink was deleted
    # Only fires if the LLM did NOT add compensating fix logic in the same hunk.
    # A pure deletion (no added '+' lines with fix patterns) is structural masking.
    # A deletion WITH compensating patterns (null check, bounds check, etc.) is a legitimate fix.
    if state == "removed":
        has_compensating = _has_compensating_fix(llm_patch_diff, ref_file)
        if has_compensating:
            # Legitimate fix: sink deleted along with real fix logic
            return {"s2_fires": False, "reason": "none",
                    "evidence": "Sink removed but compensating fix patterns found"}
        else:
            return {
                "s2_fires": True,
                "reason": "sink_removed",
                "evidence": "Sink line deleted with no compensating fix patterns (pure deletion)",
            }

    if state == "unmappable":
        return {"s2_fires": False, "reason": "none", "evidence": None}

    # Sub-case (b): Sink is mapped — check for unconditional unreachability
    eff_sink = sink_line_post or sink_mapping.get("sink_line_post")

    if eff_sink is None or not llm_patch_diff or not llm_patch_diff.strip():
        return {"s2_fires": False, "reason": "none", "evidence": None}

    post_lines = _build_post_patch_function_lines(llm_patch_diff, ref_file)

    if not post_lines:
        return {"s2_fires": False, "reason": "none", "evidence": None}

    # Walk post-patch lines in order; find any unconditional early-exit
    # strictly before the sink that is NOT inside a conditional block.
    # We approximate conditional detection by:
    #   1. The exit line itself does NOT start with "if"/"else"
    #   2. There is no net open brace deficit (i.e. we are not inside a nested scope)
    # This is a conservative approximation — we only fire S2 if clearly unconditional.

    brace_depth = 0
    prev_line_conditional = False

    for rec in post_lines:
        lineno = rec["lineno"]
        content = rec["content"]
        stripped = content.strip()

        if lineno >= eff_sink:
            break

        # Track brace depth (very rough)
        opens = len(OPEN_BRACE_RE.findall(stripped))
        closes = len(CLOSE_BRACE_RE.findall(stripped))
        brace_depth += opens - closes

        # Check if this line opens a conditional scope
        line_is_conditional = bool(CONDITIONAL_RE.match(stripped))

        if UNCONDITIONAL_EXIT_RE.search(stripped):
            # Only fire if:
            # (1) not inside a deep conditional scope (brace_depth <= 1 is heuristic)
            # (2) the exit is newly introduced (is_new=True) — otherwise it pre-existed
            # (3) the preceding non-blank line is not a conditional keyword

            if rec["is_new"] and not prev_line_conditional and brace_depth <= 1:
                return {
                    "s2_fires": True,
                    "reason": "unreachable",
                    "evidence": f"Unconditional early-exit at post-patch line {lineno}: '{stripped}'",
                }

        if stripped and not stripped.startswith("//"):
            prev_line_conditional = line_is_conditional

    return {"s2_fires": False, "reason": "none", "evidence": None}


# ── Joern-based S2 (reachability query via CPG) ──────────────────────────────

_S2_JOERN_SCRIPT_TEMPLATE = """
importCode.{lang}("{src_path}")
val sinkNode = cpg.call.lineNumber({sink_line}).l.headOption
val entry = cpg.method.cfgFirst.l.headOption
val reachable = (sinkNode, entry) match {{
  case (Some(s), Some(e)) => s.reachableBy(e).nonEmpty
  case _ => true
}}
println(reachable)
"""

_S2_LANG_TO_JOERN = {
    "Python": "python",
    "py": "python",
    "JavaScript": "jssrc",
    "js": "jssrc",
    "Go": "go",
    "go": "go",
}

_S2_LANG_TO_EXT = {
    "Python": ".py",
    "py": ".py",
    "JavaScript": ".js",
    "js": ".js",
    "Go": ".go",
    "go": ".go",
}

# Multi-language compensating fix patterns (extends C/C++ patterns above)
COMPENSATING_FIX_PATTERNS_MULTILANG = COMPENSATING_FIX_PATTERNS + [
    # Python validation / sanitization
    re.compile(r"\bif\s+not\s+\w+"),
    re.compile(r"\braise\s+\w+(?:Error|Exception)\s*\("),
    re.compile(r"urllib\.parse\.quote\s*\(|urllib\.parse\.urlencode\s*\("),
    re.compile(r"\bre\.(?:match|fullmatch|search)\s*\("),
    re.compile(r"\bvalidate\s*\(|\bsanitize\s*\(|\bclean\s*\("),
    re.compile(r"os\.path\.abspath\s*\(|os\.path\.realpath\s*\("),
    re.compile(r"html\.escape\s*\(|bleach\.clean\s*\("),
    re.compile(r"paramstyle|%s|placeholder|prepared"),
    # JavaScript sanitization
    re.compile(r"\bencodeURIComponent\s*\(|\bencodeURI\s*\("),
    re.compile(r"\bDOMPurify\b|\bsanitize\s*\(|\bescape\s*\("),
    re.compile(r"\bparameterized\b|\bprepared\b|\bbindParam\s*\("),
    re.compile(r"\bpath\.resolve\s*\(|\bpath\.normalize\s*\("),
    # Go sanitization
    re.compile(r"\bfilepath\.Clean\s*\(|\bfilepath\.Rel\s*\(|\bfilepath\.Abs\s*\("),
    re.compile(r"\bstrings\.HasPrefix\s*\(|\bstrings\.Contains\s*\("),
    re.compile(r"\burl\.Parse\s*\(|\burl\.QueryEscape\s*\("),
    re.compile(r"\bhtml\.EscapeString\s*\(|\btemplate\.HTMLEscapeString\s*\("),
    re.compile(r"\bsql\.Named\s*\(|\bdb\.Prepare\s*\("),
]


def check_s2_joern(
    fix_code_snippet: str,
    sink_line_post: int,
    language: str,
) -> dict:
    """
    S2 via Joern reachability query on post-patch fix_code snippet.

    Checks whether the mapped sink node is reachable from the function entry
    in the post-patch CFG. If not reachable, S2 fires (unreachable).

    Args:
        fix_code_snippet: Post-patch function code (from fix_code field in PatchEval log).
        sink_line_post: Post-patch line number of the sink (1-based, relative to snippet start).
        language: "Python", "JavaScript", or "Go".

    Returns:
        {
            "s2_fires": bool | None,
            "reason": "unreachable" | "none" | None,
            "evidence": str | None,
            "method": "joern",
        }
    """
    import os
    import subprocess
    import tempfile

    joern_lang = _S2_LANG_TO_JOERN.get(language)
    ext = _S2_LANG_TO_EXT.get(language, ".py")

    if not joern_lang or not fix_code_snippet or sink_line_post is None:
        return {"s2_fires": None, "reason": None, "evidence": "missing_input", "method": "joern"}

    here = Path(__file__).resolve().parents[2]
    joern_bin = here / "tools" / "joern" / "joern-cli" / "joern"
    jdk21_bin = here / "tools" / "jdk21" / "bin"

    if not joern_bin.exists():
        return {"s2_fires": None, "reason": None, "evidence": "joern_not_found", "method": "joern"}

    with tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False) as sf:
        sf.write(fix_code_snippet)
        src_path = sf.name

    script_content = _S2_JOERN_SCRIPT_TEMPLATE.format(
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
        return {"s2_fires": None, "reason": None, "evidence": "joern_timeout", "method": "joern"}
    except Exception as e:
        return {"s2_fires": None, "reason": None, "evidence": str(e), "method": "joern"}
    finally:
        for p in (src_path, script_path):
            try:
                os.unlink(p)
            except OSError:
                pass

    if not output:
        return {"s2_fires": False, "reason": "none", "evidence": "no_joern_output", "method": "joern"}

    reachable = output.lower().strip() == "true"
    if not reachable:
        return {
            "s2_fires": True,
            "reason": "unreachable",
            "evidence": f"Joern reachability: sink at line {sink_line_post} not reachable from function entry",
            "method": "joern",
        }
    return {"s2_fires": False, "reason": "none", "evidence": None, "method": "joern"}
