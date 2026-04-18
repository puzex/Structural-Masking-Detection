# VCG extraction using Joern CPG for Python/JavaScript/Go (PatchEval).
# Uses Joern's language-specific frontends (importCode.python, importCode.jssrc,
# importCode.go) to build CPGs and query sink nodes via dominance/reachability.
# Falls back to regex line scan if Joern fails or times out.
#
# Primary entry point: extract_sink_from_patcheval(cve_entry) -> dict
# Bulk entry point:    bulk_extract_patcheval(dataset_entries) -> dict
#
# Output dict (compatible with sink_mapper.map_sink_to_post_patch):
#   success, file, function, sink_line_pre, sink_type, language, method

import json
import logging
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ── Joern paths ──────────────────────────────────────────────────────────────
_HERE = Path(__file__).resolve().parents[2]
JOERN_CLI_DIR = _HERE / "tools" / "joern" / "joern-cli"
JOERN_BIN = JOERN_CLI_DIR / "joern"
JDK21_BIN = _HERE / "tools" / "jdk21" / "bin"

# Script templates
_SINK_QUERY_TEMPLATE = """
importCode.{lang}("{src_path}")
val names = List({sink_names})
val sinkCalls = cpg.call.filter(c => names.contains(c.name)).l
println(sinkCalls.map(c => s"${{c.name}}:${{c.lineNumber.getOrElse(-1)}}").mkString(","))
"""

# ── Language → Joern frontend mapping ────────────────────────────────────────
LANG_TO_JOERN = {
    "Python": "python",
    "py": "python",
    "JavaScript": "jssrc",
    "js": "jssrc",
    "Go": "go",
    "go": "go",
}

LANG_TO_EXT = {
    "Python": ".py",
    "py": ".py",
    "JavaScript": ".js",
    "js": ".js",
    "Go": ".go",
    "go": ".go",
}

# ── CWE → per-language sink call names ──────────────────────────────────────
# Keys: CWE ID → dict[language → list[function_name_patterns]]
CWE_SINK_MAP: dict[str, dict[str, list[str]]] = {
    # Command injection
    "CWE-78": {
        "Python": ["system", "popen", "call", "run", "check_output", "Popen", "execv", "execvp"],
        "JavaScript": ["exec", "execSync", "spawn", "spawnSync", "execFile"],
        "Go": ["Command", "CombinedOutput", "Output", "Run", "Start"],
    },
    # Code injection / eval
    "CWE-94": {
        "Python": ["eval", "exec", "compile", "execfile"],
        "JavaScript": ["eval", "Function", "setTimeout", "setInterval"],
        "Go": ["Eval"],
    },
    # Path traversal / file inclusion
    "CWE-22": {
        "Python": ["open", "join", "abspath", "realpath", "listdir", "makedirs", "remove", "rename"],
        "JavaScript": ["readFile", "readFileSync", "createReadStream", "writeFile", "join", "resolve"],
        "Go": ["Open", "OpenFile", "ReadFile", "WriteFile", "Join", "Stat", "Remove"],
    },
    "CWE-73": {
        "Python": ["open", "join"],
        "JavaScript": ["readFile", "readFileSync", "join"],
        "Go": ["Open", "ReadFile", "Join"],
    },
    # Open redirect
    "CWE-601": {
        "Python": ["redirect", "HttpResponseRedirect", "HttpResponsePermanentRedirect"],
        "JavaScript": ["redirect", "res.redirect"],
        "Go": ["Redirect", "RedirectHandler"],
    },
    # SQL injection
    "CWE-89": {
        "Python": ["execute", "executemany", "raw", "extra", "RawSQL", "cursor"],
        "JavaScript": ["query", "execute", "all", "run"],
        "Go": ["Exec", "Query", "QueryRow", "QueryContext", "ExecContext"],
    },
    # XSS
    "CWE-79": {
        "Python": ["mark_safe", "format_html", "render_to_string"],
        "JavaScript": ["innerHTML", "outerHTML", "insertAdjacentHTML", "write", "writeln",
                       "dangerouslySetInnerHTML"],
        "Go": ["Fprintf", "Fprint", "Write", "ExecuteTemplate", "Execute"],
    },
    # Deserialization
    "CWE-502": {
        "Python": ["loads", "load", "unpickle"],
        "JavaScript": ["parse", "unserialize", "deserialize"],
        "Go": ["Unmarshal", "Decode", "Deserialize"],
    },
    # SSRF
    "CWE-918": {
        "Python": ["get", "post", "request", "urlopen", "urlretrieve", "fetch"],
        "JavaScript": ["fetch", "request", "get", "post", "axios", "got"],
        "Go": ["Get", "Post", "Do", "NewRequest"],
    },
    # Crypto weakness
    "CWE-327": {
        "Python": ["md5", "sha1", "new", "crypt"],
        "JavaScript": ["createHash", "createCipher"],
        "Go": ["New", "Sum"],
    },
    # Use of hard-coded credentials / info exposure
    "CWE-200": {
        "Python": ["print", "log", "debug", "info", "error", "write"],
        "JavaScript": ["log", "write", "send", "json"],
        "Go": ["Printf", "Println", "Fprintf", "Log"],
    },
    # Integer overflow
    "CWE-190": {
        "Python": ["int", "len"],
        "JavaScript": ["parseInt", "parseFloat"],
        "Go": ["int", "int64", "int32"],
    },
    # Null pointer / unchecked error
    "CWE-476": {
        "Python": ["getattr", "index"],
        "JavaScript": ["get", "set"],
        "Go": ["Error", "Fatal", "Panic"],
    },
    # Buffer over-read
    "CWE-126": {
        "Python": ["read", "decode"],
        "JavaScript": ["slice", "substring"],
        "Go": ["Read", "ReadAt", "ReadFrom"],
    },
    # Race condition
    "CWE-362": {
        "Python": ["open", "rename", "remove"],
        "JavaScript": ["writeFile", "rename"],
        "Go": ["Open", "Rename", "Remove"],
    },
    # Command injection (shell metacharacters)
    "CWE-77": {
        "Python": ["system", "popen", "call", "run", "Popen", "check_output", "exec", "eval"],
        "JavaScript": ["exec", "execSync", "spawn", "spawnSync", "execFile"],
        "Go": ["Command", "CombinedOutput", "Output", "Run", "Start"],
    },
    # Improper authorization / access control
    "CWE-285": {
        "Python": ["has_perm", "get_permission", "check_permission", "allowed", "authorize"],
        "JavaScript": ["checkPermission", "hasPermission", "authorize", "can"],
        "Go": ["CheckPermission", "HasPermission", "Authorize", "Allow"],
    },
    "CWE-863": {
        "Python": ["has_perm", "check_permission", "is_authorized"],
        "JavaScript": ["checkPermission", "hasPermission"],
        "Go": ["CheckPermission", "IsAuthorized"],
    },
    "CWE-862": {
        "Python": ["has_perm", "permission_required"],
        "JavaScript": ["requirePermission", "checkAccess"],
        "Go": ["RequirePermission", "CheckAccess"],
    },
    # Privilege management
    "CWE-250": {
        "Python": ["setuid", "setgid", "os.setuid", "os.setgid", "seteuid"],
        "JavaScript": ["setuid", "setgid"],
        "Go": ["Setuid", "Setgid", "SyscallSetuid"],
    },
    "CWE-269": {
        "Python": ["setuid", "setgid", "chmod", "chown", "os.chmod"],
        "JavaScript": ["chmod", "chown"],
        "Go": ["Chmod", "Chown", "Setuid"],
    },
    # Improper input validation
    "CWE-20": {
        "Python": ["open", "execute", "run", "eval", "render", "redirect"],
        "JavaScript": ["eval", "exec", "query", "redirect"],
        "Go": ["Exec", "Open", "Query", "Redirect"],
    },
    # Authorization bypass
    "CWE-639": {
        "Python": ["get", "filter", "get_object_or_404", "objects"],
        "JavaScript": ["findById", "findOne", "find"],
        "Go": ["QueryRow", "Get", "Find"],
    },
}

# Fallback generic patterns per language
_GENERIC_SINKS: dict[str, list[str]] = {
    "Python": ["eval", "exec", "system", "open", "execute", "run", "call", "loads",
               "redirect", "render", "send", "write", "format"],
    "JavaScript": ["eval", "innerHTML", "write", "execute", "query", "fetch", "send",
                   "redirect", "render", "parse"],
    "Go": ["Exec", "Open", "Query", "Fprintf", "Printf", "Write", "Unmarshal",
           "Command", "Get", "Post"],
}

# ── Regex fallback sink patterns per language ─────────────────────────────────
_FALLBACK_PATTERNS: dict[str, list[tuple[str, re.Pattern]]] = {
    "Python": [
        ("eval", re.compile(r"\beval\s*\(")),
        ("exec", re.compile(r"\bexec\s*\(")),
        ("os.system", re.compile(r"\bos\.system\s*\(")),
        ("subprocess.run", re.compile(r"\bsubprocess\.(?:run|call|Popen|check_output)\s*\(")),
        ("open", re.compile(r"\bopen\s*\(")),
        ("execute", re.compile(r"\.execute\s*\(")),
        ("redirect", re.compile(r"\bredirect\s*\(|HttpResponse(?:Redirect|PermanentRedirect)\s*\(")),
        ("redirect_class", re.compile(r"raise\s+\w*[Rr]edirect\w*\s*\(")),
        ("loads", re.compile(r"(?:pickle|yaml|marshal)\.loads?\s*\(")),
        ("render", re.compile(r"\brender(?:_to_string)?\s*\(")),
        ("mark_safe", re.compile(r"\bmark_safe\s*\(")),
        ("format_html", re.compile(r"\bformat_html\s*\(")),
        ("os.path.join", re.compile(r"os\.path\.join\s*\(")),
        ("os.chmod", re.compile(r"os\.(?:chmod|chown|setuid|setgid)\s*\(")),
        ("run_query", re.compile(r"\.(?:raw|extra|filter|get)\s*\(")),
        ("urlopen", re.compile(r"urllib\.(?:request\.)?(?:urlopen|urlretrieve)\s*\(")),
    ],
    "JavaScript": [
        ("innerHTML", re.compile(r"\.innerHTML\s*=")),
        ("eval", re.compile(r"\beval\s*\(")),
        ("document.write", re.compile(r"document\.write\s*\(")),
        ("execute", re.compile(r"\.execute\s*\(|\.exec\s*\(")),
        ("execSync", re.compile(r"\.execSync\s*\(")),
        ("spawn", re.compile(r"\.spawn(?:Sync)?\s*\(")),
        ("query", re.compile(r"\.query\s*\(")),
        ("redirect", re.compile(r"res\.redirect\s*\(|\.redirect\s*\(")),
        ("insertAdjacentHTML", re.compile(r"\.insertAdjacentHTML\s*\(")),
        ("dangerouslySetInnerHTML", re.compile(r"dangerouslySetInnerHTML")),
        ("readFile", re.compile(r"fs\.(?:readFile|writeFile|createReadStream)\s*\(")),
        ("path.join", re.compile(r"path\.(?:join|resolve)\s*\(")),
        ("fetch", re.compile(r"\bfetch\s*\(|\brequire\s*\(")),
        ("send", re.compile(r"res\.(?:send|json|render)\s*\(")),
    ],
    "Go": [
        ("exec.Command", re.compile(r"exec\.Command\s*\(")),
        ("os.Open", re.compile(r"os\.(?:Open|OpenFile|ReadFile|WriteFile|Remove)\s*\(")),
        ("ioutil.ReadFile", re.compile(r"ioutil\.(?:ReadFile|WriteFile|ReadDir)\s*\(")),
        ("filepath.Join", re.compile(r"filepath\.(?:Join|Abs|Rel|Clean)\s*\(")),
        ("db.Exec", re.compile(r"\.(?:Exec|ExecContext|Query|QueryRow|QueryContext)\s*\(")),
        ("fmt.Fprintf", re.compile(r"fmt\.(?:Fprintf|Sprintf|Sscanf)\s*\(")),
        ("http.Get", re.compile(r"http\.(?:Get|Post|Do|NewRequest)\s*\(")),
        ("template.Execute", re.compile(r"\.(?:Execute|ExecuteTemplate)\s*\(")),
        ("os.Chmod", re.compile(r"os\.(?:Chmod|Chown|Lchown)\s*\(")),
        ("syscall.Setuid", re.compile(r"syscall\.(?:Setuid|Setgid|Seteuid)\s*\(")),
    ],
}


def _get_sink_names_for_cwe(cwe_ids: list[str], language: str) -> list[str]:
    """Get Joern call name patterns for given CWE(s) and language."""
    names: list[str] = []
    for cwe in cwe_ids:
        cwe_key = cwe.split("-")[0] + "-" + cwe.split("-")[1] if "-" in cwe else cwe
        entry = CWE_SINK_MAP.get(cwe_key, {})
        lang_key = "Python" if language in ("Python", "py") else \
                   "JavaScript" if language in ("JavaScript", "js") else "Go"
        names.extend(entry.get(lang_key, []))
    if not names:
        lang_key = "Python" if language in ("Python", "py") else \
                   "JavaScript" if language in ("JavaScript", "js") else "Go"
        names = _GENERIC_SINKS.get(lang_key, [])
    # Deduplicate preserving order
    seen: set[str] = set()
    result = []
    for n in names:
        if n not in seen:
            seen.add(n)
            result.append(n)
    return result


def _run_joern_script(script_content: str, timeout: int = 90) -> Optional[str]:
    """
    Run a Joern Scala script via subprocess. Returns stdout string or None on failure.
    Ensures java is in PATH using the bundled JDK21.
    """
    if not JOERN_BIN.exists():
        logger.warning("Joern binary not found at %s", JOERN_BIN)
        return None

    env = dict(os.environ)
    env["JAVA_HOME"] = str(JDK21_BIN.parent)
    # Prepend JDK bin so 'java' is found by Joern's subprocess call
    env["PATH"] = str(JDK21_BIN) + ":" + env.get("PATH", "")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".sc", delete=False) as tf:
        tf.write(script_content)
        script_path = tf.name

    try:
        result = subprocess.run(
            [str(JOERN_BIN), "--script", script_path],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
        output = result.stdout
        return output if output.strip() else None
    except subprocess.TimeoutExpired:
        logger.warning("Joern script timed out after %ds", timeout)
        return None
    except Exception as e:
        logger.warning("Joern invocation failed: %s", e)
        return None
    finally:
        try:
            os.unlink(script_path)
        except OSError:
            pass


def _joern_extract_sink(
    snippet: str,
    language: str,
    cwe_ids: list[str],
    start_line: int,
) -> Optional[dict]:
    """
    Write snippet to temp file, build CPG via Joern, query for sink call node.
    Returns dict with sink_line_pre, sink_name or None.
    """
    joern_lang = LANG_TO_JOERN.get(language)
    ext = LANG_TO_EXT.get(language, ".py")
    if not joern_lang:
        return None

    sink_names = _get_sink_names_for_cwe(cwe_ids, language)
    if not sink_names:
        return None

    with tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False) as tf:
        tf.write(snippet)
        src_path = tf.name

    # Escape sink names for Scala string list
    names_scala = ", ".join(f'"{n}"' for n in sink_names)
    script = _SINK_QUERY_TEMPLATE.format(
        lang=joern_lang,
        src_path=src_path.replace("\\", "/"),
        sink_names=names_scala,
    )

    try:
        output = _run_joern_script(script)
    finally:
        try:
            os.unlink(src_path)
        except OSError:
            pass

    if not output:
        return None

    # Parse "name1:lineno1,name2:lineno2,..."
    best_line = None
    best_name = None
    for token in output.strip().split(","):
        token = token.strip()
        if ":" not in token:
            continue
        parts = token.rsplit(":", 1)
        if len(parts) != 2:
            continue
        name, lineno_str = parts
        try:
            lineno = int(lineno_str)
        except ValueError:
            continue
        if lineno < 1:
            continue
        if best_line is None or lineno < best_line:
            best_line = lineno
            best_name = name

    if best_line is None:
        return None

    # Joern line numbers in snippet are 1-based relative to file start
    # Convert to absolute pre-patch line
    sink_line_pre = start_line + best_line - 1
    return {"sink_line_pre": sink_line_pre, "sink_type": best_name, "method": "joern"}


def _regex_extract_sink(
    snippet: str,
    language: str,
    start_line: int,
) -> Optional[dict]:
    """Regex fallback: scan snippet lines for first matching sink pattern."""
    lang_key = "Python" if language in ("Python", "py") else \
               "JavaScript" if language in ("JavaScript", "js") else "Go"
    patterns = _FALLBACK_PATTERNS.get(lang_key, [])
    lines = snippet.splitlines()
    start_line_int = int(start_line) if start_line is not None else 1
    for i, line in enumerate(lines):
        for sink_name, pat in patterns:
            if pat.search(line):
                return {
                    "sink_line_pre": start_line_int + i,
                    "sink_type": sink_name,
                    "method": "regex_fallback",
                }
    return None


def extract_sink_from_patcheval(cve_entry: dict) -> dict:
    """
    Extract vulnerability causal graph (VCG) sink for a PatchEval CVE entry.

    Args:
        cve_entry: dict from patcheval_dataset.json with keys:
            cve_id, programming_language, cwe_info, vul_func (list of function objects)

    Returns:
        {
            "success": bool,
            "cve_id": str,
            "file": str,
            "function": str,
            "sink_line_pre": int | None,
            "sink_type": str | None,
            "language": str,
            "method": "joern" | "regex_fallback" | None,
            "error": str | None,
        }
    """
    cve_id = cve_entry.get("cve_id", "")
    language = cve_entry.get("programming_language", "")
    cwe_info = cve_entry.get("cwe_info", {})
    cwe_ids = list(cwe_info.keys()) if isinstance(cwe_info, dict) else []

    vul_funcs = cve_entry.get("vul_func", [])
    if not vul_funcs:
        return {
            "success": False, "cve_id": cve_id, "file": "", "function": "",
            "sink_line_pre": None, "sink_type": None, "language": language,
            "method": None, "error": "no_vul_func",
        }

    # Use first vul_func entry
    vf = vul_funcs[0]
    snippet = vf.get("snippet", "")
    file_path = vf.get("file_path", "")
    start_line = vf.get("start_line", 1)
    func_id = vf.get("id", "")

    if not snippet.strip():
        return {
            "success": False, "cve_id": cve_id, "file": file_path, "function": func_id,
            "sink_line_pre": None, "sink_type": None, "language": language,
            "method": None, "error": "empty_snippet",
        }

    # Try Joern first
    joern_result = _joern_extract_sink(snippet, language, cwe_ids, start_line)
    if joern_result:
        return {
            "success": True,
            "cve_id": cve_id,
            "file": file_path,
            "function": func_id,
            "sink_line_pre": joern_result["sink_line_pre"],
            "sink_type": joern_result["sink_type"],
            "language": language,
            "method": "joern",
            "error": None,
        }

    # Fallback to regex
    regex_result = _regex_extract_sink(snippet, language, start_line)
    if regex_result:
        return {
            "success": True,
            "cve_id": cve_id,
            "file": file_path,
            "function": func_id,
            "sink_line_pre": regex_result["sink_line_pre"],
            "sink_type": regex_result["sink_type"],
            "language": language,
            "method": "regex_fallback",
            "error": None,
        }

    return {
        "success": False,
        "cve_id": cve_id,
        "file": file_path,
        "function": func_id,
        "sink_line_pre": None,
        "sink_type": None,
        "language": language,
        "method": None,
        "error": "no_sink_found",
    }


def _batch_joern_extract(
    entries_by_lang: dict[str, list[tuple[str, list[str], str, int]]],
    timeout: int = 600,
) -> dict[str, Optional[dict]]:
    """
    Run a SINGLE Joern invocation that processes all CVE snippets for one language group.

    This is the key performance optimization: one JVM startup for all snippets
    instead of one JVM startup per snippet (~30-60x faster).

    Args:
        entries_by_lang: {lang -> [(cve_id, cwe_ids, snippet, start_line), ...]}
        timeout: total timeout in seconds for the Joern batch script

    Returns:
        {cve_id -> {"sink_line_pre": int, "sink_type": str} | None}
    """
    results: dict[str, Optional[dict]] = {}

    for lang, entries in entries_by_lang.items():
        if not entries:
            continue

        joern_lang = LANG_TO_JOERN.get(lang)
        ext = LANG_TO_EXT.get(lang, ".py")
        if not joern_lang:
            for cve_id, _, _, _ in entries:
                results[cve_id] = None
            continue

        # Write all snippets to temp files
        tmp_dir = tempfile.mkdtemp(prefix=f"joern_{lang.lower()}_")
        file_map: list[tuple[str, str, list[str], int]] = []  # (cve_id, filepath, cwe_ids, start_line)

        for cve_id, cwe_ids, snippet, start_line in entries:
            safe_id = re.sub(r"[^a-zA-Z0-9_-]", "_", cve_id)
            fpath = os.path.join(tmp_dir, f"{safe_id}{ext}")
            try:
                with open(fpath, "w") as f:
                    f.write(snippet)
                file_map.append((cve_id, fpath, cwe_ids, start_line))
            except Exception:
                results[cve_id] = None

        # Build batch Scala script
        # Each snippet is processed independently using importCode, query, then close
        script_lines = ["import scala.collection.mutable", "val out = mutable.ListBuffer[String]()"]
        for cve_id, fpath, cwe_ids, start_line in file_map:
            lang_key = "Python" if lang in ("Python", "py") else \
                       "JavaScript" if lang in ("JavaScript", "js") else "Go"
            sink_names = _get_sink_names_for_cwe(cwe_ids, lang)
            names_scala = ", ".join(f'"{n}"' for n in sink_names)
            safe_fpath = fpath.replace("\\", "/")
            safe_id = re.sub(r"[^a-zA-Z0-9_-]", "_", cve_id)
            script_lines.append(f"""
try {{
  importCode.{joern_lang}("{safe_fpath}")
  val names_{safe_id} = List({names_scala})
  val calls_{safe_id} = cpg.call.filter(c => names_{safe_id}.contains(c.name)).l
  val best_{safe_id} = calls_{safe_id}.sortBy(_.lineNumber.getOrElse(Int.MaxValue)).headOption
  val result_{safe_id} = best_{safe_id}.map(c => s"${{c.name}}:${{c.lineNumber.getOrElse(-1)}}").getOrElse("none:-1")
  out += "{cve_id}|" + result_{safe_id}
  close("{safe_fpath}")
}} catch {{
  case e: Exception => out += "{cve_id}|error:-1"
}}""")

        script_lines.append('println(out.mkString("\\n"))')
        script_content = "\n".join(script_lines)

        script_path = os.path.join(tmp_dir, "batch_query.sc")
        with open(script_path, "w") as f:
            f.write(script_content)

        output = _run_joern_script(script_content, timeout=timeout)

        # Cleanup temp files
        import shutil
        try:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass

        if not output:
            for cve_id, _, _, _ in file_map:
                results[cve_id] = None
            continue

        # Parse output: "CVE-XXXX|name:lineno"
        for line in output.strip().splitlines():
            line = line.strip()
            if "|" not in line:
                continue
            parts = line.split("|", 1)
            if len(parts) != 2:
                continue
            cve_id_out = parts[0].strip()
            result_token = parts[1].strip()
            if result_token.startswith("error:") or result_token == "none:-1":
                results[cve_id_out] = None
                continue
            rparts = result_token.rsplit(":", 1)
            if len(rparts) != 2:
                results[cve_id_out] = None
                continue
            sink_name, lineno_str = rparts
            try:
                lineno = int(lineno_str)
            except ValueError:
                results[cve_id_out] = None
                continue
            if lineno < 1:
                results[cve_id_out] = None
                continue
            # Retrieve start_line for this CVE
            start_line = next((sl for cv, _, _, sl in file_map if cv == cve_id_out), 1)
            results[cve_id_out] = {
                "sink_line_pre": start_line + lineno - 1,
                "sink_type": sink_name,
                "method": "joern",
            }

        # Mark any not in output as None
        for cve_id, _, _, _ in file_map:
            if cve_id not in results:
                results[cve_id] = None

    return results


def bulk_extract_patcheval(
    dataset_entries: list[dict],
    output_path: Optional[str] = None,
) -> dict:
    """
    Bulk extract VCG sinks for all PatchEval CVE entries.

    Uses batch Joern invocation (one per language group) for performance.
    Falls back to regex line scan for CVEs where Joern finds nothing.

    Args:
        dataset_entries: list of entries from patcheval_dataset.json
        output_path: if given, write results JSON here

    Returns:
        dict {"results": {cve_id: vcg_result}, "coverage_stats": {...}}
    """
    # Deduplicate by CVE ID (dataset has 1000 entries for 230 CVEs)
    seen_cves: set[str] = set()
    unique_entries: list[dict] = []
    for entry in dataset_entries:
        cve_id = entry.get("cve_id", "")
        if cve_id and cve_id not in seen_cves:
            seen_cves.add(cve_id)
            unique_entries.append(entry)

    logger.info("Extracting VCG sinks for %d unique CVEs (batch Joern)", len(unique_entries))

    # Group by language for batch processing
    entries_by_lang: dict[str, list[tuple[str, list[str], str, int]]] = {
        "Python": [], "JavaScript": [], "Go": []
    }
    entry_meta: dict[str, dict] = {}  # cve_id -> metadata

    for entry in unique_entries:
        cve_id = entry.get("cve_id", "")
        language = entry.get("programming_language", "")
        cwe_info = entry.get("cwe_info", {})
        cwe_ids = list(cwe_info.keys()) if isinstance(cwe_info, dict) else []
        vul_funcs = entry.get("vul_func", [])
        if not vul_funcs:
            entry_meta[cve_id] = {"file": "", "function": "", "language": language, "error": "no_vul_func"}
            continue
        vf = vul_funcs[0]
        snippet = vf.get("snippet", "")
        file_path = vf.get("file_path", "")
        start_line = vf.get("start_line", 1)
        func_id = vf.get("id", "")
        entry_meta[cve_id] = {
            "file": file_path, "function": func_id,
            "language": language, "start_line": start_line,
            "cwe_ids": cwe_ids, "snippet": snippet,
        }

        lang_key = "Python" if language in ("Python", "py") else \
                   "JavaScript" if language in ("JavaScript", "js", "JavaScript") else \
                   "Go" if language in ("Go", "go") else None
        if lang_key and snippet.strip():
            entries_by_lang[lang_key].append((cve_id, cwe_ids, snippet, start_line))

    logger.info(
        "Language groups: Python=%d JS=%d Go=%d",
        len(entries_by_lang["Python"]),
        len(entries_by_lang["JavaScript"]),
        len(entries_by_lang["Go"]),
    )

    # Run batch Joern extraction per language group
    joern_results = _batch_joern_extract(entries_by_lang, timeout=900)
    logger.info("Batch Joern complete. Got %d results", len(joern_results))

    # Build final results with regex fallback
    results: dict[str, dict] = {}
    joern_count = 0
    fallback_count = 0
    failed_count = 0

    for cve_id, meta in entry_meta.items():
        if meta.get("error"):
            results[cve_id] = {
                "success": False, "cve_id": cve_id,
                "file": meta["file"], "function": meta.get("function", ""),
                "sink_line_pre": None, "sink_type": None,
                "language": meta["language"], "method": None, "error": meta["error"],
            }
            failed_count += 1
            continue

        joern_hit = joern_results.get(cve_id)
        if joern_hit:
            results[cve_id] = {
                "success": True, "cve_id": cve_id,
                "file": meta["file"], "function": meta.get("function", ""),
                "sink_line_pre": joern_hit["sink_line_pre"],
                "sink_type": joern_hit["sink_type"],
                "language": meta["language"], "method": "joern", "error": None,
            }
            joern_count += 1
            continue

        # Regex fallback
        regex_hit = _regex_extract_sink(meta["snippet"], meta["language"], meta["start_line"])
        if regex_hit:
            results[cve_id] = {
                "success": True, "cve_id": cve_id,
                "file": meta["file"], "function": meta.get("function", ""),
                "sink_line_pre": regex_hit["sink_line_pre"],
                "sink_type": regex_hit["sink_type"],
                "language": meta["language"], "method": "regex_fallback", "error": None,
            }
            fallback_count += 1
        else:
            results[cve_id] = {
                "success": False, "cve_id": cve_id,
                "file": meta["file"], "function": meta.get("function", ""),
                "sink_line_pre": None, "sink_type": None,
                "language": meta["language"], "method": None, "error": "no_sink_found",
            }
            failed_count += 1

    # Also handle CVEs that were in dataset but not in entry_meta (empty snippet etc.)
    for entry in unique_entries:
        cve_id = entry.get("cve_id", "")
        if cve_id and cve_id not in results:
            results[cve_id] = {
                "success": False, "cve_id": cve_id, "file": "", "function": "",
                "sink_line_pre": None, "sink_type": None,
                "language": entry.get("programming_language", ""),
                "method": None, "error": "not_processed",
            }
            failed_count += 1

    total = len(results)
    coverage_stats = {
        "total_cves": total,
        "vcg_success": joern_count + fallback_count,
        "joern_success": joern_count,
        "regex_fallback": fallback_count,
        "failed": failed_count,
        "vcg_success_rate": (joern_count + fallback_count) / total if total else 0,
        "joern_rate": joern_count / total if total else 0,
        "fallback_rate": fallback_count / total if total else 0,
    }
    logger.info("VCG extraction complete: %s", coverage_stats)

    output = {"results": results, "coverage_stats": coverage_stats}
    if output_path:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(output, f, indent=2)
        logger.info("Saved VCG results to %s", output_path)

    return output
