# Utilities for reconstructing pre-patch and post-patch source files from PatchEval data.
# PatchEval input.json provides vulnerability function snippets (vul_func).
# Log files provide LLM-generated fix snippets (fix_code) per CVE.
# This module wraps snippets into valid standalone source files for CodeQL DB creation.

import json
import os
import tempfile
from pathlib import Path
from typing import Optional

LANG_EXT = {
    "Python": ".py",
    "JavaScript": ".js",
    "Go": ".go",
    "py": ".py",
    "javascript": ".js",
    "npm": ".js",
    "go": ".go",
}

LANG_CODE = {
    "Python": "python",
    "JavaScript": "javascript",
    "Go": "go",
    "py": "python",
    "javascript": "javascript",
    "npm": "javascript",
    "go": "go",
}


def load_input_metadata(input_json_path: str) -> dict:
    """
    Load PatchEval input.json and return a dict keyed by CVE ID.
    Each value: {cwe_id, programming_language, vul_funcs, fix_funcs}
    where vul_funcs is a list of {id, snippet, file_path, ...}.
    """
    with open(input_json_path) as f:
        data = json.load(f)
    meta = {}
    for item in data:
        cve = item.get("cve_id")
        if not cve:
            continue
        cwe = item.get("cwe_id", [])
        if isinstance(cwe, str):
            cwe = [cwe]
        lang = item.get("programming_language", "")
        vul_funcs = item.get("vul_func", [])
        fix_funcs = item.get("fix_func", [])
        meta[cve] = {
            "cwe_id": cwe,
            "programming_language": lang,
            "lang_code": LANG_CODE.get(lang, lang.lower()),
            "vul_funcs": vul_funcs,
            "fix_funcs": fix_funcs,
        }
    return meta


def _python_wrapper(snippet: str) -> str:
    """Wrap a Python function/class snippet into a minimal standalone module."""
    lines = snippet.splitlines()
    if not lines:
        return snippet
    # Check indentation — if all lines are indented, wrap in a dummy class
    first_nonblank = next((l for l in lines if l.strip()), "")
    if first_nonblank and first_nonblank[0] in (" ", "\t"):
        # Method body — wrap in a class
        return "class _Wrapper:\n" + "\n".join("    " + l if not l.startswith(" " * 4) else l for l in lines) + "\n"
    return snippet + "\n"


def _javascript_wrapper(snippet: str) -> str:
    """Wrap a JS function snippet into a minimal standalone module."""
    return "'use strict';\n" + snippet + "\n"


def _go_wrapper(snippet: str, filename: str = "main.go") -> tuple:
    """Wrap a Go function snippet into a minimal package.
    Returns (source_code, go_mod_content).
    """
    source = "package main\n\nimport (\n\t\"fmt\"\n\t\"net/http\"\n\t\"os\"\n)\n\n"
    source += "var _ = fmt.Sprintf\nvar _ = http.Get\nvar _ = os.Getenv\n\n"
    source += snippet + "\n"
    go_mod = "module temp\n\ngo 1.21\n"
    return source, go_mod


def write_pre_patch_source(cve_id: str, meta: dict, tmpdir: str) -> Optional[str]:
    """
    Write pre-patch source for a CVE to a temp directory.
    Returns the path to the written source file, or None on failure.
    """
    entry = meta.get(cve_id)
    if not entry:
        return None
    lang = entry["programming_language"]
    vul_funcs = entry["vul_funcs"]
    if not vul_funcs:
        return None

    snippet = "\n\n".join(vf.get("snippet", "") for vf in vul_funcs if vf.get("snippet"))
    if not snippet:
        return None

    return _write_source(snippet, lang, tmpdir, prefix="pre_")


def write_post_patch_source(cve_id: str, fix_code: dict, meta: dict, tmpdir: str) -> Optional[str]:
    """
    Write post-patch source for a CVE to a temp directory using LLM fix_code.
    fix_code: dict mapping vul_func_id -> patched_snippet (from log entry).
    Returns the path to the written source file, or None on failure.
    """
    entry = meta.get(cve_id)
    if not entry:
        return None
    lang = entry["programming_language"]
    if not fix_code:
        return None

    snippet = "\n\n".join(str(v) for v in fix_code.values() if v)
    if not snippet:
        return None

    return _write_source(snippet, lang, tmpdir, prefix="post_")


def _write_source(snippet: str, lang: str, tmpdir: str, prefix: str = "") -> Optional[str]:
    """Write a language-appropriate source file and return its path."""
    ext = LANG_EXT.get(lang, ".txt")
    lang_code = LANG_CODE.get(lang, lang.lower())

    if lang_code == "python":
        source = _python_wrapper(snippet)
        fpath = os.path.join(tmpdir, f"{prefix}code.py")
        with open(fpath, "w") as f:
            f.write(source)
        return fpath

    elif lang_code == "javascript":
        source = _javascript_wrapper(snippet)
        fpath = os.path.join(tmpdir, f"{prefix}code.js")
        with open(fpath, "w") as f:
            f.write(source)
        # Write a minimal package.json so CodeQL JS extractor works
        pkg_json = os.path.join(tmpdir, "package.json")
        if not os.path.exists(pkg_json):
            with open(pkg_json, "w") as f:
                f.write('{"name": "temp", "version": "1.0.0"}\n')
        return fpath

    elif lang_code == "go":
        source, go_mod = _go_wrapper(snippet)
        fpath = os.path.join(tmpdir, f"{prefix}main.go")
        with open(fpath, "w") as f:
            f.write(source)
        mod_path = os.path.join(tmpdir, "go.mod")
        if not os.path.exists(mod_path):
            with open(mod_path, "w") as f:
                f.write(go_mod)
        return fpath

    else:
        fpath = os.path.join(tmpdir, f"{prefix}code{ext}")
        with open(fpath, "w") as f:
            f.write(snippet)
        return fpath


def make_temp_pair_dirs(base_tmpdir: Optional[str] = None) -> tuple:
    """Create a pair of temp directories for pre/post patch source files."""
    parent = tempfile.mkdtemp(dir=base_tmpdir)
    pre_dir = os.path.join(parent, "pre")
    post_dir = os.path.join(parent, "post")
    os.makedirs(pre_dir, exist_ok=True)
    os.makedirs(post_dir, exist_ok=True)
    return parent, pre_dir, post_dir
