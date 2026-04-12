#!/usr/bin/env python3
"""
Pre-hook: detects duplicate function/class/type definitions before Write or Edit.
Reads tool input from stdin (JSON), checks the new content against the existing codebase,
and prints a warning to stdout if duplicates are found. Always exits 0 (warn, never block).
"""
from __future__ import annotations  # makes list[str] etc. work on Python 3.7+

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path("/Users/pranavsaji/Downloads/Projects/agentguard")

# Only match top-level (non-indented) definitions — local closures inside methods are not duplicates
PYTHON_DEF_RE = re.compile(r"^(?:async )?def ([a-zA-Z_]\w*)\s*\(|^class ([a-zA-Z_]\w*)\s*[:(]", re.MULTILINE)

PYTHON_KEYWORDS = frozenset({
    "import", "from", "as", "if", "else", "elif", "for", "while", "try",
    "except", "finally", "with", "return", "yield", "pass", "break",
    "continue", "raise", "assert", "del", "lambda", "global", "nonlocal",
    "True", "False", "None", "and", "or", "not", "in", "is",
})
TS_DEF_RE = re.compile(
    r"^export\s+(?:default\s+)?(?:async\s+)?(?:function|class|const|type|interface|enum)\s+(\w+)"
    r"|^(?:async\s+)?function\s+(\w+)"
    r"|^class\s+(\w+)",
    re.MULTILINE,
)

IGNORE_DIRS = {"__pycache__", ".git", "node_modules", ".next", ".venv", "venv", "dist", "build"}


def extract_names(content: str, ext: str) -> list[str]:
    names = []
    # Common method names valid to define on multiple classes — not true duplicates
    COMMON_METHODS = frozenset({
        "scan", "run", "execute", "handle", "process", "validate", "serialize",
        "deserialize", "connect", "close", "start", "stop", "reset", "update",
        "delete", "create", "get", "list", "set", "save", "load", "parse",
        "format", "encode", "decode", "send", "receive", "read", "write",
        "health", "status", "test",
    })
    if ext in {".py"}:
        for m in PYTHON_DEF_RE.finditer(content):
            name = m.group(1) or m.group(2)
            # Skip dunders, private methods, keywords, and common method names
            is_dunder = name.startswith("__")
            is_private = name.startswith("_")
            if (name and not is_dunder and not is_private
                    and name not in PYTHON_KEYWORDS
                    and name not in COMMON_METHODS):
                names.append(name)
    elif ext in {".ts", ".tsx"}:
        for m in TS_DEF_RE.finditer(content):
            name = m.group(1) or m.group(2) or m.group(3)
            if name:
                names.append(name)
    return list(set(names))


def search_codebase(name: str, ext: str, exclude_path: str) -> list[str]:
    if ext == ".py":
        # Only match module-level definitions (line starts with def/class, no leading whitespace)
        patterns = [f"^def {name}\\b", f"^async def {name}\\b", f"^class {name}\\b"]
    else:
        patterns = [f"^export.*function {name}\\b", f"^function {name}\\b",
                    f"^class {name}\\b", f"^const {name} =", f"^interface {name}\\b",
                    f"^type {name} ="]

    hits = []
    for pattern in patterns:
        try:
            result = subprocess.run(
                ["grep", "-rn", "-E", "--include=*" + ext, pattern, str(ROOT)],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                if exclude_path and exclude_path in line:
                    continue
                if any(skip in line for skip in IGNORE_DIRS):
                    continue
                hits.append(line.strip())
        except Exception:
            pass
    return hits


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        sys.exit(0)

    tool_input = data.get("tool_input", {})
    file_path = tool_input.get("file_path", "")
    content = tool_input.get("content") or tool_input.get("new_string", "")

    if not file_path or not content:
        sys.exit(0)

    ext = Path(file_path).suffix
    if ext not in {".py", ".ts", ".tsx"}:
        sys.exit(0)

    names = extract_names(content, ext)
    if not names:
        sys.exit(0)

    duplicates = {}
    for name in names:
        hits = search_codebase(name, ext, file_path)
        if hits:
            duplicates[name] = hits

    if duplicates:
        print("\n🔍 DUPLICATE DETECTION WARNING")
        print("=" * 60)
        for name, hits in duplicates.items():
            print(f"\n  ⚠️  '{name}' is already defined at:")
            for hit in hits[:3]:
                print(f"      {hit}")
        print("\n  Consider importing the existing implementation instead of redefining.")
        print("=" * 60)


if __name__ == "__main__":
    main()
