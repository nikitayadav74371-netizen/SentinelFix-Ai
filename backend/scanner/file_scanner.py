"""
Walks a project directory and yields the set of files Sentinel AI should
inspect, skipping dependency/build/VCS directories that would otherwise
produce huge amounts of noise (and, for node_modules/vendor, findings in
code the user doesn't own or control).
"""
from __future__ import annotations
import os
from typing import List, Tuple

from backend.rules import SCANNED_EXTENSIONS

SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "env", "__pycache__",
    "vendor", "dist", "build", ".idea", ".vscode", "site-packages",
    ".pytest_cache", ".mypy_cache", "target", ".next", "coverage",
    "sentinelfix_workdir",
}

MAX_FILE_BYTES = 2_000_000  # skip pathological / binary-ish giant files


def discover_files(root: str) -> List[str]:
    """Return absolute paths of every candidate source file under root."""
    results = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if ext not in SCANNED_EXTENSIONS:
                continue
            full = os.path.join(dirpath, fn)
            try:
                if os.path.getsize(full) > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            results.append(full)
    return sorted(results)


def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def relpath(path: str, root: str) -> str:
    return os.path.relpath(path, root).replace(os.sep, "/")
