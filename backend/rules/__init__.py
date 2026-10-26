from __future__ import annotations
from typing import List, Dict, Any, Callable

from . import python_rules, js_rules, php_rules, c_cpp_rules, generic_rules

EXT_LANGUAGE = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".php": "php",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".css": "css",
    ".html": "html",
    ".htm": "html",
}

LANGUAGE_SCANNERS: Dict[str, List[Callable[[str, str], List[Dict[str, Any]]]]] = {
    "python": [python_rules.scan],
    "javascript": [js_rules.scan],
    "php": [php_rules.scan],
    "c": [c_cpp_rules.scan],
    "cpp": [c_cpp_rules.scan],
    "css": [generic_rules.scan_css],
    "html": [generic_rules.scan_html],
}

SCANNED_EXTENSIONS = set(EXT_LANGUAGE.keys())


def language_for(ext: str) -> str:
    return EXT_LANGUAGE.get(ext.lower(), "unknown")


def run_all_rules(file_path: str, ext: str, content: str) -> List[Dict[str, Any]]:
    """Run language-specific rules plus the cross-language generic rules."""
    language = language_for(ext)
    findings: List[Dict[str, Any]] = []
    for scanner in LANGUAGE_SCANNERS.get(language, []):
        findings.extend(scanner(file_path, content))
    # Generic secret scanning applies everywhere (including HTML/JS embedded config etc.)
    findings.extend(generic_rules.scan_generic(file_path, content))
    for f in findings:
        f.setdefault("confidence", 0.9)
    return findings, language
