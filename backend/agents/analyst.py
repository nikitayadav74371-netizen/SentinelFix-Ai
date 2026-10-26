"""
SecurityAnalyst agent: walks the project and produces raw Findings by
running the rule engine against every candidate source file.
"""
from __future__ import annotations
import os
from typing import List, Callable, Optional

from backend.scanner.file_scanner import discover_files, read_text, relpath
from backend.rules import run_all_rules
from backend.models.schemas import Finding


def analyze_project(root: str, on_progress: Optional[Callable[[str, int, int], None]] = None) -> List[Finding]:
    files = discover_files(root)
    findings: List[Finding] = []
    total = len(files)
    for idx, path in enumerate(files, start=1):
        rel = relpath(path, root)
        if on_progress:
            on_progress(rel, idx, total)
        try:
            content = read_text(path)
        except Exception:
            continue
        ext = os.path.splitext(path)[1]
        raw_findings, language = run_all_rules(path, ext, content)
        for rf in raw_findings:
            findings.append(Finding(
                file=rel,
                language=language,
                line=rf["line"],
                end_line=rf.get("end_line", rf["line"]),
                vuln_type=rf["vuln_type"],
                severity=rf["severity"],
                cwe=rf["cwe"],
                title=rf["title"],
                description=rf["description"],
                snippet=rf["snippet"],
                confidence=rf.get("confidence", 0.9),
                extra=rf.get("extra", {}),
            ))
    return findings
