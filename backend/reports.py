"""Builds the human-readable Markdown report and the final result ZIP."""
from __future__ import annotations
import json
import os
import zipfile
from datetime import datetime
from typing import List

from backend.models.schemas import JobState, FindingLifecycle

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
STATUS_LABEL = {
    "VERIFIED": "VERIFIED SECURITY FIX",
    "MANUAL_REVIEW_REQUIRED": "MANUAL REVIEW REQUIRED",
    "REJECTED": "REJECTED (regression failed)",
    "FALSE_POSITIVE": "FALSE POSITIVE",
}


def _sorted(findings: List[FindingLifecycle]):
    return sorted(findings, key=lambda lc: (SEV_ORDER.get(str(lc.finding.severity.value), 9), lc.finding.file, lc.finding.line))


def build_markdown(job: JobState, source_label: str) -> str:
    s = job.summary
    out = [
        "# Sentinel AI - Security Verification & Repair Report",
        "",
        f"- **Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"- **Source:** {source_label}",
        f"- **Files scanned:** {job.files_total}",
        f"- **Total findings:** {s.get('total_findings', 0)}",
        f"- **Verified fixes:** {s.get('verified_fixed', 0)}",
        f"- **Manual review required:** {s.get('manual_review_required', 0)}",
        f"- **False positives dismissed:** {s.get('false_positives', 0)}",
        "",
        "> Pipeline: Security Analyst -> Exploit Validator -> Patch Generator -> Security Judge -> Regression Tests.",
        "> Your original files were never modified; patched files are in the `patched_project/` folder of this ZIP.",
        "",
        "## Findings",
        "",
    ]
    for lc in _sorted(job.findings):
        f = lc.finding
        out += [
            f"### [{f.severity.value.upper()}] {f.title}",
            f"- **File:** `{f.file}` line {f.line}  |  **CWE:** {f.cwe}  |  **Type:** `{f.vuln_type.value}`",
            f"- **Status:** {STATUS_LABEL.get(lc.final_status or '', lc.final_status)}",
            f"- **Why it matters:** {f.description}",
        ]
        if lc.validation and lc.validation.attack_vector:
            out.append(f"- **Attack vector:** {lc.validation.attack_vector}")
        if lc.patch_attempts:
            pa = lc.patch_attempts[-1]
            out.append(f"- **Fix ({pa.strategy}):** {pa.explanation}")
            if pa.diff:
                out += ["", "```diff", pa.diff.rstrip(), "```"]
        for jv in lc.judge_verdicts:
            out.append(f"- Judge attempt {jv.attempt_number}: **{jv.verdict}** - {jv.reasoning}")
        if lc.regression:
            out.append(f"- Regression: syntax_ok={lc.regression.syntax_ok}, structure_preserved={lc.regression.structure_preserved} ({lc.regression.details})")
        if lc.final_status == "MANUAL_REVIEW_REQUIRED":
            out.append("- **Action:** no safe automatic patch was verified. Review this code manually.")
        out.append("")
    out += [
        "## After applying the patches",
        "",
        "- If secrets were moved to environment variables, a `.env` file was generated in the patched project. **Do not commit it** (`.gitignore` was updated).",
        "- Re-run your application's own tests / manual checks. Regression checks here are static (syntax + structure); the application is never executed.",
    ]
    return "\n".join(out)


def build_zip(job: JobState, patched_root: str, zip_path: str, source_label: str) -> str:
    os.makedirs(os.path.dirname(zip_path), exist_ok=True)
    md = build_markdown(job, source_label)
    payload = {
        "job_id": job.job_id,
        "source": source_label,
        "summary": job.summary,
        "findings": [lc.model_dump(mode="json") for lc in job.findings],
    }
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("SENTINELAI_REPORT.md", md)
        z.writestr("sentinelai_report.json", json.dumps(payload, indent=2))
        for dirpath, dirnames, filenames in os.walk(patched_root):
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                z.write(full, os.path.join("patched_project", os.path.relpath(full, patched_root)))
    return zip_path
