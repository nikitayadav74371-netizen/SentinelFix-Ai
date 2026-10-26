"""
Pipeline orchestrator: runs Analyst -> Validator -> (Patcher <-> Judge loop)
-> Regression for a whole project, emitting progress events matching the
stage diagram the user specified, and produces the final patched project
tree + report.
"""
from __future__ import annotations
import os
import shutil
import traceback
from typing import Callable, Optional, Dict, Any, List

from backend.models.schemas import (
    Finding, FindingLifecycle, PipelineStage, JobState, ValidationResult,
    PatchAttempt, JudgeVerdict, RegressionResult,
)
from backend.scanner.file_scanner import discover_files, read_text, relpath, SKIP_DIRS
from backend.agents.analyst import analyze_project
from backend.agents.validator import validate_findings
from backend.agents.judge import judge_patch
from backend.agents.regression import run_regression
from backend.patchers.patch_utils import safe_replace, unified_diff
from backend.patchers import python_patcher as pyp
from backend.patchers import js_patcher as jsp
from backend.patchers.llm_patcher import generate_llm_patch
from backend.llm_client import OllamaClient

MAX_PATCH_ATTEMPTS = 3

DETERMINISTIC_PYTHON = {"hardcoded_credential", "hardcoded_secret_key", "debug_mode_enabled", "sql_injection"}


def _copy_tree(src: str, dst: str):
    if os.path.exists(dst):
        shutil.rmtree(dst)

    def ignore(dirpath, names):
        return [n for n in names if n in SKIP_DIRS]

    shutil.copytree(src, dst, ignore=ignore)


class Orchestrator:
    def __init__(self, job: JobState, on_event: Callable[[Dict[str, Any]], None]):
        self.job = job
        self.on_event = on_event
        self.llm = OllamaClient(
            host=job.request.ollama_host or "http://localhost:11434",
            model=job.request.ollama_model or "qwen2.5-coder:7b",
        )
        self.env_vars_collected: List[tuple] = []

    def emit(self, event_type: str, **data):
        self.on_event({"type": event_type, **data})

    def run(self, source_root: str, output_root: str):
        job = self.job
        try:
            self.emit("stage", stage="scanning", message=f"Discovering source files under {source_root}")
            files = discover_files(source_root)
            job.files_total = len(files)
            self.emit("files_discovered", count=len(files))

            # ---- Security Analyst ----
            self.emit("stage", stage="analyzing", message="Security Analyst: scanning files for vulnerabilities")
            findings = analyze_project(
                source_root,
                on_progress=lambda rel, i, n: self.emit("analyzing_file", file=rel, index=i, total=n),
            )
            self.emit("analysis_complete", findings_count=len(findings))

            # ---- Exploit Validator ----
            self.emit("stage", stage="validating", message="Exploit Validator: confirming exploitability")
            validations = validate_findings(findings, self.llm if job.request.use_llm else None)

            lifecycles: Dict[str, FindingLifecycle] = {}
            confirmed: List[Finding] = []
            for f in findings:
                v = validations[f.id]
                lc = FindingLifecycle(finding=f, validation=v)
                if not v.is_exploitable:
                    lc.stage = PipelineStage.FALSE_POSITIVE
                    lc.final_status = "FALSE_POSITIVE"
                else:
                    lc.stage = PipelineStage.PATCHING
                    confirmed.append(f)
                lifecycles[f.id] = lc
                self.emit(
                    "finding_validated", finding_id=f.id, file=f.file, line=f.line,
                    vuln_type=f.vuln_type, severity=f.severity, title=f.title,
                    is_exploitable=v.is_exploitable, confidence=f.confidence,
                )

            self.emit("validation_complete", confirmed_count=len(confirmed), false_positive_count=len(findings) - len(confirmed))

            # Prepare output tree (copy of source, files get overwritten as patched).
            _copy_tree(source_root, output_root)

            # ---- Patch Generator + Security Judge (per file) ----
            by_file: Dict[str, List[Finding]] = {}
            for f in confirmed:
                by_file.setdefault(f.file, []).append(f)

            for rel_file, file_findings in by_file.items():
                self._process_file(source_root, output_root, rel_file, file_findings, lifecycles)

            # Any findings for files with zero confirmed issues never got touched above;
            # nothing else to do for them.

            # ---- Aggregate .env + .gitignore ----
            self._finalize_env(output_root)

            job.findings = list(lifecycles.values())
            summary = self._build_summary(job.findings)
            job.summary = summary
            self.emit("pipeline_complete", summary=summary)

        except Exception as e:
            tb = traceback.format_exc()
            self.emit("error", message=str(e), traceback=tb)
            raise

    # ------------------------------------------------------------------
    def _process_file(self, source_root, output_root, rel_file, file_findings, lifecycles):
        abs_path = os.path.join(source_root, rel_file)
        try:
            original_content = read_text(abs_path)
        except Exception as e:
            for f in file_findings:
                lifecycles[f.id].final_status = "ERROR"
                lifecycles[f.id].stage = PipelineStage.REJECTED_FINAL
            return
        original_lines = original_content.splitlines()
        ext = os.path.splitext(rel_file)[1]
        language = file_findings[0].language

        current_content = original_content
        handled_ids: set = set()

        self.emit("stage", stage="patching", file=rel_file, message=f"Patch Generator: working on {rel_file}")

        # --- Special case: JS credential + XSS resolved together ---
        if language == "javascript":
            cred_findings = [f for f in file_findings if f.vuln_type == "hardcoded_credential"]
            xss_findings = [f for f in file_findings if f.vuln_type == "xss_innerhtml"]
            for cf in cred_findings:
                if cf.id in handled_ids:
                    continue
                outcome = jsp.patch_credential_and_related_xss(current_content, cf, xss_findings)
                if outcome.ok:
                    pre_content = current_content
                    applied = current_content
                    success = True
                    for old, new in outcome.replacements:
                        result = safe_replace(applied, old, new)
                        if result is None:
                            success = False
                            break
                        applied = result
                    if success:
                        verdict = judge_patch(ext, language, pre_content, applied, outcome.replacements)
                        self._record_patch_attempt(lifecycles[cf.id], 1, "deterministic", outcome, verdict, pre_content, applied)
                        if verdict["verdict"] == "PASS":
                            current_content = applied
                            handled_ids.add(cf.id)
                            lifecycles[cf.id].final_status = "VERIFIED"
                            lifecycles[cf.id].stage = PipelineStage.VERIFIED
                            # Also resolve any XSS findings whose snippet fell inside the rewritten block.
                            for xf in xss_findings:
                                if xf.id in handled_ids:
                                    continue
                                if xf.snippet.strip() and xf.snippet.strip() in (outcome.replacements[-1][0] if outcome.replacements else ""):
                                    attempt = PatchAttempt(
                                        finding_id=xf.id, attempt_number=1, strategy="deterministic",
                                        original_snippet=xf.snippet, patched_snippet="(resolved as part of combined credential+XSS patch)",
                                        diff="", explanation="Resolved together with the adjacent hardcoded-credential fix in the same function.",
                                    )
                                    lifecycles[xf.id].patch_attempts.append(attempt)
                                    lifecycles[xf.id].judge_verdicts.append(JudgeVerdict(finding_id=xf.id, attempt_number=1, verdict="PASS", reasoning="Resolved as part of combined patch.", checks={"combined_patch": True}))
                                    lifecycles[xf.id].final_status = "VERIFIED"
                                    lifecycles[xf.id].stage = PipelineStage.VERIFIED
                                    handled_ids.add(xf.id)
                                    self.emit("finding_patched", finding_id=xf.id, file=rel_file, verdict="PASS")
                            self.emit("finding_patched", finding_id=cf.id, file=rel_file, verdict="PASS")

        # --- Remaining findings, one at a time (patched + judged with explicit content threading) ---
        current_content = self._apply_accepted_patches(
            original_content, original_lines, ext, language, file_findings, lifecycles, handled_ids, rel_file
        )

        # --- Env bootstrap (python only, if any credential/secret patches were applied) ---
        if language == "python" and self.env_vars_collected and any(
            lifecycles[f.id].final_status == "VERIFIED" and f.vuln_type in ("hardcoded_credential", "hardcoded_secret_key")
            for f in file_findings
        ):
            current_content = pyp.apply_env_bootstrap(current_content)

        # --- Write patched file to output tree ---
        out_path = os.path.join(output_root, rel_file)
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(current_content)

        # --- File-level regression ---
        reg = run_regression(rel_file, original_content, current_content, language)
        for f in file_findings:
            lifecycles[f.id].regression = RegressionResult(
                file=rel_file, syntax_ok=reg["syntax_ok"], structure_preserved=reg["structure_preserved"],
                details=f"{reg['syntax_detail']} {reg['structure_detail']}",
            )
            if lifecycles[f.id].final_status == "VERIFIED" and (not reg["syntax_ok"] or not reg["structure_preserved"]):
                lifecycles[f.id].final_status = "REJECTED"
                lifecycles[f.id].stage = PipelineStage.REJECTED_FINAL
        self.emit("file_regression_complete", file=rel_file, syntax_ok=reg["syntax_ok"], structure_preserved=reg["structure_preserved"])

    # ------------------------------------------------------------------
    def _apply_accepted_patches(self, original_content, original_lines, ext, language, file_findings, lifecycles, handled_ids, rel_file):
        current_content = original_content
        # Findings resolved by the combined JS credential+XSS patch already
        # had their PatchAttempt/JudgeVerdict recorded earlier; re-derive the
        # merged text here (pure function of original_content) so remaining
        # findings can be layered on top of it.
        if language == "javascript":
            cred_findings = [f for f in file_findings if f.vuln_type == "hardcoded_credential" and f.id in handled_ids]
            xss_findings_all = [f for f in file_findings if f.vuln_type == "xss_innerhtml"]
            for cf in cred_findings:
                outcome = jsp.patch_credential_and_related_xss(current_content, cf, xss_findings_all)
                if outcome.ok:
                    applied = current_content
                    ok_all = True
                    for old, new in outcome.replacements:
                        r = safe_replace(applied, old, new)
                        if r is None:
                            ok_all = False
                            break
                        applied = r
                    if ok_all:
                        current_content = applied

        for f in file_findings:
            if f.id in handled_ids:
                continue
            current_content = self._patch_and_judge(f, language, ext, original_lines, lifecycles, current_content, rel_file)
        return current_content

    def _patch_and_judge(self, f: Finding, language, ext, original_lines, lifecycles, current_content, rel_file) -> str:
        lc = lifecycles[f.id]
        pre_content = current_content
        attempt_no = 0
        prior_rejection = None
        self.emit("finding_patching", finding_id=f.id, file=rel_file, vuln_type=f.vuln_type, line=f.line)

        while attempt_no < MAX_PATCH_ATTEMPTS:
            attempt_no += 1
            outcome = None
            strategy = "deterministic"

            if language == "python" and f.vuln_type == "hardcoded_credential":
                outcome = pyp.patch_hardcoded_credential(original_lines, f)
            elif language == "python" and f.vuln_type == "hardcoded_secret_key":
                outcome = pyp.patch_hardcoded_secret_key(original_lines, f)
            elif language == "python" and f.vuln_type == "debug_mode_enabled":
                outcome = pyp.patch_debug_mode(original_lines, f)
            elif language == "python" and f.vuln_type == "sql_injection":
                outcome = pyp.patch_sql_injection(original_lines, f)
            elif language == "javascript" and f.vuln_type == "xss_innerhtml":
                outcome = jsp.patch_innerhtml_standalone(original_lines, f)
            elif language == "javascript" and f.vuln_type == "hardcoded_credential":
                outcome = jsp.patch_credential_standalone(original_lines, f)

            if outcome is not None and outcome.ok:
                applied = pre_content
                ok_all = True
                for old, new in outcome.replacements:
                    r = safe_replace(applied, old, new)
                    if r is None:
                        ok_all = False
                        break
                    applied = r
                if not ok_all:
                    strategy = "deterministic"
                    verdict = {"verdict": "REJECT", "checks": {"applied_cleanly": False}, "reasoning": "Patch anchor text was not found (or was ambiguous) at apply time; the file may have changed since detection."}
                    self._record_patch_attempt(lc, attempt_no, strategy, outcome, verdict, pre_content, pre_content)
                    prior_rejection = verdict["reasoning"]
                    continue

                verdict = judge_patch(ext, language, pre_content, applied, outcome.replacements)
                self._record_patch_attempt(lc, attempt_no, strategy, outcome, verdict, pre_content, applied)
                if verdict["verdict"] == "PASS":
                    lc.final_status = "VERIFIED"
                    lc.stage = PipelineStage.VERIFIED
                    self.emit("finding_patched", finding_id=f.id, file=rel_file, verdict="PASS", attempt=attempt_no)
                    if outcome.env_var:
                        self.env_vars_collected.append(outcome.env_var)
                    return applied
                else:
                    prior_rejection = verdict["reasoning"]
                    self.emit("finding_patched", finding_id=f.id, file=rel_file, verdict="REJECT", attempt=attempt_no, reason=prior_rejection)
                    continue

            # --- No deterministic patcher, or it failed to produce output: try LLM ---
            if self.job.request.use_llm:
                context_start = max(0, f.line - 6)
                context_end = min(len(original_lines), f.end_line + 5)
                context = "\n".join(original_lines[context_start:context_end])
                llm_outcome = generate_llm_patch(
                    self.llm, f.title, f.description, language, f.snippet, context, prior_rejection,
                )
                if llm_outcome.ok:
                    r = safe_replace(pre_content, f.snippet, llm_outcome.new_snippet)
                    if r is not None:
                        verdict = judge_patch(ext, language, pre_content, r, [(f.snippet, llm_outcome.new_snippet)], strategy="llm_assisted")
                        pa_outcome_stub = pyp.PatchOutcome(
                            ok=True, replacements=[(f.snippet, llm_outcome.new_snippet)],
                            explanation=llm_outcome.explanation,
                        )
                        self._record_patch_attempt(lc, attempt_no, "llm_assisted", pa_outcome_stub, verdict, pre_content, r)
                        if verdict["verdict"] == "PASS":
                            lc.final_status = "VERIFIED"
                            lc.stage = PipelineStage.VERIFIED
                            self.emit("finding_patched", finding_id=f.id, file=rel_file, verdict="PASS", attempt=attempt_no, strategy="llm_assisted")
                            return r
                        prior_rejection = verdict["reasoning"]
                        continue
                else:
                    lc.final_status = None  # keep looping is pointless; fall through to manual review below
                    break
            else:
                break

        # Exhausted attempts (or no strategy available at all): flag for manual review, leave file unchanged for this finding.
        lc.final_status = "MANUAL_REVIEW_REQUIRED"
        lc.stage = PipelineStage.REJECTED_FINAL
        self.emit("finding_manual_review", finding_id=f.id, file=rel_file, reason=prior_rejection or "No safe automatic patch available for this vulnerability type.")
        return pre_content

    def _record_patch_attempt(self, lc: FindingLifecycle, attempt_no, strategy, outcome, verdict, pre_content, post_content):
        old_combined = "\n".join(o for o, _n in outcome.replacements)
        new_combined = "\n".join(n for _o, n in outcome.replacements)
        diff = unified_diff(old_combined + "\n", new_combined + "\n", lc.finding.file)
        pa = PatchAttempt(
            finding_id=lc.finding.id, attempt_number=attempt_no, strategy=strategy,
            original_snippet=old_combined, patched_snippet=new_combined, diff=diff,
            explanation=getattr(outcome, "explanation", ""),
        )
        lc.patch_attempts.append(pa)
        lc.judge_verdicts.append(JudgeVerdict(
            finding_id=lc.finding.id, attempt_number=attempt_no,
            verdict=verdict["verdict"], reasoning=verdict["reasoning"], checks=verdict["checks"],
        ))

    # ------------------------------------------------------------------
    def _finalize_env(self, output_root: str):
        if not self.env_vars_collected:
            return
        env_path = os.path.join(output_root, ".env")
        existing = {}
        if os.path.exists(env_path):
            with open(env_path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line and "=" in line and not line.startswith("#"):
                        k, v = line.split("=", 1)
                        existing[k.strip()] = v.strip()
        for name, value in self.env_vars_collected:
            existing[name] = value
        with open(env_path, "w", encoding="utf-8") as fh:
            fh.write("# Generated by SentinelFix AI -- do not commit this file.\n")
            for k, v in existing.items():
                fh.write(f"{k}={v}\n")

        gitignore_path = os.path.join(output_root, ".gitignore")
        lines = []
        if os.path.exists(gitignore_path):
            with open(gitignore_path, "r", encoding="utf-8") as fh:
                lines = fh.read().splitlines()
        if ".env" not in lines:
            lines.append(".env")
            with open(gitignore_path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")

    # ------------------------------------------------------------------
    def _build_summary(self, lifecycles: List[FindingLifecycle]) -> Dict[str, Any]:
        total = len(lifecycles)
        verified = sum(1 for lc in lifecycles if lc.final_status == "VERIFIED")
        rejected = sum(1 for lc in lifecycles if lc.final_status == "REJECTED")
        manual = sum(1 for lc in lifecycles if lc.final_status == "MANUAL_REVIEW_REQUIRED")
        false_pos = sum(1 for lc in lifecycles if lc.final_status == "FALSE_POSITIVE")
        by_severity: Dict[str, int] = {}
        by_type: Dict[str, int] = {}
        for lc in lifecycles:
            by_severity[lc.finding.severity] = by_severity.get(lc.finding.severity, 0) + 1
            by_type[lc.finding.vuln_type] = by_type.get(lc.finding.vuln_type, 0) + 1
        return {
            "total_findings": total,
            "verified_fixed": verified,
            "rejected": rejected,
            "manual_review_required": manual,
            "false_positives": false_pos,
            "by_severity": by_severity,
            "by_vuln_type": by_type,
        }
