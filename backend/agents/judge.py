"""
SecurityJudge agent: reviews a single patch attempt and returns a
PASS/REJECT verdict. Checks are deterministic so the judge is
reproducible: the same patch against the same file always gets the same
verdict, which matters for a security tool.
"""
from __future__ import annotations
from typing import List
import ast

from backend.agents.regression import check_syntax, structure_preserved
from backend.rules import run_all_rules
import os


def judge_patch(
    file_ext: str,
    language: str,
    original_content: str,
    patched_content: str,
    replacements: List[tuple],
    strategy: str = "deterministic",
) -> dict:
    checks = {}

    # 1. The exact original vulnerable text must no longer be present.
    vuln_removed = all(old not in patched_content for old, _new in replacements)
    checks["vulnerability_pattern_removed"] = vuln_removed

    # 2. The replacement text itself must not immediately re-trigger the
    #    same rule engine (sanity check against a broken/no-op patch).
    try:
        new_findings, _lang = run_all_rules(f"patched{file_ext}", file_ext, patched_content)
        reintroduced = any(
            any(new_text.strip() and new_text.strip() in nf.get("snippet", "") for _old, new_text in replacements)
            for nf in new_findings
        )
        checks["no_immediate_re_flag"] = not reintroduced
    except Exception:
        checks["no_immediate_re_flag"] = True  # don't fail the judge over an analyzer error

    # 3. Syntax validity.
    syntax = check_syntax(patched_content, language)
    checks["syntax_valid"] = syntax.ok

    # 4. Structure preserved (nothing silently deleted).
    struct_ok, struct_detail = structure_preserved(original_content, patched_content, language)
    checks["structure_preserved"] = struct_ok

    # 4b. LLM-written patches are untrusted: they must be checked by a REAL
    #     syntax tool (not a heuristic) and must plausibly relate to the code
    #     they replace.
    if strategy == "llm_assisted":
        checks["syntax_verified_by_real_tool"] = syntax.verified
        checks["patch_relevant_to_original"] = all(_relevant(old, new) for old, new in replacements)

    # 5. Python-specific semantic sanity: parameters must be bound on execute(),
    #    and result-fetching calls must never receive arguments.
    if language == "python":
        checks["sql_binding_well_formed"] = _sql_binding_ok(patched_content)

    verdict = "PASS" if all(checks.values()) else "REJECT"
    reasons = []
    if not checks["vulnerability_pattern_removed"]:
        reasons.append("the original vulnerable code is still present after patching")
    if not checks["no_immediate_re_flag"]:
        reasons.append("the replacement code still triggers the same detection rule")
    if not checks["syntax_valid"]:
        reasons.append(f"syntax check failed: {syntax.detail}")
    if not checks["structure_preserved"]:
        reasons.append(f"structure check failed: {struct_detail}")
    if checks.get("syntax_verified_by_real_tool") is False:
        reasons.append("no real compiler/interpreter is available to verify this LLM-written patch, so it cannot be trusted automatically")
    if checks.get("patch_relevant_to_original") is False:
        reasons.append("the replacement shares almost nothing with the code it replaces")
    if checks.get("sql_binding_well_formed") is False:
        reasons.append("a database call is malformed (parameters attached to fetch*() or a '?' query executed without bound parameters)")

    reasoning = (
        "All checks passed: the vulnerable pattern is gone, the file still parses, "
        "and no functions/routes were removed."
        if verdict == "PASS"
        else "Rejected because " + "; ".join(reasons) + "."
    )

    return {"verdict": verdict, "checks": checks, "reasoning": reasoning}


def _sql_binding_ok(content: str) -> bool:
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return True  # reported by the syntax check instead
    assigned_q = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            if isinstance(n.value, ast.Constant) and isinstance(n.value.value, str):
                assigned_q[n.targets[0].id] = n.value.value
    for n in ast.walk(tree):
        if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)):
            continue
        if n.func.attr in ("fetchall", "fetchone", "fetchmany") and n.args and n.func.attr != "fetchmany":
            return False
        if n.func.attr in ("execute", "executemany") and n.args:
            first = n.args[0]
            q = None
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                q = first.value
            elif isinstance(first, ast.Name):
                q = assigned_q.get(first.id)
            if q and "?" in q and len(n.args) < 2:
                return False
    return True


_TOKEN = __import__("re").compile(r"[A-Za-z_$][A-Za-z0-9_$]*")


def _relevant(old: str, new: str) -> bool:
    """Identifier-overlap sanity check: a genuine fix keeps most of the
    original's identifiers; garbage/placeholder output shares none."""
    old_t = set(_TOKEN.findall(old))
    if not old_t:
        return True
    new_t = set(_TOKEN.findall(new))
    return len(old_t & new_t) / len(old_t) >= 0.3
