"""
RegressionTester agent.

Deliberately does NOT execute the target application (arbitrary code
execution of an unknown, possibly-vulnerable project is out of scope for
an automated tool run against someone's local files). Instead it performs
static regression checks that are safe to run unconditionally:

  1. Syntax validity of the patched file (py_compile / node --check /
     gcc -fsyntax-only, per language).
  2. Structural preservation: the count of function/route/class
     definitions must not have decreased (patches may add helper
     functions, but must never silently delete existing ones).

This is intentionally conservative: it catches "the patch broke the
file" but does not claim to prove runtime behavior is identical -- the
final report tells the user to re-run their app's own test steps after
applying patches, same as the test project READMEs ask for.
"""
from __future__ import annotations
import ast
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Optional


@dataclass
class SyntaxCheckResult:
    ok: bool
    detail: str
    verified: bool = True   # False = no real tool actually checked it


def check_python_syntax(content: str) -> SyntaxCheckResult:
    try:
        compile(content, "<patched>", "exec")
        return SyntaxCheckResult(True, "Python syntax OK (compiled with py_compile-equivalent check).")
    except SyntaxError as e:
        return SyntaxCheckResult(False, f"SyntaxError: {e.msg} at line {e.lineno}")


def check_js_syntax(content: str) -> SyntaxCheckResult:
    node = shutil.which("node")
    if not node:
        return SyntaxCheckResult(True, "node not available in this environment; JS syntax check skipped.", verified=False)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False, encoding="utf-8") as tf:
        tf.write(content)
        tmp_path = tf.name
    try:
        proc = subprocess.run([node, "--check", tmp_path], capture_output=True, text=True, timeout=15)
        if proc.returncode == 0:
            return SyntaxCheckResult(True, "JavaScript syntax OK (node --check).")
        return SyntaxCheckResult(False, f"node --check failed: {proc.stderr.strip()[:400]}")
    except subprocess.TimeoutExpired:
        return SyntaxCheckResult(False, "node --check timed out.")
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def check_c_cpp_syntax(content: str, is_cpp: bool) -> SyntaxCheckResult:
    compiler = shutil.which("g++") if is_cpp else shutil.which("gcc")
    if not compiler:
        return SyntaxCheckResult(True, "No C/C++ compiler available in this environment; syntax check skipped.", verified=False)
    suffix = ".cpp" if is_cpp else ".c"
    with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False, encoding="utf-8") as tf:
        tf.write(content)
        tmp_path = tf.name
    try:
        proc = subprocess.run([compiler, "-fsyntax-only", "-w", tmp_path], capture_output=True, text=True, timeout=20)
        stderr = proc.stderr
        if proc.returncode == 0:
            return SyntaxCheckResult(True, "C/C++ syntax OK.")
        if "fatal error:" in stderr and "No such file or directory" in stderr:
            return SyntaxCheckResult(True, "Could not fully verify (missing project headers not present in isolation); no syntax errors detected before that point.", verified=False)
        return SyntaxCheckResult(False, f"Compiler reported errors: {stderr.strip()[:400]}")
    except subprocess.TimeoutExpired:
        return SyntaxCheckResult(False, "Syntax check timed out.")
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def check_php_syntax(content: str) -> SyntaxCheckResult:
    php = shutil.which("php")
    if not php:
        balance_ok = content.count("{") == content.count("}") and content.count("(") == content.count(")")
        return SyntaxCheckResult(balance_ok, "php binary not available; performed a brace/paren balance check only." if balance_ok else "Brace/paren mismatch detected in patched file.", verified=False)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".php", delete=False, encoding="utf-8") as tf:
        tf.write(content)
        tmp_path = tf.name
    try:
        proc = subprocess.run([php, "-l", tmp_path], capture_output=True, text=True, timeout=15)
        return SyntaxCheckResult(proc.returncode == 0, proc.stdout.strip() or proc.stderr.strip())
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def check_syntax(content: str, language: str) -> SyntaxCheckResult:
    if language == "python":
        return check_python_syntax(content)
    if language == "javascript":
        return check_js_syntax(content)
    if language == "c":
        return check_c_cpp_syntax(content, is_cpp=False)
    if language == "cpp":
        return check_c_cpp_syntax(content, is_cpp=True)
    if language == "php":
        return check_php_syntax(content)
    return SyntaxCheckResult(True, f"No syntax checker for language '{language}'; skipped.", verified=False)


def _count_python_defs(content: str) -> Optional[int]:
    try:
        tree = ast.parse(content)
        return sum(1 for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)))
    except SyntaxError:
        return None


def _count_js_functions(content: str) -> int:
    return len(re.findall(r"\bfunction\s+[A-Za-z_$]", content)) + len(re.findall(r"=>\s*{", content))


def structure_preserved(original: str, patched: str, language: str) -> tuple[bool, str]:
    if language == "python":
        before = _count_python_defs(original)
        after = _count_python_defs(patched)
        if before is None or after is None:
            return True, "Could not fully parse for structure comparison; skipped."
        ok = after >= before
        return ok, f"Function/class definitions: {before} -> {after}."
    if language == "javascript":
        before = _count_js_functions(original)
        after = _count_js_functions(patched)
        ok = after >= before
        return ok, f"Function declarations/expressions: {before} -> {after}."
    return True, "No structure check defined for this language; skipped."


def run_regression(file_path: str, original: str, patched: str, language: str) -> dict:
    syntax = check_syntax(patched, language)
    struct_ok, struct_detail = structure_preserved(original, patched, language)
    return {
        "file": file_path,
        "syntax_ok": syntax.ok,
        "syntax_verified": syntax.verified,
        "syntax_detail": syntax.detail,
        "structure_preserved": struct_ok,
        "structure_detail": struct_detail,
    }
