"""
Deterministic patch generation for Python findings. Each function takes
the ORIGINAL (pristine) file lines plus a Finding and returns a
PatchOutcome describing the exact text to replace. The orchestrator
applies these via safe_replace() against the file's current (possibly
already-partially-patched-by-other-findings) content, anchored on the
untouched original text, so patches can be composed in any order.
"""
from __future__ import annotations
import ast
import re
import secrets
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

from backend.rules.python_rules import flatten_concat
from backend.patchers.patch_utils import indent_of

CRED_LINE_RE = re.compile(
    r"^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(['\"])(.*)\3\s*(#.*)?$"
)
SECRET_KEY_LINE_RE = re.compile(
    r"^(\s*)(\w+\.secret_key|(?:\w+\.config\[\s*['\"]SECRET_KEY['\"]\s*\]))\s*=\s*(['\"])(.*)\3"
)
DEBUG_TRUE_RE = re.compile(r"debug\s*=\s*True")


@dataclass
class PatchOutcome:
    ok: bool
    # List of (old_exact_text, new_text) pairs to apply via safe_replace.
    # Almost always one pair; SQL-injection-by-indirect-variable needs two
    # (the assignment line and the .execute() call line).
    replacements: List[tuple] = field(default_factory=list)
    explanation: str = ""
    env_var: Optional[tuple] = None          # (NAME, original_value)
    needs_os_import: bool = False
    failure_reason: Optional[str] = None


def _env_var_name_for(py_var_name: str, file_hint: str) -> str:
    # Namespace generically-named vars (e.g. app.secret_key) to avoid collisions.
    base = re.sub(r"[^A-Za-z0-9_]", "_", py_var_name).upper()
    if base in ("SECRET_KEY", "SECRETKEY"):
        return "FLASK_SECRET_KEY"
    return base


def patch_hardcoded_credential(original_lines: List[str], finding) -> PatchOutcome:
    line_no = finding.line
    if line_no < 1 or line_no > len(original_lines):
        return PatchOutcome(ok=False, failure_reason="line out of range")
    original_line = original_lines[line_no - 1]
    m = CRED_LINE_RE.match(original_line)
    if not m:
        return PatchOutcome(ok=False, failure_reason="pattern did not match at patch time")
    indent, var_name, _quote, value, _comment = m.groups()
    env_name = _env_var_name_for(var_name, "")
    new_line = f'{indent}{var_name} = os.environ.get("{env_name}", "")'
    explanation = (
        f"Moved `{var_name}` out of source into the environment variable `{env_name}`. "
        f"The value is now loaded at runtime via `os.environ.get(...)` instead of being "
        f"stored as a literal. A `.env` file (excluded from version control) supplies the "
        f"original value so the application keeps working unchanged."
    )
    return PatchOutcome(
        ok=True, replacements=[(original_line, new_line)], explanation=explanation,
        env_var=(env_name, value), needs_os_import=True,
    )


def patch_hardcoded_secret_key(original_lines: List[str], finding) -> PatchOutcome:
    line_no = finding.line
    if line_no < 1 or line_no > len(original_lines):
        return PatchOutcome(ok=False, failure_reason="line out of range")
    original_line = original_lines[line_no - 1]
    m = SECRET_KEY_LINE_RE.match(original_line)
    if not m:
        return PatchOutcome(ok=False, failure_reason="pattern did not match at patch time")
    indent, target, _quote, _value = m.groups()
    env_name = "FLASK_SECRET_KEY"
    # Generate a strong random secret once; persisted via .env so sessions
    # remain valid across restarts instead of rotating every launch.
    generated = secrets.token_hex(32)
    new_line = f'{indent}{target} = os.environ.get("{env_name}", "")'
    explanation = (
        "Moved the Flask session-signing secret out of source into the environment "
        f"variable `{env_name}`. A cryptographically random 256-bit value was generated "
        "and written to `.env` so existing sessions keep working, and the key is no "
        "longer visible to anyone with source/repo access."
    )
    return PatchOutcome(
        ok=True, replacements=[(original_line, new_line)], explanation=explanation,
        env_var=(env_name, generated), needs_os_import=True,
    )


def patch_debug_mode(original_lines: List[str], finding) -> PatchOutcome:
    line_no = finding.line
    if line_no < 1 or line_no > len(original_lines):
        return PatchOutcome(ok=False, failure_reason="line out of range")
    original_line = original_lines[line_no - 1]
    if not DEBUG_TRUE_RE.search(original_line):
        return PatchOutcome(ok=False, failure_reason="pattern did not match at patch time")
    new_line = DEBUG_TRUE_RE.sub("debug=False", original_line)
    return PatchOutcome(
        ok=True, replacements=[(original_line, new_line)],
        explanation="Disabled the Werkzeug debugger (debug=True -> debug=False). The "
                    "interactive debugger allows arbitrary code execution from the "
                    "browser and must never be enabled outside local development.",
    )


def _build_param_expr(wrap_prefix: str, expr_src: str, wrap_suffix: str) -> str:
    if wrap_prefix or wrap_suffix:
        wp = wrap_prefix.replace("\\", "\\\\").replace('"', '\\"')
        ws = wrap_suffix.replace("\\", "\\\\").replace('"', '\\"')
        return f'f"{wp}{{{expr_src}}}{ws}"'
    return expr_src


def _parameterize_concat(parts: List[tuple]) -> tuple[str, List[str]]:
    """Given flatten_concat() parts, return (template_string, [param_src, ...])."""
    template = ""
    params: List[str] = []
    pending_literal = ""
    n = len(parts)
    parts = list(parts)  # local mutable copy
    for idx in range(n):
        kind, val = parts[idx]
        if kind == "lit":
            pending_literal += val
            continue
        # kind == 'expr'
        last_quote_pos = max(pending_literal.rfind("'"), pending_literal.rfind('"'))
        used_quote_char = None
        wrap_prefix = ""
        new_pending = pending_literal
        if last_quote_pos != -1:
            used_quote_char = pending_literal[last_quote_pos]
            wrap_prefix = pending_literal[last_quote_pos + 1:]
            new_pending = pending_literal[:last_quote_pos]

        wrap_suffix = ""
        if idx + 1 < n and parts[idx + 1][0] == "lit" and used_quote_char:
            nxt = parts[idx + 1][1]
            first_quote_pos = nxt.find(used_quote_char)
            if first_quote_pos != -1:
                wrap_suffix = nxt[:first_quote_pos]
                parts[idx + 1] = ("lit", nxt[first_quote_pos + 1:])

        template += new_pending + "?"
        pending_literal = ""

        expr_src = ast.unparse(val)
        params.append(_build_param_expr(wrap_prefix, expr_src, wrap_suffix))

    template += pending_literal
    return template, params


EXEC_METHODS = ("execute", "executemany", "executescript")


def _find_execute_call(stmt_tree: ast.AST) -> Optional[ast.Call]:
    """Return the .execute()-style Call node inside a parsed statement (not
    an enclosing chained call such as `.fetchall()`)."""
    for n in ast.walk(stmt_tree):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in EXEC_METHODS:
            return n
    return None


def patch_sql_injection(original_lines: List[str], finding) -> PatchOutcome:
    extra: Dict[str, Any] = finding.extra or {}
    mode = extra.get("mode")
    call_line_no = extra.get("call_line")
    if not call_line_no or call_line_no < 1 or call_line_no > len(original_lines):
        return PatchOutcome(ok=False, failure_reason="missing call line metadata")

    call_line_text = original_lines[call_line_no - 1]

    try:
        if mode == "inline":
            call_tree = ast.parse(call_line_text.strip())
            call_expr = _find_execute_call(call_tree)
            if call_expr is None:
                return PatchOutcome(ok=False, failure_reason="could not locate execute() call on its line")
            arg_node = call_expr.args[0]
            parts = flatten_concat(arg_node) if isinstance(arg_node, ast.BinOp) else None
            if parts is None:
                return PatchOutcome(ok=False, failure_reason="inline expr not a concat chain (needs LLM assist)")
            template, params = _parameterize_concat(parts)
            quote = '"' if '"' not in template else "'"
            new_args_src = f"{quote}{template}{quote}, ({', '.join(params)}{',' if len(params) == 1 else ''})"
            # Rebuild the call line text by replacing just the argument list.
            new_call_line = indent_of(call_line_text) + _rebuild_call_line(call_line_text, call_expr, new_args_src)
            explanation = (
                "Rewrote the query to use parameterized placeholders (`?`) instead of "
                "string concatenation, and pass the untrusted value as a bound parameter. "
                "The database driver now handles escaping, so crafted input can no longer "
                "alter the query's structure."
            )
            return PatchOutcome(ok=True, replacements=[(call_line_text, new_call_line)], explanation=explanation)

        elif mode == "indirect":
            var_name = extra.get("var_name")
            assign_line_no = extra.get("assign_line")
            if not assign_line_no or assign_line_no < 1 or assign_line_no > len(original_lines):
                return PatchOutcome(ok=False, failure_reason="missing assign line metadata")
            assign_line_text = original_lines[assign_line_no - 1]

            assign_tree = ast.parse(assign_line_text.strip())
            assign_node = assign_tree.body[0]  # type: ignore
            value_node = assign_node.value  # type: ignore
            parts = flatten_concat(value_node) if isinstance(value_node, ast.BinOp) else None
            if parts is None:
                return PatchOutcome(ok=False, failure_reason="assign expr not a concat chain (needs LLM assist)")
            template, params = _parameterize_concat(parts)
            quote = '"' if '"' not in template else "'"
            assign_indent = indent_of(assign_line_text)
            new_assign_line = f"{assign_indent}{var_name} = {quote}{template}{quote}"

            call_tree = ast.parse(call_line_text.strip())
            call_expr = _find_execute_call(call_tree)
            if call_expr is None:
                return PatchOutcome(ok=False, failure_reason="could not locate execute() call on its line")
            new_args_src = f"{var_name}, ({', '.join(params)}{',' if len(params) == 1 else ''})"
            new_call_line = indent_of(call_line_text) + _rebuild_call_line(call_line_text, call_expr, new_args_src)

            explanation = (
                f"Rewrote the `{var_name}` query template to use a parameterized "
                "placeholder (`?`) instead of concatenating the search term directly, "
                "and updated the `.execute()` call to pass it as a bound parameter."
            )
            return PatchOutcome(
                ok=True,
                replacements=[
                    (assign_line_text, new_assign_line),
                    (call_line_text, new_call_line),
                ],
                explanation=explanation,
            )
    except (SyntaxError, IndexError, AttributeError) as e:
        return PatchOutcome(ok=False, failure_reason=f"AST re-parse failed at patch time: {e}")

    return PatchOutcome(ok=False, failure_reason="unrecognized SQL injection mode")


ENV_LOADER_MARKER = "# --- SentinelFix AI: environment loader (auto-generated) ---"
ENV_LOADER_BLOCK = '''import os

# --- SentinelFix AI: environment loader (auto-generated) ---
def _sentinelfix_load_env(path=".env"):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as _f:
            for _line in _f:
                _line = _line.strip()
                if _line and not _line.startswith("#") and "=" in _line:
                    _k, _v = _line.split("=", 1)
                    os.environ.setdefault(_k.strip(), _v.strip())
_sentinelfix_load_env()
# --- end SentinelFix AI environment loader ---
'''


def apply_env_bootstrap(content: str) -> str:
    """Idempotently ensure `import os` + the .env loader block are present,
    inserted right after the file's last top-level import (or at the top
    if there are none). Safe to call multiple times."""
    if ENV_LOADER_MARKER in content:
        return content

    has_os_import = re.search(r"^\s*import\s+os\b", content, re.MULTILINE) is not None
    block = ENV_LOADER_BLOCK if not has_os_import else ENV_LOADER_BLOCK.split("\n", 1)[1]

    try:
        tree = ast.parse(content)
    except SyntaxError:
        return block + "\n" + content  # best effort

    last_import_end = 0
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            last_import_end = max(last_import_end, getattr(node, "end_lineno", node.lineno))

    lines = content.splitlines(keepends=True)
    if last_import_end == 0:
        return block + "\n" + content
    insert_at = last_import_end  # 0-indexed position right after that line
    new_lines = lines[:insert_at] + ["\n", block, "\n"] + lines[insert_at:]
    return "".join(new_lines)


def _rebuild_call_line(call_line_text: str, call_expr: ast.Call, new_args_src: str) -> str:
    """Replace only the argument list of the `X.execute(...)` call, keeping
    everything else on the line (e.g. `rows = conn.execute(q).fetchall()`)."""
    func_src = ast.unparse(call_expr.func)
    old_call_src = func_src + "(" + ", ".join(ast.unparse(a) for a in call_expr.args) + ")"
    new_call_src = func_src + "(" + new_args_src + ")"
    stripped = call_line_text.strip()
    if old_call_src in stripped:
        return stripped.replace(old_call_src, new_call_src, 1)
    return stripped.replace(ast.unparse(call_expr), new_call_src, 1)
