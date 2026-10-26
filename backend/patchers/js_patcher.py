"""
Deterministic patch generation for JavaScript findings.

Client-side code has no server to hold secrets in environment variables,
so the credential fix here is different from the Python one: the plaintext
value is replaced with a SHA-256 hash, and the comparison is rewritten to
hash the entered password (via the browser's native crypto.subtle API) and
compare digests. This removes the plaintext credential from source while
preserving the exact login behaviour.

When a hardcoded-credential finding and an innerHTML XSS finding both fall
inside the same comparator function, they're resolved together in a single
function rewrite (see analyst_support.group_js_findings) to avoid two
independent multi-line patches invalidating each other's anchors.
"""
from __future__ import annotations
import re
import hashlib
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

CRED_DECL_RE = re.compile(
    r'^([ \t]*)(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*([\'"`])((?:(?!\3).)+)\3\s*;?[ \t]*$',
    re.MULTILINE,
)
INNERHTML_LINE_RE = re.compile(r"(\.innerHTML)(\s*=\s*)")

SHA256_HELPER = '''async function sentinelFixSha256Hex(text) {
  const data = new TextEncoder().encode(text);
  const digestBuffer = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digestBuffer)).map(b => b.toString(16).padStart(2, "0")).join("");
}

'''


@dataclass
class JsPatchOutcome:
    ok: bool
    replacements: List[tuple] = field(default_factory=list)
    explanation: str = ""
    failure_reason: Optional[str] = None
    resolved_extra_finding_lines: List[int] = field(default_factory=list)
    env_var: Optional[tuple] = None
    needs_os_import: bool = False


def _extract_brace_block(content: str, keyword_start: int) -> Optional[tuple]:
    """Given the index of a `function` keyword, return (block_text, end_idx)
    for the full `function ... { ... }` block via brace counting."""
    brace_open = content.find("{", keyword_start)
    if brace_open == -1:
        return None
    depth = 0
    i = brace_open
    while i < len(content):
        if content[i] == "{":
            depth += 1
        elif content[i] == "}":
            depth -= 1
            if depth == 0:
                return content[keyword_start:i + 1], i + 1
        i += 1
    return None


def _find_comparator_function(content: str, var_name: str) -> Optional[tuple]:
    """Find a `function name(...) { ... }` block that compares some
    variable against `var_name` via === / ==. Returns (block_text, start_idx)."""
    for m in re.finditer(r"(async\s+)?function\s+[A-Za-z_$][\w$]*\s*\([^)]*\)\s*", content):
        start = m.start()
        block_info = _extract_brace_block(content, start)
        if not block_info:
            continue
        block, _end = block_info
        if re.search(rf"[=!]==?\s*{re.escape(var_name)}\b", block) or re.search(
            rf"{re.escape(var_name)}\s*[=!]==?", block
        ):
            return block, start
    return None


def patch_credential_and_related_xss(content: str, cred_finding, xss_findings: list) -> JsPatchOutcome:
    """Rewrites a `const X_PASSWORD = "...";` declaration plus its comparator
    function into a SHA-256-hash-based check, and simultaneously fixes any
    innerHTML XSS assignments that fall within that same function body."""
    decl_matches = list(CRED_DECL_RE.finditer(content))
    target_decl = None
    for dm in decl_matches:
        # Match by variable name appearing in the finding snippet
        if dm.group(2) in (cred_finding.snippet or ""):
            target_decl = dm
            break
    if target_decl is None and decl_matches:
        target_decl = decl_matches[0]
    if target_decl is None:
        return JsPatchOutcome(ok=False, failure_reason="could not locate credential declaration at patch time")

    var_name = target_decl.group(2)
    plaintext = target_decl.group(4)
    decl_full_text = target_decl.group(0)
    quote = target_decl.group(3)
    indent = target_decl.group(1)
    hash_hex = hashlib.sha256(plaintext.encode("utf-8")).hexdigest()
    hash_var_name = var_name + "_HASH" if not var_name.endswith("_HASH") else var_name

    comparator = _find_comparator_function(content, var_name)
    if not comparator:
        return JsPatchOutcome(ok=False, failure_reason="could not locate a comparator function referencing the credential")
    func_block, func_start = comparator

    # Determine the entered-value variable being compared against var_name.
    cmp_match = re.search(rf"([A-Za-z_$][\w$]*)\s*[=!]==?\s*{re.escape(var_name)}\b", func_block)
    reversed_order = False
    if not cmp_match:
        cmp_match = re.search(rf"{re.escape(var_name)}\s*[=!]==?\s*([A-Za-z_$][\w$]*)\b", func_block)
        reversed_order = True
    if not cmp_match:
        return JsPatchOutcome(ok=False, failure_reason="could not locate comparison expression")
    entered_var = cmp_match.group(1)

    new_block = func_block

    # 1) Make the function async (if not already).
    if not re.match(r"async\s+function", new_block):
        new_block = re.sub(r"^function\b", "async function", new_block, count=1)

    # 2) Insert the hash computation right before the line containing the comparison.
    #    We anchor on the *statement line* that contains the comparator match to
    #    insert a preceding line with matching indentation.
    lines = new_block.splitlines(keepends=True)
    out_lines = []
    inserted = False
    for line in lines:
        if not inserted and re.search(rf"[=!]==?\s*{re.escape(var_name)}\b", line) or (
            not inserted and re.search(rf"{re.escape(var_name)}\s*[=!]==?", line)
        ):
            line_indent = line[: len(line) - len(line.lstrip(" \t"))]
            out_lines.append(f"{line_indent}const hashedInput = await sentinelFixSha256Hex({entered_var});\n")
            if reversed_order:
                new_line = re.sub(
                    rf"{re.escape(var_name)}\s*([=!]==?)\s*{re.escape(entered_var)}\b",
                    rf"{hash_var_name} \1 hashedInput",
                    line,
                )
            else:
                new_line = re.sub(
                    rf"{re.escape(entered_var)}\s*([=!]==?)\s*{re.escape(var_name)}\b",
                    rf"hashedInput \1 {hash_var_name}",
                    line,
                )
            out_lines.append(new_line)
            inserted = True
        else:
            out_lines.append(line)
    new_block = "".join(out_lines)

    # 3) Fix any innerHTML assignments within this function to use textContent
    #    (covers the common "display an error/message" pattern safely).
    new_block = INNERHTML_LINE_RE.sub(r".textContent\2", new_block)

    # 4) Build the new declaration + helper + function, inserted as one unit.
    new_decl = f'{indent}const {hash_var_name} = {quote}{hash_hex}{quote};'

    old_combo = decl_full_text
    new_combo = new_decl
    # We replace the declaration in place, and separately replace the function
    # block (with helper prepended) in place — two independent, uniquely
    # anchored replacements composed together.
    resolved_lines = [f.line for f in xss_findings if f.snippet.strip() and f.snippet.strip() in func_block]

    return JsPatchOutcome(
        ok=True,
        replacements=[
            (decl_full_text, new_decl),
            (func_block, SHA256_HELPER + new_block),
        ],
        explanation=(
            f"Replaced the plaintext credential `{var_name}` with a SHA-256 hash "
            f"(`{hash_var_name}`). The login check now hashes the entered password "
            "in the browser (via crypto.subtle.digest) and compares digests, so the "
            "real password is never present in source, while any `.innerHTML` "
            "assignment inside the same function was also switched to `.textContent` "
            "to close the DOM-XSS sink in the same pass."
        ),
        resolved_extra_finding_lines=resolved_lines,
    )


def patch_innerhtml_standalone(original_lines: List[str], finding) -> JsPatchOutcome:
    line_no = finding.line
    if line_no < 1 or line_no > len(original_lines):
        return JsPatchOutcome(ok=False, failure_reason="line out of range")
    original_line = original_lines[line_no - 1]
    if ".innerHTML" not in original_line:
        return JsPatchOutcome(ok=False, failure_reason="pattern did not match at patch time")
    new_line = INNERHTML_LINE_RE.sub(r".textContent\2", original_line)
    return JsPatchOutcome(
        ok=True,
        replacements=[(original_line, new_line)],
        explanation=(
            "Replaced `.innerHTML` with `.textContent`. The assigned value is "
            "user-influenced text meant to be displayed as-is; `.textContent` "
            "inserts it as plain text instead of parsing it as HTML, closing the "
            "DOM XSS sink while preserving the exact same visible output for "
            "normal input."
        ),
    )


def patch_credential_standalone(original_lines: List[str], finding) -> JsPatchOutcome:
    """Fallback when no comparator function could be located: hash the
    constant in place. The comparison site(s) are left for manual review
    since we can't safely locate every usage without a JS parser."""
    line_no = finding.line
    if line_no < 1 or line_no > len(original_lines):
        return JsPatchOutcome(ok=False, failure_reason="line out of range")
    original_line = original_lines[line_no - 1]
    m = CRED_DECL_RE.match(original_line + "\n")
    if not m:
        return JsPatchOutcome(ok=False, failure_reason="pattern did not match at patch time")
    indent, var_name, quote, value = m.groups()
    hash_hex = hashlib.sha256(value.encode("utf-8")).hexdigest()
    hash_var = var_name + "_HASH"
    new_line = f"{indent}const {hash_var} = {quote}{hash_hex}{quote};"
    return JsPatchOutcome(
        ok=True,
        replacements=[(original_line, new_line)],
        explanation=(
            f"Replaced the plaintext value of `{var_name}` with its SHA-256 hash. "
            "NOTE: no comparator function could be located automatically to update "
            "to a hash-based check — search the file for other uses of the original "
            "variable name and update them to hash-compare, or request an LLM-assisted "
            "patch."
        ),
    )
