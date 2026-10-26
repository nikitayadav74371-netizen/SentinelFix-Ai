"""
JavaScript / TypeScript vulnerability detection rules (regex-based).

JS is scanned lexically rather than via a full parser (no JS AST library
is available in this environment); patterns are written narrowly to keep
false-positive risk low while still catching the realistic, common cases.
"""
from __future__ import annotations
import re
from typing import List, Dict, Any

CRED_NAME = re.compile(
    r"^\s*(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*(?:PASSWORD|PASSWD|PWD|SECRET|API_KEY|APIKEY|TOKEN|ACCESS_KEY)[A-Za-z0-9_$]*)\s*=\s*(['\"`])((?:(?!\2).){3,})\2",
    re.IGNORECASE,
)

HEX_HASH_RE = re.compile(r"^[0-9a-fA-F]{32,128}$")


def is_hash_literal(value: str) -> bool:
    """A 32-128 char hex string is a digest, not a plaintext secret."""
    return bool(HEX_HASH_RE.match(value))


# innerHTML assignment where the right-hand side is NOT a static string
# literal (i.e. it involves a variable, concatenation, or template literal
# interpolation) -> potential DOM XSS.
INNERHTML_DYNAMIC = re.compile(
    r"\.innerHTML\s*=\s*(?!['\"][^'\"]*['\"]\s*;?\s*$)(.+)$"
)
INNERHTML_CONCAT_OR_TEMPLATE = re.compile(r"\+|\$\{")

DOC_WRITE = re.compile(r"document\.write\s*\(")
EVAL_CALL = re.compile(r"(?<![\w.])eval\s*\(")
NEW_FUNCTION = re.compile(r"new\s+Function\s*\(")
INSECURE_RANDOM_FOR_TOKEN = re.compile(r"Math\.random\s*\(\)")
LOCALSTORAGE_TOKEN = re.compile(r"localStorage\.setItem\s*\(\s*['\"](?:[^'\"]*token[^'\"]*|[^'\"]*password[^'\"]*)['\"]", re.IGNORECASE)
SET_TIMEOUT_STRING = re.compile(r"setTimeout\s*\(\s*['\"]")


def scan(file_path: str, content: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    lines = content.splitlines()

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue

        m = CRED_NAME.match(line)
        if m and not is_hash_literal(m.group(3)):
            findings.append({
                "line": i, "end_line": i,
                "vuln_type": "hardcoded_credential",
                "severity": "critical",
                "cwe": "CWE-798",
                "title": f"Hardcoded credential: {m.group(1)}",
                "description": (
                    f"The client-side variable `{m.group(1)}` embeds a credential "
                    "directly in JavaScript that is shipped to every visitor's "
                    "browser. It can be read by anyone via view-source or the "
                    "browser devtools regardless of any obfuscation/minification."
                ),
                "snippet": line,
            })
            continue

        m = INNERHTML_DYNAMIC.search(line)
        if m:
            rhs = m.group(1)
            # Only flag when it's built dynamically (concat / template literal / bare identifier),
            # not an obviously static/safe assignment.
            if INNERHTML_CONCAT_OR_TEMPLATE.search(rhs) or re.match(r"^[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)*\s*;?\s*$", rhs.strip()):
                findings.append({
                    "line": i, "end_line": i,
                    "vuln_type": "xss_innerhtml",
                    "severity": "high",
                    "cwe": "CWE-79",
                    "title": "DOM XSS via innerHTML",
                    "description": (
                        "User-influenced or dynamic data is written into the DOM via "
                        "`.innerHTML`, which parses the string as HTML. If the value "
                        "ever contains attacker-controlled input (e.g. a username, "
                        "query parameter, or form field), it can inject a `<script>` "
                        "or event-handler payload that executes in the victim's "
                        "browser session."
                    ),
                    "snippet": line,
                })
                continue

        if DOC_WRITE.search(line):
            findings.append({
                "line": i, "end_line": i, "vuln_type": "xss_innerhtml", "severity": "high",
                "cwe": "CWE-79", "title": "document.write() with dynamic content",
                "description": "document.write() injects raw HTML into the page. If the content includes any user-controlled data, this is a direct DOM XSS sink.",
                "snippet": line,
            })
        if EVAL_CALL.search(line):
            findings.append({
                "line": i, "end_line": i, "vuln_type": "eval_usage", "severity": "high",
                "cwe": "CWE-95", "title": "Use of eval()",
                "description": "eval() executes arbitrary JavaScript from a string. Any user-influenced input reaching eval() is direct code execution in the page's context.",
                "snippet": line,
            })
        if NEW_FUNCTION.search(line):
            findings.append({
                "line": i, "end_line": i, "vuln_type": "eval_usage", "severity": "medium",
                "cwe": "CWE-95", "title": "Dynamic code execution via new Function()",
                "description": "new Function() compiles and runs a string as code, functionally equivalent to eval() for security purposes.",
                "snippet": line,
            })
        if SET_TIMEOUT_STRING.search(line):
            findings.append({
                "line": i, "end_line": i, "vuln_type": "eval_usage", "severity": "low",
                "cwe": "CWE-95", "title": "setTimeout() with a string argument",
                "description": "Passing a string to setTimeout() causes it to be evaluated like eval(). Pass a function reference instead.",
                "snippet": line,
            })
        if LOCALSTORAGE_TOKEN.search(line):
            findings.append({
                "line": i, "end_line": i, "vuln_type": "insecure_deserialization", "severity": "low",
                "cwe": "CWE-922", "title": "Sensitive token stored in localStorage",
                "description": "Tokens/passwords stored in localStorage are readable by any JavaScript on the page (including injected via XSS) and persist indefinitely. Prefer an httpOnly, Secure cookie.",
                "snippet": line,
            })

    return findings
