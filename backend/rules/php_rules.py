"""PHP vulnerability detection rules (regex-based)."""
from __future__ import annotations
import re
from typing import List, Dict, Any

CRED_NAME = re.compile(
    r"^\s*\$([A-Za-z_][A-Za-z0-9_]*(?:password|passwd|pwd|secret|api_key|apikey|token)[A-Za-z0-9_]*)\s*=\s*(['\"])((?:(?!\2).){3,})\2",
    re.IGNORECASE,
)

HEX_HASH_RE = re.compile(r"^[0-9a-fA-F]{32,128}$")


def is_hash_literal(value: str) -> bool:
    """A 32-128 char hex string is a digest, not a plaintext secret."""
    return bool(HEX_HASH_RE.match(value))

SUPERGLOBAL = r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\["
SQL_CALL = re.compile(
    r"(mysqli?_query|->query|->exec|PDO::query)\s*\([^)]*" + SUPERGLOBAL,
    re.IGNORECASE,
)
SQL_CONCAT = re.compile(
    r"(SELECT|INSERT|UPDATE|DELETE)\b.{0,200}\.\s*\$_(?:GET|POST|REQUEST)", re.IGNORECASE | re.DOTALL,
)
EVAL_CALL = re.compile(r"\beval\s*\(")
INCLUDE_DYNAMIC = re.compile(r"\b(include|include_once|require|require_once)\s*\(?\s*\$_(?:GET|POST|REQUEST)", re.IGNORECASE)
SYSTEM_CALL = re.compile(r"\b(system|exec|shell_exec|passthru|popen)\s*\([^)]*\$_(?:GET|POST|REQUEST)", re.IGNORECASE)
MD5_CALL = re.compile(r"\bmd5\s*\(")
XSS_ECHO = re.compile(r"echo\s+.*\$_(?:GET|POST|REQUEST)\b(?!.*htmlspecialchars)", re.IGNORECASE)
UNSAFE_UNSERIALIZE = re.compile(r"\bunserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)", re.IGNORECASE)


def scan(file_path: str, content: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    lines = content.splitlines()

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            continue

        m = CRED_NAME.match(line)
        if m and not is_hash_literal(m.group(3)):
            findings.append({
                "line": i, "end_line": i, "vuln_type": "hardcoded_credential", "severity": "critical",
                "cwe": "CWE-798", "title": f"Hardcoded credential: ${m.group(1)}",
                "description": f"The variable ${m.group(1)} stores a credential directly in source code, exposing it to anyone with source/repo access.",
                "snippet": line,
            })
            continue

        if SQL_CALL.search(line) or SQL_CONCAT.search(line):
            findings.append({
                "line": i, "end_line": i, "vuln_type": "sql_injection", "severity": "critical",
                "cwe": "CWE-89", "title": "SQL Injection via unsanitized superglobal",
                "description": "A SQL query is built using request data ($_GET/$_POST/$_REQUEST) without parameter binding, allowing an attacker to alter query logic.",
                "snippet": line,
            })
        if EVAL_CALL.search(line):
            findings.append({
                "line": i, "end_line": i, "vuln_type": "eval_usage", "severity": "high",
                "cwe": "CWE-95", "title": "Use of eval()",
                "description": "eval() executes a string as PHP code. Any user-influenced input reaching it is direct remote code execution.",
                "snippet": line,
            })
        if INCLUDE_DYNAMIC.search(line):
            findings.append({
                "line": i, "end_line": i, "vuln_type": "path_traversal", "severity": "critical",
                "cwe": "CWE-98", "title": "Local/Remote File Inclusion",
                "description": "include/require is passed a filename derived from request data, allowing local (or remote, if allow_url_include is on) file inclusion and potential code execution.",
                "snippet": line,
            })
        if SYSTEM_CALL.search(line):
            findings.append({
                "line": i, "end_line": i, "vuln_type": "command_injection", "severity": "critical",
                "cwe": "CWE-78", "title": "Command injection via shell exec with request data",
                "description": "A shell command is built directly from request parameters and executed, allowing arbitrary command injection.",
                "snippet": line,
            })
        if MD5_CALL.search(line):
            findings.append({
                "line": i, "end_line": i, "vuln_type": "weak_crypto", "severity": "medium",
                "cwe": "CWE-327", "title": "Weak hash algorithm (md5)",
                "description": "md5() is not suitable for password hashing or integrity-sensitive use. Use password_hash()/password_verify() for passwords.",
                "snippet": line,
            })
        if XSS_ECHO.search(line):
            findings.append({
                "line": i, "end_line": i, "vuln_type": "xss_innerhtml", "severity": "high",
                "cwe": "CWE-79", "title": "Reflected XSS via unescaped echo",
                "description": "Request data is echoed directly into the HTML response without htmlspecialchars()/escaping, allowing script injection.",
                "snippet": line,
            })
        if UNSAFE_UNSERIALIZE.search(line):
            findings.append({
                "line": i, "end_line": i, "vuln_type": "insecure_deserialization", "severity": "critical",
                "cwe": "CWE-502", "title": "Unsafe unserialize() of request data",
                "description": "unserialize() on attacker-controlled input can trigger PHP object injection and, depending on available gadget classes, remote code execution.",
                "snippet": line,
            })

    return findings
