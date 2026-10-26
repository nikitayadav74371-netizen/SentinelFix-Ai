"""
Cross-language rules applied to every text file regardless of extension
(private key blocks, cloud provider key formats, generic API-key-shaped
strings), plus light HTML/CSS specific checks.
"""
from __future__ import annotations
import re
from typing import List, Dict, Any

PRIVATE_KEY_BLOCK = re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----")
AWS_ACCESS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
GENERIC_API_KEY_ASSIGN = re.compile(
    r"^\s*[\"']?[A-Za-z0-9_.\-]*(?:api[_-]?key|secret|token)[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_\-./+=]{16,})[\"']",
    re.IGNORECASE,
)
SLACK_TOKEN = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")

# HTML-specific
INLINE_EVENT_WITH_CONCAT = re.compile(r"on\w+\s*=\s*\"[^\"]*\+[^\"]*\"")
HTTP_FORM_ACTION_ON_HTTPS_PAGE = re.compile(r"action\s*=\s*[\"']http://", re.IGNORECASE)
AUTOCOMPLETE_PASSWORD = re.compile(r"type\s*=\s*[\"']password[\"'](?![^>]*autocomplete)", re.IGNORECASE)

# CSS-specific (legacy but still flagged by scanners)
CSS_EXPRESSION = re.compile(r"expression\s*\(")
CSS_HTTP_IMPORT = re.compile(r"@import\s+url\(\s*['\"]?http://", re.IGNORECASE)


def scan_generic(file_path: str, content: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    lines = content.splitlines()
    for i, line in enumerate(lines, start=1):
        if PRIVATE_KEY_BLOCK.search(line):
            findings.append({
                "line": i, "end_line": i, "vuln_type": "hardcoded_credential", "severity": "critical",
                "cwe": "CWE-798", "title": "Embedded private key",
                "description": "A PEM private key block is committed directly in source. Anyone with repo access can extract and use this key.",
                "snippet": line,
            })
            continue
        if AWS_ACCESS_KEY.search(line):
            findings.append({
                "line": i, "end_line": i, "vuln_type": "hardcoded_credential", "severity": "critical",
                "cwe": "CWE-798", "title": "Hardcoded AWS access key",
                "description": "An AWS access key ID literal is present in source. This should be treated as compromised and rotated, and moved to environment/secret storage.",
                "snippet": line,
            })
            continue
        if SLACK_TOKEN.search(line):
            findings.append({
                "line": i, "end_line": i, "vuln_type": "hardcoded_credential", "severity": "critical",
                "cwe": "CWE-798", "title": "Hardcoded Slack token",
                "description": "A Slack API token literal is present in source and should be moved to environment/secret storage and rotated.",
                "snippet": line,
            })
            continue
        m = GENERIC_API_KEY_ASSIGN.match(line)
        if m and not any(k in line for k in ("os.environ", "process.env", "getenv", "{{", "${")):
            findings.append({
                "line": i, "end_line": i, "vuln_type": "hardcoded_credential", "severity": "medium",
                "cwe": "CWE-798", "title": "Possible hardcoded API key/token",
                "description": "A field named like an API key/secret/token is assigned a literal value directly in this file rather than being sourced from environment/config.",
                "snippet": line, "confidence": 0.6,
            })
    return findings


def scan_html(file_path: str, content: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    lines = content.splitlines()
    for i, line in enumerate(lines, start=1):
        if INLINE_EVENT_WITH_CONCAT.search(line):
            findings.append({
                "line": i, "end_line": i, "vuln_type": "xss_innerhtml", "severity": "medium",
                "cwe": "CWE-79", "title": "Inline event handler built from concatenation",
                "description": "An inline HTML event handler attribute is built via string concatenation, which risks injecting attacker-controlled markup/script if any part is dynamic.",
                "snippet": line,
            })
    return findings


def scan_css(file_path: str, content: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    lines = content.splitlines()
    for i, line in enumerate(lines, start=1):
        if CSS_EXPRESSION.search(line):
            findings.append({
                "line": i, "end_line": i, "vuln_type": "eval_usage", "severity": "low",
                "cwe": "CWE-79", "title": "CSS expression() (legacy IE code execution)",
                "description": "CSS expression() allowed arbitrary script execution in legacy Internet Explorer. It should be removed even though modern browsers no longer support it, as it's dead weight and a historical red flag.",
                "snippet": line,
            })
        if CSS_HTTP_IMPORT.search(line):
            findings.append({
                "line": i, "end_line": i, "vuln_type": "ssrf", "severity": "low",
                "cwe": "CWE-319", "title": "Insecure (http://) @import",
                "description": "Importing a stylesheet over plain HTTP on an otherwise HTTPS site allows network attackers to tamper with the imported CSS (and, via CSS-based attacks, page behavior).",
                "snippet": line,
            })
    return findings
