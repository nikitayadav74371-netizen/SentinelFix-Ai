"""C / C++ vulnerability detection rules (regex-based)."""
from __future__ import annotations
import re
from typing import List, Dict, Any

GETS_CALL = re.compile(r"\bgets\s*\(")
STRCPY_CALL = re.compile(r"\bstrcpy\s*\(")
STRCAT_CALL = re.compile(r"\bstrcat\s*\(")
SPRINTF_CALL = re.compile(r"\bsprintf\s*\(")
SCANF_UNBOUNDED = re.compile(r"\bscanf\s*\(\s*\"[^\"]*%s")
SYSTEM_CALL = re.compile(r"\bsystem\s*\(")
POPEN_CALL = re.compile(r"\bpopen\s*\(")
MALLOC_NO_CHECK = re.compile(r"=\s*malloc\s*\(")  # informational only, low severity
FORMAT_STRING = re.compile(r"\bprintf\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\)")  # printf(var) not printf("%s", var)
HARDCODED_CRED = re.compile(
    r"(?:char\s*\*?\s*|const\s+char\s*\*?\s*|#define\s+)([A-Za-z_][A-Za-z0-9_]*(?:PASSWORD|PASSWD|PWD|SECRET|API_KEY|APIKEY|TOKEN)[A-Za-z0-9_]*)\s*(?:\[\s*\]\s*)?=?\s*\"([^\"]{3,})\"",
    re.IGNORECASE,
)


HEX_HASH_RE = re.compile(r"^[0-9a-fA-F]{32,128}$")


def is_hash_literal(value: str) -> bool:
    """A 32-128 char hex string is a digest, not a plaintext secret."""
    return bool(HEX_HASH_RE.match(value))


def scan(file_path: str, content: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    lines = content.splitlines()

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue

        m = HARDCODED_CRED.search(line)
        if m and not is_hash_literal(m.group(2)):
            findings.append({
                "line": i, "end_line": i, "vuln_type": "hardcoded_credential", "severity": "critical",
                "cwe": "CWE-798", "title": f"Hardcoded credential: {m.group(1)}",
                "description": f"The identifier {m.group(1)} stores a credential directly in source, exposing it to anyone with binary/source access.",
                "snippet": line,
            })
            continue

        if GETS_CALL.search(line):
            findings.append({
                "line": i, "end_line": i, "vuln_type": "buffer_overflow", "severity": "critical",
                "cwe": "CWE-120", "title": "Use of gets()",
                "description": "gets() performs no bounds checking and is a classic unbounded stack buffer overflow primitive. It has been removed from the C11 standard library for this reason.",
                "snippet": line,
            })
        if STRCPY_CALL.search(line):
            findings.append({
                "line": i, "end_line": i, "vuln_type": "buffer_overflow", "severity": "high",
                "cwe": "CWE-120", "title": "Use of strcpy()",
                "description": "strcpy() does not bound-check the destination buffer. If the source string length is not guaranteed to fit, this can overflow the destination buffer.",
                "snippet": line,
            })
        if STRCAT_CALL.search(line):
            findings.append({
                "line": i, "end_line": i, "vuln_type": "buffer_overflow", "severity": "high",
                "cwe": "CWE-120", "title": "Use of strcat()",
                "description": "strcat() does not bound-check the destination buffer, risking a buffer overflow when the combined string exceeds the buffer size.",
                "snippet": line,
            })
        if SPRINTF_CALL.search(line):
            findings.append({
                "line": i, "end_line": i, "vuln_type": "buffer_overflow", "severity": "high",
                "cwe": "CWE-120", "title": "Use of sprintf()",
                "description": "sprintf() writes to the destination buffer without a size limit. Use snprintf() with an explicit buffer size instead.",
                "snippet": line,
            })
        if SCANF_UNBOUNDED.search(line):
            findings.append({
                "line": i, "end_line": i, "vuln_type": "buffer_overflow", "severity": "high",
                "cwe": "CWE-120", "title": "Unbounded scanf(\"%s\", ...)",
                "description": "%s in scanf() without a field-width limit can write past the destination buffer if the input exceeds its size.",
                "snippet": line,
            })
        if SYSTEM_CALL.search(line):
            findings.append({
                "line": i, "end_line": i, "vuln_type": "command_injection", "severity": "critical",
                "cwe": "CWE-78", "title": "Use of system()",
                "description": "system() passes a string to the OS shell. If any part of that string is influenced by external input, this allows shell command injection.",
                "snippet": line,
            })
        if POPEN_CALL.search(line):
            findings.append({
                "line": i, "end_line": i, "vuln_type": "command_injection", "severity": "high",
                "cwe": "CWE-78", "title": "Use of popen()",
                "description": "popen() runs a command through the shell. External input reaching this call enables command injection.",
                "snippet": line,
            })
        if FORMAT_STRING.search(line):
            findings.append({
                "line": i, "end_line": i, "vuln_type": "format_string", "severity": "high",
                "cwe": "CWE-134", "title": "Uncontrolled format string",
                "description": "printf() is called with a variable as the format string instead of a literal. If the variable can contain user input, format specifiers like %n allow memory reads/writes.",
                "snippet": line,
            })

    return findings
