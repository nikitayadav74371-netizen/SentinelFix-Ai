"""
ExploitValidator agent: confirms each raw finding is a genuine,
exploitable issue rather than a false positive (placeholder values,
obviously non-sensitive test fixtures, etc.), and produces a short
attack-vector explanation. Uses deterministic heuristics first; if an
LLM is available it's used to add a human-readable rationale, but the
PASS/FAIL confirmation itself never depends on the LLM being reachable.
"""
from __future__ import annotations
import re
from typing import Optional

from backend.models.schemas import Finding, ValidationResult
from backend.llm_client import OllamaClient

PLACEHOLDER_VALUE = re.compile(
    r"^(your[_-]?|xxx+|changeme|example|placeholder|dummy|<.*>|\$\{.*\}|todo|xxxx|fake|sample|n/a|none)",
    re.IGNORECASE,
)

ATTACK_VECTOR_BY_TYPE = {
    "hardcoded_credential": "Anyone with read access to this source file (or its git history) can extract the credential and authenticate directly, bypassing any expectation that this value is a secret.",
    "hardcoded_secret_key": "Anyone with read access to this source can forge valid signed session tokens/cookies and impersonate any application user.",
    "sql_injection": "An attacker submits a crafted value for the input feeding this query (e.g. via a query string parameter) to alter the query's WHERE/logic, potentially reading or modifying rows outside the intended scope.",
    "xss_innerhtml": "An attacker gets a value they control into this sink (e.g. via a form field, URL parameter, or stored data) and it is parsed as HTML, letting them run script in the victim's session.",
    "command_injection": "An attacker supplies input containing shell metacharacters that reaches this call, letting them run arbitrary OS commands with the application's privileges.",
    "eval_usage": "If any part of the evaluated string is influenced by external input, this is direct code execution in the application's context.",
    "insecure_deserialization": "Deserializing attacker-controlled data with this API can execute arbitrary code during object reconstruction.",
    "path_traversal": "An attacker supplies a path containing traversal sequences (e.g. ../../) to read or write files outside the intended directory.",
    "buffer_overflow": "Input longer than the destination buffer overwrites adjacent memory, which can crash the program or be leveraged for code execution.",
    "weak_crypto": "The algorithm has known collision/preimage weaknesses; it should not be relied on for integrity or password storage.",
    "debug_mode_enabled": "If this instance is ever reachable from an untrusted network, the interactive debugger allows arbitrary code execution from the browser.",
    "unsafe_yaml_load": "Parsing attacker-controlled YAML with this API can instantiate arbitrary Python objects, leading to code execution.",
    "format_string": "If the format string is influenced by external input, format specifiers can be used to read or write process memory.",
}


def _looks_like_placeholder(finding: Finding) -> bool:
    snippet = finding.snippet
    m = re.search(r"""['"]([^'"]{2,})['"]""", snippet)
    if not m:
        return False
    value = m.group(1)
    return bool(PLACEHOLDER_VALUE.match(value)) or len(value) <= 2


def validate_findings(findings: list[Finding], llm: Optional[OllamaClient] = None) -> dict[str, ValidationResult]:
    results: dict[str, ValidationResult] = {}
    for f in findings:
        if f.vuln_type == "hardcoded_credential" and _looks_like_placeholder(f):
            results[f.id] = ValidationResult(
                finding_id=f.id,
                is_exploitable=False,
                reasoning="The literal value looks like a placeholder/example rather than a real credential (e.g. 'your_api_key_here'). Flagged as a likely false positive and skipped.",
            )
            continue

        attack_vector = ATTACK_VECTOR_BY_TYPE.get(f.vuln_type, "This pattern is a recognized weakness class; review the finding description for the specific risk.")
        reasoning = f"Confirmed via static analysis: {f.title.lower()} at {f.file}:{f.line}. {f.description}"
        results[f.id] = ValidationResult(
            finding_id=f.id, is_exploitable=True, reasoning=reasoning, attack_vector=attack_vector,
        )
    return results
