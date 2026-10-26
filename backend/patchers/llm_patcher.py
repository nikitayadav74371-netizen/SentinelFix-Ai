"""
LLM-assisted patch generation, used only when no deterministic patcher
exists for a (language, vuln_type) pair. Always validated by the same
SecurityJudge checks as deterministic patches before being accepted, and
never applied if the model is unavailable or its output doesn't survive
validation after retries -- the finding is left unmodified and flagged
for manual review instead.
"""
from __future__ import annotations
import json
import re
from dataclasses import dataclass, field
from typing import Optional, List

from backend.llm_client import OllamaClient

SYSTEM_PROMPT = (
    "You are a precise, conservative application-security patch generator. "
    "You will be shown one vulnerable code snippet from a larger file and a "
    "description of the vulnerability. Produce the SMALLEST possible fix that "
    "eliminates the vulnerability while preserving the exact same functional "
    "behavior for legitimate input. Respond with ONLY a JSON object of the form "
    '{"patched_snippet": "<the replacement code, matching the original snippet\'s '
    'scope exactly line-for-line where possible>", "explanation": "<one or two '
    'sentences, plain language>"}. Do not include markdown fences, comments '
    "outside the JSON, or any text before/after the JSON object."
)


@dataclass
class LLMPatchOutcome:
    ok: bool
    new_snippet: Optional[str] = None
    explanation: str = ""
    failure_reason: Optional[str] = None


def generate_llm_patch(
    llm: OllamaClient,
    finding_title: str,
    finding_description: str,
    language: str,
    original_snippet: str,
    surrounding_context: str,
    prior_rejection_reason: Optional[str] = None,
) -> LLMPatchOutcome:
    if not llm.is_available():
        return LLMPatchOutcome(ok=False, failure_reason="Ollama is not reachable at the configured host.")

    retry_note = ""
    if prior_rejection_reason:
        retry_note = (
            f"\n\nA previous attempt was REJECTED for this reason: {prior_rejection_reason}\n"
            "Produce a different patch that avoids this problem."
        )

    prompt = f"""Language: {language}
Vulnerability: {finding_title}
Description: {finding_description}

Surrounding context (for reference only, do not repeat it in your answer):
```
{surrounding_context}
```

Vulnerable snippet to replace exactly:
```
{original_snippet}
```
{retry_note}

Respond with only the JSON object described in your instructions."""

    resp = llm.generate_json(prompt, system=SYSTEM_PROMPT)
    if not resp.available:
        return LLMPatchOutcome(ok=False, failure_reason=resp.error or "LLM call failed")

    try:
        data = json.loads(resp.text)
        new_snippet = data.get("patched_snippet")
        explanation = data.get("explanation", "LLM-generated patch.")
    except (json.JSONDecodeError, AttributeError):
        # Best-effort: try to pull a code block out even if it didn't obey the JSON instruction.
        m = re.search(r"```(?:\w+)?\s*(.*?)```", resp.text, re.DOTALL)
        if m:
            new_snippet = m.group(1).strip()
            explanation = "LLM-generated patch (extracted from non-JSON response)."
        else:
            return LLMPatchOutcome(ok=False, failure_reason="Could not parse LLM response as JSON or extract a code block.")

    if not new_snippet or new_snippet.strip() == original_snippet.strip():
        return LLMPatchOutcome(ok=False, failure_reason="LLM did not produce a distinct patch.")

    return LLMPatchOutcome(ok=True, new_snippet=new_snippet, explanation=explanation)
