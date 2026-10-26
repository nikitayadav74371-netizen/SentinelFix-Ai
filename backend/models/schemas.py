"""
Pydantic schemas shared across the SentinelFix AI pipeline.
"""
from __future__ import annotations

from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
import uuid
import time


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class VulnType(str, Enum):
    HARDCODED_CREDENTIAL = "hardcoded_credential"
    HARDCODED_SECRET_KEY = "hardcoded_secret_key"
    SQL_INJECTION = "sql_injection"
    XSS_INNERHTML = "xss_innerhtml"
    COMMAND_INJECTION = "command_injection"
    EVAL_USAGE = "eval_usage"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    WEAK_CRYPTO = "weak_crypto"
    PATH_TRAVERSAL = "path_traversal"
    BUFFER_OVERFLOW = "buffer_overflow"
    XXE = "xxe"
    OPEN_REDIRECT = "open_redirect"
    DEBUG_MODE_ENABLED = "debug_mode_enabled"
    INSECURE_RANDOM = "insecure_random"
    SSRF = "ssrf"
    CSRF_MISSING = "csrf_missing"
    FORMAT_STRING = "format_string"
    UNSAFE_YAML_LOAD = "unsafe_yaml_load"


class PipelineStage(str, Enum):
    QUEUED = "queued"
    ANALYZING = "analyzing"
    VALIDATING = "validating"
    PATCHING = "patching"
    JUDGING = "judging"
    REGRESSION = "regression"
    VERIFIED = "verified"
    REJECTED_FINAL = "rejected_final"
    FALSE_POSITIVE = "false_positive"


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    file: str
    language: str
    line: int
    end_line: int
    vuln_type: VulnType
    severity: Severity
    cwe: str
    title: str
    description: str
    snippet: str
    confidence: float = 0.9
    extra: Dict[str, Any] = Field(default_factory=dict)


class ValidationResult(BaseModel):
    finding_id: str
    is_exploitable: bool
    reasoning: str
    attack_vector: Optional[str] = None


class PatchAttempt(BaseModel):
    finding_id: str
    attempt_number: int
    strategy: str  # "deterministic" | "llm_assisted"
    original_snippet: str
    patched_snippet: str
    diff: str
    explanation: str


class JudgeVerdict(BaseModel):
    finding_id: str
    attempt_number: int
    verdict: str  # "PASS" | "REJECT"
    reasoning: str
    checks: Dict[str, bool] = Field(default_factory=dict)


class RegressionResult(BaseModel):
    file: str
    syntax_ok: bool
    structure_preserved: bool
    details: str


class FindingLifecycle(BaseModel):
    finding: Finding
    stage: PipelineStage = PipelineStage.QUEUED
    validation: Optional[ValidationResult] = None
    patch_attempts: List[PatchAttempt] = Field(default_factory=list)
    judge_verdicts: List[JudgeVerdict] = Field(default_factory=list)
    regression: Optional[RegressionResult] = None
    final_status: Optional[str] = None  # "VERIFIED" | "REJECTED" | "FALSE_POSITIVE"


class ScanRequest(BaseModel):
    source_type: str  # "local" | "github"
    local_path: Optional[str] = None
    github_url: Optional[str] = None
    ollama_model: Optional[str] = "qwen2.5-coder:7b"
    ollama_host: Optional[str] = "http://localhost:11434"
    use_llm: bool = True
    auto_apply: bool = True


class JobState(BaseModel):
    job_id: str
    created_at: float = Field(default_factory=time.time)
    status: str = "queued"  # queued | scanning | patching | done | error
    request: ScanRequest
    resolved_root: Optional[str] = None
    files_scanned: int = 0
    files_total: int = 0
    findings: List[FindingLifecycle] = Field(default_factory=list)
    error: Optional[str] = None
    output_zip: Optional[str] = None
    summary: Dict[str, Any] = Field(default_factory=dict)
