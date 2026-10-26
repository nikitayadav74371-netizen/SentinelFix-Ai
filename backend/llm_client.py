"""
Thin client for a local Ollama instance. Every call degrades gracefully:
if Ollama isn't running or the model isn't pulled, callers get
`available=False` back and fall back to the deterministic rule-based
pipeline rather than raising and killing the whole job.
"""
from __future__ import annotations
import json
import requests
from dataclasses import dataclass
from typing import Optional


@dataclass
class LLMResponse:
    available: bool
    text: str = ""
    error: Optional[str] = None


class OllamaClient:
    def __init__(self, host: str = "http://localhost:11434", model: str = "qwen2.5-coder:7b", timeout: int = 240):
        self.host = host.rstrip("/")
        self.model = model
        self.timeout = timeout

    def is_available(self) -> bool:
        try:
            r = requests.get(f"{self.host}/api/tags", timeout=3)
            return r.status_code == 200
        except requests.RequestException:
            return False

    def list_models(self) -> list[str]:
        try:
            r = requests.get(f"{self.host}/api/tags", timeout=3)
            r.raise_for_status()
            data = r.json()
            return [m["name"] for m in data.get("models", [])]
        except requests.RequestException:
            return []

    def generate(self, prompt: str, system: Optional[str] = None, temperature: float = 0.1) -> LLMResponse:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": temperature},
        }
        if system:
            payload["system"] = system
        try:
            r = requests.post(f"{self.host}/api/generate", json=payload, timeout=self.timeout)
            if r.status_code == 404:
                return LLMResponse(available=False, error=f"Model '{self.model}' not found on Ollama host. Run `ollama pull {self.model}`.")
            r.raise_for_status()
            data = r.json()
            return LLMResponse(available=True, text=data.get("response", "").strip())
        except requests.ConnectionError:
            return LLMResponse(available=False, error=f"Could not connect to Ollama at {self.host}. Is `ollama serve` running?")
        except requests.Timeout:
            return LLMResponse(available=False, error="Ollama request timed out.")
        except requests.RequestException as e:
            return LLMResponse(available=False, error=str(e))

    def generate_json(self, prompt: str, system: Optional[str] = None) -> LLMResponse:
        """Ask for strict JSON output and attempt to parse/clean it."""
        resp = self.generate(prompt, system=system, temperature=0.0)
        if not resp.available:
            return resp
        text = resp.text.strip()
        # Strip markdown code fences if the model added them despite instructions.
        if text.startswith("```"):
            text = text.strip("`")
            if text.startswith("json"):
                text = text[4:]
        text = text.strip()
        return LLMResponse(available=True, text=text)
