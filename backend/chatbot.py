"""
Security Q&A Copilot — Sentinel AI Cloud Engine (OpenRouter or Groq)
Supports full multi-turn conversation history for both providers.
"""
from __future__ import annotations
import os
import requests
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

# ─── API Keys (set whichever you have) ───────────────────────────
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")
GROQ_API_KEY       = os.environ.get("GROQ_API_KEY", "")
# Preferred cloud provider: "openrouter" or "groq"
CLOUD_PROVIDER = "openrouter"

# ─── Model lists ──────────────────────────────────────────────────
OPENROUTER_FREE_MODELS = [
    "qwen/qwen3-8b:free",
    "qwen/qwq-32b:free",
    "google/gemma-3-12b-it:free",
    "microsoft/phi-4-reasoning:free",
    "meta-llama/llama-3.3-70b-instruct:free",
    "deepseek/deepseek-r1:free",
    "mistralai/mistral-7b-instruct:free",
]

GROQ_DEFAULT_MODELS = [
    "llama-3.3-70b-versatile",
    "llama-3.1-8b-instant",
    "qwen-qwq-32b",
    "gemma2-9b-it",
    "mixtral-8x7b-32768",
]

router = APIRouter(prefix="/api/chat", tags=["Security Copilot"])

SYSTEM_COPILOT_PROMPT = """You are SentinelCopilot, an elite application security engineer embedded inside Sentinel AI — an autonomous vulnerability detection and code remediation platform.

You specialize in static analysis, secure coding standards (OWASP Top 10, CWE, NIST), automated vulnerability remediation, and software architecture.

GUIDELINES:
1. Answer only what the user is asking. Never refer to any previous scan results or project context unless the user explicitly shares code or file content in this conversation.
2. When code or documents are provided, analyze them systematically.
3. When asked for code, write clean, modern, secure-by-default production code.
4. Structure responses with clear headings and properly fenced code blocks.
5. Be direct, precise, and professional — like a senior security architect.
"""


class ChatMessage(BaseModel):
    role: str   # "user" or "assistant"
    content: str


class ChatRequest(BaseModel):
    message: str
    history: List[ChatMessage] = []   # Full conversation history from frontend
    provider: str = "system"          # "system" or "online"
    model: str = "qwen2.5-coder:7b"
    system_host: str = "http://localhost:11434"
    file_context: Optional[str] = None
    file_name: Optional[str] = None


def _build_messages(req: ChatRequest) -> list:
    """Assemble full messages array with system prompt + history + current message."""
    user_content = req.message
    if req.file_context and req.file_name:
        user_content = (
            f"FILE ATTACHED: `{req.file_name}`\n"
            f"```\n{req.file_context}\n```\n\n"
            f"USER QUERY: {req.message}"
        )

    messages = [{"role": "system", "content": SYSTEM_COPILOT_PROMPT}]
    # Replay history
    for h in req.history:
        messages.append({"role": h.role, "content": h.content})
    messages.append({"role": "user", "content": user_content})
    return messages


@router.get("/models")
def get_available_models(host: str = "http://localhost:11434"):
    # --- System (Local Ollama) ---
    system_models = []
    system_online = False
    try:
        r = requests.get(f"{host.rstrip('/')}/api/tags", timeout=3)
        if r.status_code == 200:
            system_online = True
            system_models = [m["name"] for m in r.json().get("models", [])]
    except Exception:
        system_online = False

    # --- Online (Cloud) ---
    online_models = []
    if CLOUD_PROVIDER == "openrouter" and OPENROUTER_API_KEY:
        try:
            r = requests.get(
                "https://openrouter.ai/api/v1/models",
                headers={"Authorization": f"Bearer {OPENROUTER_API_KEY}"},
                timeout=5,
            )
            if r.status_code == 200:
                data = r.json().get("data", [])
                # Prefer free models, filter noise
                free = [m["id"] for m in data if ":free" in m.get("id", "")]
                online_models = free if free else [m["id"] for m in data[:20]]
            else:
                online_models = OPENROUTER_FREE_MODELS
        except Exception:
            online_models = OPENROUTER_FREE_MODELS
    elif GROQ_API_KEY:
        try:
            r = requests.get(
                "https://api.groq.com/openai/v1/models",
                headers={"Authorization": f"Bearer {GROQ_API_KEY}"},
                timeout=4,
            )
            if r.status_code == 200:
                data = r.json().get("data", [])
                online_models = [m["id"] for m in data if "whisper" not in m["id"]]
            else:
                online_models = GROQ_DEFAULT_MODELS
        except Exception:
            online_models = GROQ_DEFAULT_MODELS
    else:
        online_models = OPENROUTER_FREE_MODELS

    return {
        "system": {
            "available": system_online,
            "models": system_models or ["qwen2.5-coder:7b", "llama3:latest"],
        },
        "online": {
            "provider": CLOUD_PROVIDER,
            "has_key": bool(OPENROUTER_API_KEY or GROQ_API_KEY),
            "models": online_models,
        },
    }


@router.post("/query")
def chat_query(req: ChatRequest):
    messages = _build_messages(req)

    # ── 1. Online Engine (Cloud) ──────────────────────────────────
    if req.provider.lower() == "online":
        if CLOUD_PROVIDER == "openrouter":
            if not OPENROUTER_API_KEY:
                raise HTTPException(400, "OpenRouter API key not configured.")
            headers = {
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://sentinel-ai.local",
                "X-Title": "Sentinel AI Copilot",
            }
            model = req.model or "qwen/qwen3-8b:free"
            payload = {
                "model": model,
                "messages": messages,
                "temperature": 0.2,
                "max_tokens": 2048,
            }
            try:
                res = requests.post(
                    "https://openrouter.ai/api/v1/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=90,
                )
                if res.status_code != 200:
                    err = res.json().get("error", {}).get("message", res.text)
                    if "rate" in err.lower() or "limit" in err.lower():
                        raise HTTPException(429, "Rate limit reached. Try a different Online Model or wait a moment.")
                    raise HTTPException(res.status_code, f"Cloud engine error: {err[:200]}")
                reply = res.json()["choices"][0]["message"]["content"]
                return {"reply": reply, "model": model, "provider": "Online Model (Cloud)"}
            except requests.RequestException as e:
                raise HTTPException(500, f"Failed to reach Online Engine: {str(e)[:200]}")

        else:  # Groq
            if not GROQ_API_KEY:
                raise HTTPException(400, "Groq API key not configured.")
            headers = {
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json",
            }
            model = req.model or "llama-3.3-70b-versatile"
            payload = {
                "model": model,
                "messages": messages,
                "temperature": 0.2,
                "max_tokens": 1500,
            }
            try:
                res = requests.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=90,
                )
                if res.status_code != 200:
                    err_msg = res.json().get("error", {}).get("message", res.text)
                    if "output tokens" in err_msg.lower() or "limit" in err_msg.lower():
                        raise HTTPException(429, "Token rate limit reached. Select a different Online Model or shorten your message.")
                    raise HTTPException(res.status_code, f"Cloud engine error (code {res.status_code}).")
                reply = res.json()["choices"][0]["message"]["content"]
                return {"reply": reply, "model": model, "provider": "Online Model (Cloud)"}
            except requests.RequestException as e:
                raise HTTPException(500, f"Failed to reach Online Engine: {str(e)[:200]}")

    # ── 2. System Engine (Local Ollama) ──────────────────────────
    else:
        host = req.system_host.rstrip("/")
        # Convert OpenAI-style messages to Ollama prompt format
        prompt_parts = []
        for m in messages:
            if m["role"] == "system":
                continue   # system is sent separately
            prefix = "User: " if m["role"] == "user" else "Assistant: "
            prompt_parts.append(f"{prefix}{m['content']}")
        prompt = "\n\n".join(prompt_parts)

        payload = {
            "model": req.model or "qwen2.5-coder:7b",
            "prompt": prompt,
            "system": SYSTEM_COPILOT_PROMPT,
            "stream": False,
            "options": {"temperature": 0.2},
        }
        try:
            res = requests.post(f"{host}/api/generate", json=payload, timeout=180)
            if res.status_code == 404:
                raise HTTPException(404, f"System Model '{req.model}' not found locally. Run `ollama pull {req.model}`.")
            if res.status_code != 200:
                raise HTTPException(res.status_code, "System Engine processing error.")
            reply = res.json().get("response", "")
            return {"reply": reply, "model": req.model, "provider": "System Model (Local)"}
        except requests.ConnectionError:
            raise HTTPException(503, "System Engine is unreachable. Please ensure Ollama is running.")
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(500, "An internal System Engine error occurred.")
