from __future__ import annotations

import os
from typing import Optional

import requests

# Load a project-local .env (if present) BEFORE reading the env vars below,
# so a developer can drop an LLM_API_KEY in .env and immediately get the fast
# hosted path without exporting anything. os.environ already set by the shell
# takes precedence (python-dotenv does not override existing values).
try:
    from dotenv import load_dotenv

    load_dotenv()
except Exception:
    pass

# --- Local Ollama (default) ------------------------------------------------
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:1b")
# CPU-only machines (e.g. Intel Macs) run this 1B model at ~1 token/sec, so a
# full 300+ token scenario answer can outlive any sane timeout. Cap the local
# generation size and give it a bounded timeout so a slow/stuck generation
# fails fast and the slot falls back instead of stalling the whole run for
# minutes. On Apple-silicon or GPU machines a real answer fits comfortably
# inside these bounds and still succeeds.
OLLAMA_MAX_TOKENS = 320
OLLAMA_TIMEOUT = 45

# --- Hosted OpenAI-compatible endpoint (Vercel / production) ----------------
# When LLM_BASE_URL + LLM_API_KEY are set the client routes requests to
# the remote endpoint via /chat/completions (OpenAI wire format).  This lets
# the Vercel serverless function call a hosted model (OpenRouter, OpenAI,
# Groq, etc.) without requiring Ollama on the same machine.
LLM_BASE_URL = os.environ.get("LLM_BASE_URL", "").rstrip("/")
LLM_API_KEY = os.environ.get("LLM_API_KEY", "")
LLM_MODEL = os.environ.get("LLM_MODEL", "")


class LocalLLMClient:
    """Thin wrapper around a local Ollama OR a hosted OpenAI-compatible LLM.

    Selection logic:
      1. If LLM_BASE_URL + LLM_API_KEY are set → hosted endpoint
         (OpenAI /chat/completions wire format).
      2. Otherwise → local Ollama at OLLAMA_URL.

    Returns None on any failure (unreachable, model missing, bad response)
    so downstream agents can tolerate imperfect model output.
    """

    def __init__(self, url: str = OLLAMA_URL, model: str = OLLAMA_MODEL):
        self._ollama_url = url
        self._ollama_model = model
        # Hosted endpoint overrides
        self._hosted_url = LLM_BASE_URL
        self._hosted_key = LLM_API_KEY
        self._hosted_model = LLM_MODEL or "gpt-4o-mini"
        self._use_hosted = bool(self._hosted_url and self._hosted_key)

        # Backwards-compatible public attributes used by other modules
        self.url = self._hosted_url if self._use_hosted else self._ollama_url
        self.model = self._hosted_model if self._use_hosted else self._ollama_model
        # Whether this client talks to a remote hosted endpoint (so the caller
        # can e.g. spend more attempts on fast hosted calls than on a slow
        # local model).
        self.is_hosted = self._use_hosted

    # ------------------------------------------------------------------
    def available(self) -> bool:
        if self._use_hosted:
            return self._check_hosted()
        return self._check_ollama()

    def _check_hosted(self) -> bool:
        try:
            r = requests.get(
                f"{self._hosted_url}/models",
                headers={"Authorization": f"Bearer {self._hosted_key}"},
                timeout=5,
            )
            if r.status_code == 200:
                return True
            # Some providers don't support /models — try a tiny completion
            return r.status_code in (401, 403)
        except Exception:
            # Even if /models fails, the endpoint may still work
            return True

    def _check_ollama(self) -> bool:
        try:
            r = requests.get(f"{self._ollama_url}/api/tags", timeout=3)
            return r.status_code == 200 and self._ollama_model in [
                m["name"] for m in r.json().get("models", [])
            ]
        except Exception:
            return False

    # ------------------------------------------------------------------
    def complete(self, prompt: str, temperature: float = 0.2,
                 max_tokens: int = 700) -> Optional[str]:
        """Return free-text completion, or None if unavailable."""
        if self._use_hosted:
            return self._complete_hosted(prompt, temperature, max_tokens)
        return self._complete_ollama(prompt, temperature, max_tokens)

    # --- Hosted (OpenAI /chat/completions) --------------------------------
    def _complete_hosted(self, prompt: str, temperature: float,
                         max_tokens: int) -> Optional[str]:
        import time
        last_error: Optional[str] = None
        # Hosted providers (esp. free tiers like Groq) rate-limit with bursts;
        # retries + backoff dramatically cut spurious fallback fills in the
        # generation arm. 429/5xx retry after backoff (honouring Retry-After
        # when the server sends it - a per-minute burst cap needs seconds, not
        # the sub-second sleeps a small model needs for its own limits).
        for attempt in range(3):
            try:
                r = requests.post(
                    f"{self._hosted_url}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self._hosted_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self._hosted_model,
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": temperature,
                        "max_tokens": max_tokens,
                    },
                    timeout=120,
                )
                if r.status_code == 429 or r.status_code >= 500:
                    # Rate-limited or transient server error. Some providers
                    # (Groq free tier) say explicitly NOT to retry when the
                    # daily/minute quota is gone - retrying then just stalls
                    # the run and burns the whole budget for nothing. Fail
                    # fast in that case so the composer falls back quickly.
                    if r.headers.get("x-should-retry", "").lower() == "false":
                        return None
                    retry_after = r.headers.get("Retry-After")
                    sleep_s = float(retry_after) if retry_after else (1.5 * (attempt + 1))
                    time.sleep(max(1.0, min(sleep_s, 15.0)))
                    continue
                r.raise_for_status()
                choice = r.json()["choices"][0]["message"]
                out = choice.get("content")
                # Some reasoning models (e.g. Groq's gpt-oss / qwen) put the answer
                # in a `reasoning` field and leave `content` empty on long prompts.
                if not out:
                    out = choice.get("reasoning")
                if out:
                    return out
                last_error = "empty response"
            except Exception as exc:
                last_error = str(exc)
                time.sleep(1.5 * (attempt + 1))
        return None

    # --- Local Ollama (/api/generate) --------------------------------------
    def _complete_ollama(self, prompt: str, temperature: float,
                         max_tokens: int) -> Optional[str]:
        if not self.available():
            return None
        payload = {
            "model": self._ollama_model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                # Cap local generations: a CPU-only box must not grind out a
                # full 650-token answer at 1 token/sec.
                "num_predict": min(max_tokens, OLLAMA_MAX_TOKENS),
            },
        }
        try:
            r = requests.post(f"{self._ollama_url}/api/generate",
                              json=payload, timeout=OLLAMA_TIMEOUT)
            r.raise_for_status()
            return r.json().get("response") or None
        except Exception:
            return None
