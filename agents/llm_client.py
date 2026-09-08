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

# Backend selector for local development. "ollama" (or "local") FORCES the
# local Ollama path even when hosted creds are set (e.g. .env carries a real
# key but you want to demo fully offline); "hosted" forces the hosted path;
# unset/"auto" uses hosted only when LLM_BASE_URL + LLM_API_KEY are set.
LLM_BACKEND = os.environ.get("LLM_BACKEND", "auto").strip().lower()


class LocalLLMClient:
    """Thin wrapper around a local Ollama OR a hosted OpenAI-compatible LLM.

    Selection logic:
      1. LLM_BACKEND=ollama (or "local") → always local Ollama.
      2. LLM_BACKEND=hosted → always the hosted endpoint.
      3. Otherwise (auto): if LLM_BASE_URL + LLM_API_KEY are set → hosted
         endpoint, else local Ollama at OLLAMA_URL.

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
        creds_present = bool(self._hosted_url and self._hosted_key)
        forced_local = LLM_BACKEND in ("ollama", "local")
        forced_hosted = LLM_BACKEND == "hosted"
        self._use_hosted = forced_hosted or (creds_present and not forced_local)
        # Resolved lazily so __init__ never does network I/O.
        self._resolved_ollama_model: Optional[str] = None
        # Reason the most recent complete() returned None, for diagnostics.
        # None when the last call succeeded or none has been made.
        self.last_error: Optional[str] = None

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
        return self._pick_ollama_model() is not None

    def _check_hosted(self) -> bool:
        """Lightweight reachability/credential check for the hosted endpoint.

        Mirrors _pick_ollama_model's shape: a short-timeout network call that
        returns False on ANY failure (missing creds, bad key, network issue,
        endpoint down) rather than raising, so callers can safely gate on
        available() before spending a real completion call. Most OpenAI-
        compatible providers (Groq, OpenRouter, OpenAI) expose GET /models
        for exactly this purpose.
        """
        self.last_error = None
        if not self._hosted_url:
            self.last_error = "LLM_BASE_URL is not set"
            return False
        if not self._hosted_key:
            self.last_error = "LLM_API_KEY is not set (is .env present in this folder?)"
            return False
        try:
            r = requests.get(
                f"{self._hosted_url}/models",
                headers={"Authorization": f"Bearer {self._hosted_key}"},
                timeout=5,
            )
            if r.status_code == 200:
                return True
            # Record WHY, so a caller/diagnostic can distinguish a revoked key
            # from a rate limit from a blocked network - all three used to
            # surface identically as a bare False.
            reason = {
                401: "key rejected (401) - revoked, mistyped, or wrong provider",
                403: "key forbidden (403) - key valid but not permitted here",
                404: "endpoint not found (404) - check LLM_BASE_URL",
                429: "rate limited or quota exhausted (429)",
            }.get(r.status_code, f"HTTP {r.status_code}")
            body = (r.text or "").strip().replace("\n", " ")[:200]
            self.last_error = f"{reason}{': ' + body if body else ''}"
            return False
        except Exception as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
            return False

    def _pick_ollama_model(self) -> Optional[str]:
        """Return the Ollama model the client should use, choosing an
        installed one so local just works. If the configured model exists,
        use it; otherwise fall back to whichever model IS installed (prefer
        the smallest so CPU boxes don't choke). None if Ollama is unreachable
        or has no models at all."""
        if self._resolved_ollama_model is not None:
            return self._resolved_ollama_model
        try:
            r = requests.get(f"{self._ollama_url}/api/tags", timeout=3)
            r.raise_for_status()
            models = r.json().get("models", [])
        except Exception:
            return None
        if not models:
            return None

        def size_of(m: dict) -> float:
            m_size = m.get("size")
            try:
                return float(m_size) if m_size is not None else float("inf")
            except (TypeError, ValueError):
                return float("inf")

        names = {m.get("name") for m in models}
        if self._ollama_model not in names:
            # Fall back to the smallest installed model so the client still
            # works even when the requested one was never pulled.
            models.sort(key=size_of)
            chosen = models[0].get("name")
            self._ollama_model = chosen
        self._resolved_ollama_model = self._ollama_model
        return self._resolved_ollama_model

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
        # Reset per call so `last_error` always describes THIS request.
        self.last_error = None
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
                    kind = "rate-limited (429)" if r.status_code == 429 else f"server error ({r.status_code})"
                    if r.headers.get("x-should-retry", "").lower() == "false":
                        self.last_error = f"{kind}; provider said do not retry (quota likely exhausted)"
                        return None
                    retry_after = r.headers.get("Retry-After")
                    sleep_s = float(retry_after) if retry_after else (1.5 * (attempt + 1))
                    last_error = f"{kind}, retrying after {sleep_s:.1f}s"
                    time.sleep(max(1.0, min(sleep_s, 15.0)))
                    continue
                if r.status_code == 404:
                    # An OpenAI-compatible endpoint returns 404 from
                    # /chat/completions when the MODEL name is unknown, not
                    # when the URL is wrong (a wrong URL fails earlier, and
                    # available() would already be False). Say so plainly -
                    # the bare HTTPError sends people checking the URL, which
                    # is the wrong place to look.
                    self.last_error = (
                        f"model '{self.model}' not found at this provider (404). "
                        f"Run: python -m scripts.list_models  to see valid names."
                    )
                    return None
                r.raise_for_status()
                choice = r.json()["choices"][0]["message"]
                out = choice.get("content")
                # Some reasoning models (e.g. Groq's gpt-oss / qwen) put the answer
                # in a `reasoning` field and leave `content` empty on long prompts.
                if not out:
                    out = choice.get("reasoning")
                if out:
                    return out
                last_error = "empty response (model returned no content)"
            except Exception as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                time.sleep(1.5 * (attempt + 1))
        self.last_error = last_error or "unknown failure"
        return None

    # --- Local Ollama (/api/generate) --------------------------------------
    def _complete_ollama(self, prompt: str, temperature: float,
                         max_tokens: int) -> Optional[str]:
        self.last_error = None
        if self._pick_ollama_model() is None:
            self.last_error = "no Ollama model available (server unreachable or no models pulled)"
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
            out = r.json().get("response") or None
            if not out:
                self.last_error = "empty response (model returned no content)"
            return out
        except Exception as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
            return None