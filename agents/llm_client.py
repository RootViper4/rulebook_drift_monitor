from __future__ import annotations

import json
import os
import re
from typing import Optional

import requests

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:1b")


class LocalLLMClient:
    """Thin wrapper around the local Ollama (OpenAI-compatible) endpoint.

    Provides deterministic JSON extraction with graceful fallback so that
    downstream agents can tolerate imperfect model output.
    """

    def __init__(self, url: str = OLLAMA_URL, model: str = MODEL):
        self.url = url
        self.model = model

    def available(self) -> bool:
        try:
            r = requests.get(f"{self.url}/api/tags", timeout=3)
            return r.status_code == 200 and self.model in [m["name"] for m in r.json().get("models", [])]
        except Exception:
            return False

    def complete(self, prompt: str, temperature: float = 0.2, max_tokens: int = 700) -> Optional[str]:
        """Return free-text completion, or None if unavailable."""
        if not self.available():
            return None
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }
        try:
            r = requests.post(f"{self.url}/api/generate", json=payload, timeout=120)
            r.raise_for_status()
            return r.json().get("response") or None
        except Exception:
            return None

    def complete_json(self, prompt: str, temperature: float = 0.1, max_tokens: int = 700) -> Optional[dict]:
        raw = self.complete(prompt, temperature=temperature, max_tokens=max_tokens)
        if not raw:
            return None
        return _try_extract_json(raw)


def _try_extract_json(raw: str) -> Optional[dict]:
    """Best-effort extraction of a JSON object from LLM output."""
    raw = raw.strip()
    # Try to find balanced JSON object anywhere in the response
    start = raw.find("{")
    if start == -1:
        return None
    depth = 0
    in_str = False
    for i in range(start, len(raw)):
        ch = raw[i]
        if ch == '"' and (i == 0 or raw[i-1] != "\\"):
            in_str = not in_str
        if in_str:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                candidate = raw[start:i+1]
                try:
                    return json.loads(candidate)
                except json.JSONDecodeError:
                    return None
    return None


def _strip_code_fences(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text)
    return text
