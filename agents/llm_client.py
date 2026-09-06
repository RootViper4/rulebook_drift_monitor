from __future__ import annotations

from typing import Optional

import requests

OLLAMA_URL = "http://localhost:11434"
MODEL = "llama3.2:1b"


class LocalLLMClient:
    """Thin wrapper around the local Ollama (OpenAI-compatible) endpoint.

    Returns None on any failure (unreachable, model missing, bad response) so
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
