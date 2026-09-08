"""List the model IDs your configured provider actually offers.

Exists because a wrong LLM_MODEL fails in a confusing way: available() passes
(the credentials and endpoint are fine - it only lists models) but every
completion returns 404 from /chat/completions. The fix is always "use a model
name this account really has", and guessing from documentation is unreliable
because provider catalogues change and vary by account.

Usage, from rulebook_drift_monitor/:
    python -m scripts.list_models

Reads the same .env as the app, so whatever it prints is valid for LLM_MODEL.
"""
from __future__ import annotations

import os

import requests

from agents.llm_client import LocalLLMClient


def main() -> None:
    llm = LocalLLMClient()

    if not getattr(llm, "is_hosted", False):
        print("LLM_BACKEND is not 'hosted' - this script only lists hosted "
              "provider models. Set LLM_BACKEND=hosted in .env first.")
        return

    url = llm.url.rstrip("/")
    key = getattr(llm, "_hosted_key", None)
    if not key:
        print("No LLM_API_KEY found. Is .env present in this folder?")
        return

    print(f"Provider: {url}")
    print(f"Currently configured LLM_MODEL: {llm.model}\n")

    try:
        r = requests.get(f"{url}/models",
                         headers={"Authorization": f"Bearer {key}"},
                         timeout=10)
    except Exception as exc:
        print(f"Could not reach the provider: {type(exc).__name__}: {exc}")
        return

    if r.status_code != 200:
        print(f"Provider returned HTTP {r.status_code}: {r.text[:300]}")
        return

    payload = r.json()
    models = payload.get("data") or payload.get("models") or []
    ids = sorted(
        m.get("id") or m.get("name")
        for m in models
        if isinstance(m, dict) and (m.get("id") or m.get("name"))
    )

    if not ids:
        print("The provider returned no model list. Raw response:")
        print(str(payload)[:600])
        return

    configured_ok = llm.model in ids
    print(f"{len(ids)} model(s) available to this account:\n")
    for mid in ids:
        mark = "  <-- currently configured" if mid == llm.model else ""
        print(f"  {mid}{mark}")

    print()
    if configured_ok:
        print(f"'{llm.model}' IS in the list, so a 404 from /chat/completions "
              f"would point at something else (check LLM_BASE_URL).")
    else:
        print(f"'{llm.model}' is NOT in the list - that is why completions "
              f"return 404. Set LLM_MODEL in .env to one of the ids above.")
        print("For this project, prefer a plain chat model over an agentic/"
              "'compound' system: the generation arm needs text only, and the "
              "agentic wrapper adds latency and tighter rate limits for no "
              "benefit here.")


if __name__ == "__main__":
    main()