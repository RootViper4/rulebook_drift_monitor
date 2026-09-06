#!/usr/bin/env python3
"""Optional pre-seeded 'drafted candidate red flags' cache.

A full run performs one LLM completion per verified gap. On a local
llama3.2:1b this serialises to minutes per run - poor for a live demo. Like
run_history.json / live_run.json, drafted flags are demo-data: they are
produced by the SAME LLM call the pipeline would make (never hand-typed),
then cached by typology so replay is instant and byte-identical. Missing ids
fall back to live generation.
"""
from __future__ import annotations

import json
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE_PATH = os.path.join(BASE_DIR, "data", "drafted_flags.json")


def load_cache() -> dict:
    try:
        with open(CACHE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_cache(data: dict) -> None:
    os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
    with open(CACHE_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def get_draft(typology_id: str) -> str | None:
    return load_cache().get(typology_id)


def cache_draft(typology_id: str, text: str) -> None:
    data = load_cache()
    if data.get(typology_id) == text:
        return
    data[typology_id] = text
    save_cache(data)