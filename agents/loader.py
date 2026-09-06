from __future__ import annotations

import json
import os
from typing import Optional

from agents.models import Rule, Typology

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
RULEBOOK_PATH = os.path.join(DATA_DIR, "rulebook.json")
TYPOLOGIES_PATH = os.path.join(DATA_DIR, "typologies.json")


def load_rulebook(path: Optional[str] = None) -> list[Rule]:
    path = path or RULEBOOK_PATH
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return [Rule(**r) for r in data["rules"]]


def load_typologies(path: Optional[str] = None) -> list[Typology]:
    path = path or TYPOLOGIES_PATH
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return [Typology(**t) for t in data["typologies"]]
