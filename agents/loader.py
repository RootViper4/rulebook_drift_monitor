from __future__ import annotations

import json
import os
import sys
from typing import Optional

from agents.models import Rule, Typology
from agents.trigger_schema import validate_rule_type, validate_trigger_schema

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
RULEBOOK_PATH = os.path.join(DATA_DIR, "rulebook.json")
LEGACY_RULEBOOK_PATH = os.path.join(DATA_DIR, "rulebook.legacy.json")
TYPOLOGIES_PATH = os.path.join(DATA_DIR, "typologies.json")
GENERATED_PATH = os.path.join(DATA_DIR, "generated_typologies.json")


class RulebookValidationError(ValueError):
    """A rule in the rulebook has a trigger (or rule_type) that is invalid."""


def _validate_rule_trigger(rule: Rule) -> list[str]:
    """Check a single rule's trigger is interpretable.

    A rule is fine if it has a structurally valid `trigger_schema`, or if it
    has a `signal_signature` that RuleEvaluationEngine.register() will still
    compile into one at runtime (the institutionalised-rule path). A rule
    with neither can never fire and never will - that must be surfaced
    loudly here, not silently treated as "never fires" during evaluation.
    """
    errors = [f"{rule.id}: {e}" for e in validate_rule_type(rule.rule_type)]
    if rule.trigger_schema:
        errors += [f"{rule.id}: {e}" for e in validate_trigger_schema(rule.trigger_schema)]
    elif not rule.signal_signature:
        errors.append(f"{rule.id}: has neither a trigger_schema nor a signal_signature - trigger cannot be interpreted")
    return errors


def load_rulebook(path: Optional[str] = None, *, strict: bool = True) -> list[Rule]:
    path = path or RULEBOOK_PATH
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    rules = [Rule(**r) for r in data["rules"]]

    errors = [err for rule in rules for err in _validate_rule_trigger(rule)]
    if errors:
        message = f"{path}: {len(errors)} rule(s) failed validation:\n  " + "\n  ".join(errors)
        if strict:
            raise RulebookValidationError(message)
        print(f"WARNING: {message}", file=sys.stderr)

    return rules


def load_legacy_rulebook(path: Optional[str] = None, *, strict: bool = True) -> list[Rule]:
    """Load the frozen DS-01..DS-40 placeholder corpus (data/rulebook.legacy.json),
    kept only so the real corpus being built in data/rulebook.json can be diffed
    against it. Not used by the running pipeline."""
    return load_rulebook(path or LEGACY_RULEBOOK_PATH, strict=strict)


def load_fixture_set(path: str) -> list[dict]:
    """Load a flat list of {"label": str, "tx": {...}} synthetic fixtures for
    direct engine verification - e.g. data/fixtures.real_rules.json - as
    opposed to the Typology corpus's gap-analysis fixtures (load_typologies)."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data["fixtures"]


def load_typologies(path: Optional[str] = None) -> list[Typology]:
    path = path or TYPOLOGIES_PATH
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return [Typology(**t) for t in data["typologies"]]


def load_generated(path: Optional[str] = None) -> list[Typology]:
    """Generated (novel) typologies from the generation-arm catalogue."""
    path = path or GENERATED_PATH
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return []
    return [Typology(**t) for t in data.get("typologies", [])]
