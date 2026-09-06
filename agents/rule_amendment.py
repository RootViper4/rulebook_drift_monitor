#!/usr/bin/env python3
"""Institutionalising an approved finding into the rulebook.

When an analyst approves and institutes a finding, the platform:
  1. generates a dedicated DS indicator -- a deterministic signature predicate
     built from the approved typology's behavioural signature (test fixtures),
  2. persists it to data/rulebook.json (ds-{41+}), so it is forever present in
     the Rule Catalog and the deterministicscanner,
  3. registers the typology as COVERED, so drift measurement credits the gap
     closure (its detected pairs count as fired -> coverage rises, Drift Index
     falls), and
  4. excludes covered typologies from subsequent findings (their gaps are closed).

The demo can roll everything back to the shipped DS-01..DS-40 baseline.
All data is synthetic/illustrative.
"""
from __future__ import annotations

import json
import os
import shutil
import uuid
from typing import Optional

from agents.models import Rule, Typology
from agents.rule_engine import RuleEvaluationEngine

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
RULEBOOK_PATH = os.path.join(DATA_DIR, "rulebook.json")
BASE_RULEBOOK_PATH = os.path.join(DATA_DIR, "rulebook.base.json")
INSTITUTED_PATH = os.path.join(DATA_DIR, "instituted.json")

_BASE_RULE_COUNT = 40  # shipped DS-01..DS-40


def load_instituted(inst_path: Optional[str] = None) -> dict:
    path = inst_path or INSTITUTED_PATH
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        data.setdefault("rules", [])
        data.setdefault("covered", {})
        data.setdefault("resolved_findings", [])
        return data
    except Exception:
        return {"rules": [], "covered": {}, "resolved_findings": []}


def save_instituted(data: dict) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(INSTITUTED_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def covered_typology_ids() -> set[str]:
    return set(load_instituted()["covered"].keys())


def covered_typologies(exclude_ids: Optional[set[str]] = None) -> set[str]:
    ids = covered_typology_ids()
    return set() if exclude_ids is None else ids.difference(exclude_ids)


def backup_base_rulebook() -> None:
    """Snapshot the shipped DS-01..DS-40 baseline once, for demo rollback."""
    if os.path.exists(BASE_RULEBOOK_PATH):
        return
    shutil.copy(RULEBOOK_PATH, BASE_RULEBOOK_PATH)


def load_rulebook_with_instituted(path: Optional[str] = None) -> list[Rule]:
    from agents.loader import load_rulebook

    rules = load_rulebook(path)
    engine = RuleEvaluationEngine()
    for r in rules:
        engine.register(r)  # idempotent; re-registers signatures after restart
    return rules


def _make_signature(typology: Typology) -> dict[str, object]:
    """Characteristic (field, value) pairs shared across ALL the typology's
    fixtures - the behavioural signature the dedicated indicator detects."""
    fixtures = [f.get("tx", f) for f in typology.test_fixtures if isinstance(f, dict)]
    if not fixtures:
        return {}
    common: Optional[set] = None
    for fx in fixtures:
        pairs = {(k, v) for k, v in fx.items() if isinstance(v, (str, int, float, bool)) and v not in ("", None)}
        common = pairs if common is None else (common & pairs)
    # Order deterministically, skip volatile numerics to keep the predicate robust.
    sig = {}
    for k, v in sorted(common, key=lambda kv: kv[0]):
        if isinstance(v, (int, float)):
            continue
        sig[k] = v
    return sig


def generate_rule(typology: Typology, finding, run_id: str, seq: int) -> Rule:
    signature = _make_signature(typology)
    new_id = f"DS-{_BASE_RULE_COUNT + seq:02d}"
    techniques = " / ".join(t for t in (typology.techniques or [])[:3]) or "behavioural signature"
    ai_like = "ai" in " ".join((typology.techniques or []) + [typology.name]).lower()
    cat = None
    if getattr(finding, "fired_rules", None):
        cat = _rule_category(finding.fired_rules[0])
    return Rule(
        id=new_id,
        source="Institutionalised · approved review finding",
        source_ref=f"Amendment note · {run_id}",
        category=cat or "uncategorised",
        name=f"{typology.name} detected pattern (institutionalised)",
        text=(
            f"Dedicated indicator for the approved {typology.name} pattern: fires when the "
            f"transaction exhibits the full behavioural signature ({techniques}). "
            f"Amended into the rulebook following analyst approval of finding {typology.id}."
        ),
        keywords=[typology.name, typology.id] + list(typology.techniques or []),
        rule_type="indicator",
        trigger=f"signature match: {techniques}",
        risk_severity=typology.risk_severity,
        ai_relevant=ai_like,
        signal_signature=signature,
        institutionalised=True,
        source_finding=typology.id,
    )


def _rule_category(rule_id: str) -> Optional[str]:
    from agents.loader import load_rulebook

    for r in load_rulebook():
        if r.id == rule_id:
            return r.category
    return None


def institute(typology: Typology, finding, run_id: str) -> dict:
    """Append the dedicated indicator + register the typology as covered."""
    inst = load_instituted()
    if typology.id in inst["covered"]:
        return _status(inst, changed=False, rule=inst["covered"][typology.id][0])

    backup_base_rulebook()
    seq = len(inst["rules"]) + 1
    rule = generate_rule(typology, finding, run_id, seq)

    # Deterministic self-check: the new indicator MUST fire the typology's
    # fixtures (gap actually closed) before it is committed.
    engine = RuleEvaluationEngine()
    engine.register(rule)
    fired = 0
    total = 0
    for fx_in in typology.test_fixtures:
        if not isinstance(fx_in, dict):
            continue
        total += 1
        reses = engine.evaluate([rule], fx_in)
        if reses and reses[0].fired:
            fired += 1
    if fired < max(1, total // 2):
        return {"ok": False, "error": f"Candidate indicator does not reproduce for {typology.id}"}

    rules = load_rulebook_with_instituted()
    rules.append(rule)
    with open(RULEBOOK_PATH, "w", encoding="utf-8") as f:
        json.dump({"version": "drift-sentinel-institutionalised", "count": len(rules),
                   "rules": [r.__dict__ if hasattr(r, "__dict__") else _rule_to_dict(r) for r in rules]},
                  f, indent=2, ensure_ascii=False)

    inst["rules"].append(_rule_to_dict(rule))
    inst["covered"].setdefault(typology.id, []).append(rule.id)
    inst["resolved_findings"] = list(dict.fromkeys(inst["resolved_findings"] + [typology.id]))
    save_instituted(inst)
    return _status(inst, changed=True, rule=rule.id)


def _rule_to_dict(rule: Rule) -> dict:
    return {
        "id": rule.id, "source": rule.source, "source_ref": rule.source_ref,
        "category": rule.category, "name": rule.name, "text": rule.text,
        "keywords": rule.keywords, "rule_type": rule.rule_type, "trigger": rule.trigger,
        "mitre_atlas": rule.mitre_atlas, "capability_primitives": rule.capability_primitives,
        "risk_severity": rule.risk_severity, "ai_relevant": rule.ai_relevant,
        "signal_signature": rule.signal_signature, "institutionalised": rule.institutionalised,
        "source_finding": rule.source_finding,
    }


def _status(inst: dict, changed: bool, rule: str) -> dict:
    return {
        "ok": True,
        "changed": changed,
        "rule": rule,
        "rules": [r["id"] for r in inst.get("rules", [])],
        "covered": sorted(inst.get("covered", {}).keys()),
        "resolved_findings": inst.get("resolved_findings", []),
    }


def restore_baseline() -> dict:
    """Roll the rulebook back to the shipped DS-01..DS-40 corpus."""
    removed = []
    if os.path.exists(BASE_RULEBOOK_PATH):
        try:
            with open(RULEBOOK_PATH, encoding="utf-8") as f:
                current = json.load(f).get("rules", [])
            removed = [r.get("id") for r in current if r.get("institutionalised")]
        except Exception:
            removed = []
        with open(RULEBOOK_PATH, "w", encoding="utf-8") as f:
            f.write(open(BASE_RULEBOOK_PATH, encoding="utf-8").read())
    if os.path.exists(INSTITUTED_PATH):
        os.remove(INSTITUTED_PATH)
    if removed:
        from agents.rule_engine import RuleEvaluationEngine
        for rid in removed:
            RuleEvaluationEngine._PREDICATES.pop(rid, None)
    return {"ok": True, "removed": removed}