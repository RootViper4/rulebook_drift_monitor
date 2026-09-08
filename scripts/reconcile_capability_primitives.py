#!/usr/bin/env python3
"""Run each AI-capability-primitive attack fixture (data/fixtures.capability_primitives.json)
through the full 40-rule corpus (data/rulebook.json) via the deterministic
RuleEvaluationEngine, and print a per-primitive coverage report: which DS rules
fired (Indicator Matched / Obligation Breached) and which primitives no rule
catches at all (DRIFT GAP).

This is a direct fixture-set run (agents.loader.load_fixture_set), not the
typology-based SimulationAgent.run_reconciliation() arm - it's the simpler
one-fixture-per-primitive check this exercise asked for.

    python3 scripts/reconcile_capability_primitives.py
"""
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from agents.loader import load_fixture_set, load_rulebook
from agents.rule_engine import RuleEvaluationEngine

FIXTURES_PATH = os.path.join(BASE, "data", "fixtures.capability_primitives.json")

# Primitives that are explicitly upstream/force-multiplier in nature (per the
# brief) rather than control surfaces a transaction rule could ever fire on.
NOT_A_CONTROL_SURFACE = {"CP-09", "CP-10"}


def main():
    rulebook = load_rulebook()
    rules_by_id = {r.id: r for r in rulebook}
    fixtures = load_fixture_set(FIXTURES_PATH)
    engine = RuleEvaluationEngine()

    by_primitive: dict[str, list[dict]] = {}
    for fx in fixtures:
        results = engine.evaluate(rulebook, fx["tx"])
        fired = [r.rule_id for r in results if r.fired]
        for cp in fx.get("capability_primitives") or ["(none - clean fixture)"]:
            by_primitive.setdefault(cp, []).append({**fx, "fired": fired})

    print("=" * 100)
    print("RECONCILIATION ARM: capability-primitive coverage against the 40-rule corpus")
    print("=" * 100)

    drift_gaps = []
    for cp in sorted(by_primitive):
        print(f"\n{cp}")
        any_fired_for_cp = False
        for fx in by_primitive[cp]:
            fired = fx["fired"]
            print(f"  fixture: {fx['id']}")
            print(f"    {fx['label']}")
            if fired:
                any_fired_for_cp = True
                tags = ", ".join(
                    f"{rid} ({'Obligation Breached' if rules_by_id[rid].rule_type == 'obligation' else 'Indicator Matched'})"
                    for rid in fired
                )
                print(f"    CAUGHT   -> {tags}")
            else:
                if cp == "(none - clean fixture)":
                    verdict = "QUIET (expected - clean fixture)"
                elif cp in NOT_A_CONTROL_SURFACE:
                    verdict = "OUT OF SCOPE (not a control surface)"
                else:
                    verdict = "SLIPPED THROUGH"
                print(f"    {verdict}")
            if fx.get("missing_fields"):
                print(f"    missing fields (would need to add): {', '.join(fx['missing_fields'])}")
            if fx.get("representation_note"):
                print(f"    note: {fx['representation_note']}")
        if cp != "(none - clean fixture)" and cp not in NOT_A_CONTROL_SURFACE and not any_fired_for_cp:
            drift_gaps.append(cp)

    print("\n" + "=" * 100)
    print("DRIFT GAPS (no rule in the 40-rule corpus fires on this primitive):")
    if drift_gaps:
        for cp in sorted(set(drift_gaps)):
            print(f"  - {cp}")
    else:
        print("  (none)")
    print("=" * 100)


if __name__ == "__main__":
    main()