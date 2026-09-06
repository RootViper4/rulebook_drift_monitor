#!/usr/bin/env python3
"""Rulebook Drift Monitor - CLI demo runner.

Run:  python3 -m demo.run   (from rulebook_drift_monitor/)
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.loader import load_rulebook, load_typologies
from agents.orchestrator import Orchestrator


COLORS = {
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "cyan": "\033[36m",
    "reset": "\033[0m",
}


def c(text: str, color: str = "reset") -> str:
    return f"{COLORS[color]}{text}{COLORS['reset']}"


def render_report(run) -> None:
    print("\n" + "=" * 76)
    print(c("  RULEBOOK DRIFT MONITOR - RANKED GAP REPORT", "bold"))
    print("=" * 76)
    print(c(f"  Run: {run.run_id}   Rulebook version: {run.rulebook_version}", "dim"))
    print(c(f"  Status: {run.status}", "yellow"))
    print("-" * 76)

    if not run.results:
        print(c("  No verified detection gaps found in this run.", "green"))
        return

    for i, f in enumerate(run.results, 1):
        print(f"\n{c(f'[{i}] {f.typology_name}  ({f.typology_id})', 'cyan')}")
        print(c(f"    MITRE ATLAS: {', '.join(f.mitre_atlas) if f.mitre_atlas else '(mapping pending)'}", "dim"))
        print(c("    Evades rules:", "red"))
        for rid in f.evaded_rules:
            print(c(f"      - {rid}", "red"))
        print(c("    Fires rules:", "green"))
        for rid in f.fired_rules:
            print(c(f"      + {rid}", "green"))
        print(f"    {c('Evidential basis:', 'bold')} {f.evidential_basis or '(documented typology)'}")
        print(f"    {c('Drafted candidate red flag:', 'bold')}")
        print(c(f"      \"{f.drafted_candidate_red_flag}\"", "yellow"))

    print("\n" + "-" * 76)
    if run.discarded:
        print(c("\n  REJECTED BY CRITIC (guardrail - not promoted):", "red"))
        for d in run.discarded:
            print(c(f"    - {d.get('typology_name')} ({d.get('typology_id')})", "red"))
            print(c(f"      {d.get('evidential_basis')}", "dim"))
    print(c("  HUMAN APPROVAL GATE: awaiting analyst acceptance / amendment / rejection.", "bold"))
    print(c("  No drafted red flag becomes guidance without a named analyst promoting it.", "dim"))
    print("=" * 76 + "\n")


def render_audit(run) -> None:
    print(c("\n  AUDIT TRAIL (auditability & traceability):", "bold"))
    for entry in run.audit:
        print(c(f"    [{entry['ts']}] {entry['node']}: {entry['message']}", "dim"))


def main() -> None:
    ap = argparse.ArgumentParser(description="Rulebook Drift Monitor")
    ap.add_argument("--trigger", default="scheduled", help="Run trigger (scheduled / event / manual)")
    ap.add_argument("--analyst", default="A. Analyst", help="Named analyst for the approval gate")
    ap.add_argument("--json", action="store_true", help="Emit raw JSON state")
    ap.add_argument("--audit", action="store_true", help="Show full audit trail")
    args = ap.parse_args()

    rulebook = load_rulebook()
    typologies = load_typologies()

    orchestrator = Orchestrator(rulebook, typologies)
    run = orchestrator.run(trigger=args.trigger, analyst=args.analyst)

    if args.json:
        print(json.dumps(run.dict(), indent=2))
        return

    render_report(run)
    if args.audit:
        render_audit(run)


if __name__ == "__main__":
    main()
