#!/usr/bin/env python3
"""Seed data/run_history.json with measured drift history from prior review states.

Each entry is a REAL library-scan of the rulebook/typology corpus as it stood at
that prior review date (constructed roll-out states of the demo corpus; all data
synthetic/illustrative). The same deterministic forecaster used live records each
state's Drift Index, so the projection algorithm operates on genuinely measured
points rather than a flat artificial series.

Replaces the file (backing up any prior copy).
"""
import os
import shutil
import sys
import tempfile
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from agents.loader import load_rulebook, load_typologies
from agents.forecaster import Forecaster, save_history

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HISTORY_PATH = os.path.join(ROOT, "data", "run_history.json")

# (date, rules_count, typologies_count)  — evolution of the demo corpus,
# ordered so the final entry equals today's full corpus (`35 typologies`).
STATES = [
    ("2026-04-20T10:00:00", 40, 16),
    ("2026-05-11T10:00:00", 40, 20),
    ("2026-06-01T10:00:00", 40, 24),
    ("2026-06-22T10:00:00", 40, 27),
    ("2026-07-13T10:00:00", 40, 30),
    ("2026-08-03T10:00:00", 40, 33),
    ("2026-08-24T10:00:00", 40, 35),
]


def main() -> int:
    rulebook = load_rulebook()
    typologies = load_typologies()
    if os.path.exists(HISTORY_PATH):
        shutil.copy(HISTORY_PATH, HISTORY_PATH + ".bak")

    entries = []
    for ts, nrules, ntypos in STATES:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = tmp.name
        save_history([], tmp_path)
        try:
            fc = Forecaster(rulebook[:nrules], typologies[:ntypos], history_path=tmp_path).forecast()
        finally:
            os.unlink(tmp_path)
        entries.append({
            "run_id": f"seed-{ts[:10]}",
            "ts": ts,
            "kind": "run",
            "drift_index": fc["drift_index"],
            "coverage": fc["coverage"]["overall"],
            "ai_pressure": fc["ai_pressure"]["share"],
            "findings": None,
            "discarded": None,
            "rulebook_version": f"DS-01..DS-{nrules:02d} · {nrules} rules",
            "note": f"historical review state ({ntypos} typologies as of {ts[:10]})",
        })
        print(f"{ts[:10]}  rules={nrules:2d} typologies={ntypos:2d} "
              f"drift={fc['drift_index']:.1f} coverage={fc['coverage']['overall']:.3f}")

    save_history(entries)
    print(f"\nSeeded {len(entries)} measured history points -> {HISTORY_PATH}")
    print("Backup of previous history: %s.bak" % HISTORY_PATH if os.path.exists(HISTORY_PATH + ".bak") else "")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())