"""Reset Drift Sentinel to a clean, nothing-decided state.

Clears the state that survives a server restart, so a demo starts from the
same place every time. The console's "Clear results" button only clears
in-memory state and the rulebook baseline; the files below persist, which is
why a fresh start needs this.

What it does by default:
  - data/rulebook.json        <- restored from data/rulebook.base.json
                                 (removes any rule instituted from an
                                 approved finding, back to DS-01..DS-40)
  - data/decisions.json       <- emptied
  - data/decisions_log.json   <- emptied
  - data/audit.json           <- emptied
  - data/run_history.json     <- trimmed to the seeded historical curve only
                                 (seed-* entries kept, run-* entries removed)

The seeded history is KEPT on purpose. The forecaster needs three or more
recorded points to fit a projection to measured history; wipe them and the
forecast page silently drops to its clearly-labelled baseline mode instead.

Every file is backed up to data/_reset_backup_<timestamp>/ before it is
touched, so a reset is reversible.

Usage, from rulebook_drift_monitor/:
    python -m scripts.reset_demo --dry-run     # show what would change
    python -m scripts.reset_demo               # do it
    python -m scripts.reset_demo --keep-audit  # keep the paper trail
    python -m scripts.reset_demo --wipe-history  # also drop seeded history

Stop the Flask server before running this. A running server holds state in
memory and will write it back over these files when it next saves.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
from datetime import datetime

DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


def _path(name: str) -> str:
    return os.path.join(DATA, name)


def _load(name):
    with open(_path(name), "r", encoding="utf-8") as f:
        return json.load(f)


def _save(name, payload) -> None:
    with open(_path(name), "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
        f.write("\n")


def main() -> None:
    ap = argparse.ArgumentParser(description="Reset Drift Sentinel demo state.")
    ap.add_argument("--dry-run", action="store_true",
                    help="report what would change without writing anything")
    ap.add_argument("--keep-audit", action="store_true",
                    help="keep data/audit.json as it is")
    ap.add_argument("--wipe-history", action="store_true",
                    help="also remove the seeded historical curve (breaks the "
                         "forecast page's measured-history mode)")
    args = ap.parse_args()

    actions: list[str] = []

    # --- rulebook -------------------------------------------------------
    base, live = _load("rulebook.base.json"), _load("rulebook.json")
    extra = [r["id"] for r in live["rules"] if r["id"] not in {b["id"] for b in base["rules"]}]
    if live == base:
        actions.append(f"rulebook.json      already at baseline ({len(base['rules'])} rules) - no change")
    else:
        detail = f" (removes {', '.join(extra)})" if extra else ""
        actions.append(f"rulebook.json      restore from base -> {len(base['rules'])} rules{detail}")

    # --- decisions ------------------------------------------------------
    dec = _load("decisions.json")
    n_dec = len(dec.get("decisions", {}))
    actions.append(f"decisions.json     {n_dec} decision(s) -> 0")

    log = _load("decisions_log.json")
    actions.append(f"decisions_log.json {len(log)} entr(y/ies) -> 0")

    # --- audit ----------------------------------------------------------
    audit = _load("audit.json")
    if args.keep_audit:
        actions.append(f"audit.json         {len(audit)} entr(y/ies) -> unchanged (--keep-audit)")
    else:
        actions.append(f"audit.json         {len(audit)} entr(y/ies) -> 0")

    # --- run history ----------------------------------------------------
    hist = _load("run_history.json")
    seeds = [h for h in hist if str(h.get("run_id", "")).startswith("seed-")]
    if args.wipe_history:
        actions.append(f"run_history.json   {len(hist)} entr(y/ies) -> 0  "
                       f"(WARNING: forecast loses measured-history mode)")
        new_hist = []
    else:
        actions.append(f"run_history.json   {len(hist)} entr(y/ies) -> {len(seeds)} "
                       f"(seeded curve kept, {len(hist) - len(seeds)} test run(s) removed)")
        new_hist = seeds

    print("\nDrift Sentinel reset\n" + "-" * 62)
    for a in actions:
        print("  " + a)

    if args.dry_run:
        print("\nDry run - nothing written. Re-run without --dry-run to apply.\n")
        return

    # --- back up, then write -------------------------------------------
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = os.path.join(DATA, f"_reset_backup_{stamp}")
    os.makedirs(backup, exist_ok=True)
    for name in ("rulebook.json", "decisions.json", "decisions_log.json",
                 "audit.json", "run_history.json"):
        shutil.copy2(_path(name), os.path.join(backup, name))

    _save("rulebook.json", base)
    _save("decisions.json", {"version": dec.get("version", 1), "decisions": {}})
    _save("decisions_log.json", [])
    if not args.keep_audit:
        _save("audit.json", [])
    _save("run_history.json", new_hist)

    print("-" * 62)
    print(f"  Backed up to: {os.path.relpath(backup, os.getcwd())}")
    print("  Reset complete. Start the server with: python -m demo.web\n")


if __name__ == "__main__":
    main()