#!/usr/bin/env python3
"""Export the current run's ranked report to live_run.json for the handout PDF.

Run while the web demo is up with a completed run:
    python3 scripts/export_live.py
"""
import json
import os
import urllib.request

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
URL = "http://127.0.0.1:5000/api/state"


def main():
    with urllib.request.urlopen(URL) as r:
        s = json.load(r)
    results = [
        {
            "name": f.get("typology_name"),
            "id": f.get("typology_id"),
            "fires": ", ".join(f.get("fired_rules", [])),
            "evades": ", ".join(f.get("evaded_rules", [])),
            "atlas": ", ".join(f.get("mitre_atlas", [])),
            "basis": f.get("evidential_basis"),
            "flag": f.get("drafted_candidate_red_flag"),
        }
        for f in s.get("findings", [])
    ]
    discarded = [
        {"name": d.get("typology_name"), "id": d.get("typology_id"),
         "why": d.get("evidential_basis")}
        for d in s.get("discarded", [])
    ]
    out = {
        "run_id": s.get("run_id"),
        "status": s.get("status"),
        "rulebook_version": s.get("rulebook_version"),
        "results": results,
        "discarded": discarded,
    }
    path = os.path.join(BASE, "live_run.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print(f"Exported {len(results)} findings + {len(discarded)} discarded to {path}")


if __name__ == "__main__":
    main()