#!/usr/bin/env python3
"""Rulebook Drift Monitor - Web demo (professional UI, async pipeline).

Run:
  python3 -m demo.web            # then open http://127.0.0.1:5000
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import Optional

from flask import Flask, jsonify, request, send_from_directory

from agents.loader import load_rulebook, load_typologies
from agents.orchestrator import Orchestrator
from agents.forecaster import Forecaster
from agents.llm_client import LocalLLMClient
import agents.rule_amendment as amendments

app = Flask(__name__, static_folder=None)

BASE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(BASE, "static")
DATA_DIR = os.path.join(os.path.dirname(BASE), "data")
HISTORY_PATH = os.path.join(DATA_DIR, "run_history.json")
DECISIONS_LOG_PATH = os.path.join(DATA_DIR, "decisions_log.json")
AUDIT_PATH = os.path.join(DATA_DIR, "audit.json")

# Vercel/serverless mode: runs complete synchronously inside the request and
# disk state only lives for the life of the function instance.
SERVERLESS = os.environ.get("SERVERLESS", "") == "1" or os.environ.get("VERCEL", "") == "1"

# In-memory store.
STORE = {
    "run": None,            # completed RunState or None
    "analyst": "A. Analyst",
    "decisions": {},        # fid -> decision label (in-memory mirror)
    "running": False,       # a run is in progress
    "started_at": None,
    "log": [],
    "abort": False,         # request the background worker to stop cleanly
    "storage": "writable",  # flipped to "readonly" if disk writes are refused
}

# Pipeline steps shown in the animation, in order.
PIPELINE_STEPS = [
    ("ingest", "Ingest corpora"),
    ("reconcile", "Reconciliation arm · documented typologies"),
    ("generate", "Generation arm · novel evasion paths"),
    ("critic", "Critic verification &amp; discard"),
    ("draft", "Draft candidate red flags"),
    ("report", "Human approval gate"),
]


# ---------------------------------------------------------------------------
# Durability helper — serverless function filesystems are read-only (except
# /tmp), so persistence best-effort: keep the in-memory state and degrade
# gracefully instead of crashing a deploy.
# ---------------------------------------------------------------------------
def _write_json(path: str, data, note: str = "") -> bool:
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except (OSError, IOError):
        STORE["storage"] = "readonly"
        if note:
            STORE["log"].append({"node": "error", "message": f"{note}"})
        return False
    return True


# ---------------------------------------------------------------------------
# Decided-log persistence (data/decisions_log.json)
#
# One shared file across both review tabs (reconciliation + generation) - the
# UI renders it as two separate per-tab logs (filtered by each entry's `mode`),
# keeping the same trust-level separation as the review lists themselves,
# without needing two files on disk. This is the durable source of truth for
# "is this finding decided" - it survives page reloads AND server restarts,
# unlike STORE["decisions"] which is only in-memory for the current process.
# ---------------------------------------------------------------------------
def _load_decisions_log() -> list[dict]:
    try:
        with open(DECISIONS_LOG_PATH, "r", encoding="utf-8") as f:
            arr = json.load(f)
        return [d for d in arr if isinstance(d, dict)]
    except Exception:
        return []


def _append_decision_log(entry: dict) -> None:
    entries = _load_decisions_log()
    entries = [e for e in entries if e.get("fid") != entry["fid"]]
    entries.append(entry)
    _write_json(DECISIONS_LOG_PATH, entries,
                note="Decided log is disk-readonly on this host — keeping in memory for this session only.")


def _resolved_ids() -> set:
    """Typologies already decided or covered are excluded from future runs."""
    covered = amendments.covered_typology_ids()
    decided = {d.get("fid") for d in _load_decisions_log()}
    return set(covered) | decided


# ---------------------------------------------------------------------------
# Audit trail — an append-only, human-readable record for the audit page.
# ---------------------------------------------------------------------------
def _audit(event: str, actor: str = "", detail: str = "", meta: dict = None) -> dict:
    entry = {
        "id": f"ae-{uuid.uuid4().hex[:8]}",
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "event": event,
        "actor": actor or STORE["analyst"],
        "detail": detail,
        "meta": meta or {},
    }
    try:
        with open(AUDIT_PATH, "r", encoding="utf-8") as f:
            arr = json.load(f)
    except Exception:
        arr = []
    arr.append(entry)
    _write_json(AUDIT_PATH, arr)
    return entry


def _load_audit() -> list[dict]:
    try:
        with open(AUDIT_PATH, "r", encoding="utf-8") as f:
            arr = json.load(f)
        return [e for e in arr if isinstance(e, dict)]
    except Exception:
        return []


def _attack_description(f, desc_by_id: dict) -> str:
    """Plain-language headline for a finding.

    Reconciliation findings: prefer the typology's own prose description (TYP
    corpus) or, for capability-primitive findings, the finding's evidential
    basis - which IS the descriptive sentence for those (see
    SimulationAgent.run_capability_primitive_reconciliation).

    Generation findings: evidential_basis is boilerplate ("self-generated from
    AI capability primitives (novel, unverified)") identical across every
    generation-arm candidate, so it is useless as a headline - typology_name
    (the actual invented scenario's name) is the specific, human-readable
    description here instead.
    """
    if desc_by_id.get(f.typology_id):
        return desc_by_id[f.typology_id]
    if getattr(f, "mode", "reconciliation") == "generation":
        return f.typology_name or f.evidential_basis
    return f.evidential_basis or f.typology_name


# ---------------------------------------------------------------------------
# Run history (data-driven forecast inputs)
# ---------------------------------------------------------------------------
def _load_history() -> list[dict]:
    try:
        with open(HISTORY_PATH, "r", encoding="utf-8") as f:
            arr = json.load(f)
        return [h for h in arr if isinstance(h, dict)]
    except Exception:
        return []


def _save_history(entries: list[dict]) -> None:
    _write_json(HISTORY_PATH, entries,
                note="Run history is disk-readonly on this host — checkpoint kept in memory for this session only.")


def _forecast_snapshot() -> dict:
    """Deterministic library-scan metrics for the CURRENT corpus."""
    return Forecaster(load_rulebook(), load_typologies()).forecast()


def _record_history(run=None, kind: str = "run", note: str = "", findings: int = None) -> dict:
    """Append a measured checkpoint to run_history.json. Auto (per run) or manual."""
    fc = _forecast_snapshot()
    findings = len(run.results) if (findings is None and run is not None) else findings
    discarded = len(run.discarded) if run is not None else None
    entry = {
        "run_id": (run.run_id if run is not None else f"checkpoint-{uuid.uuid4().hex[:8]}"),
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "kind": kind,
        "drift_index": fc["drift_index"],
        "coverage": fc["coverage"]["overall"],
        "ai_pressure": fc["ai_pressure"]["share"],
        "findings": findings,
        "discarded": discarded,
        "rulebook_version": fc["rulebook_version"],
    }
    if note:
        entry["note"] = note
    entries = _load_history()
    entries = [e for e in entries if e.get("run_id") != entry["run_id"]]
    entries.append(entry)
    _save_history(entries)
    return entry


# ---------------------------------------------------------------------------
# Background run worker
# ---------------------------------------------------------------------------
def _run_worker(trigger: str):
    STORE["running"] = True
    STORE["abort"] = False
    STORE["started_at"] = time.time()
    STORE["log"] = []
    # Diff: snapshot which typologies the PREVIOUS completed run flagged.
    STORE["prev_ids"] = [f.typology_id for f in (STORE["run"].results or [])] if STORE["run"] else []
    _audit("run_started", detail=f"Run triggered ({trigger})", meta={"trigger": trigger})

    def live_progress(phase: str, message: str):
        STORE["log"].append({"node": phase, "message": message,
                             "ts": time.strftime("%H:%M:%S")})

    def should_abort() -> bool:
        return bool(STORE["abort"])

    try:
        rulebook = load_rulebook()
        all_typologies = load_typologies()
        excluded = _resolved_ids()
        typologies = [t for t in all_typologies if t.id not in excluded]
        if excluded:
            live_progress("ingest",
                          f"Skipping {len(excluded)} already-reviewed/covered typolog"
                          f"{'y' if len(excluded) == 1 else 'ies'} · scanning {len(typologies)} remaining")
            _audit("run_skip", detail=f"{len(excluded)} already-reviewed/covered typologies excluded",
                   meta={"excluded": len(excluded)})
        orch = Orchestrator(rulebook, typologies)
        state = orch.run(trigger=trigger, analyst=STORE["analyst"],
                         on_progress=live_progress, abort_check=should_abort)
        if state.status == "aborted":
            STORE["log"].append({"node": "orchestrator",
                                 "message": "Run aborted by analyst before completion."})
            STORE["run"] = None
            STORE["decisions"] = {}
            _audit("run_aborted", detail="Run aborted by analyst")
        else:
            STORE["run"] = state
            STORE["decisions"] = {}
            STORE["log"] = list(state.audit) if state else []
            _record_history(state)
            _audit("run_finished",
                   detail=f"Completed · {len(state.results)} findings to review",
                   meta={"findings": len(state.results), "discarded": len(state.discarded or [])})
    except Exception as exc:
        STORE["log"].append({"node": "error", "message": f"Run failed: {exc}"})
        STORE["run"] = None
        _audit("run_error", detail=f"Run failed: {exc}")
    finally:
        STORE["abort"] = False
        STORE["running"] = False


def _start_background_run(trigger: str) -> None:
    """Start a background thread doing a real run; returns immediately.
    In SERVERLESS mode the function cannot keep a thread alive after the
    request, so the run is executed inline (synchronously) instead."""
    if SERVERLESS:
        _run_worker(trigger)
        return
    t = threading.Thread(target=_run_worker, args=(trigger,), daemon=True)
    t.start()


# ---------------------------------------------------------------------------
# JSON serialisation helpers
# ---------------------------------------------------------------------------
def _finding_json(f, desc_by_id=None):
    desc_by_id = desc_by_id or {}
    return {
        "typology_id": f.typology_id,
        "typology_name": f.typology_name,
        "attack_description": _attack_description(f, desc_by_id),
        "mode": getattr(f, "mode", "reconciliation"),
        "fired_rules": f.fired_rules,
        "evaded_rules": f.evaded_rules,
        "mitre_atlas": f.mitre_atlas,
        "evidential_basis": f.evidential_basis or "documented typology",
        "drafted_candidate_red_flag": f.drafted_candidate_red_flag,
        # Provenance for generation-mode findings ("llm" / "deterministic_fallback"
        # / "fixed_probe"); blank for reconciliation findings. getattr default
        # keeps this safe against any GapFinding built before this field existed
        # (e.g. cached objects from data/drafted_flags.json predating this change).
        "generation_source": getattr(f, "generation_source", ""),
        "capability_primitives": getattr(f, "capability_primitives", []),
        "fully_verified": getattr(f, "fully_verified", True),
        "unmodeled_fields": getattr(f, "unmodeled_fields", []),
        "unverified_atlas": getattr(f, "unverified_atlas", []),
    }


def _discarded_json(d):
    return {
        "typology_name": d.get("typology_name"),
        "typology_id": d.get("typology_id"),
        "evidential_basis": d.get("evidential_basis"),
    }


def _state_json():
    run = STORE["run"]
    decisions = STORE["decisions"]
    inst = amendments.load_instituted()
    covered = sorted(inst.get("covered", {}).keys())
    prev_ids = set(STORE.get("prev_ids") or [])
    desc_by_id = {t.id: t.description for t in load_typologies()}
    decisions_log = _load_decisions_log()
    decided_fids = {d.get("fid") for d in decisions_log}
    excluded = _resolved_ids()

    findings = [_finding_json(f, desc_by_id) for f in (run.results if run else [])]
    for f in findings:
        f["delta"] = "new" if f["typology_id"] not in prev_ids else "repeat"
    diff_new = [f["typology_id"] for f in findings if f["delta"] == "new"]
    diff_repeat = [f["typology_id"] for f in findings if f["delta"] == "repeat"]
    diff_regressed = [t for t in (prev_ids - {f["typology_id"] for f in findings})]
    reviewed = sum(1 for f in findings if f["typology_id"] in decided_fids)
    total = len(findings)
    all_decided = bool(total) and reviewed == total

    # The two review tabs read from strictly separate slices of the same run -
    # "Known Attacks" (mode=reconciliation, documented capability-primitive
    # attacks) never mixes with "Emerging Threats" (mode=generation,
    # self-invented novelties). A decided finding (present in the persisted
    # decisions_log) is removed from both review lists - it now lives only in
    # the Decided log, and stays removed across reloads/restarts because the
    # filter is keyed off the on-disk log, not in-memory state.
    reconciliation_findings = [
        f for f in findings
        if f.get("mode", "reconciliation") == "reconciliation" and f["typology_id"] not in decided_fids
    ]
    generation_findings = [
        f for f in findings
        if f.get("mode") == "generation" and f["typology_id"] not in decided_fids
    ]

    status = None
    if run is not None:
        status = run.status
        if status == "aborted":
            status = "aborted"
        elif all_decided:
            status = "review_complete"
        elif reviewed > 0:
            status = "under_review"
        elif status == "awaiting_human_approval" and total == 0:
            status = "ready_no_findings"

    return {
        "running": STORE["running"],
        "started_at": STORE["started_at"],
        "serverless": SERVERLESS,
        "storage": STORE.get("storage", "writable"),
        "analyst": STORE["analyst"],
        "has_run": run is not None,
        "run_id": run.run_id if run else None,
        "rulebook_version": getattr(run, "rulebook_version", None) if run else None,
        "status": status,
        "raw_status": getattr(run, "status", None) if run else None,
        "reviewed": reviewed,
        "total": total,
        "all_decided": all_decided,
        "findings": findings,
        "reconciliation_findings": reconciliation_findings,
        "generation_findings": generation_findings,
        "decisions_log": decisions_log,
        "discarded": [_discarded_json(d) for d in (run.discarded if run else [])],
        "convergence": list(getattr(run, "convergence", []) or []) if run else [],
        "decisions": decisions,
        "audit": list(run.audit) if run else [],
        "log": STORE["log"],
        "pipeline": PIPELINE_STEPS,
        "excluded": {
            "count": len(excluded),
            "ids": sorted(excluded),
            "remaining": len([t for t in load_typologies() if t.id not in excluded]),
        },
        "amendments": {
            "covered": covered,
            "resolved_findings": inst.get("resolved_findings", []),
            "rules": [
                {"id": r["id"], "name": r.get("name"), "category": r.get("category"),
                 "risk_severity": r.get("risk_severity"),
                 "source_finding": r.get("source_finding")}
                for r in inst.get("rules", [])
            ],
        },
        "diff": {
            "new": diff_new,
            "repeat": diff_repeat,
            "regressed": diff_regressed,
            "prev_count": len(prev_ids),
        },
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return send_from_directory(STATIC, "index.html")


@app.route("/index.html")
def run_console():
    return send_from_directory(STATIC, "index.html")


@app.route("/dashboard.html")
def dashboard():
    return send_from_directory(STATIC, "dashboard.html")


@app.route("/rules.html")
def rules_page():
    return send_from_directory(STATIC, "rules.html")


@app.route("/forecast.html")
def forecast_page():
    return send_from_directory(STATIC, "forecast.html")


@app.route("/compare.html")
def compare_page():
    return send_from_directory(STATIC, "compare.html")


@app.route("/audit.html")
def audit_page():
    return send_from_directory(STATIC, "audit.html")


@app.route("/static/<path:path>")
def static_files(path: str):
    return send_from_directory(STATIC, path)


# ---------------------------------------------------------------------------
# Compare + Audit APIs
# ---------------------------------------------------------------------------
def _run_summary(state, exp_mode: str) -> Optional[dict]:
    """Slice a single unified run into per-arm stats for the compare page."""
    if state is None:
        return None
    results = [f for f in (state.results or [])
               if getattr(f, "mode", "reconciliation") == exp_mode]
    fired_total = sum(len(f.fired_rules) for f in results)
    evaded_total = sum(len(f.evaded_rules) for f in results)
    top: dict[str, int] = {}
    for f in results:
        for rid in f.evaded_rules:
            top[rid] = top.get(rid, 0) + 1
    by_id = {r.id: r for r in load_rulebook()}
    top_evaded = [{"id": i, "name": by_id[i].name if i in by_id else i, "count": c}
                  for i, c in sorted(top.items(), key=lambda kv: -kv[1])[:8]]
    decided_fids = {d.get("fid") for d in _load_decisions_log()}
    return {
        "run_id": state.run_id,
        "status": state.status,
        "total": len(results),
        "reviewed": sum(1 for f in results if f.typology_id in decided_fids),
        "avg_evaded": round(evaded_total / len(results), 2) if results else 0,
        "avg_fired": round(fired_total / len(results), 2) if results else 0,
        "fired_total": fired_total,
        "evaded_total": evaded_total,
        "top_evaded": top_evaded,
        "discarded": len(state.discarded or []),
        "findings": [
            {"typology_id": f.typology_id, "typology_name": f.typology_name,
             "fired": len(f.fired_rules), "evaded": len(f.evaded_rules),
             "mode": getattr(f, "mode", "reconciliation")}
            for f in results
        ],
    }


@app.route("/api/compare")
def api_compare():
    run = STORE["run"]
    return jsonify({
        "documented": _run_summary(run, "reconciliation"),
        "generated": _run_summary(run, "generation"),
        "running": STORE["running"],
        "excluded": {
            "count": len(_resolved_ids()),
            "remaining": len([t for t in load_typologies() if t.id not in _resolved_ids()]),
        },
        "rules_total": len(load_rulebook()),
    })


@app.route("/api/audit")
def api_audit():
    audits = sorted(_load_audit(), key=lambda e: e.get("ts", ""), reverse=True)
    return jsonify({"entries": audits})


@app.route("/api/state")
def api_state():
    return jsonify(_state_json())


@app.route("/api/run", methods=["POST"])
def api_run():
    if STORE["running"]:
        return jsonify({"error": "A run is already in progress."}), 409
    trigger = (request.json or {}).get("trigger", "manual")
    _start_background_run(trigger)
    if SERVERLESS:
        return jsonify({"started": True, "sync": True, "state": _state_json()})
    return jsonify({"started": True})


@app.route("/api/decide", methods=["POST"])
def api_decide():
    data = request.json or {}
    fid = data.get("fid")
    decision = data.get("decision")
    rationale = (data.get("rationale") or "").strip()
    rule_text = (data.get("rule_text") or "").strip()
    if not fid or decision not in ("accept", "amend", "reject"):
        return jsonify({"error": "bad request"}), 400
    if not rationale:
        return jsonify({"error": "A rationale is required to record this decision."}), 400
    label = {"accept": "accepted ✓", "amend": "amended ✎", "reject": "rejected ✗"}[decision]
    STORE["decisions"][fid] = label
    STORE.setdefault("rationales", {})[fid] = rationale
    verb = {
        "accept": "Promoted to draft guidance for further review.",
        "amend": "Returned for amendment.",
        "reject": "Rejected; not promoted.",
    }[decision]
    run = STORE["run"]
    finding = next((f for f in (run.results if run else []) if f.typology_id == fid), None)
    mode = getattr(finding, "mode", "reconciliation") if finding else "reconciliation"
    desc_by_id = {t.id: t.description for t in load_typologies()}
    headline = _attack_description(finding, desc_by_id) if finding else fid
    original_text = (finding.drafted_candidate_red_flag or "").strip() if finding else ""
    final_text = rule_text or original_text
    rule_text_amended = bool(rule_text) and rule_text != original_text

    STORE["log"].append({
        "node": "human-gate",
        "message": (f"Analyst {STORE['analyst']} → {label} finding "
                    f"'{finding.typology_name if finding else fid}' "
                    f"[{'Known Attacks' if mode == 'reconciliation' else 'Emerging Threats'}]. "
                    f"{verb} Rationale: {rationale}"),
        # DS/CP codes and the source tab kept here for audit traceability,
        # never surfaced as the primary log line - the plain-language
        # `message` above is what renders.
        "reference": {
            "typology_id": fid,
            "mode": mode,
            "fired_rules": finding.fired_rules if finding else [],
            "evaded_rules": finding.evaded_rules if finding else [],
        },
    })

    # Durable decided-log entry (data/decisions_log.json) - this is what
    # removes the finding from the review list across reloads/restarts and
    # what backs the "Decided" log in the UI.
    _append_decision_log({
        "fid": fid,
        "mode": mode,
        "headline": headline,
        "typology_name": finding.typology_name if finding else fid,
        "decision": decision,
        "decision_label": label,
        "rationale": rationale,
        "analyst": STORE["analyst"],
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "fired_rules": finding.fired_rules if finding else [],
        "evaded_rules": finding.evaded_rules if finding else [],
        "original_rule_text": original_text,
        "final_rule_text": final_text,
        "rule_text_amended": rule_text_amended,
    })
    _audit("finding_decided", detail=f"{label} {fid}",
           meta={"fid": fid, "decision": decision, "mode": mode, "reason": rationale})
    return jsonify({"ok": True, "decision": label})


@app.route("/api/institute", methods=["POST"])
def api_institute():
    """Approve + institutionalise a finding: generates a dedicated DS indicator,
    covers the typology's gap set, records a post-amendment checkpoint."""
    data = request.json or {}
    fid = data.get("fid")
    if not fid:
        return jsonify({"error": "bad request"}), 400
    run = STORE["run"]
    finding = next((f for f in (run.results if run else []) if f.typology_id == fid), None)
    if finding is None:
        return jsonify({"error": "finding not found"}), 404
    typology = next((t for t in load_typologies() if t.id == fid), None)
    if typology is None:
        return jsonify({"error": "typology not found"}), 404

    res = amendments.institute(typology, finding, run.run_id if run else "review")
    if not res.get("ok"):
        return jsonify({"error": res.get("error", "could not institute")}), 400

    STORE["decisions"][fid] = "instituted ✓"
    STORE["log"].append({
        "node": "human-gate",
        "message": f"Analyst {STORE['analyst']} → instituted {res['rule']} for '{fid}' · gap closed, drift re-scanned.",
    })
    _append_decision_log({
        "fid": fid,
        "mode": getattr(finding, "mode", "reconciliation"),
        "headline": _attack_description(finding, {t.id: t.description for t in load_typologies()}),
        "typology_name": finding.typology_name,
        "decision": "institute",
        "decision_label": "instituted ✓",
        "rationale": "Institutionalised as a standing DS indicator (gap closed by amendment).",
        "analyst": STORE["analyst"],
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "fired_rules": finding.fired_rules,
        "evaded_rules": finding.evaded_rules,
        "original_rule_text": (finding.drafted_candidate_red_flag or "").strip(),
        "final_rule_text": res.get("rule", ""),
        "rule_text_amended": True,
    })
    entry = _record_history(kind="checkpoint",
                            note=f"post-amendment re-scan after instituting {res['rule']} ({fid})")
    fc = _forecast_snapshot()
    _audit("rule_instituted", detail=f"{res['rule']} instituted · covers {fid}",
           meta={"rule": res["rule"], "fid": fid,
                 "reason": "Institutionalised as a standing DS indicator (gap closed by amendment)."})
    return jsonify({
        "ok": True,
        **res,
        "drift_index": fc["drift_index"],
        "coverage": fc["coverage"]["overall"],
        "recorded": entry,
    })


@app.route("/api/reset", methods=["POST"])
def api_reset():
    if STORE["running"]:
        STORE["abort"] = True
        return jsonify({"ok": True, "aborted": True})
    STORE["run"] = None
    STORE["decisions"] = {}
    STORE["log"] = []
    STORE["started_at"] = None
    STORE["prev_ids"] = []
    # Roll the rulebook back to the shipped DS-01..DS-40 baseline (demo idempotency).
    restored = amendments.restore_baseline()
    _audit("console_reset", detail="Console state cleared ; baseline restored")
    return jsonify({"ok": True, "aborted": False, "restored": restored.get("removed", [])})


@app.route("/api/record", methods=["POST"])
def api_record():
    """Manually record a forecast checkpoint from the current corpus scan."""
    entry = _record_history(kind="checkpoint")
    _audit("checkpoint_recorded",
           detail=f"Checkpoint {entry.get('run_id')} recorded · drift {entry.get('drift_index')}",
           meta={"run_id": entry.get("run_id")})
    return jsonify({"ok": True, "recorded": entry})


@app.route("/api/fraudtest", methods=["POST"])
def api_fraudtest():
    """Throw a fraud at the rulebook, live.

    Body: {label, tx: {...fixture fields...}, commit?: bool}
    Runs the deterministic engine over the supplied scenario and reports which
    rules caught it vs which it slipped past. Optionally commits the scenario as
    a finding so it lands in the human approval gate.
    """
    from agents.models import GapFinding, RunState
    from agents.rule_engine import RuleEvaluationEngine
    data = request.json or {}
    label = (data.get("label") or "").strip()[:80] or "Real-time attack test"
    raw = data.get("tx")
    if not isinstance(raw, dict) or not raw:
        return jsonify({"error": "missing scenario (tx)"}), 400
    rulebook = load_rulebook()
    engine = RuleEvaluationEngine()
    results = engine.evaluate(rulebook, raw)
    fired = sorted({r.rule_id for r in results if r.fired})
    evaded = sorted({r.rule_id for r in results if not r.fired})
    by_id = {r.id: r for r in rulebook}

    def meta(ids):
        return [{"id": i, "name": by_id[i].name, "category": by_id[i].category,
                 "text": by_id[i].text, "trigger": by_id[i].trigger,
                 "severity": by_id[i].risk_severity} for i in ids]

    committed = None
    if data.get("commit"):
        fid = "UX-" + uuid.uuid4().hex[:8]
        run = STORE["run"]
        if run is None:
            run = RunState(run_id=f"run-{uuid.uuid4().hex[:8]}",
                           rulebook_version=by_id["DS-01"].source if "DS-01" in by_id else "DS rulebook",
                           rulebook=rulebook, typologies=load_typologies(),
                           status="awaiting_human_approval")
            STORE["run"] = run
        finding = GapFinding(
            typology_id=fid,
            typology_name=label,
            fired_rules=fired,
            evaded_rules=evaded,
            evidential_basis="Real-time attack submitted by the analyst in the app (attack test)",
            drafted_candidate_red_flag=(
                f"No rule flagged this scenario: '{label}' carried no suspicious signals, "
                f"so the rulebook stayed quiet. Nothing to send to review."
                if not fired else
                f"Draft indicator for '{label}': screen this customer for the pattern just described "
                f"— it slipped past {len(evaded)} of {len(rulebook)} rules (DS-{', DS-'.join(evaded)}) "
                f"and was caught by {len(fired)} (DS-{', DS-'.join(fired)})."
            ),
            plausible=True,
            verified=True,
        )
        run.results.append(finding)
        STORE["decisions"].setdefault(fid, "")
        STORE["log"].append({
            "node": "human-gate",
            "message": f"Analyst {STORE['analyst']} submitted attack test '{label}' ({fid}) · "
                       f"caught {len(fired)} rule(s), slipped past {len(evaded)} · sent to human gate.",
        })
        STORE["prev_ids"] = STORE.get("prev_ids") or [f.typology_id for f in run.results[:-1]] or []
        _audit("attack_submitted",
               detail=f"Attack test '{label}' ({fid}) · caught {len(fired)}, slipped past {len(evaded)}",
               meta={"fid": fid, "label": label, "fired": fired, "evaded": evaded})
        committed = fid

    verdict = (
        "No rule flagged this scenario — nothing suspicious for the rules to catch "
        f"(all {len(rulebook)} stayed quiet)."
        if not fired
        else (
            f"Fully caught — every suspicious signal was flagged ({len(fired)} rule"
            f"{'s' if len(fired)!=1 else ''} fired)."
            if not evaded
            else f"Partly caught — {len(fired)} rule{'s' if len(fired)!=1 else ''} fired, "
                 f"but this attack slipped past {len(evaded)} of {len(rulebook)} rules · potential gap"
        )
    )
    return jsonify({
        "label": label,
        "fired": meta(fired),
        "evaded": meta(evaded),
        "fired_ids": fired,
        "evaded_ids": evaded,
        "rules_total": len(rulebook),
        "verdict": verdict,
        "committed": committed,
    })


@app.route("/api/probe")
def api_probe():
    """Adversarial red-team probe: inject a poisoned typology, show critic verdict."""
    from agents.probe import probe as run_probe
    scheme = request.args.get("scheme", type=int, default=0)
    victim = request.args.get("victim", type=int, default=0)
    rulebook = load_rulebook()
    typologies = load_typologies()
    res = run_probe(rulebook, typologies, scheme_index=scheme, victim_index=victim)
    STORE["log"].append({
        "node": "critic",
        "message": (f"Red-team probe → {res['verdict']} (victim {res['victim']['id']}, "
                    f"claim {len(res['claim'])} rules vs actual {len(res['actual_evaded'])})"),
    })
    _audit("red_team_probe",
           detail=f"Probe → {res['verdict']} · victim {res['victim']['id']}",
           meta={"victim": res["victim"]["id"], "verdict": res["verdict"]})
    return jsonify(res)


@app.route("/api/dossier")
def api_dossier():
    """Compliance dossier: approved + amended findings as JSON."""
    return jsonify(_build_dossier())


@app.route("/api/dossier.pdf")
def api_dossier_pdf():
    """Compliance dossier as a printable PDF attachment."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from io import BytesIO

    d = _build_dossier()
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, rightMargin=46, leftMargin=46,
                            topMargin=46, bottomMargin=46)
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Title"], fontSize=17, leading=20,
                        textColor=colors.HexColor("#1e2556"))
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=12, leading=15,
                        spaceBefore=12, textColor=colors.HexColor("#3b47b0"))
    body = styles["BodyText"]
    small = ParagraphStyle("small", parent=styles["BodyText"], fontSize=8.4,
                           textColor=colors.HexColor("#666666"))
    est = []
    est.append(Paragraph("Rulebook Drift Monitor · Compliance Dossier", h1))
    est.append(Paragraph(f"Run <b>{d['run_id']}</b> · analyst {d['analyst']} · "
                         f"rulebook {d['rulebook_version']} · generated {d['generated_at']}", small))
    est.append(Spacer(1, 10))
    est.append(Paragraph(f"<b>Current scan</b> — Drift Index <b>{d['drift_index']}/100</b> "
                         f"({d['drift_band']}) · indicator coverage {d['coverage']:.1%} · "
                         f"AI-evasion pressure {d['ai_pressure']:.0%}", body))

    if d["amendments"]:
        est.append(Paragraph("Institutionalised amendments", h2))
        rows = [["Indicator", "Finding", "Category", "Severity"]]
        for a in d["amendments"]:
            rows.append([a["id"], a["source_finding"], a["category"], a["risk_severity"]])
        t = Table(rows, colWidths=[70, 120, 130, 70])
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef0fb")),
                               ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
                               ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                               ("FONTSIZE", (0, 0), (-1, -1), 8.5)]))
        est.append(t)

    approved = d["approved_findings"]
    est.append(Paragraph(f"Approved &amp; amended findings ({len(approved)})", h2))
    if not approved:
        est.append(Paragraph("None approved at time of export.", body))
    for f in approved:
        est.append(Paragraph(f"<b>{f['typology_id']}</b> · {f['typology_name']} "
                             f"· <i>{f['decision']}</i>", body))
        est.append(Paragraph(f"Fired: {', '.join(f['fired_rules']) or '—'} · "
                             f"Evaded: {', '.join(f['evaded_rules']) or '—'}", small))
        est.append(Paragraph(f"Red flag: {f['red_flag']}", small))
        est.append(Paragraph(f"Evidence: {f['evidential_basis']}", small))
        if f.get("rationale"):
            est.append(Paragraph(f"Analyst rationale: {f['rationale']}", small))
        est.append(Spacer(1, 6))

    est.append(Paragraph("Prepared for demonstration purposes · all data synthetic &amp; illustrative.",
                         small))
    doc.build(est)
    data = buf.getvalue()
    from flask import Response
    return Response(data, mimetype="application/pdf",
                    headers={"Content-Disposition":
                             f'attachment; filename="drift-dossier-{d["run_id"]}.pdf"'})


def _build_dossier() -> dict:
    run = STORE["run"]
    decisions = STORE["decisions"]
    fc = _forecast_snapshot()
    findings = _state_json()["findings"]
    rationales = STORE.get("rationales", {})
    approved = [
        {
            "typology_id": f["typology_id"],
            "typology_name": f["typology_name"],
            "decision": decisions.get(f["typology_id"], ""),
            "rationale": rationales.get(f["typology_id"], ""),
            "fired_rules": f.get("fired_rules", []),
            "evaded_rules": f.get("evaded_rules", []),
            "red_flag": f.get("drafted_candidate_red_flag", ""),
            "evidential_basis": f.get("evidential_basis", ""),
        }
        for f in findings
        if decisions.get(f["typology_id"]) and "reject" not in decisions[f["typology_id"]]
    ]
    return {
        "run_id": run.run_id if run else None,
        "analyst": STORE["analyst"],
        "rulebook_version": fc["rulebook_version"],
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "drift_index": fc["drift_index"],
        "drift_band": fc["drift_band"],
        "coverage": fc["coverage"]["overall"],
        "ai_pressure": fc["ai_pressure"]["share"],
        "amendments": _state_json()["amendments"]["rules"],
        "approved_findings": approved,
    }


def _rule_json(r):
    return {
        "id": r.id, "name": r.name, "text": r.text, "category": r.category,
        "rule_type": r.rule_type, "risk_severity": r.risk_severity,
        "ai_relevant": r.ai_relevant, "trigger": r.trigger,
        "source": r.source, "source_ref": r.source_ref,
        "keywords": r.keywords, "mitre_atlas": r.mitre_atlas,
        "capability_primitives": r.capability_primitives,
        "institutionalised": getattr(r, "institutionalised", False),
        "source_finding": getattr(r, "source_finding", "") or "",
    }


def _dashboard_json():
    rulebook = load_rulebook()
    typologies = load_typologies()
    llm = LocalLLMClient()
    by_category: dict[str, int] = {}
    by_type: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    ai = 0
    for r in rulebook:
        by_category[r.category] = by_category.get(r.category, 0) + 1
        by_type[r.rule_type] = by_type.get(r.rule_type, 0) + 1
        by_severity[r.risk_severity] = by_severity.get(r.risk_severity, 0) + 1
        if r.ai_relevant:
            ai += 1
    return {
        "rules": {
            "total": len(rulebook),
            "by_category": by_category,
            "by_type": by_type,
            "by_severity": by_severity,
            "ai_relevant": ai,
        },
        "typologies": [
            {"id": t.id, "name": t.name, "severity": t.risk_severity,
             "fixtures": len(t.test_fixtures), "expected_gap": t.expected_gap}
            for t in typologies
        ],
        "evasion_matrix": Forecaster(rulebook, typologies).evasion_matrix(),
        "state": _state_json(),
        "llm": {"available": llm.available(), "backend": f"Ollama · {llm.model}"},
    }


@app.route("/api/rules")
def api_rules():
    return jsonify({"rules": [_rule_json(r) for r in load_rulebook()]})


@app.route("/api/dashboard")
def api_dashboard():
    return jsonify(_dashboard_json())


@app.route("/api/forecast")
def api_forecast():
    return jsonify(Forecaster(load_rulebook(), load_typologies()).forecast())


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)