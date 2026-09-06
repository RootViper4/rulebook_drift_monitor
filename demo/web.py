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

from flask import Flask, jsonify, request, send_from_directory

from agents.loader import load_rulebook, load_typologies
from agents.orchestrator import Orchestrator
from agents.forecaster import Forecaster
import agents.rule_amendment as amendments

app = Flask(__name__, static_folder=None)

BASE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(BASE, "static")
DATA_DIR = os.path.join(os.path.dirname(BASE), "data")
HISTORY_PATH = os.path.join(DATA_DIR, "run_history.json")

# In-memory store.
STORE = {
    "run": None,            # completed RunState or None
    "analyst": "A. Analyst",
    "decisions": {},        # fid -> decision label
    "running": False,       # a run is in progress
    "started_at": None,
    "log": [],
    "abort": False,         # request the background worker to stop cleanly
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
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(HISTORY_PATH, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2, ensure_ascii=False)


def _forecast_snapshot() -> dict:
    """Deterministic library-scan metrics for the CURRENT corpus."""
    return Forecaster(load_rulebook(), load_typologies()).forecast()


def _record_history(run=None, kind: str = "run", note: str = "") -> dict:
    """Append a measured checkpoint to run_history.json. Auto (per run) or manual."""
    fc = _forecast_snapshot()
    findings = len(run.results) if run is not None else None
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

    def live_progress(phase: str, message: str):
        STORE["log"].append({"node": phase, "message": message,
                             "ts": time.strftime("%H:%M:%S")})

    def should_abort() -> bool:
        return bool(STORE["abort"])

    try:
        rulebook = load_rulebook()
        all_typologies = load_typologies()
        covered = amendments.covered_typology_ids()
        # Gap backlog: typologies whose approved indicators now cover their
        # detected gap set are excluded from the next reconciliation scan.
        typologies = [t for t in all_typologies if t.id not in covered]
        if covered:
            STORE["log"].append({"node": "ingest",
                                 "message": f"Gap backlog reduced: {len(covered)} typologies covered by institutionalised indicators · scanning {len(typologies)} remaining"})
        orch = Orchestrator(rulebook, typologies)
        state = orch.run(trigger=trigger, analyst=STORE["analyst"],
                         on_progress=live_progress, abort_check=should_abort)
        if state.status == "aborted":
            STORE["log"].append({"node": "orchestrator",
                                 "message": "Run aborted by analyst before completion."})
            STORE["run"] = None
            STORE["decisions"] = {}
        else:
            STORE["run"] = state
            STORE["decisions"] = {}
            STORE["log"] = list(state.audit) if state else []
            _record_history(state)
    except Exception as exc:
        STORE["log"].append({"node": "error", "message": f"Run failed: {exc}"})
        STORE["run"] = None
    finally:
        STORE["abort"] = False
        STORE["running"] = False


def _start_background_run(trigger: str) -> None:
    """Start a background thread doing a real run; returns immediately."""
    t = threading.Thread(target=_run_worker, args=(trigger,), daemon=True)
    t.start()


# ---------------------------------------------------------------------------
# JSON serialisation helpers
# ---------------------------------------------------------------------------
def _finding_json(f):
    return {
        "typology_id": f.typology_id,
        "typology_name": f.typology_name,
        "fired_rules": f.fired_rules,
        "evaded_rules": f.evaded_rules,
        "mitre_atlas": f.mitre_atlas,
        "evidential_basis": f.evidential_basis or "documented typology",
        "drafted_candidate_red_flag": f.drafted_candidate_red_flag,
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
    findings = [_finding_json(f) for f in (run.results if run else [])]
    for f in findings:
        f["delta"] = "new" if f["typology_id"] not in prev_ids else "repeat"
    diff_new = [f["typology_id"] for f in findings if f["delta"] == "new"]
    diff_repeat = [f["typology_id"] for f in findings if f["delta"] == "repeat"]
    diff_regressed = [t for t in (prev_ids - {f["typology_id"] for f in findings})]
    reviewed = sum(1 for f in findings if f["typology_id"] in decisions)
    total = len(findings)
    all_decided = bool(total) and reviewed == total

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
        "discarded": [_discarded_json(d) for d in (run.discarded if run else [])],
        "decisions": decisions,
        "audit": list(run.audit) if run else [],
        "log": STORE["log"],
        "pipeline": PIPELINE_STEPS,
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


@app.route("/docs.html")
def docs_page():
    return send_from_directory(STATIC, "docs.html")


@app.route("/static/<path:path>")
def static_files(path: str):
    return send_from_directory(STATIC, path)


@app.route("/api/state")
def api_state():
    return jsonify(_state_json())


@app.route("/api/run", methods=["POST"])
def api_run():
    if STORE["running"]:
        return jsonify({"error": "A run is already in progress."}), 409
    trigger = (request.json or {}).get("trigger", "manual")
    _start_background_run(trigger)
    return jsonify({"started": True})


@app.route("/api/decide", methods=["POST"])
def api_decide():
    data = request.json or {}
    fid = data.get("fid")
    decision = data.get("decision")
    if not fid or decision not in ("accept", "amend", "reject"):
        return jsonify({"error": "bad request"}), 400
    label = {"accept": "accepted ✓", "amend": "amended ✎", "reject": "rejected ✗"}[decision]
    STORE["decisions"][fid] = label
    verb = {
        "accept": "Promoted to draft guidance for further review.",
        "amend": "Returned for amendment.",
        "reject": "Rejected; not promoted.",
    }[decision]
    STORE["log"].append({
        "node": "human-gate",
        "message": f"Analyst {STORE['analyst']} → {label} finding '{fid}'. {verb}",
    })
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
    entry = _record_history(kind="checkpoint",
                            note=f"post-amendment re-scan after instituting {res['rule']} ({fid})")
    fc = _forecast_snapshot()
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
    return jsonify({"ok": True, "aborted": False, "restored": restored.get("removed", [])})


@app.route("/api/record", methods=["POST"])
def api_record():
    """Manually record a forecast checkpoint from the current corpus scan."""
    entry = _record_history(kind="checkpoint")
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
    approved = [
        {
            "typology_id": f["typology_id"],
            "typology_name": f["typology_name"],
            "decision": decisions.get(f["typology_id"], ""),
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
        "llm": {"available": True, "backend": "Ollama · llama3.2:1b"},
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
