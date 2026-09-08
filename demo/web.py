#!/usr/bin/env python3
"""Rulebook Drift Monitor - Web demo (professional UI, async pipeline).

Run:
  python3 -m demo.web            # then open http://127.0.0.1:5000
"""
from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
import os
import secrets
import sys
import tempfile
import threading
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import timedelta
from functools import wraps
from typing import Optional

from flask import (Flask, has_request_context, jsonify, redirect, request,
                   send_from_directory, session)

from agents.loader import load_rulebook, load_typologies
from agents.orchestrator import Orchestrator
from agents.forecaster import Forecaster
from agents.llm_client import LocalLLMClient
import agents.rule_amendment as amendments
from demo import auth

app = Flask(__name__, static_folder=None)

BASE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(BASE, "static")
DATA_DIR = os.path.join(os.path.dirname(BASE), "data")
HISTORY_PATH = os.path.join(DATA_DIR, "run_history.json")
DECISIONS_LOG_PATH = os.path.join(DATA_DIR, "decisions_log.json")
AUDIT_PATH = os.path.join(DATA_DIR, "audit.json")
SESSION_KEY_PATH = os.path.join(DATA_DIR, ".session_key")


def _env_flag(name: str) -> bool:
    """True only for an affirmative value.

    `bool(os.environ.get(name))` is true for "0" and "false" as well, which is
    how a deployment ends up with Secure cookies on a plain-HTTP host and an
    unexplainable sign-in loop. Read the value, do not just test for presence.
    """
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


# Vercel/serverless mode: runs complete synchronously inside the request and
# disk state only lives for the life of the function instance.
SERVERLESS = _env_flag("SERVERLESS") or _env_flag("VERCEL")

# Identifies this process/instance. Two requests reporting different ids means
# the host is load-balancing across instances, which is what makes a shared
# signing key non-negotiable.
INSTANCE_ID = f"inst-{uuid.uuid4().hex[:8]}"

# Unsigned breadcrumb dropped at sign-in and read only by /api/session-check.
SIGNIN_MARKER_COOKIE = "ds_signin_marker"


# ---------------------------------------------------------------------------
# Session security
#
# The session cookie is signed with `app.secret_key`. If two processes sign
# with different keys, a cookie minted by one is unreadable by the other: the
# user signs in, the next request lands elsewhere, the session looks empty and
# they are bounced back to the login page. That is the sign-in loop, and the
# old code invited it by generating a fresh random key whenever SECRET_KEY was
# unset. Resolution order below is deliberate:
#
#   1. SECRET_KEY from the environment  - the correct answer for a deployment.
#   2. data/.session_key on disk        - survives a local restart, so a stale
#                                         browser tab is not silently signed out.
#   3. Derived from the deployment id   - read-only serverless filesystem: every
#                                         instance of the same deployment derives
#                                         the same key, so sessions are portable
#                                         across instances and cold starts.
#   4. Random, this process only        - last resort, and it says so out loud.
#
# Step 3 is a prototype accommodation, not a security design: the seed is not
# secret, so a determined attacker who knows it could forge a session cookie.
# It is here so a missing environment variable degrades to "works" instead of
# "unusable", on a demonstrator holding only synthetic data. Set SECRET_KEY.
# ---------------------------------------------------------------------------
def _resolve_secret_key() -> tuple[str, str]:
    """Return `(key, source)` — see the resolution order above."""
    explicit = os.environ.get("SECRET_KEY", "").strip()
    if explicit:
        return explicit, "environment"

    try:
        with open(SESSION_KEY_PATH, "r", encoding="utf-8") as f:
            saved = f.read().strip()
        if len(saved) >= 32:
            return saved, "key file"
    except OSError:
        pass

    deployment = (os.environ.get("VERCEL_DEPLOYMENT_ID")
                  or os.environ.get("VERCEL_GIT_COMMIT_SHA")
                  or os.environ.get("VERCEL_URL")
                  or "")
    if deployment:
        derived = hashlib.sha256(f"drift-sentinel-session::{deployment}".encode("utf-8")).hexdigest()
        return derived, "derived from deployment id"

    fresh = secrets.token_hex(32)
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(SESSION_KEY_PATH, "w", encoding="utf-8") as f:
            f.write(fresh)
        return fresh, "key file (created)"
    except OSError:
        return fresh, "ephemeral (this process only)"


SECRET_KEY, SECRET_KEY_SOURCE = _resolve_secret_key()
app.secret_key = SECRET_KEY

# A Secure cookie is dropped by the browser on plain HTTP, so this must track
# the scheme the app is actually served over — not merely whether some Vercel
# variable happens to exist. ALLOW_INSECURE_COOKIE is the escape hatch for
# running a serverless-mode build locally over http://.
COOKIE_SECURE = (_env_flag("HTTPS_ONLY") or SERVERLESS) and not _env_flag("ALLOW_INSECURE_COOKIE")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,      # not reachable from JavaScript
    SESSION_COOKIE_SAMESITE="Lax",     # blocks cross-site POSTs carrying the cookie
    SESSION_COOKIE_SECURE=COOKIE_SECURE,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)

if SECRET_KEY_SOURCE.startswith("ephemeral"):
    print("[drift-sentinel] WARNING: no SECRET_KEY and data/ is not writable. "
          "Sessions will not survive a restart or a second instance — set SECRET_KEY.")

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
    "run_source": "memory",  # "memory" | "snapshot" — where the current run came from
    "snapshot_mtime": None,  # guards against re-reading an unchanged snapshot
    "snapshot_disabled": False,  # set when the run could not be written down
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

# Pages reachable without signing in. Everything else is part of the gap report
# surface, which the concept note restricts to named FIC / FSCA analysts.
PUBLIC_PAGES = {"home.html", "login.html"}
LOGIN_PAGE = "login.html"


# ---------------------------------------------------------------------------
# Identity, session and access control
# ---------------------------------------------------------------------------
def current_user() -> Optional[dict]:
    """The signed-in user for this request, or None.

    Safe to call from the background run worker, where there is no request
    context and therefore no session.
    """
    if not has_request_context():
        return None
    user = session.get("user")
    return user if isinstance(user, dict) and user.get("username") else None


def _actor() -> str:
    """Display label recorded against an action, e.g. 'N. Hlophe (FSCA)'."""
    user = current_user()
    if not user:
        return STORE["analyst"]
    org = user.get("organisation")
    return f"{user['display_name']} ({org})" if org else user["display_name"]


def _actor_meta() -> dict:
    """Identity fields stamped onto every decision and audit entry."""
    user = current_user()
    if not user:
        return {"actor_username": "", "actor_role": "", "actor_org": "", "session_id": ""}
    return {
        "actor_username": user.get("username", ""),
        "actor_role": user.get("role", ""),
        "actor_org": user.get("organisation", ""),
        "session_id": session.get("session_id", ""),
    }


def _csrf_token() -> str:
    """Per-session token, minted lazily and returned to the client by /api/me."""
    token = session.get("csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf"] = token
    return token


def _wants_json() -> bool:
    return request.path.startswith("/api/")


def require_login(view):
    """Any signed-in user. API calls get 401 JSON; pages get a redirect."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if current_user() is None:
            if _wants_json():
                return jsonify({"error": "Sign in to continue.", "auth": "required"}), 401
            return redirect(f"/{LOGIN_PAGE}?next={request.path.lstrip('/')}")
        return view(*args, **kwargs)
    return wrapper


def require_analyst(view):
    """Actions that change state need the analyst role, not just a session."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        user = current_user()
        if user is None:
            return jsonify({"error": "Sign in to continue.", "auth": "required"}), 401
        if user.get("role") != auth.ROLE_ANALYST:
            _audit("access_denied",
                   detail=f"{_actor()} attempted {request.path} without decision rights",
                   meta={"path": request.path, **_actor_meta()})
            return jsonify({"error": "Your account is read-only. Only an analyst can do this.",
                            "auth": "forbidden"}), 403
        return view(*args, **kwargs)
    return wrapper


@app.before_request
def _csrf_guard():
    """Reject state-changing calls that do not carry the session's CSRF token.

    The cookie is already SameSite=Lax, so this is defence in depth: it also
    catches a stale tab posting after a sign-out/sign-in cycle, which is the
    case that would otherwise attribute an action to the wrong analyst.
    """
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return None
    if request.path == "/api/login":
        return None
    sent = request.headers.get("X-CSRF-Token", "")
    known = session.get("csrf", "")
    if not known or not sent or not hmac.compare_digest(sent, known):
        return jsonify({"error": "Your session token is stale — reload the page and retry.",
                        "auth": "csrf"}), 403
    return None


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
        # Local wall-clock is what the analyst recognises; the UTC stamp is what
        # survives a server in another timezone, so the trail carries both.
        "ts_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event": event,
        "actor": actor or _actor(),
        "detail": detail,
        "meta": {**_actor_meta(), **(meta or {})},
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
# ---------------------------------------------------------------------------
# Run persistence
#
# A completed run used to live only in STORE, a module-level dict. That is one
# process’s memory, and it made the run console and the review queue quietly
# dependent on being served by the same process for the life of the review: the
# check would finish with findings on screen, and "Decisions waiting for you"
# would be empty, because the process answering that request had never seen the
# run. A restart, a second worker, or a serverless instance recycling all
# produced the same silent emptiness — no error, just nothing to decide.
#
# So every completed run is now written to disk and rehydrated on demand. The
# snapshot is the run, not a summary of it: findings, discarded candidates,
# audit trail and convergence groups all round-trip, so a rehydrated run
# supports deciding, instituting and the dossier export exactly as a live one
# does.
#
# Scope, stated plainly: this fixes restarts and multiple workers on one host.
# It does not make state shared across serverless instances, because each
# instance has its own /tmp. That needs an external store and is a separate
# piece of work.
# ---------------------------------------------------------------------------
RUN_SNAPSHOT_NAME = "last_run.json"


def _snapshot_paths() -> list:
    """Where a run snapshot may live, in order of preference.

    `data/` first so a snapshot sits with the rest of the demo state and
    survives a machine restart; the system temp directory second, for hosts
    that mount the project read-only.
    """
    return [os.path.join(DATA_DIR, RUN_SNAPSHOT_NAME),
            os.path.join(tempfile.gettempdir(), f"drift_sentinel_{RUN_SNAPSHOT_NAME}")]


def _save_run_snapshot(state) -> bool:
    """Persist a completed run. Returns False if nowhere was writable."""
    payload = {
        "saved_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "saved_by_instance": INSTANCE_ID,
        "analyst": STORE.get("analyst", ""),
        "prev_ids": list(STORE.get("prev_ids") or []),
        "log": list(STORE.get("log") or []),
        "started_at": STORE.get("started_at"),
        "run": state.dict(),
    }
    for path in _snapshot_paths():
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False)
            try:
                STORE["snapshot_mtime"] = os.path.getmtime(path)
            except OSError:
                STORE["snapshot_mtime"] = None
            return True
        except (OSError, IOError, TypeError, ValueError):
            continue
    # Nowhere was writable. Stop reading snapshots too: an older file may still
    # be on disk, and rehydrating from it would replace the run this process is
    # holding with a stale one — worse than not persisting at all.
    STORE["storage"] = "readonly"
    STORE["snapshot_disabled"] = True
    return False


def _clear_run_snapshot() -> None:
    """Remove the snapshot so a reset or an abort does not resurrect a run."""
    removed_all = True
    for path in _snapshot_paths():
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        except OSError:
            removed_all = False
    STORE["snapshot_mtime"] = None
    # A snapshot we cannot delete would come straight back on the next read.
    if not removed_all:
        STORE["snapshot_disabled"] = True


def _read_run_snapshot() -> Optional[tuple]:
    """Return `(payload, mtime)` for the first readable snapshot, else None."""
    for path in _snapshot_paths():
        try:
            mtime = os.path.getmtime(path)
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f), mtime
        except (OSError, ValueError):
            continue
    return None


def _build_dataclass(cls, data):
    """Rebuild a dataclass from a dict, ignoring fields it no longer has.

    Tolerating unknown keys matters: a snapshot written before a schema change
    should degrade to a readable run, not raise and lose the queue entirely.
    """
    if not isinstance(data, dict):
        return None
    names = {f.name for f in dataclasses.fields(cls)}
    return cls(**{k: v for k, v in data.items() if k in names})


def _rebuild_run(data: dict):
    """Turn a snapshot dict back into a RunState with real dataclass members."""
    from agents.models import GapFinding, RunState, Rule, Typology
    if not isinstance(data, dict) or not data.get("run_id"):
        return None
    try:
        state = RunState(
            run_id=data["run_id"],
            rulebook_version=data.get("rulebook_version", ""),
            status=data.get("status", "awaiting_human_approval"),
            discarded=list(data.get("discarded") or []),
            log=list(data.get("log") or []),
            audit=list(data.get("audit") or []),
            convergence=list(data.get("convergence") or []),
        )
        state.rulebook = [r for r in (_build_dataclass(Rule, d) for d in (data.get("rulebook") or [])) if r]
        state.typologies = [t for t in (_build_dataclass(Typology, d) for d in (data.get("typologies") or [])) if t]
        state.results = [g for g in (_build_dataclass(GapFinding, d) for d in (data.get("results") or [])) if g]
        return state
    except (TypeError, KeyError, ValueError):
        return None


def _current_run():
    """The run this request should work against.

    Prefers what is already in memory; falls back to the snapshot on disk when
    this process has never held a run, or when another process has written a
    newer one. Every read of the current run goes through here — that is what
    keeps the run console and the review queue looking at the same thing.
    """
    if STORE["running"] or STORE.get("snapshot_disabled"):
        return STORE["run"]

    found = _read_run_snapshot()
    if found is None:
        return STORE["run"]
    payload, mtime = found

    # Already loaded this exact snapshot: nothing to do.
    if STORE["run"] is not None and STORE.get("snapshot_mtime") == mtime:
        return STORE["run"]

    state = _rebuild_run(payload.get("run") or {})
    if state is None:
        return STORE["run"]

    STORE["run"] = state
    STORE["snapshot_mtime"] = mtime
    STORE["run_source"] = ("memory" if payload.get("saved_by_instance") == INSTANCE_ID
                           else "snapshot")
    STORE["prev_ids"] = list(payload.get("prev_ids") or [])
    if payload.get("analyst"):
        STORE["analyst"] = payload["analyst"]
    if not STORE.get("log"):
        STORE["log"] = list(payload.get("log") or [])
    if STORE.get("started_at") is None:
        STORE["started_at"] = payload.get("started_at")
    return state


def _run_worker(trigger: str, actor: str = ""):
    # The worker runs outside the request context, so the analyst who pressed
    # the button is captured here and used for every entry the run writes.
    if actor:
        STORE["analyst"] = actor
    STORE["running"] = True
    STORE["abort"] = False
    STORE["started_at"] = time.time()
    STORE["log"] = []
    # Diff: snapshot which typologies the PREVIOUS completed run flagged.
    _previous = _current_run()
    STORE["prev_ids"] = (
        [_diff_identity(getattr(f, "mode", "reconciliation"), f.typology_id, f.typology_name)
         for f in (_previous.results or [])]
        if _previous else []
    )
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
            _clear_run_snapshot()
            _audit("run_aborted", detail="Run aborted by analyst")
        else:
            STORE["run"] = state
            STORE["decisions"] = {}
            STORE["log"] = list(state.audit) if state else []
            STORE["run_source"] = "memory"
            STORE["snapshot_disabled"] = False
            _record_history(state)
            # Write the run down before telling anyone it finished. The review
            # queue reads this, so a run that is not persisted is a run that
            # can vanish between the console and the decision page.
            if not _save_run_snapshot(state):
                STORE["log"].append({
                    "node": "orchestrator",
                    "message": ("Findings could not be written to disk — they will be lost if this "
                                "process restarts. Decide them in this session."),
                    "ts": time.strftime("%H:%M:%S"),
                })
            _audit("run_finished",
                   detail=f"Completed · {len(state.results)} findings to review",
                   meta={"findings": len(state.results), "discarded": len(state.discarded or [])})
    except Exception as exc:
        STORE["log"].append({"node": "error", "message": f"Run failed: {exc}"})
        STORE["run"] = None
        _clear_run_snapshot()
        _audit("run_error", detail=f"Run failed: {exc}")
    finally:
        STORE["abort"] = False
        STORE["running"] = False


def _start_background_run(trigger: str, actor: str = "") -> None:
    """Start a background thread doing a real run; returns immediately.
    In SERVERLESS mode the function cannot keep a thread alive after the
    request, so the run is executed inline (synchronously) instead."""
    if SERVERLESS:
        _run_worker(trigger, actor)
        return
    t = threading.Thread(target=_run_worker, args=(trigger, actor), daemon=True)
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
        # Only meaningful when generation_source is "deterministic_fallback" -
        # why the model-written attempt for this slot failed, so a hosted
        # backend reporting "available" and still producing zero LLM-sourced
        # findings is explainable from the row itself, not just the run log.
        "fallback_reason": getattr(f, "fallback_reason", ""),
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


def _diff_identity(mode: str, typology_id: str, typology_name: str) -> str:
    """The key used to decide NEW vs REPEAT across runs — deliberately NOT
    always the same thing as the id shown on the row.

    Reconciliation findings (CP-01..CP-12) get their id from a fixed library of
    documented capability primitives - CP-01 always means the same attack, so
    the id itself is a stable content identity and is used directly.

    Generation findings do not have that property. GEN-01/GEN-02/GEN-03 are
    slot POSITIONS assigned by `enumerate(scenarios, 1)` in
    SimulationAgent.run_generation - slot 1 is always "GEN-01" no matter what
    the model proposed for it that run. Comparing on typology_id therefore
    compared "was something in slot 1 last time" rather than "was this
    scenario seen before", so a genuinely novel finding two runs in a row
    could land in the same slot and be reported as a repeat of last run's
    unrelated scenario - and once a run had happened once, this made
    everything downstream look like nothing was ever new. Confirmed
    2026-09-08: two runs producing different scenario names in the same slot
    both showed delta="repeat".

    For generation-mode findings the key is content-derived instead: the
    scenario's own name, normalised. That correctly calls two runs landing on
    the same idea (including two identical deterministic-fallback picks,
    which SHOULD read as repeats) a repeat, and two different ideas that
    happen to share a slot number NEW, which is the property that actually
    matters to an analyst deciding what to look at first.
    """
    if mode == "generation":
        return f"generation::{(typology_name or '').strip().lower()}"
    return typology_id


def _state_json():
    run = _current_run()
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
        key = _diff_identity(f.get("mode", "reconciliation"), f["typology_id"], f.get("typology_name", ""))
        f["delta"] = "new" if key not in prev_ids else "repeat"
    diff_new = [f["typology_id"] for f in findings if f["delta"] == "new"]
    diff_repeat = [f["typology_id"] for f in findings if f["delta"] == "repeat"]
    current_keys = {_diff_identity(f.get("mode", "reconciliation"), f["typology_id"], f.get("typology_name", ""))
                    for f in findings}
    diff_regressed = [t for t in (prev_ids - current_keys)]
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
        # "memory" when this process ran the check itself, "snapshot" when it
        # rehydrated the run from disk. Useful when a queue looks unexpectedly
        # empty: it says whether the run was found at all.
        "run_source": STORE.get("run_source", "memory") if run is not None else "none",
        "analyst": _actor(),
        "user": current_user(),
        "can_decide": bool(current_user() and current_user().get("role") == auth.ROLE_ANALYST),
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
def _serve_page(name: str):
    """Serve a static page, redirecting to the login page when it is gated.

    Gating the HTML as well as the API matters: the findings surface is an
    attack map, so an anonymous visitor should never receive the console shell
    at all, not merely fail its first API call.
    """
    if name not in PUBLIC_PAGES and current_user() is None:
        return redirect(f"/{LOGIN_PAGE}?next={name}")
    return send_from_directory(STATIC, name)


@app.route("/")
def index():
    return _serve_page("home.html")


@app.route("/home.html")
def home_page():
    return _serve_page("home.html")


@app.route("/login.html")
def login_page():
    return send_from_directory(STATIC, "login.html")


@app.route("/index.html")
def run_console():
    return _serve_page("index.html")


@app.route("/dashboard.html")
def dashboard():
    return _serve_page("dashboard.html")


@app.route("/rules.html")
def rules_page():
    return _serve_page("rules.html")


@app.route("/forecast.html")
def forecast_page():
    return _serve_page("forecast.html")


@app.route("/compare.html")
def compare_page():
    return _serve_page("compare.html")


@app.route("/review.html")
def review_page():
    return _serve_page("review.html")


@app.route("/sandbox.html")
def sandbox_page():
    return _serve_page("sandbox.html")


# ---------------------------------------------------------------------------
# Authentication API
# ---------------------------------------------------------------------------
@app.route("/api/me")
def api_me():
    """Who am I? Also mints the CSRF token the client sends back on writes."""
    user = current_user()
    payload = {"authenticated": user is not None, "csrf": _csrf_token()}
    if user:
        payload["user"] = user
        payload["signed_in_at"] = session.get("signed_in_at", "")
    else:
        # Shown on the login page only while the seeded demo accounts are live.
        payload["demo_accounts"] = auth.demo_accounts()
        payload["demo_password"] = auth.DEFAULT_PASSWORD if auth.demo_credentials_active() else ""
    return jsonify(payload)


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.json or {}
    username = (data.get("username") or "").strip()
    record, error = auth.authenticate(username, data.get("password") or "")
    if record is None:
        _audit("login_failed", actor=username or "unknown",
               detail=f"Failed sign-in for '{username or 'unknown'}'",
               meta={"username": username})
        return jsonify({"error": error}), 401

    # Rotate the session on privilege change: a fresh id and CSRF token means a
    # token captured before sign-in cannot be replayed against the new session.
    session.clear()
    session.permanent = True
    session["user"] = auth.public_user(record)
    session["session_id"] = f"sess-{uuid.uuid4().hex[:10]}"
    session["signed_in_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    token = _csrf_token()
    STORE["analyst"] = _actor()
    _audit("login_success", detail=f"{_actor()} signed in",
           meta={"role": record.get("role", "")})

    response = jsonify({"ok": True, "user": session["user"], "csrf": token})
    # Diagnostic breadcrumb, carrying no authority of its own: it records only
    # that a sign-in happened here and when. If this comes back on a later
    # request while the signed session does not, the session cookie is being
    # rejected rather than never issued — which is the difference between "you
    # never signed in" and "the signing keys do not match". /api/session-check
    # is the only reader; nothing in the app trusts it.
    response.set_cookie(
        SIGNIN_MARKER_COOKIE, f"{INSTANCE_ID}@{session['signed_in_at']}",
        max_age=int(timedelta(hours=8).total_seconds()),
        httponly=True, samesite="Lax", secure=COOKIE_SECURE,
    )
    return response


@app.route("/api/logout", methods=["POST"])
def api_logout():
    if current_user() is not None:
        _audit("logout", detail=f"{_actor()} signed out")
    session.clear()
    response = jsonify({"ok": True})
    response.delete_cookie(SIGNIN_MARKER_COOKIE)
    return response


@app.route("/api/session-check")
def api_session_check():
    """Why a sign-in did not stick. Open this straight after signing in.

    A sign-in loop has three possible causes and this separates them:

    * No cookie comes back at all -> the browser is not storing or not sending
      it. `cookie_secure` true on an http:// request is the usual reason: the
      browser drops a Secure cookie on a plain connection, silently.
    * The sign-in marker comes back but the signed session does not -> this
      process cannot verify a cookie another process signed. Compare
      `secret_key_source` and `secret_key_fingerprint`, and watch `instance`
      change between reloads. Set SECRET_KEY.
    * Both come back and `authenticated` is still false -> the session survived
      but holds no user, so the sign-in itself did not write to it.

    Nothing secret is returned. The fingerprint is a truncated digest of the
    signing key: enough to tell two keys apart, not enough to reconstruct one.
    """
    cookie_name = app.config.get("SESSION_COOKIE_NAME") or "session"
    session_cookie = bool(request.cookies.get(cookie_name))
    marker = request.cookies.get(SIGNIN_MARKER_COOKIE, "")
    authenticated = current_user() is not None
    return jsonify({
        "verdict": _session_verdict(session_cookie, marker, authenticated),
        "authenticated": authenticated,
        "instance": INSTANCE_ID,
        "serverless": SERVERLESS,
        "secret_key_source": SECRET_KEY_SOURCE,
        "secret_key_fingerprint": hashlib.sha256(SECRET_KEY.encode("utf-8")).hexdigest()[:12],
        "cookie_name": cookie_name,
        "session_cookie_received": session_cookie,
        "signin_marker": marker or None,
        "cookie_secure": bool(app.config.get("SESSION_COOKIE_SECURE")),
        "cookie_samesite": app.config.get("SESSION_COOKIE_SAMESITE"),
        "request_scheme": request.scheme,
        "session_holds_user": bool(session.get("user")),
        "server_time": time.strftime("%Y-%m-%dT%H:%M:%S"),
    })


def _session_verdict(session_cookie: bool, marker: str, authenticated: bool) -> str:
    """One plain sentence naming the fault, for whoever is looking at this."""
    if authenticated:
        return "Signed in, and this instance can read the session. Nothing wrong here."

    if app.config.get("SESSION_COOKIE_SECURE") and request.scheme != "https":
        return ("Cookies are marked Secure but this request arrived over http, so the browser "
                "discards the session cookie on sight. Serve over https, or set "
                "ALLOW_INSECURE_COOKIE=1 for local use.")

    if marker:
        signed_in_on = marker.split("@")[0]
        if signed_in_on != INSTANCE_ID:
            return (f"A sign-in happened on {signed_in_on} but this is {INSTANCE_ID}, and the "
                    "session it issued is not readable here — the two processes are signing with "
                    f"different keys (current source: {SECRET_KEY_SOURCE}). Set SECRET_KEY in the "
                    "environment so every instance shares one, then redeploy.")
        return ("A sign-in happened on this instance but the session no longer holds a user. "
                "The process most likely restarted, or the session expired.")

    if session_cookie:
        return "A session cookie arrived but carries no signed-in user — nobody has signed in on this browser yet."
    return "No session cookie and no sign-in marker: nobody has signed in from this browser yet."


@app.route("/<page>.html")
def any_page(page: str):
    """Serve any .html that exists in the static folder.

    The explicit routes above are kept so nothing changes for the pages that
    already had one, but this catch-all means adding a new page is a matter of
    dropping the file in demo/static/ - no route needed, and no silent 404 that
    looks like a missing file when it is actually a missing route.

    `page` cannot contain a slash (Flask's default string converter stops at
    one), and send_from_directory refuses to escape STATIC, so this cannot be
    used to read files outside the static folder.
    """
    target = os.path.join(STATIC, f"{page}.html")
    if not os.path.isfile(target):
        return (
            f"<h1>Page not found</h1><p>There is no <code>{page}.html</code> in "
            f"<code>{STATIC}</code>.</p><p>The route is working - the file is "
            f"missing. Check the file was extracted to the right folder.</p>",
            404,
        )
    return _serve_page(f"{page}.html")


@app.route("/audit.html")
def audit_page():
    return _serve_page("audit.html")


@app.route("/static/<path:path>")
def static_files(path: str):
    return send_from_directory(STATIC, path)


@app.after_request
def _no_store(response):
    """Serve pages, scripts and stylesheets fresh every time.

    A browser holding a cached copy of app.js from before the sign-in gate
    existed keeps polling gated endpoints and getting 401s, which looks like a
    server fault and is really a stale asset. Images are left cacheable.
    """
    content_type = response.headers.get("Content-Type", "")
    if content_type.startswith(("text/html", "text/css", "application/javascript",
                               "text/javascript", "application/json")):
        response.headers["Cache-Control"] = "no-store, must-revalidate"
    return response


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
@require_login
def api_compare():
    run = _current_run()
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
@require_login
def api_audit():
    audits = sorted(_load_audit(), key=lambda e: e.get("ts", ""), reverse=True)
    return jsonify({"entries": audits})


@app.route("/api/state")
@require_login
def api_state():
    return jsonify(_state_json())


@app.route("/api/run", methods=["POST"])
@require_analyst
def api_run():
    if STORE["running"]:
        return jsonify({"error": "A run is already in progress."}), 409
    trigger = (request.json or {}).get("trigger", "manual")
    STORE["analyst"] = _actor()
    _start_background_run(trigger, _actor())
    if SERVERLESS:
        return jsonify({"started": True, "sync": True, "state": _state_json()})
    return jsonify({"started": True})


@app.route("/api/decide", methods=["POST"])
@require_analyst
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
    run = _current_run()
    finding = next((f for f in (run.results if run else []) if f.typology_id == fid), None)
    mode = getattr(finding, "mode", "reconciliation") if finding else "reconciliation"
    desc_by_id = {t.id: t.description for t in load_typologies()}
    headline = _attack_description(finding, desc_by_id) if finding else fid
    original_text = (finding.drafted_candidate_red_flag or "").strip() if finding else ""
    final_text = rule_text or original_text
    rule_text_amended = bool(rule_text) and rule_text != original_text

    STORE["log"].append({
        "node": "human-gate",
        "message": (f"Analyst {_actor()} → {label} finding "
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
        "analyst": _actor(),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        **_actor_meta(),
        "fired_rules": finding.fired_rules if finding else [],
        "evaded_rules": finding.evaded_rules if finding else [],
        "original_rule_text": original_text,
        "final_rule_text": final_text,
        "rule_text_amended": rule_text_amended,
    })
    _audit("finding_decided", detail=f"{label} {fid}",
           meta={"fid": fid, "decision": decision, "mode": mode, "reason": rationale})
    return jsonify({"ok": True, "decision": label})


_SEVERITY_ORDER = ["low", "medium", "high", "critical"]


def _severity_from_evaded(rule_ids) -> str:
    """Highest severity among the rules a finding got past; medium if unknown."""
    by_id = {r.id: r for r in load_rulebook()}
    ranks = [_SEVERITY_ORDER.index(by_id[i].risk_severity)
             for i in (rule_ids or [])
             if i in by_id and by_id[i].risk_severity in _SEVERITY_ORDER]
    return _SEVERITY_ORDER[max(ranks)] if ranks else "medium"


def _typology_for(fid: str, finding, run):
    """Resolve the Typology-shaped object institutionalisation needs.

    Only the legacy corpus (TYP-001..TYP-014) has real Typology records. A run's
    findings never do: the reconciliation arm reports per AI capability
    primitive (CP-01..CP-12, from data/fixtures.capability_primitives.json) and
    the generation arm invents its own (GEN-01..). Looking the finding's id up
    in the corpus therefore missed every time, and "Institute rule" answered
    404 on every row in the queue.

    So: try the corpus, then the run's own typology list, and otherwise build a
    stand-in from the finding itself — carrying the fixtures it was verified
    against, so `amendments.institute` can still run its deterministic
    gap-closed self-check on real evidence rather than on nothing. Returns None
    when the finding has no fixture at all, so the caller can say why instead of
    letting the guardrail pass vacuously.
    """
    from agents.models import Typology

    corpus = next((t for t in load_typologies() if t.id == fid), None)
    if corpus is not None:
        return corpus

    in_run = next((t for t in (getattr(run, "typologies", None) or []) if t.id == fid), None)
    if in_run is not None:
        return in_run

    # An empty fixture dict is not evidence. CP-02, for instance, records its
    # fields as `missing_fields` because nothing in the corpus can represent
    # staff impersonation - so there is genuinely nothing to test an amendment
    # against, and the caller should say that rather than let the self-check
    # pass on an empty set.
    fixtures = [fx for fx in (getattr(finding, "test_fixtures", None) or [])
                if isinstance(fx, dict) and (fx.get("tx") or fx)]
    if not fixtures:
        return None

    # Techniques feed the generated rule's name, keywords and trigger text.
    # Built from the finding's own identifiers rather than the reconciliation
    # arm's raw match vocabulary, which includes whole representation notes and
    # would produce an unreadable rule.
    techniques = [t for t in ([fid] + list(getattr(finding, "capability_primitives", None) or [])
                              + [finding.typology_name]) if t]
    return Typology(
        id=fid,
        name=finding.typology_name,
        source="Institutionalised from a reviewed finding (no corpus typology)",
        description=(finding.evidential_basis or finding.typology_name),
        techniques=list(dict.fromkeys(techniques)),
        mitre_atlas=list(getattr(finding, "mitre_atlas", None) or []),
        test_fixtures=fixtures,
        # generate_rule() copies this onto the new indicator, and it drives the
        # severity mix on the dashboard. Inherit the worst severity among the
        # rules this finding actually defeated rather than defaulting every
        # institutionalised rule to medium: an indicator written to close a gap
        # that let a critical rule down should not be filed as a middling one.
        risk_severity=_severity_from_evaded(getattr(finding, "evaded_rules", None)),
    )


@app.route("/api/institute", methods=["POST"])
@require_analyst
def api_institute():
    """Approve + institutionalise a finding: generates a dedicated DS indicator,
    covers the typology's gap set, records a post-amendment checkpoint."""
    data = request.json or {}
    fid = data.get("fid")
    if not fid:
        return jsonify({"error": "bad request"}), 400
    run = _current_run()
    finding = next((f for f in (run.results if run else []) if f.typology_id == fid), None)
    if finding is None:
        return jsonify({"error": "finding not found"}), 404
    typology = _typology_for(fid, finding, run)
    if typology is None:
        return jsonify({"error": ("This finding carries no fixture to test an amendment against, "
                                  "so the gap-closed self-check cannot run. Accept or amend it "
                                  "instead, and raise the missing field with the domain team.")}), 400

    res = amendments.institute(typology, finding, run.run_id if run else "review")
    if not res.get("ok"):
        return jsonify({"error": res.get("error", "could not institute")}), 400

    STORE["decisions"][fid] = "instituted ✓"
    STORE["log"].append({
        "node": "human-gate",
        "message": f"Analyst {_actor()} → instituted {res['rule']} for '{fid}' · gap closed, drift re-scanned.",
    })
    _append_decision_log({
        "fid": fid,
        "mode": getattr(finding, "mode", "reconciliation"),
        "headline": _attack_description(finding, {t.id: t.description for t in load_typologies()}),
        "typology_name": finding.typology_name,
        "decision": "institute",
        "decision_label": "instituted ✓",
        "rationale": "Institutionalised as a standing DS indicator (gap closed by amendment).",
        "analyst": _actor(),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        **_actor_meta(),
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
@require_analyst
def api_reset():
    if STORE["running"]:
        STORE["abort"] = True
        return jsonify({"ok": True, "aborted": True})
    STORE["run"] = None
    STORE["decisions"] = {}
    STORE["log"] = []
    STORE["started_at"] = None
    STORE["prev_ids"] = []
    _clear_run_snapshot()
    # Roll the rulebook back to the shipped DS-01..DS-40 baseline (demo idempotency).
    restored = amendments.restore_baseline()
    _audit("console_reset", detail="Console state cleared ; baseline restored")
    return jsonify({"ok": True, "aborted": False, "restored": restored.get("removed", [])})


@app.route("/api/record", methods=["POST"])
@require_analyst
def api_record():
    """Manually record a forecast checkpoint from the current corpus scan."""
    entry = _record_history(kind="checkpoint")
    _audit("checkpoint_recorded",
           detail=f"Checkpoint {entry.get('run_id')} recorded · drift {entry.get('drift_index')}",
           meta={"run_id": entry.get("run_id")})
    return jsonify({"ok": True, "recorded": entry})


@app.route("/api/fraudtest", methods=["POST"])
@require_analyst
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
        run = _current_run()
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
            # Keep the submitted scenario on the finding. It is the only
            # evidence a later "Institute rule" has to run its gap-closed
            # self-check against; without it the analyst's own test attack
            # would be the one row in the queue that could never be adopted.
            test_fixtures=[raw],
        )
        run.results.append(finding)
        STORE["decisions"].setdefault(fid, "")
        STORE["log"].append({
            "node": "human-gate",
            "message": f"Analyst {_actor()} submitted attack test '{label}' ({fid}) · "
                       f"caught {len(fired)} rule(s), slipped past {len(evaded)} · sent to human gate.",
        })
        STORE["prev_ids"] = STORE.get("prev_ids") or [
            _diff_identity(getattr(f, "mode", "reconciliation"), f.typology_id, f.typology_name)
            for f in run.results[:-1]
        ] or []
        _audit("attack_submitted",
               detail=f"Attack test '{label}' ({fid}) · caught {len(fired)}, slipped past {len(evaded)}",
               meta={"fid": fid, "label": label, "fired": fired, "evaded": evaded})
        _save_run_snapshot(run)
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
@require_analyst
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
@require_login
def api_dossier():
    """Compliance dossier: approved + amended findings as JSON."""
    dossier = _build_dossier()
    _audit("dossier_exported", detail=f"{_actor()} exported the findings dossier (JSON)",
           meta={"format": "json", "findings": len(dossier.get("approved_findings", []))})
    return jsonify(dossier)


@app.route("/api/dossier.pdf")
@require_login
def api_dossier_pdf():
    """Compliance dossier as a printable PDF attachment."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from io import BytesIO

    d = _build_dossier()
    _audit("dossier_exported", detail=f"{_actor()} exported the findings dossier (PDF)",
           meta={"format": "pdf", "findings": len(d.get("approved_findings", []))})
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
    run = _current_run()
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
        "analyst": _actor(),
        "exported_by": _actor_meta(),
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
@require_login
def api_rules():
    return jsonify({"rules": [_rule_json(r) for r in load_rulebook()]})


@app.route("/api/dashboard")
@require_login
def api_dashboard():
    return jsonify(_dashboard_json())


@app.route("/api/forecast")
@require_login
def api_forecast():
    return jsonify(Forecaster(load_rulebook(), load_typologies()).forecast())


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)