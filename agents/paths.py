"""Where Drift Sentinel reads and writes its data files - the ONE place this
is decided, so every module agrees.

Why this exists: six files (loader.py, probe.py, rule_amendment.py,
draft_cache.py, forecaster.py, demo/web.py) each independently computed their
own "data/" path relative to the repo. That works fine on a machine you
control, but breaks hard on Vercel: outside /tmp, a Vercel serverless
function's filesystem is READ-ONLY. Every write this app does at runtime -
recording a decision, appending to the audit trail, instituting an approved
rule, checkpointing forecast history - would raise an OSError on the very
first attempt in production, not fail gracefully.

The fix: on Vercel (which sets the VERCEL env var itself, so detection needs
no configuration), redirect all writes to /tmp/drift_sentinel_data instead,
seeding it from the repo's real data/ on first use so reads still see the
shipped rulebook, typologies, fixtures, etc.

IMPORTANT CAVEAT THIS DOES NOT FIX: /tmp on a serverless platform is
per-instance and not guaranteed to persist between invocations, and multiple
concurrent instances each get their OWN /tmp. This stops the app from
CRASHING on Vercel. It does not make decisions, audit entries, or run state
reliably durable or consistent across users/instances there - that needs a
real external store (a database, Vercel KV, etc.), which is a bigger change
than a paths fix. Treat the Vercel deploy as best-effort for a single
presenter's session, not as reliable multi-user infrastructure.
"""
from __future__ import annotations

import os
import shutil

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_REPO_DATA_DIR = os.path.join(_REPO_ROOT, "data")

# Vercel sets this automatically on every deployment - no config needed.
# https://vercel.com/docs/environment-variables/system-environment-variables
_ON_VERCEL = bool(os.environ.get("VERCEL"))

_TMP_DATA_DIR = "/tmp/drift_sentinel_data"

_seeded = False


def _seed_tmp_once() -> None:
    """Copy the repo's shipped data files into /tmp on first use, so reads
    on Vercel see the same baseline rulebook/typologies/fixtures as local -
    only the writable copy moves, not the content."""
    global _seeded
    if _seeded:
        return
    os.makedirs(_TMP_DATA_DIR, exist_ok=True)
    if os.path.isdir(_REPO_DATA_DIR):
        for name in os.listdir(_REPO_DATA_DIR):
            src = os.path.join(_REPO_DATA_DIR, name)
            dst = os.path.join(_TMP_DATA_DIR, name)
            if os.path.isfile(src) and not os.path.exists(dst):
                shutil.copy2(src, dst)
    _seeded = True


def get_data_dir() -> str:
    """Return the directory Drift Sentinel should read/write data files
    from: the repo's data/ folder normally, or a seeded /tmp copy on
    Vercel where the repo folder is read-only."""
    if _ON_VERCEL:
        _seed_tmp_once()
        return _TMP_DATA_DIR
    return _REPO_DATA_DIR


def is_ephemeral_deploy() -> bool:
    """True when running somewhere writes are not reliably durable (right
    now: Vercel). Callers that want to warn the user about a caveat (e.g. a
    banner noting decisions may not persist) can check this."""
    return _ON_VERCEL