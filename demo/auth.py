#!/usr/bin/env python3
"""Named-analyst accounts for the Drift Sentinel console.

The concept note promises that nothing enters guidance without *a named
analyst* accepting, amending or rejecting it, and that the gap report is
access-restricted. Both promises need an identity to hang off, so this module
provides one: a small local account store, PBKDF2 password verification, and
brute-force throttling. `demo/web.py` puts the authenticated user into the
Flask session and stamps their identity onto every decision and audit entry.

Design notes
------------
* Passwords are never stored, only PBKDF2-HMAC-SHA256 digests with a per-user
  random salt, compared with `hmac.compare_digest`.
* The store is a JSON file (`data/users.json`) seeded on first start. On a
  read-only filesystem (serverless) the seed stays in memory for the life of
  the instance instead of crashing the deploy.
* This is prototype-grade identity for a demonstrator. A production deployment
  would federate to the authority's own IdP (SAML/OIDC) and drop this module;
  the rest of the app only depends on `current_user()` returning a record.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from typing import Optional

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
USERS_PATH = os.path.join(DATA_DIR, "users.json")

PBKDF2_ALGORITHM = "pbkdf2_sha256"
PBKDF2_ITERATIONS = 240_000
SALT_BYTES = 16

# Roles. `analyst` may change state (decide, institute, run, reset); `observer`
# may read the console but not act on a finding. Least privilege by default.
ROLE_ANALYST = "analyst"
ROLE_OBSERVER = "observer"
ROLES = {
    ROLE_ANALYST: "Can run checks and accept, amend, reject or institute findings.",
    ROLE_OBSERVER: "Read-only. Can view findings and the paper trail, cannot decide.",
}

# Brute-force throttling (per username, in-memory, per process).
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 15 * 60

_LOCK = threading.Lock()
_FAILED: dict[str, list] = {}          # username -> [attempts, first_attempt_ts]
_MEMORY_USERS: Optional[dict] = None   # fallback store when disk is read-only
_SEEDED_WITH_DEFAULTS = False          # drives the demo-credentials hint on the login page

# Demo accounts, seeded once on first start. The two analyst accounts mirror the
# end-users named in the concept note: a typologies analyst at the FIC and a
# supervision specialist at the FSCA.
DEFAULT_PASSWORD = os.environ.get("DRIFT_DEMO_PASSWORD", "drift-sentinel-2026")
DEFAULT_USERS = [
    {
        "username": "n.hlophe",
        "display_name": "N. Hlophe",
        "organisation": "FSCA",
        "title": "Supervision specialist · FinTech",
        "role": ROLE_ANALYST,
    },
    {
        "username": "g.kana",
        "display_name": "G. Kana",
        "organisation": "FIC",
        "title": "Typologies analyst",
        "role": ROLE_ANALYST,
    },
    {
        "username": "e.reddy",
        "display_name": "E. Reddy",
        "organisation": "UNISA",
        "title": "Domain reviewer",
        "role": ROLE_OBSERVER,
    },
]


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------
def hash_password(password: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    """Return a self-describing digest: algorithm$iterations$salt$hash."""
    if not password:
        raise ValueError("password must not be empty")
    salt = secrets.token_bytes(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"{PBKDF2_ALGORITHM}${iterations}${salt.hex()}${digest.hex()}"


def verify_password(stored: str, password: str) -> bool:
    """Constant-time check of `password` against a stored digest."""
    try:
        algorithm, iterations, salt_hex, digest_hex = (stored or "").split("$")
        if algorithm != PBKDF2_ALGORITHM:
            return False
        candidate = hashlib.pbkdf2_hmac(
            "sha256", (password or "").encode("utf-8"),
            bytes.fromhex(salt_hex), int(iterations),
        )
    except (ValueError, AttributeError):
        return False
    return hmac.compare_digest(candidate.hex(), digest_hex)


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------
def _seed_users() -> dict:
    """Build the default account set with freshly hashed passwords."""
    global _SEEDED_WITH_DEFAULTS
    _SEEDED_WITH_DEFAULTS = True
    return {
        u["username"]: {**u, "password_hash": hash_password(DEFAULT_PASSWORD),
                        "created": time.strftime("%Y-%m-%dT%H:%M:%S")}
        for u in DEFAULT_USERS
    }


def load_users() -> dict:
    """Load the account store, seeding it on first use.

    Falls back to an in-memory store when the filesystem is read-only, so a
    serverless deploy still authenticates for the life of the instance.
    """
    global _MEMORY_USERS
    if _MEMORY_USERS is not None:
        return _MEMORY_USERS
    try:
        with open(USERS_PATH, "r", encoding="utf-8") as f:
            users = json.load(f)
        if isinstance(users, dict) and users:
            return users
    except (OSError, ValueError):
        pass
    users = _seed_users()
    if not save_users(users):
        _MEMORY_USERS = users
    return users


def save_users(users: dict) -> bool:
    """Persist the account store. Returns False on a read-only filesystem."""
    global _MEMORY_USERS
    try:
        os.makedirs(os.path.dirname(USERS_PATH), exist_ok=True)
        with open(USERS_PATH, "w", encoding="utf-8") as f:
            json.dump(users, f, indent=2, ensure_ascii=False)
    except OSError:
        _MEMORY_USERS = users
        return False
    return True


def public_user(record: dict) -> dict:
    """Strip the credential material before a record crosses into a response."""
    return {
        "username": record.get("username", ""),
        "display_name": record.get("display_name", record.get("username", "")),
        "organisation": record.get("organisation", ""),
        "title": record.get("title", ""),
        "role": record.get("role", ROLE_OBSERVER),
        "can_decide": record.get("role") == ROLE_ANALYST,
    }


def set_password(username: str, password: str) -> bool:
    """Replace a user's password. Returns False if the user does not exist."""
    users = load_users()
    record = users.get((username or "").strip().lower())
    if record is None:
        return False
    record["password_hash"] = hash_password(password)
    record["password_changed"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    save_users(users)
    return True


# ---------------------------------------------------------------------------
# Throttling + authentication
# ---------------------------------------------------------------------------
def _lockout_remaining(username: str) -> int:
    """Seconds left on a lockout, 0 if the account is not locked."""
    with _LOCK:
        state = _FAILED.get(username)
        if not state or state[0] < MAX_FAILED_ATTEMPTS:
            return 0
        elapsed = time.time() - state[1]
        if elapsed >= LOCKOUT_SECONDS:
            _FAILED.pop(username, None)
            return 0
        return int(LOCKOUT_SECONDS - elapsed)


def _record_failure(username: str) -> None:
    with _LOCK:
        state = _FAILED.get(username)
        if state is None or (time.time() - state[1]) > LOCKOUT_SECONDS:
            _FAILED[username] = [1, time.time()]
        else:
            state[0] += 1


def _clear_failures(username: str) -> None:
    with _LOCK:
        _FAILED.pop(username, None)


def authenticate(username: str, password: str) -> tuple[Optional[dict], str]:
    """Check credentials.

    Returns `(user_record, "")` on success, or `(None, reason)` on failure.
    The reason given to the caller is deliberately the same for an unknown user
    and a wrong password, so the response cannot be used to enumerate accounts.
    """
    username = (username or "").strip().lower()
    if not username or not password:
        return None, "Enter both a username and a password."

    locked_for = _lockout_remaining(username)
    if locked_for:
        return None, f"Too many failed attempts. Try again in {locked_for // 60 + 1} minute(s)."

    record = load_users().get(username)
    # Always run a hash comparison so timing does not distinguish an unknown
    # username from a wrong password.
    stored = record.get("password_hash", "") if record else hash_password(secrets.token_hex(8))
    if not verify_password(stored, password) or record is None:
        _record_failure(username)
        return None, "Username or password is incorrect."

    _clear_failures(username)
    return record, ""


def demo_credentials_active() -> bool:
    """True while the store still holds the seeded demo accounts."""
    if _SEEDED_WITH_DEFAULTS:
        return True
    users = load_users()
    return all(u["username"] in users for u in DEFAULT_USERS)


def demo_accounts() -> list[dict]:
    """Account list shown on the login page while demo credentials are in use."""
    if not demo_credentials_active():
        return []
    users = load_users()
    return [public_user(users[u["username"]]) for u in DEFAULT_USERS if u["username"] in users]
