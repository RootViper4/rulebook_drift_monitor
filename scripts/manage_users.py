#!/usr/bin/env python3
"""Manage the analyst accounts that can sign in to the console.

Accounts live in `data/users.json`, which is seeded with the demo accounts on
first start. Use this script to add real people, change a password, change a
role, or remove an account.

    python3 -m scripts.manage_users list
    python3 -m scripts.manage_users add m.mohlerepe --name "M. Mohlerepe" \
            --org Cenfri --title "AI builder" --role analyst
    python3 -m scripts.manage_users passwd n.hlophe
    python3 -m scripts.manage_users role e.reddy analyst
    python3 -m scripts.manage_users remove g.kana

Passwords are prompted for, never passed as an argument, so they do not end up
in shell history or in `ps` output. Only the PBKDF2 digest is stored. Pass
--password only in a non-interactive setting (a seeding script), knowing it is
visible to anything that can read the process table.
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from demo import auth

MIN_PASSWORD_LENGTH = 10


def _prompt_password(username: str, supplied: str = "") -> str:
    """Read a password twice from the terminal and sanity-check its length."""
    if supplied:
        return supplied
    while True:
        first = getpass.getpass(f"New password for {username}: ")
        if len(first) < MIN_PASSWORD_LENGTH:
            print(f"  Too short — use at least {MIN_PASSWORD_LENGTH} characters.")
            continue
        if first != getpass.getpass("Confirm password: "):
            print("  Those did not match. Try again.")
            continue
        return first


def cmd_list(_args) -> int:
    users = auth.load_users()
    if not users:
        print("No accounts yet — start the app once to seed the demo accounts.")
        return 0
    width = max(len(u) for u in users)
    print(f"{'USERNAME'.ljust(width)}  ROLE       ORGANISATION  NAME")
    for username, record in sorted(users.items()):
        print(f"{username.ljust(width)}  {record.get('role','').ljust(9)}  "
              f"{(record.get('organisation') or '—').ljust(12)}  {record.get('display_name','')}")
    if auth.demo_credentials_active():
        print("\nThe seeded demo accounts are still present. Remove them before any "
              "deployment that is not a demonstration.")
    return 0


def cmd_add(args) -> int:
    username = args.username.strip().lower()
    users = auth.load_users()
    if username in users:
        print(f"'{username}' already exists — use `passwd` or `role` to change it.")
        return 1
    if args.role not in auth.ROLES:
        print(f"Unknown role '{args.role}'. Choose one of: {', '.join(auth.ROLES)}")
        return 1
    password = _prompt_password(username, args.password)
    users[username] = {
        "username": username,
        "display_name": args.name or username,
        "organisation": args.org or "",
        "title": args.title or "",
        "role": args.role,
        "password_hash": auth.hash_password(password),
        "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    if not auth.save_users(users):
        print("Could not write data/users.json — the filesystem is read-only here, "
              "so this account exists only in memory. Run this on a writable host.")
        return 1
    print(f"Added {username} ({args.role}) — {args.name or username}"
          + (f", {args.org}" if args.org else ""))
    return 0


def cmd_passwd(args) -> int:
    username = args.username.strip().lower()
    if username not in auth.load_users():
        print(f"No such account: '{username}'")
        return 1
    password = _prompt_password(username, args.password)
    if not auth.set_password(username, password):
        print("Password change failed.")
        return 1
    print(f"Password updated for {username}.")
    return 0


def cmd_role(args) -> int:
    username = args.username.strip().lower()
    users = auth.load_users()
    if username not in users:
        print(f"No such account: '{username}'")
        return 1
    if args.role not in auth.ROLES:
        print(f"Unknown role '{args.role}'. Choose one of: {', '.join(auth.ROLES)}")
        return 1
    users[username]["role"] = args.role
    auth.save_users(users)
    print(f"{username} is now {args.role} — {auth.ROLES[args.role]}")
    return 0


def cmd_remove(args) -> int:
    username = args.username.strip().lower()
    users = auth.load_users()
    if username not in users:
        print(f"No such account: '{username}'")
        return 1
    if len([u for u in users.values() if u.get("role") == auth.ROLE_ANALYST]) <= 1 \
            and users[username].get("role") == auth.ROLE_ANALYST:
        print("This is the last analyst account. Add another one before removing it, "
              "or nobody will be able to decide a finding.")
        return 1
    users.pop(username)
    auth.save_users(users)
    print(f"Removed {username}. Their entries in the audit trail are left untouched.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="manage_users",
        description="Add, list and update the accounts that can sign in to the console.")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="show every account and its role").set_defaults(func=cmd_list)

    add = sub.add_parser("add", help="create an account")
    add.add_argument("username", help="sign-in name, e.g. m.mohlerepe")
    add.add_argument("--name", default="", help="display name shown on decisions")
    add.add_argument("--org", default="", help="organisation, e.g. FIC")
    add.add_argument("--title", default="", help="job title, shown on hover")
    add.add_argument("--role", default=auth.ROLE_ANALYST, choices=sorted(auth.ROLES))
    add.add_argument("--password", default="", help="non-interactive only; prefer the prompt")
    add.set_defaults(func=cmd_add)

    pw = sub.add_parser("passwd", help="change an account's password")
    pw.add_argument("username")
    pw.add_argument("--password", default="", help="non-interactive only; prefer the prompt")
    pw.set_defaults(func=cmd_passwd)

    role = sub.add_parser("role", help="change an account's role")
    role.add_argument("username")
    role.add_argument("role", choices=sorted(auth.ROLES))
    role.set_defaults(func=cmd_role)

    rm = sub.add_parser("remove", help="delete an account")
    rm.add_argument("username")
    rm.set_defaults(func=cmd_remove)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())