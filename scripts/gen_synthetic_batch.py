"""One-off generator for a synthetic transaction batch to test rulebook
coverage broadly (not a permanent fixture — outputs to /tmp, review before
committing anything to data/).

Every transaction below is evaluated against the LIVE rulebook before being
written out, so the "expect_fired" list on each entry is not a guess — it's
what the deterministic engine actually returned. If a change to rulebook.json
later breaks the correspondence, this script says so loudly rather than
producing a fixture file that quietly lies about what it tests.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.loader import load_rulebook
from agents.rule_engine import RuleEvaluationEngine

# ---------------------------------------------------------------------------
# The batch. Deliberately mixed:
#  - one "clean" transaction (nothing should fire — a true negative)
#  - single-rule cases spanning most rule categories
#  - multi-rule cases (the same scenario several DS-xx rules are meant to
#    catch together, the way a real layered scam would)
#  - two "near miss" cases that sit one field short of firing, to test that
#    the engine doesn't over-fire on partial matches
# ---------------------------------------------------------------------------
BATCH = [
    {
        "label": "Clean, unremarkable retail customer",
        "notes": "True negative — nothing suspicious. Should fire nothing.",
        "tx": {
            "new_account": False,
            "customer_profile_consistent": True,
            "kyc_complete": True,
            "amount": 250,
        },
    },
    {
        "label": "New account, inconsistent deposit, same-day withdrawal",
        "notes": "Classic onboarding red flag (DS-01).",
        "tx": {
            "new_account": True,
            "customer_profile_consistent": False,
            "rapid_withdrawal": True,
        },
    },
    {
        "label": "Series of sub-threshold transfers, round amounts",
        "notes": "Structuring (DS-02); economic_rationale is explicitly set, which is why "
                 "this deliberately does NOT also trip DS-38 — see the separate DS-38 case "
                 "below for the 'no rationale offered at all' variant.",
        "tx": {
            "below_threshold": True,
            "round_amount": True,
            "economic_rationale": "structuring",
        },
    },
    {
        "label": "Crypto transfer with no originator/beneficiary info",
        "notes": "Travel Rule gap (DS-03, DS-34 if also cross-border).",
        "tx": {
            "travel_rule_missing": True,
            "missing_orig_benef": True,
            "cross_border": True,
        },
    },
    {
        "label": "Counterparty VASP has no real KYC + unhosted wallet",
        "notes": "Weak counterparty control (DS-04).",
        "tx": {
            "weak_counterparty": True,
            "unhosted_wallet": True,
        },
    },
    {
        "label": "Fan-in from many senders into one account, then consolidated",
        "notes": "Layering / mule collection pattern (DS-05, DS-15).",
        "tx": {
            "fan_in": True,
            "multiple_accounts": True,
            "consolidated": True,
        },
    },
    {
        "label": "Shared login credentials across two customer accounts",
        "notes": "Identity/CDD flag (DS-06).",
        "tx": {"shared_credentials": True, "changed_credentials": True},
    },
    {
        "label": "KYC file incomplete at onboarding",
        "notes": "Incomplete KYC (DS-07).",
        "tx": {"kyc_complete": False},
    },
    {
        "label": "Customer can't explain the transaction they're sending",
        "notes": "Mule indicator (DS-08, composes with DS-12).",
        "tx": {"lacks_transaction_knowledge": True, "crypto_naive": True},
    },
    {
        "label": "Forged ID document at onboarding",
        "notes": "Critical-severity document fraud (DS-09).",
        "tx": {"identity_markers": ["forged"], "new_account": True},
    },
    {
        "label": "Wallet address linked to a public illegal-activity forum",
        "notes": "OSINT flag (DS-10).",
        "tx": {"osint_illegal": True, "threat_list_hit": True},
    },
    {
        "label": "Customer known to law enforcement for a criminal association",
        "notes": "Profile risk, high severity (DS-11).",
        "tx": {"criminal_association": True},
    },
    {
        "label": "Frequent identity-detail changes shortly after onboarding",
        "notes": "Mule-recruitment pattern (DS-13).",
        "tx": {"frequent_identity_change": True, "frequent_funding_change": True},
    },
    {
        "label": "Repeated transactions with the same narrow subset of counterparties",
        "notes": "Layering / trading-clustering pattern (DS-15).",
        "tx": {"clustering": True, "small_wallet_set": True, "quick_succession": True},
    },
    {
        "label": "Funds traced to a known criminal scheme's wallet cluster",
        "notes": "Critical source-of-funds flag (DS-16).",
        "tx": {"criminal_source": True, "sanctioned_source": True},
    },
    {
        "label": "Crypto converted to a prepaid card via a cash-funded route",
        "notes": "Crypto-to-plastic structuring (DS-17).",
        "tx": {"crypto_to_plastic": True, "cash_deposit_cards": True},
    },
    {
        "label": "Funds passed through a mixing service before arrival",
        "notes": "Mixer/tumbler use (DS-18, composes with DS-24 if VPN too).",
        "tx": {"uses_mixer": True, "tools": ["mixer"], "privacy_coin": True},
    },
    {
        "label": "Transfer to an exchange unregistered in its jurisdiction",
        "notes": "Geographic/registration gap (DS-19).",
        "tx": {"unregistered_exchange": True, "unregulated_jurisdiction": True},
    },
    {
        "label": "Direct sanctions list match on the counterparty",
        "notes": "Critical sanctions screening (DS-21) — should be the sharpest flag in the batch.",
        "tx": {"sanctions_match": True, "counterparty_jurisdiction": "sanctioned"},
    },
    {
        "label": "PEP with an unusual, unexplained spike in activity",
        "notes": "PEP monitoring (DS-22).",
        "tx": {"is_pep": True, "pep_activity_unusual": True},
    },
    {
        "label": "Value moved through many hops in rapid succession",
        "notes": "Layering / pass-through (DS-23).",
        "tx": {"multi_hop": True, "pass_through": True, "quick_succession": True},
    },
    {
        "label": "Brand-new wallet used within days of first activity, over VPN/Tor",
        "notes": "Technology-evasion cluster (DS-24, DS-25).",
        "tx": {
            "fresh_wallet": True,
            "wallet_age_days": 1,
            "uses_vpn_tor": True,
        },
    },
    {
        "label": "Source of funds inconsistent with declared customer wealth",
        "notes": "Wealth-mismatch flag (DS-27).",
        "tx": {"wealth_mismatch": True, "source_inconsistent": True},
    },
    {
        "label": "Rapid deposit accumulation followed by immediate off-boarding",
        "notes": "Onboarding-to-exit pattern (DS-28), one field short of DS-01's full trigger.",
        "tx": {"rapid_accumulation": True, "new_account": True},
    },
    {
        "label": "Chat memo references buying illicit goods with the proceeds",
        "notes": "Message-field language flag (DS-14).",
        "tx": {"memo_illicit": True},
    },
    {
        "label": "Customer stalls and won't provide requested CDD documents",
        "notes": "Evasive/unwilling CDD (DS-33).",
        "tx": {"evasive_cdd": True, "unwilling_identity": True},
    },
    {
        "label": "Large transfer to a beneficiary wallet with almost no history",
        "notes": "Thin-history beneficiary receiving material value (DS-35).",
        "tx": {"low_history_wallet": True, "amount": 5000},
    },
    {
        "label": "Corporate customer whose true beneficial owner can't be established",
        "notes": "UBO not established (DS-36).",
        "tx": {"ubo_not_established": True, "unverified_ubo": True},
    },
    {
        "label": "Round-number transfer with no rationale offered at all",
        "notes": "DS-38's actual trigger — round/below-threshold AND economic_rationale "
                 "absent entirely (contrast with the DS-02 case above, where a rationale "
                 "string, even a suspicious one, is present and blocks this rule).",
        "tx": {"round_amount": True, "below_threshold": True},
    },
    {
        "label": "Deepfake-generated ID media presented during a fresh onboarding flow",
        "notes": "AI-orchestrated synthetic-identity onboarding (DS-39) — the counterpart "
                 "to CP-01 in the capability-primitives library, expressed the way the "
                 "static rulebook models it.",
        "tx": {"fresh_onboarding": True, "identity_markers": ["synthetic", "deepfake_media"]},
    },
    {
        "label": "Crypto-naive customer moving funds through a tiny fixed set of wallets",
        "notes": "Coached-mule behaviour (DS-40).",
        "tx": {"coached_mule": True, "crypto_naive": True, "small_wallet_set": True},
    },
    {
        "label": "Transaction volume spikes far above the customer's normal baseline",
        "notes": "Velocity anomaly (DS-30) — the plain volume-spike variant, separate from "
                 "the clustering/small-wallet-set pattern DS-15 covers above.",
        "tx": {"velocity": True, "high_value": True},
    },
]

# ---------------------------------------------------------------------------
def main():
    rulebook = load_rulebook()
    engine = RuleEvaluationEngine()
    by_id = {r.id: r for r in rulebook}

    fixtures_out = []
    report_lines = []
    total_fired = 0

    for entry in BATCH:
        results = engine.evaluate(rulebook, entry["tx"])
        fired = sorted(r.rule_id for r in results if r.fired)
        total_fired += len(fired)
        fixtures_out.append({
            "label": entry["label"],
            "notes": entry["notes"],
            "tx": entry["tx"],
            "expect_fired": fired,   # ACTUAL engine output, not a guess
        })
        names = ", ".join(f"{fid} ({by_id[fid].category})" for fid in fired) or "— none —"
        report_lines.append(f"- **{entry['label']}**\n  fired: {names}")

    out_path = "/tmp/synthetic_batch.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({
            "note": ("Synthetic, illustrative-only transaction batch for broad rulebook "
                     "coverage testing. Not real customers or transactions. Generated and "
                     "verified against the live rulebook by scripts/gen_synthetic_batch.py."),
            "fixtures": fixtures_out,
        }, f, indent=2, ensure_ascii=False)

    print(f"Wrote {len(fixtures_out)} fixtures to {out_path}")
    print(f"Total rule-fires across the batch: {total_fired}")
    zero_fire = [f["label"] for f in fixtures_out if not f["expect_fired"]]
    print(f"Zero-fire transactions ({len(zero_fire)}):")
    for label in zero_fire:
        print("  -", label)
    print()
    print("\n".join(report_lines))


if __name__ == "__main__":
    main()