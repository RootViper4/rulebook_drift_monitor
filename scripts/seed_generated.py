#!/usr/bin/env python3
"""Seed the generated-typology catalogue.

Designs ~34 speculative AI-fraud patterns, runs each through the deterministic
rule engine, and keeps only those that BOTH fire at least one rule AND evade at
least one *relevant* rule (so the finding is a real, demonstrable gap). The
first 20 passing patterns are assigned GEN-01..GEN-20 and written to
data/generated_typologies.json, mirroring the schema of typologies.json.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.loader import load_rulebook  # noqa: E402
from agents.rule_engine import RuleEvaluationEngine  # noqa: E402

DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


def C(name, techniques, fixture, severity="high", atlas=None, desc=""):
    return {
        "name": name,
        "tech": techniques,
        "fx": fixture,
        "severity": severity,
        "atlas": atlas or [],
        "desc": desc or "Speculative AI-fraud pattern synthesised from capability primitives.",
    }


CANDIDATES = [
    C("Aggregator-route pass-through sweep", ["pass-through", "fan-out", "layering"],
      {"pass_through": True}, atlas=["TA0007 Evasion", "T1071 Layer"]),
    C("Nominee beneficial-ownership shell", ["beneficial ownership", "ubo", "legal person", "weak counterparty", "vasp"],
      {"ubo_not_established": True}, desc="Legal-person nominees hide the real owner; the underlying counterparty is unvetted."),
    C("Fresh-wallet mule herd under the thresholds", ["fresh wallet", "new wallet", "mule", "coached", "crypto-naive", "structuring", "no history"],
      {"fresh_wallet": True, "wallet_age_days": 1, "coached_mule": True, "crypto_naive": True, "amount": 200}),
    C("Stolen-card funds converted to plastic", ["stolen card", "crypto-to-plastic", "risk list", "darknet", "extortion"],
      {"crypto_to_plastic": True}),
    C("High-velocity layering in a short window", ["velocity", "high-value", "baseline", "24-hour", "clustered"],
      {"velocity": True, "high_value": True, "quick_succession": True}),
    C("Unregistered-exchange off-ramp funnel", ["unregistered exchange", "high-risk jurisdiction", "grey list", "vasp"],
      {"unregistered_exchange": True, "counterparty_jurisdiction": "regulated"}),
    C("Deepfake-audio authorised beneficiary swap", ["deepfake", "liveness", "impersonation", "travel rule", "cross-border", "missing information"],
      {"identity_markers": ["liveness_bypass"], "cross_border": True}),
    C("Synthetic-identity laddering into private custody", ["synthetic identity", "self-custody", "unhosted wallet", "unregulated jurisdiction", "attribution"],
      {"ai_orchestrated_onboarding": True, "unhosted_wallet": True}),
    C("Relocation to a no-rationale shell office", ["unregulated jurisdiction", "no rationale", "beneficial ownership", "ubo", "legal person"],
      {"offices_relocation": True}),
    C("Cross-border cascade with missing identifying info", ["cross-border", "travel rule", "originator", "beneficiary", "identifying information", "missing information"],
      {"missing_orig_benef": True}),
    C("Round-amount netting dressed as salary", ["round amount", "no rationale", "mule", "coached"],
      {"coached_mule": True, "round_amount": True, "economic_rationale": "salary"}),
    C("Shared-credential zombie account goldmine", ["shared credentials", "shared ip", "changed credentials", "identity"],
      {"shared_credentials": True}),
    C("Crypto-naive mule with limited digital literacy", ["crypto-naive", "mule", "coached", "unfamiliar", "victim", "small set"],
      {"crypto_naive": True}),
    C("Darkweb drug vendor single-address settlement", ["threat intelligence", "risk list", "darkweb forum", "illegal activity", "public forum", "darknet", "extortion"],
      {"threat_list_hit": True, "osint_illegal": True}),
    C("Payroll-sized transfer to a low-history beneficiary wallet", ["low history", "beneficiary", "material transfer", "fresh wallet", "no history"],
      {"low_history_wallet": True, "amount": 5000}),
    C("PEP moving value through an unmonitored corridor", ["pep", "enhanced due diligence", "high-risk jurisdiction", "grey list", "geographic"],
      {"is_pep": True, "pep_activity_unusual": True, "counterparty_jurisdiction": "regulated"}),
    C("Cash-network card loadouts just under limits", ["crypto-to-plastic", "cash deposit", "round amount", "sub-threshold", "structuring"],
      {"cash_deposit_cards": True, "economic_rationale": "wages"}),
    C("Mixer-settled tranche to unhosted cold storage", ["mixer", "tumbler", "sanitisation", "unhosted wallet", "privacy coin", "self-custody"],
      {"uses_mixer": True}),
    C("Anonymised geo-jump from a sanctioned mirador", ["vpn", "tor", "geo mismatch", "anonymisation", "proxy", "sanctions", "freeze", "screening"],
      {"uses_vpn_tor": True, "counterparty_jurisdiction": "regulated"}),
    C("Fan-in consolidation of many small wallets", ["fan-in", "consolidation", "multiple senders", "clustering", "subset of individuals", "fresh wallet"],
      {"fan_in": True, "small_wallet_set": True}),
    C("Mule-ring rapid accumulation then off-boarding", ["accumulate", "off-board", "rapid accumulation", "new account", "withdrawal", "mule", "coached"],
      {"rapid_accumulation": True, "coached_mule": True}),
    C("Profile-mismatched flipper on a brand-new account", ["rapid deposit", "rapid withdrawal", "profile mismatch", "velocity", "behavioural", "spike"],
      {"new_account": True, "customer_profile_consistent": False}),
    C("Structured 24-hour cluster just below the line", ["structuring", "24-hour", "clustered", "high-value", "round amount"],
      {"below_threshold": True, "round_amount": True, "economic_rationale": "payroll"}),
    C("Unaware beneficiary of sanctioned extortion proceeds", ["extortion", "sanctions", "freeze", "screening", "darknet"],
      {"sanctioned_source": True}),
    C("No-rationale relocation to a grey-listed jurisdiction", ["unregulated jurisdiction", "relocation", "geographic", "offices relocation"],
      {"offices_relocation": True, "counterparty_jurisdiction": "regulated"}),
    C("Liveness-replay identity swap at onboarding", ["liveness", "deepfake", "impersonation", "onboarding", "changed email", "changed ip"],
      {"identity_markers": ["liveness_bypass"], "frequent_identity_change": True}),
    C("Cash-funded plastic top-ups round-tripping via VA", ["crypto-to-plastic", "cash deposit", "24-hour"],
      {"cash_deposit_cards": True, "rapid_withdrawal": True}),
    C("Darkweb vendor settlement with no paper trail", ["cross-border", "travel rule", "missing information", "public forum", "illegal activity", "darknet", "illegal goods"],
      {"osint_illegal": True, "memo_illicit": True}),
    C("Aggregator obfuscation on a VA/plastic loop", ["privacy coin", "token swap", "convertible", "obfuscation", "crypto-to-plastic"],
      {"crypto_to_plastic": True}),
    C("Geo-mismatched login through a sanctions hotspot", ["geo mismatch", "anonymisation", "proxy", "sanctions"],
      {"ip_geo_mismatch": True}),
    C("KYC-refusing bulk sender of structured value", ["incomplete kyc", "declines requests", "cdd", "evasive", "high-value", "sub-threshold"],
      {"kyc_complete": False, "high_value": True}),
    C("Wealth-mismatch financed by a hacked account", ["source of funds", "source of wealth", "inconsistent", "funding", "changes"],
      {"wealth_mismatch": True}),
    C("Frequent identity change laundering an unknown origin", ["changed credentials", "changed email", "identity", "ubo", "beneficial ownership"],
      {"changed_credentials": True}),
    C("Audit-trail-dodging hops through pass-through wallets", ["pass-through", "hop", "rapid", "audit trail", "velocity", "spike"],
      {"multi_hop": True}),
]


def main():
    rulebook = load_rulebook()
    engine = RuleEvaluationEngine()
    passed, failed = [], []
    for c in CANDIDATES:
        results = engine.evaluate(rulebook, c["fx"])
        fired = sorted({r.rule_id for r in results if r.fired})
        vocab = " ".join(c["tech"] + [c["name"]]).lower()
        relevant = [r for r in rulebook if _relevant(r, vocab)]
        evaded = [r.id for r in relevant if r.id not in fired]
        if not evaded:
            failed.append((c["name"], "no relevant rule evaded", [r.id for r in relevant]))
            continue
        if not fired:
            failed.append((c["name"], "nothing fired", []))
            continue
        passed.append((c, fired, evaded))

    passed = passed[:20]
    out = []
    for i, (c, fired, evaded) in enumerate(passed, 1):
        gid = f"GEN-{i:02d}"
        out.append({
            "id": gid,
            "name": c["name"],
            "description": c["desc"],
            "source": "Generation arm · AI capability-primitive synthesis (novel, unverified)",
            "techniques": c["tech"],
            "mitre_atlas": c["atlas"],
            "risk_severity": c["severity"],
            "expected_gap": evaded[0] if evaded else "",
            "test_fixtures": [{"tx": c["fx"]}],
        })

    os.makedirs(DATA, exist_ok=True)
    path = os.path.join(DATA, "generated_typologies.json")
    payload = {
        "version": "1.0",
        "source_notes": "20 generated (novel) typologies seeded from AI-fraud capability synthesis. "
                        "Each verified to fire >=1 rule and evade >=1 relevant rule in the demo engine.",
        "generated": [
            {"id": "GEN-01", "name": t["name"], "fired": len([]), "evaded_primary": t["expected_gap"]}
            for t in out
        ],
        "typologies": out,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    print(f"wrote {len(out)} generated typologies -> {path}")
    print(f"{len(failed)} candidates dropped:")
    for name, why, rel in failed:
        print(f"  - {name}: {why} (relevant: {', '.join(rel[:6])})")
    for t, fired, evaded in passed:
        print(f"  {t['name'][:52]:<54} fired {len(fired):>2} · evaded {len(evaded):>2} · {evaded[:3]}")


def _relevant(rule, vocab):
    if any(k in vocab for k in rule.keywords):
        return True
    for word in vocab.split():
        if word and word in rule.keywords:
            return True
    return False


if __name__ == "__main__":
    main()