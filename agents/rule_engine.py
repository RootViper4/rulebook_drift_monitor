from __future__ import annotations

from typing import Callable, Optional

from agents.models import Rule, RuleResult, TestCase


Fixture = dict


class RuleEvaluationEngine:
    """Deterministic rule-evaluation engine (Drift Sentinel).

    Each DS rule carries an explicit trigger predicate expressed against the
    structured transaction fixture. A rule fires ONLY when its exact trigger is
    satisfied, giving a precise, auditable fired/evaded set - independent of
    LLM output. This is the reliability core of the platform.

    Fixtures may be flat dicts or wrapped as {"tx": {...}}; both are supported.
    """

    # rule_id -> predicate(fx) -> bool
    _PREDICATES: dict[str, Callable[[Fixture], bool]] = {}

    # Shared field derivations -------------------------------------------------
    @staticmethod
    def _markers(fx: Fixture) -> list[str]:
        return [str(m).lower() for m in (fx.get("identity_markers") or [])]

    @staticmethod
    def _tools(fx: Fixture) -> list[str]:
        return [str(k).lower() for k in (fx.get("tools") or [])]

    @staticmethod
    def _jur(fx: Fixture) -> Optional[str]:
        return fx.get("counterparty_jurisdiction")

    @staticmethod
    def _is(fx: Fixture, key: str) -> bool:
        return bool(fx.get(key))

    def __init__(self) -> None:
        if self._PREDICATES:
            return
        m = lambda k: self._markers(k)  # noqa: E731
        t = lambda k: self._tools(k)    # noqa: E731
        j = lambda k: self._jur(k)      # noqa: E731
        i = lambda k, key: self._is(k, key)  # noqa: E731
        P = self._PREDICATES

        def any_marker(fx, vals):
            return any(x in m(fx) for x in vals)

        # --- Onboarding / KYC ---
        P["DS-01"] = lambda fx: (i(fx, "new_account") or i(fx, "fresh_onboarding")) \
            and fx.get("customer_profile_consistent") is False or i(fx, "rapid_withdrawal")
        P["DS-09"] = lambda fx: any_marker(fx, ["forged", "deepfake_media", "edited", "liveness_bypass"])
        P["DS-28"] = lambda fx: i(fx, "rapid_accumulation") or (i(fx, "new_account") and i(fx, "rapid_withdrawal"))
        P["DS-39"] = lambda fx: i(fx, "ai_orchestrated_onboarding") or (
            i(fx, "fresh_onboarding") and any_marker(fx, ["synthetic", "deepfake_media"]))

        # --- Structuring / pattern ---
        P["DS-02"] = lambda fx: i(fx, "below_threshold") or i(fx, "round_amount") \
            or (fx.get("economic_rationale") == "structuring")
        P["DS-17"] = lambda fx: i(fx, "crypto_to_plastic") or i(fx, "cash_deposit_cards")
        P["DS-30"] = lambda fx: i(fx, "velocity") or (i(fx, "high_value") and i(fx, "quick_succession"))
        P["DS-38"] = lambda fx: (i(fx, "round_amount") or i(fx, "below_threshold")) \
            and not fx.get("economic_rationale")

        # --- Travel Rule ---
        P["DS-03"] = lambda fx: i(fx, "travel_rule_missing") or i(fx, "missing_orig_benef")
        P["DS-34"] = lambda fx: (i(fx, "travel_rule_missing") or i(fx, "missing_orig_benef")) \
            and fx.get("cross_border")

        # --- Counterparty / wallet ---
        P["DS-04"] = lambda fx: i(fx, "weak_counterparty") or i(fx, "unhosted_wallet")
        P["DS-26"] = lambda fx: i(fx, "unhosted_wallet") or i(fx, "self_custody")
        P["DS-31"] = lambda fx: i(fx, "threat_list_hit") or i(fx, "criminal_source")
        P["DS-35"] = lambda fx: i(fx, "low_history_wallet") and fx.get("amount", 0) >= 1000

        # --- Layering / behaviour ---
        P["DS-05"] = lambda fx: i(fx, "fan_in") or (i(fx, "multiple_accounts") and i(fx, "consolidated"))
        P["DS-15"] = lambda fx: i(fx, "clustering") or i(fx, "small_wallet_set")
        P["DS-23"] = lambda fx: i(fx, "pass_through") or i(fx, "multi_hop")

        # --- Identity & CDD ---
        P["DS-06"] = lambda fx: i(fx, "shared_credentials")
        P["DS-07"] = lambda fx: fx.get("kyc_complete") is False or i(fx, "unwilling_identity")
        P["DS-08"] = lambda fx: i(fx, "lacks_transaction_knowledge")
        P["DS-13"] = lambda fx: i(fx, "frequent_identity_change") or i(fx, "changed_credentials")
        P["DS-33"] = lambda fx: i(fx, "evasive_cdd") or i(fx, "unwilling_identity")
        P["DS-36"] = lambda fx: i(fx, "unverified_ubo") or i(fx, "ubo_not_established")

        # --- Profile / sender-recipient / mule ---
        P["DS-10"] = lambda fx: i(fx, "osint_illegal")
        P["DS-11"] = lambda fx: i(fx, "criminal_association")
        P["DS-12"] = lambda fx: i(fx, "crypto_naive")
        P["DS-14"] = lambda fx: i(fx, "memo_illicit")
        P["DS-40"] = lambda fx: i(fx, "coached_mule")

        # --- Source of funds ---
        P["DS-16"] = lambda fx: i(fx, "stolen_card") or i(fx, "criminal_source") or i(fx, "sanctioned_source")
        P["DS-18"] = lambda fx: i(fx, "uses_mixer") or i(fx, "tumbler") or ("mixer" in t(fx))
        P["DS-27"] = lambda fx: i(fx, "source_inconsistent") or i(fx, "wealth_mismatch")
        P["DS-29"] = lambda fx: i(fx, "frequent_funding_change")

        # --- Geographic ---
        P["DS-19"] = lambda fx: i(fx, "unregistered_exchange")
        P["DS-20"] = lambda fx: i(fx, "unregulated_jurisdiction") or i(fx, "offices_relocation")
        P["DS-37"] = lambda fx: j(fx) in ("high_risk", "grey_list", "sanctioned")

        # --- Sanctions ---
        P["DS-21"] = lambda fx: j(fx) == "sanctioned" or i(fx, "sanctions_match")

        # --- Technology / anonymity ---
        P["DS-24"] = lambda fx: i(fx, "uses_vpn_tor") or i(fx, "ip_geo_mismatch")
        P["DS-25"] = lambda fx: i(fx, "fresh_wallet") \
            and (fx.get("wallet_age_days") is not None and fx.get("wallet_age_days", 999) <= 3)
        P["DS-32"] = lambda fx: i(fx, "privacy_coin") or i(fx, "token_swap")

        # --- PEP ---
        P["DS-22"] = lambda fx: i(fx, "is_pep") and i(fx, "pep_activity_unusual")

    def register(self, rule: Rule) -> None:
        """Register a predicate for a dynamically-instituted rule.

        Institutionalised rules carry a `signal_signature`: the exact set of
        (field, value) pairs that characterise the approved typology's
        behavioural signature. The predicate fires when every pair is present
        in the fixture under test - a precise, auditable dedicated indicator.
        No-op if the rule id already has a predicate.
        """
        rule_id = rule.id
        if rule_id in self._PREDICATES:
            return
        sig = dict(rule.signal_signature or {})
        if not sig:
            return

        def pred(fx: Fixture, _sig=sig):
            return all(fx.get(k) == v for k, v in _sig.items())

        self._PREDICATES[rule_id] = pred

    def evaluate(self, rulebook: list[Rule], fixture: dict) -> list[RuleResult]:
        results: list[RuleResult] = []
        fx = fixture.get("tx", fixture) if isinstance(fixture, dict) else fixture
        for rule in rulebook:
            results.append(self._eval_rule(rule, fx))
        return results

    def _eval_rule(self, rule: Rule, fx: Fixture) -> RuleResult:
        r = RuleResult(rule_id=rule.id)
        pred = self._PREDICATES.get(rule.id)
        if pred is None:
            # Rules without an explicit trigger never fire (safe default).
            r.confidence = 0.1
            return r
        try:
            fired = bool(pred(fx))
        except Exception:
            fired = False
        r.fired = fired
        r.confidence = 0.9 if fired else 0.1
        r.rationale = ("trigger matched: " + rule.trigger) if fired else "trigger not matched"
        r.evaded = not fired
        return r

    def find_gaps(self, rulebook: list[Rule], fixture: dict) -> list[Rule]:
        """A gap is a relevant rule that should logically have fired given the
        fixture but did not - i.e. the typology's operational reality evades it."""
        results = self.evaluate(rulebook, fixture)
        fired = {r.rule_id for r in results if r.fired}
        return [r for r in rulebook if r.id not in fired]