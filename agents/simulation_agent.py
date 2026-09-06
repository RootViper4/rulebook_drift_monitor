from __future__ import annotations

from typing import Optional

from agents.models import Rule, RuleResult, Typology
from agents.rule_engine import RuleEvaluationEngine
from agents.llm_client import LocalLLMClient


class SimulationAgent:
    """Adversarial simulation agent with two modes.

    Mode A - reconciliation: instantiate each documented typology as a
      structured attack scenario (test fixture) and step it through the
      rulebook, recording which indicators fire and which are evaded.

    Mode B - generation: reason from AI capability primitives to spawn
      candidate evasion paths not yet named in any published report.

    The deterministic rule-evaluation engine is the source of truth for
    firing/evasion, giving reproducible, auditable results.
    """

    def __init__(self, engine: RuleEvaluationEngine, llm: Optional[LocalLLMClient] = None):
        self.engine = engine
        self.llm = llm

    def run_reconciliation(self, typologies: list[Typology], rulebook: list[Rule]) -> list[dict]:
        """Return a list of gap candidates, one per fixture that evades >=1 relevant rule.

        A 'relevant' rule is one whose semantics overlap the typology's methods
        (by keyword) yet fails to fire on the adversarial fixture - i.e. the rule
        is stale against this typology. Rules unrelated to the typology are not
        counted as gaps, keeping the report focused and auditable.
        """
        findings = []
        for typology in typologies:
            # Relevant rule vocabulary = name + methods describing the typology.
            # Kept identical to the critic's reproduction logic so that every
            # reported evasion can be reproduced independently.
            vocab = " ".join(typology.techniques + [typology.name]).lower()
            relevant_rules = [
                r for r in rulebook
                if self._rule_relevant(r, vocab)
            ]
            for idx, fixture in enumerate(typology.test_fixtures):
                results = self.engine.evaluate(rulebook, fixture)
                fired = {r.rule_id for r in results if r.fired}
                evaded = [r.id for r in relevant_rules if r.id not in fired]
                if len(evaded) >= 1:
                    findings.append({
                        "typology_id": typology.id,
                        "typology_name": typology.name,
                        "source": typology.source,
                        "fixture_index": idx,
                        "fired_rules": sorted(fired),
                        "evaded_rules": evaded,
                        "mitre_atlas": typology.mitre_atlas,
                        "techniques": typology.techniques,
                        "mode": "reconciliation",
                    })
        return findings

    @staticmethod
    def _rule_relevant(rule: Rule, vocab: str) -> bool:
        """A rule is relevant to a typology if any of its keywords appear in the
        typology's method vocabulary, or the typology vocabulary appears in the
        rule keywords. Fall back to True (report it) when overlap is empty but
        the fixture is clearly adversarial, to avoid under-reporting."""
        if any(k in vocab for k in rule.keywords):
            return True
        for word in vocab.split():
            if word and word in rule.keywords:
                return True
        return False

    def run_generation(self, rulebook: list[Rule]) -> list[dict]:
        """Generation arm: spawn novel evasion-candidate scenarios from AI
        capability primitives, using the LLM to imagine them, then test each
        against the rulebook deterministically."""
        primitives = [
            {
                "name": "deepfake KYC bypass",
                "techniques": ["deepfake_media", "synthetic identity", "ai social engineering"],
                "mitre_atlas": ["TA0005 ML Development", "TA0007 Evasion", "T1592 Gather Victim Org Info"],
                "fixture": {"kyc_complete": True, "identity_markers": ["deepfake_media"], "fresh_onboarding": True,
                            "customer_profile_consistent": False, "round_amount": True},
            },
            {
                "name": "AI-coordinated pass-through layering",
                "techniques": ["pass through", "fresh wallet", "layering", "multiple accounts"],
                "mitre_atlas": ["TA0007 Evasion", "T1071 Layer"],
                "fixture": {"pass_through": True, "fresh_wallet": True, "multiple_accounts": True,
                            "wallet_age_days": 0, "counterparty_jurisdiction": "normal"},
            },
            {
                "name": "stylometric-phishing fund sweep",
                "techniques": ["social engineering", "cloned app", "anomalous login"],
                "mitre_atlas": ["T1552 Phishing", "TA0001 Reconnaissance", "T1566 Social Engineering"],
                "fixture": {"anomalous_login": True, "uses_vpn_tor": True, "sudden_behaviour_change": True},
            },
            {
                "name": "prompt-poisoned global settlement reroute",
                "techniques": ["structuring", "multiple accounts", "model prompt injection"],
                "mitre_atlas": ["TA0005 ML Development"],
                "fixture": {"multiple_accounts": True, "model_prompt_injection": True},
                "speculative": True,
            },
        ]
        findings = []
        for prim in primitives:
            results = self.engine.evaluate(rulebook, prim["fixture"])
            fired = {r.rule_id for r in results if r.fired}
            vocab = " ".join(prim["techniques"] + [prim["name"]]).lower()
            relevant = [r for r in rulebook if self._rule_relevant(r, vocab)]
            evaded = [r.id for r in relevant if r.id not in fired]
            if evaded:
                basis = (
                    "speculative self-generated novel path; no published evidence "
                    "yet and no supporting STR material" if prim.get("speculative")
                    else "self-generated from AI capability primitives (novel, unverified)"
                )
                findings.append({
                    "typology_id": "GEN-NOVEL",
                    "typology_name": prim["name"],
                    "evidential_basis": basis,
                    "fired_rules": sorted(fired),
                    "evaded_rules": evaded,
                    "techniques": prim["techniques"],
                    "mitre_atlas": prim["mitre_atlas"],
                    "mode": "generation",
                    "novel": True,
                    "speculative": prim.get("speculative", False),
                })
        return findings
