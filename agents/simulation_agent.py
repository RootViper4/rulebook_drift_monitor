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

    def run_capability_primitive_reconciliation(self, rulebook: list[Rule], fixtures_path: str) -> list[dict]:
        """Reconciliation arm, capability-primitive edition - the 'Known Attacks'
        tab's data source.

        Steps each of the documented AI-capability-primitive attack fixtures
        (data/fixtures.capability_primitives.json) through the rulebook, one
        finding per primitive (its fixture(s) aggregated by union of fired
        rules), recording which rules fire and which topically-relevant rules
        stay silent. Primitives explicitly marked as non-control-surfaces
        (upstream aggravating factors with no detection point of their own -
        CP-09 reconnaissance, CP-10 dark-LLM tooling) are skipped: they are not
        attacks a rule could ever catch, so they are not reportable gaps.

        Unlike `run_reconciliation` (kept below, untouched, for the legacy
        typology corpus), every remaining primitive is reported regardless of
        whether any rule fired - a primitive with zero relevant rules at all
        (e.g. CP-02 vishing) is exactly the kind of drift gap this tab exists
        to surface, not a candidate to filter out.
        """
        from agents.loader import load_fixture_set

        not_a_control_surface = {"CP-09", "CP-10"}
        fixtures = load_fixture_set(fixtures_path)
        by_primitive: dict[str, list[dict]] = {}
        for fx in fixtures:
            for cp in (fx.get("capability_primitives") or []):
                if cp in not_a_control_surface:
                    continue
                by_primitive.setdefault(cp, []).append(fx)

        findings = []
        for cp in sorted(by_primitive):
            fxs = by_primitive[cp]
            fired: set[str] = set()
            vocab_parts = [cp]
            notes = []
            for fx in fxs:
                results = self.engine.evaluate(rulebook, fx["tx"])
                fired |= {r.rule_id for r in results if r.fired}
                if fx.get("label"):
                    vocab_parts.append(fx["label"])
                if fx.get("representation_note"):
                    vocab_parts.append(fx["representation_note"])
                    notes.append(fx["representation_note"])
            vocab = " ".join(vocab_parts).lower()
            relevant = [r for r in rulebook if self._rule_relevant(r, vocab)]
            evaded = sorted(r.id for r in relevant if r.id not in fired)

            raw_label = fxs[0].get("label", cp)
            desc = raw_label.split(":", 1)[1].strip() if ":" in raw_label else raw_label
            short_name = desc.split(",")[0].split(";")[0].strip()

            findings.append({
                "typology_id": cp,
                "typology_name": short_name,
                "evidential_basis": desc,
                "fired_rules": sorted(fired),
                "evaded_rules": evaded,
                "techniques": vocab_parts,
                "mitre_atlas": [],
                "fixtures": [fx["tx"] for fx in fxs],
                "mode": "reconciliation",
            })
        return findings

    def run_generation(self, rulebook: list[Rule]) -> list[dict]:
        """Generation arm: spawn novel evasion-candidate scenarios from AI
        capability primitives, using the LLM to imagine them, then test each
        against the rulebook deterministically."""
        # NOTE: these fixtures/keyword sets are written against the CURRENT
        # 20-rule real corpus (data/rulebook.json's fixture field names and
        # keywords) - not the legacy 40-rule placeholder set. They describe
        # genuinely novel patterns not among the 12 documented capability
        # primitives (data/fixtures.capability_primitives.json), which is
        # what makes this the "invent something unrecorded" arm rather than a
        # restatement of Known Attacks.
        primitives = [
            {
                "name": "AI-negotiated OTC settlement structuring",
                "techniques": ["unregistered exchange", "structuring", "ai negotiation", "otc settlement"],
                "mitre_atlas": ["TA0007 Evasion", "T1071 Layer"],
                "fixture": {},
            },
            {
                "name": "Deepfake board-resolution corporate onboarding",
                "techniques": ["forged documents", "identity fraud", "corporate onboarding", "deepfake board resolution"],
                "mitre_atlas": ["TA0005 ML Development", "T1592 Gather Victim Org Info"],
                "fixture": {},
            },
            {
                "name": "AI-scripted multi-hop settlement evading travel-rule disclosure",
                "techniques": ["travel rule", "originator", "beneficiary", "cross-border", "ai-scripted multi-hop settlement"],
                "mitre_atlas": ["TA0007 Evasion"],
                "fixture": {},
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
        for idx, prim in enumerate(primitives, 1):
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
                    # Unique per candidate - these previously all shared the
                    # literal id "GEN-NOVEL", which silently collapsed every
                    # generation-arm novelty onto one review-list entry.
                    "typology_id": f"GEN-{idx:02d}",
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
