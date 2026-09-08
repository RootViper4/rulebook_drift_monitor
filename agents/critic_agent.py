from __future__ import annotations

from typing import Optional

from agents.models import Rule
from agents.rule_engine import RuleEvaluationEngine
from agents.simulation_agent import SimulationAgent
from agents.llm_client import LocalLLMClient


class CriticAgent:
    """Independent critic / verifier.

    Separated from the generator so that no agent marks its own work. Re-tests
    every claimed gap with the deterministic engine and discards findings it
    cannot reproduce or judges implausible (e.g. a typology that fires no rule
    but is not genuinely adversarial, or a generation-arm novelty with no
    evidential basis)."""

    def __init__(self, engine: RuleEvaluationEngine, llm: Optional[LocalLLMClient] = None):
        self.engine = engine
        self.llm = llm

    def verify(self, candidate: dict, rulebook: list[Rule],
               fixtures_by_typology: Optional[dict[str, list[dict]]] = None,
               known_gaps: Optional[list[str]] = None) -> dict:
        """Return the candidate with verified/plausible flags set, or mark it discarded."""
        result = dict(candidate)
        known_gaps = known_gaps or []

        # Reproducibility: re-run the deterministic engine on the same fixture(s).
        #
        # FIXED: this used to only apply to mode == "reconciliation". Every
        # mode == "generation" candidate skipped reproduction entirely and
        # kept the default reproduced = True, meaning the generation arm's
        # findings were accepted purely on the plausibility check below - the
        # opposite of "the critic re-tests every claim". Generation
        # candidates now carry an inline "fixture" (see
        # agents/simulation_agent.py::run_generation) and are re-run exactly
        # like reconciliation candidates.
        reproduced = True
        if candidate.get("mode") == "reconciliation":
            # Capability-primitive reconciliation candidates carry their own
            # fixture(s) inline (no per-typology test_fixtures lookup needed -
            # there is no typology behind a CP-XX id).
            inline_fixtures = candidate.get("fixtures")
            if inline_fixtures:
                fired: set[str] = set()
                for fx in inline_fixtures:
                    results = self.engine.evaluate(rulebook, fx)
                    fired |= {r.rule_id for r in results if r.fired}
            else:
                fixture = self._get_fixture(candidate, fixtures_by_typology)
                if fixture is None:
                    return self._discard(result, "no fixture available to re-run")
                results = self.engine.evaluate(rulebook, fixture)
                fired = {r.rule_id for r in results if r.fired}
            # Recompute the expected evasion set (relevant rules that don't fire),
            # using the same independence-preserving logic as the reporter.
            vocab = " ".join(
                candidate.get("techniques", []) + [candidate.get("typology_name", "")]
            ).lower()
            relevant = [r for r in rulebook if SimulationAgent._rule_relevant(r, vocab)]
            evaded = set(r.id for r in relevant if r.id not in fired)
            reproduced = set(candidate.get("evaded_rules", [])) <= evaded

        elif candidate.get("mode") == "generation":
            fixture = candidate.get("fixture")
            if fixture is None:
                return self._discard(result, "no fixture available to re-run")
            results = self.engine.evaluate(rulebook, fixture)
            fired = {r.rule_id for r in results if r.fired}
            vocab = " ".join(
                candidate.get("techniques", []) + [candidate.get("typology_name", "")]
            ).lower()
            relevant = [r for r in rulebook if SimulationAgent._rule_relevant(r, vocab)]
            evaded = set(r.id for r in relevant if r.id not in fired)
            reproduced = set(candidate.get("evaded_rules", [])) <= evaded

        # Plausibility: generation-arm novelties must carry an evidential basis,
        # and purely speculative paths with no published/STR support are rejected.
        plausible = True
        if candidate.get("mode") == "generation":
            if not candidate.get("evidential_basis"):
                plausible = False
            if candidate.get("speculative"):
                result["evidential_basis"] = (
                    "rejected by critic: speculative self-generated path with no "
                    "supporting published evidence or STR material"
                )
                plausible = False

        # Known-gap back-test: if this was a seeded/historical gap, that is a plus.
        backtest_match = any(g in (candidate.get("typology_id") or "") for g in known_gaps)

        result["reproduced"] = reproduced
        result["plausible"] = plausible
        result["backtest_match"] = backtest_match
        result["verified"] = reproduced and plausible
        if not result["verified"]:
            result["status"] = "discarded"
            result["fully_verified"] = False
        else:
            # A generation candidate can be reproducible and plausible while
            # still referencing field(s) the rulebook has never heard of
            # (SimulationAgent._sanitize_scenario keeps these separately as
            # unmodeled_fields rather than rejecting the whole candidate -
            # see agents/simulation_agent.py). That's a genuine coverage
            # idea, not nothing, but it must not read to the analyst as an
            # equally-solid finding as one where every field was tested
            # against the real rulebook. Downgrade rather than discard: it
            # still reaches the human gate, just visibly marked.
            unmodeled_fields = candidate.get("unmodeled_fields") or []
            if unmodeled_fields:
                result["status"] = "confirmed_partial_coverage"
                result["fully_verified"] = False
            else:
                result["status"] = "confirmed"
                result["fully_verified"] = True
        return result

    def _get_fixture(self, candidate: dict, fixtures_by_typology: Optional[dict[str, list[dict]]]) -> Optional[dict]:
        if not fixtures_by_typology:
            return None
        fixtures = fixtures_by_typology.get(candidate.get("typology_id"))
        if not fixtures:
            return None
        idx = candidate.get("fixture_index", 0)
        return fixtures[idx] if idx < len(fixtures) else fixtures[-1]

    def _discard(self, result: dict, reason: str) -> dict:
        result["reproduced"] = False
        result["plausible"] = False
        result["verified"] = False
        result["fully_verified"] = False
        result["status"] = "discarded"
        result["evidential_basis"] = result.get("evidential_basis") or reason
        return result