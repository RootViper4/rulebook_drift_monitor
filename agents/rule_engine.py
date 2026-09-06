from __future__ import annotations

from agents.models import Rule, RuleResult
from agents.trigger_schema import TriggerSchemaError, evaluate_trigger

Fixture = dict


class RuleEvaluationEngine:
    """Deterministic rule-evaluation engine (Drift Sentinel).

    Every DS rule carries an explicit `trigger_schema` (see
    agents/trigger_schema.py for the grammar) expressed against the
    structured transaction fixture. A rule fires ONLY when its exact trigger
    tree is satisfied, giving a precise, auditable fired/evaded set -
    independent of LLM output. This is the reliability core of the platform.

    There is no hardcoded per-rule predicate table: data/rulebook.json's
    `trigger_schema` field is the single source of truth, interpreted
    uniformly by `evaluate_trigger()`.

    Fixtures may be flat dicts or wrapped as {"tx": {...}}; both are supported.
    """

    def register(self, rule: Rule) -> None:
        """Compile a `signal_signature` into a trigger_schema for a
        dynamically-instituted rule that doesn't carry one yet.

        Institutionalised rules carry a `signal_signature`: the exact set of
        (field, value) pairs that characterise the approved typology's
        behavioural signature. This compiles that into an
        {"all": [{"field": k, "op": "eq", "value": v}, ...]} tree, so it
        fires through the same interpreter as every other rule. No-op if the
        rule already has a trigger_schema.
        """
        if rule.trigger_schema:
            return
        sig = dict(rule.signal_signature or {})
        if not sig:
            return
        rule.trigger_schema = {
            "all": [{"field": k, "op": "eq", "value": v} for k, v in sorted(sig.items())]
        }

    def evaluate(self, rulebook: list[Rule], fixture: dict) -> list[RuleResult]:
        results: list[RuleResult] = []
        fx = fixture.get("tx", fixture) if isinstance(fixture, dict) else fixture
        for rule in rulebook:
            results.append(self._eval_rule(rule, fx))
        return results

    def _eval_rule(self, rule: Rule, fx: Fixture) -> RuleResult:
        r = RuleResult(rule_id=rule.id)
        node = rule.trigger_schema
        if not node:
            # No interpretable trigger. Loaders (agents/loader.py) reject
            # this for the base rulebook at load time; this is a defensive
            # fallback only, e.g. an instituted rule evaluated before
            # register() has compiled its signal_signature.
            r.confidence = 0.1
            r.rationale = "no structured trigger_schema - treated as never firing"
            return r
        try:
            fired = evaluate_trigger(node, fx)
        except TriggerSchemaError as exc:
            r.confidence = 0.1
            r.rationale = f"trigger_schema could not be interpreted: {exc}"
            return r
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
