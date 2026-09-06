"""Structured trigger schema for Drift Sentinel rules.

Each rule's firing condition lives in the `trigger_schema` field on `Rule`
(agents/models.py), as a small boolean tree, interpreted uniformly by
`evaluate_trigger()` below. This is the single source of truth for rule
firing logic: `agents/rule_engine.py` routes every rule through this
interpreter instead of a hardcoded per-rule Python predicate, so
data/rulebook.json is the only place a trigger condition is defined.

Grammar
-------
A node is either a combinator or a leaf comparison.

Combinators (children are themselves nodes):
    {"all": [node, ...]}   -> True iff every child is True   (AND)
    {"any": [node, ...]}   -> True iff at least one child is True (OR)
    {"not": node}          -> True iff the child is False

Leaf comparison:
    {"field": <fixture key>, "op": <op>, "value": <literal>, ...}

    field    key looked up in the (already-unwrapped) fixture dict via
             fx.get(field), or fx.get(field, default) when "default" is set.
    op       one of:
               eq      actual == value
               ne      actual != value
               gte     actual >= value            (actual is None -> False)
               lte     actual <= value             (actual is None -> False)
               exists  field is present in fx AND its value is not None
               truthy  bool(actual) is True (Python truthiness - matches the
                       historical `if fx.get(k)` style checks this schema
                       replaces)
               in      set-membership, direction-agnostic:
                         - if `actual` is a list/tuple/set: True iff it
                           intersects `value` (a scalar `value` is treated
                           as a single-item list)
                         - otherwise: True iff `actual` is in `value`
                       pass "ci": true to case-fold string comparisons
                       (used for free-text lists such as identity_markers
                       and tools; omit it for exact-match fields such as
                       jurisdiction codes).
    value    required for eq/ne/gte/lte/in; ignored for exists/truthy.
    default  optional fx.get(field, default) fallback, for gte/lte checks
             against a field that may be absent from the fixture.

Example (DS-22 - PEP relationship with unusual activity, both required):
    {"all": [
        {"field": "is_pep", "op": "truthy"},
        {"field": "pep_activity_unusual", "op": "truthy"}
    ]}

Fixtures may be flat dicts or wrapped as {"tx": {...}}; the caller
(RuleEvaluationEngine.evaluate) unwraps that before handing fixtures to
evaluate_trigger, so this module only ever sees a flat dict.

rule_type: indicator vs. obligation
------------------------------------
`Rule.rule_type` (agents/models.py) is "indicator", "obligation", or
"mixed". It does not change how a trigger_schema tree is *evaluated* -
evaluate_trigger() has no notion of rule_type and never will; a rule fires
whenever its tree evaluates True, full stop. What rule_type changes is how
the tree must be *authored*:

  - indicator: the tree encodes the suspicious pattern directly. It fires
    when that pattern is present in the fixture (e.g. DS-01: new account +
    inconsistent profile + rapid withdrawal, all truthy).

  - obligation: the tree must encode the BREACH of the requirement, not the
    requirement itself. A CASP obligation ("must transmit X before the
    transfer") has no natural indicator-shaped reading - there is no
    "suspicious pattern" to look for, only a compliance failure to detect.
    The correct encoding is: (transfer qualifies for the obligation) AND
    NOT (required action was taken). See DS-03: {"all": [qualifying_
    transfer truthy, not(travel_rule_info_transmitted truthy)]} - it fires
    exactly when a qualifying transfer happened without the required
    disclosure, and stays quiet when the disclosure was made. Do not
    contort this into a positive-pattern leaf; if the cleanest expression
    of an obligation's breach condition is "required_field is false or
    missing", write exactly that (an `eq`/`not`/`truthy` leaf) rather than
    inventing an artificial "indicator" framing for it.

  - mixed: a rule with both a genuine indicator half and a genuine
    obligation half. Encode the half that's actually in trigger_schema and
    say in `text` which half is covered and which isn't - do not average
    the two into a single tree that represents neither correctly.

This is a documentation-only distinction here; RULE_TYPES/validate_rule_type
below only check that the label itself is one of the recognised values.
"""
from __future__ import annotations

from typing import Any

Node = dict
Fixture = dict

_LEAF_OPS = {"eq", "ne", "gte", "lte", "exists", "truthy", "in"}
_VALUE_REQUIRED_OPS = {"eq", "ne", "gte", "lte", "in"}
_COMBINATORS = {"all", "any", "not"}

RULE_TYPES = {"indicator", "obligation", "mixed"}


def validate_rule_type(rule_type: str) -> list[str]:
    """Check a Rule.rule_type label is one of the recognised values."""
    if rule_type not in RULE_TYPES:
        return [f"rule_type {rule_type!r} is not one of {sorted(RULE_TYPES)}"]
    return []


class TriggerSchemaError(ValueError):
    """A trigger_schema tree is structurally invalid and cannot be interpreted."""


def _as_list(value: Any) -> list:
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _fold(value: Any, ci: bool) -> Any:
    return value.lower() if ci and isinstance(value, str) else value


def _eval_leaf(node: Node, fx: Fixture) -> bool:
    field = node["field"]
    op = node["op"]
    actual = fx.get(field, node["default"]) if "default" in node else fx.get(field)

    if op == "truthy":
        return bool(actual)
    if op == "exists":
        return field in fx and fx.get(field) is not None
    if op == "eq":
        return actual == node.get("value")
    if op == "ne":
        return actual != node.get("value")
    if op == "gte":
        return actual is not None and actual >= node.get("value")
    if op == "lte":
        return actual is not None and actual <= node.get("value")
    if op == "in":
        ci = bool(node.get("ci"))
        targets = {_fold(v, ci) for v in _as_list(node.get("value"))}
        if isinstance(actual, (list, tuple, set)):
            return bool({_fold(v, ci) for v in actual} & targets)
        return _fold(actual, ci) in targets
    raise TriggerSchemaError(f"unknown leaf op {op!r}")


def evaluate_trigger(node: Node, fx: Fixture) -> bool:
    """Walk a trigger_schema tree against a flat fixture dict."""
    if not isinstance(node, dict) or not node:
        raise TriggerSchemaError(f"trigger_schema node must be a non-empty object, got {node!r}")
    if "all" in node:
        return all(evaluate_trigger(c, fx) for c in node["all"])
    if "any" in node:
        return any(evaluate_trigger(c, fx) for c in node["any"])
    if "not" in node:
        return not evaluate_trigger(node["not"], fx)
    if "field" in node and "op" in node:
        return _eval_leaf(node, fx)
    raise TriggerSchemaError(f"unrecognised trigger_schema node: {node!r}")


def validate_trigger_schema(node: Node, *, _path: str = "$") -> list[str]:
    """Structurally validate a trigger_schema tree.

    Returns a list of human-readable error strings (empty == valid). This is
    a static check of shape only - it does not evaluate the tree - but it
    guarantees evaluate_trigger() will not raise TriggerSchemaError for
    anything that passes.
    """
    if not isinstance(node, dict) or not node:
        return [f"{_path}: node must be a non-empty object"]

    present_combinators = [k for k in _COMBINATORS if k in node]
    is_leaf_shaped = "field" in node or "op" in node

    if present_combinators and is_leaf_shaped:
        return [f"{_path}: node mixes combinator {present_combinators[0]!r} with leaf keys"]
    if len(present_combinators) > 1:
        return [f"{_path}: node has more than one combinator key {present_combinators!r}"]

    if "all" in node or "any" in node:
        key = "all" if "all" in node else "any"
        children = node[key]
        if not isinstance(children, list) or not children:
            return [f"{_path}.{key}: must be a non-empty list of nodes"]
        errors: list[str] = []
        for idx, child in enumerate(children):
            errors += validate_trigger_schema(child, _path=f"{_path}.{key}[{idx}]")
        return errors

    if "not" in node:
        return validate_trigger_schema(node["not"], _path=f"{_path}.not")

    if not is_leaf_shaped:
        return [f"{_path}: not a recognised combinator ({sorted(_COMBINATORS)}) or leaf ('field'/'op')"]

    errors = []
    field = node.get("field")
    if not isinstance(field, str) or not field:
        errors.append(f"{_path}: leaf missing a non-empty string 'field'")
    op = node.get("op")
    if op not in _LEAF_OPS:
        errors.append(f"{_path}: leaf op {op!r} is not one of {sorted(_LEAF_OPS)}")
    elif op in _VALUE_REQUIRED_OPS and "value" not in node:
        errors.append(f"{_path}: op {op!r} requires a 'value'")
    return errors
