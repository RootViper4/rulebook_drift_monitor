from __future__ import annotations

import difflib
import json
import re
from typing import Any, Optional

from agents.models import Rule, RuleResult, Typology
from agents.rule_engine import RuleEvaluationEngine
from agents.llm_client import LocalLLMClient

# Compact grounding summary of the capability-primitives library (CP-01..10),
# drawn from Capability-Primitives_Library_AI-Fraud_Tactics.docx. If that
# document changes, update this constant to match - it is the only grounding
# the LLM gets for what an "AI capability primitive" is, so drift here means
# the model reasons from a stale library.
CP_LIBRARY_SUMMARY = [
    ("CP-01", "Real-time deepfake video/face-swap defeating liveness checks at onboarding"),
    ("CP-02", "Real-time voice cloning for vishing / staff impersonation"),
    ("CP-03", "AI-generated synthetic identity documents (passports, IDs, proof-of-address)"),
    ("CP-04", "Photo enhancement / stolen-identity reanimation for background checks"),
    ("CP-05", "Automated multi-language victim engagement at scale (LLM-run scam conversations)"),
    ("CP-06", "AI-generated institutional impersonation content (fake bank/exchange messages)"),
    ("CP-07", "AI-generated replica platforms (fake exchange apps/websites)"),
    ("CP-08", "Synthetic-identity reuse to reopen/unfreeze a previously flagged account"),
    ("CP-09", "AI-assisted reconnaissance and victim targeting (not a control surface itself)"),
    ("CP-10", "Commoditised dark-LLM tooling (FraudGPT/WormGPT-class) lowering skill barriers"),
]
_KNOWN_CP_IDS = {cp_id for cp_id, _ in CP_LIBRARY_SUMMARY}

GENERATION_ARM_TARGET_COUNT = 3  # how many novel scenarios per run
GENERATION_ARM_ATTEMPTS_PER_SLOT = 2  # LLM attempts before falling back for THAT slot only
_ALLOWED_FIXTURE_VALUE_TYPES = (bool, int, float, str)

# The exact placeholder(s) shown in the prompt's JSON template, across both
# prompt versions used so far. A model that copies the template instead of
# generating a real fixture returns keys that match one of these sets
# exactly - not a real evasion pattern in any rulebook, so a reliable tell
# the model didn't do the task. Confirmed happening in practice TWICE on a
# local 1B model: {"field_name": true, "other_field": false} on 2026-09-07
# (first prompt version), then {"field_a": true, "field_b": true} again on
# 2026-09-07 after the prompt's example placeholder names were changed but
# this constant wasn't updated to match - the exact-match check is fragile
# to future prompt wording changes, which is why _PLACEHOLDER_FIELD_PATTERN
# below adds a general pattern check as a second line of defence.
_PLACEHOLDER_FIXTURE_KEYS = {"field_name", "other_field"}
_PLACEHOLDER_FIXTURE_KEYS_ALT = {"field_a", "field_b"}
# General fallback: reject a fixture whose keys are ALL of the generic
# "field_<single letter>" shape (field_a, field_b, field_c...), regardless
# of the exact prompt wording at the time - catches the same failure mode
# even if the prompt's example placeholders are edited again later.
_PLACEHOLDER_FIELD_PATTERN = re.compile(r"^field_[a-z]$")

# The exact placeholder ATLAS entry from the prompt's JSON template.
_PLACEHOLDER_ATLAS_VALUE = "resource development"

# A proposed scenario whose name is this similar (0.0-1.0, difflib ratio) to
# an EXISTING rule's name is treated as "copied the rule back, not a novel
# gap" and rejected - confirmed happening in practice: the same local model
# run restated DS-39 and DS-40 nearly verbatim as if they were undetected
# gaps, despite the prompt explicitly saying not to.
_NAME_SIMILARITY_REJECT_THRESHOLD = 0.82


class SimulationAgent:
    """Adversarial simulation agent with two modes.

    Mode A - reconciliation: instantiate each documented typology as a
      structured attack scenario (test fixture) and step it through the
      rulebook, recording which indicators fire and which are evaded.

    Mode B - generation: reason from the AI capability-primitives library to
      propose novel evasion-candidate scenarios not among the documented
      attack fixtures already covered by the reconciliation arm, then test
      each against the same deterministic engine.

      Generation mode asks the local model for ONE scenario at a time (not a
      batch of three in one prompt), with up to GENERATION_ARM_ATTEMPTS_PER_
      SLOT tries per slot before falling back - only for that slot, not the
      whole run. This is deliberately different from the earlier all-or-
      nothing batch design: a single small local model is far more likely to
      produce one valid, well-formed JSON object than three at once inside a
      shared token budget, so per-slot requests give the model a genuinely
      fair chance to succeed on SOME slots even when it can't reliably do
      all three - rather than the whole run silently falling back the moment
      any one part of a combined response goes wrong.

      The model never decides whether something is a gap - only the
      deterministic engine does, by evaluating the proposed fixture against
      the real rulebook. Every LLM-proposed scenario is validated
      (_sanitize_scenario) before use; a rejected or unavailable slot uses a
      hand-authored fallback scenario, and every finding is tagged with
      which path actually produced it (generation_source: "llm" vs
      "deterministic_fallback" vs "fixed_probe") so nothing is presented as
      more machine-generated than it actually was.

    The deterministic rule-evaluation engine is the source of truth for
    firing/evasion in BOTH modes, giving reproducible, auditable results
    the critic agent can independently re-run (agents/critic_agent.py
    re-runs generation-mode candidates exactly as it does reconciliation
    ones, using the candidate's inline "fixture").
    """

    def __init__(self, engine: RuleEvaluationEngine, llm: Optional[LocalLLMClient] = None):
        self.engine = engine
        self.llm = llm

    # ------------------------------------------------------------------
    # Mode A: reconciliation (legacy typology corpus) - unchanged
    # ------------------------------------------------------------------

    def run_reconciliation(self, typologies: list[Typology], rulebook: list[Rule]) -> list[dict]:
        """Return a list of gap candidates, one per fixture that evades >=1 relevant rule.

        A 'relevant' rule is one whose semantics overlap the typology's methods
        (by keyword) yet fails to fire on the adversarial fixture - i.e. the rule
        is stale against this typology. Rules unrelated to the typology are not
        counted as gaps, keeping the report focused and auditable.
        """
        findings = []
        for typology in typologies:
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
        tab's data source. (Unchanged.)
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

    # ------------------------------------------------------------------
    # Mode B: generation (per-slot LLM prompting, with per-slot fallback)
    # ------------------------------------------------------------------

    def run_generation(self, rulebook: list[Rule]) -> list[dict]:
        """Generation arm: propose novel evasion-candidate scenarios and test
        each against the rulebook deterministically.

        Pipeline:
          1. _llm_compose_scenarios asks for GENERATION_ARM_TARGET_COUNT
             scenarios ONE AT A TIME, each in its own small prompt, each
             validated before acceptance. A slot that fails after
             GENERATION_ARM_ATTEMPTS_PER_SLOT tries uses a hand-authored
             fallback scenario for THAT SLOT ONLY - other slots are
             unaffected, so a run can genuinely mix model-written and
             fallback findings.
          2. Always append one fixed speculative probe scenario, independent
             of (1), so the critic's plausibility guardrail has a
             guaranteed candidate to reject every run (see agents/
             critic_agent.py and agents/probe.py).
          3. Evaluate every scenario's fixture through the real engine and
             only report it if something relevant genuinely stays silent.
        """
        scenarios = self._llm_compose_scenarios(rulebook)
        scenarios = scenarios + [self._speculative_probe_scenario()]

        findings = []
        for idx, prim in enumerate(scenarios, 1):
            fixture = prim["fixture"]
            results = self.engine.evaluate(rulebook, fixture)
            fired = {r.rule_id for r in results if r.fired}
            vocab = " ".join(prim["techniques"] + [prim["name"]]).lower()
            relevant = [r for r in rulebook if self._rule_relevant(r, vocab)]
            evaded = [r.id for r in relevant if r.id not in fired]
            if not evaded:
                continue

            is_probe = prim.get("_fixed_probe", False)
            source = "fixed_probe" if is_probe else prim.get("_source", "deterministic_fallback")
            basis = (
                "speculative self-generated novel path; no published evidence "
                "yet and no supporting STR material" if prim.get("speculative")
                else f"{'model-proposed' if source == 'llm' else 'self-generated from AI capability primitives'} "
                     f"(novel, unverified); composes {', '.join(prim.get('capability_primitives', []) or ['unspecified'])}"
            )
            findings.append({
                "typology_id": f"GEN-{idx:02d}",
                "typology_name": prim["name"],
                "evidential_basis": basis,
                "fired_rules": sorted(fired),
                "evaded_rules": evaded,
                "techniques": prim["techniques"],
                "capability_primitives": prim.get("capability_primitives", []),
                "mitre_atlas": prim.get("mitre_atlas", []),
                "mode": "generation",
                "novel": True,
                "speculative": prim.get("speculative", False),
                "generation_source": source,
                "fixture": fixture,
            })
        return findings

    # -- LLM path: one scenario per call, per-slot fallback --------------

    def _llm_compose_scenarios(self, rulebook: list[Rule]) -> list[dict]:
        """Return GENERATION_ARM_TARGET_COUNT scenario dicts, each tagged
        with "_source": "llm" or "deterministic_fallback". If no model is
        available at all, every slot uses the fallback immediately (no
        wasted attempts).

        Each candidate is checked against BOTH the rulebook's existing rule
        names (via _sanitize_scenario) AND every name already accepted in an
        earlier slot THIS run (via _name_too_similar below). The prompt asks
        the model not to repeat a previous slot's idea, but that is only an
        instruction - a small model can and did ignore it in practice
        (confirmed 2026-09-07: two slots returned the identical scenario
        name verbatim). This is the enforced check that instruction was
        missing; a duplicate is treated as a failed attempt for that slot,
        exactly like an unparseable or template-copy response, and retried
        or -ultimately- filled by the deterministic fallback."""
        fallback = self._fallback_scenarios()
        if not self.llm or not self.llm.available():
            return [dict(fb, _source="deterministic_fallback") for fb in fallback]

        known_fields = sorted(self._collect_known_fields(rulebook))
        existing_rule_names = [r.name for r in rulebook]
        scenarios: list[dict] = []
        proposed_names: list[str] = []

        for i in range(GENERATION_ARM_TARGET_COUNT):
            cleaned = None
            for _attempt in range(GENERATION_ARM_ATTEMPTS_PER_SLOT):
                prompt = self._build_single_scenario_prompt(rulebook, known_fields, proposed_names)
                raw = self.llm.complete(prompt, temperature=0.55, max_tokens=650)
                if not raw:
                    continue
                parsed = self._parse_json_scenarios(raw)
                if not parsed:
                    continue
                candidate = self._sanitize_scenario(parsed[0], existing_rule_names)
                if not candidate:
                    continue
                if self._name_too_similar(candidate["name"], proposed_names):
                    continue
                cleaned = candidate
                break
            if cleaned:
                cleaned["_source"] = "llm"
                scenarios.append(cleaned)
                proposed_names.append(cleaned["name"])
            else:
                # Per-slot fallback also needs to avoid duplicating a name
                # already used this run (fallback[i % len(fallback)] could
                # collide with an earlier LLM-accepted name in principle).
                fb = None
                for candidate_fb in fallback[i:] + fallback[:i]:
                    if not self._name_too_similar(candidate_fb["name"], proposed_names):
                        fb = dict(candidate_fb)
                        break
                fb = fb or dict(fallback[i % len(fallback)])
                fb["_source"] = "deterministic_fallback"
                scenarios.append(fb)
                proposed_names.append(fb["name"])
        return scenarios

    @staticmethod
    def _name_too_similar(name: str, other_names: list[str]) -> bool:
        """True if `name` is a near-duplicate of any name in `other_names`,
        using the same similarity threshold as the rulebook-name check in
        _sanitize_scenario. Used to stop two generation-arm slots in the
        same run from reporting the same idea twice under slightly
        different attempts."""
        name_norm = name.lower()
        for other in other_names:
            if difflib.SequenceMatcher(None, name_norm, other.lower()).ratio() >= _NAME_SIMILARITY_REJECT_THRESHOLD:
                return True
        return False

    @staticmethod
    def _collect_known_fields(rulebook: list[Rule]) -> set[str]:
        """Walk every rule's trigger_schema tree and collect the field names
        already in use, so the prompt can ground the model in real
        vocabulary."""
        fields: set[str] = set()

        def _walk(node: Any) -> None:
            if not isinstance(node, dict):
                return
            if "field" in node:
                fields.add(node["field"])
            for key in ("all", "any"):
                for child in node.get(key, []) or []:
                    _walk(child)
            if "not" in node:
                _walk(node["not"])

        for rule in rulebook:
            _walk(rule.trigger_schema or {})
        return fields

    @staticmethod
    def _build_single_scenario_prompt(rulebook: list[Rule], known_fields: list[str], avoid_names: list[str]) -> str:
        """Deliberately smaller than a "propose 3 at once" prompt: rule
        NAMES + categories only (no full trigger sentences), one scenario
        requested, not three. This is the core of the fix - a batch-of-3
        prompt against the full trigger text was observed exhausting a 1B
        model's effective context before it could produce clean output;
        this prompt is roughly a third the size and asks for a third of the
        work per call.

        FIXTURE SIZE CAP: confirmed in practice (2026-09-07) that showing
        the model the full field vocabulary invited it to enumerate nearly
        every field as false, one per line, burning the entire output token
        budget before it could reach the closing braces - every one of 3
        test slots was truncated mid-JSON this way. Two changes address it:
        only a sample of the vocabulary is shown (not the full list, so
        there is less to imitate), and the instruction below is explicit
        and repeated about keeping the fixture to a handful of fields."""
        rule_lines = "\n".join(f"- {r.id} [{r.category}]: {r.name}" for r in rulebook)
        cp_lines = "\n".join(f"- {cp_id}: {desc}" for cp_id, desc in CP_LIBRARY_SUMMARY)
        # Show at most 24 fields as illustrative examples, not the whole
        # vocabulary - showing everything measurably caused the model to
        # try to enumerate everything.
        sample_fields = known_fields[:24]
        fields_line = ", ".join(sample_fields)
        avoid = "; ".join(avoid_names) if avoid_names else "(nothing yet - you're first)"

        return f"""You are assisting a financial regulator's horizon-scanning system.
Propose exactly ONE novel crypto-AML evasion scenario that is NOT already
named by any rule below, and NOT similar to anything in the avoid-list.
Combine AI capability primitives in a new way. Stay at the level of a
regulatory indicator gap - describe WHAT pattern would evade detection and
WHY, never step-by-step attacker instructions or exploit code.

EXISTING RULE NAMES (do not restate or paraphrase any of these as a "gap"):
{rule_lines}

ALREADY PROPOSED THIS RUN (avoid - do not repeat or rephrase):
{avoid}

AI CAPABILITY PRIMITIVES (CP-01 to CP-10 ONLY - never invent another number):
{cp_lines}

SOME field names already used in the rulebook, as examples only - NOT a
checklist to complete (reuse one of these if it genuinely fits; otherwise
invent a short new field name of your own):
{fields_line}

CRITICAL - keep the fixture SHORT: include ONLY the 2 to 5 fields that are
actually true or relevant to YOUR scenario, using real field names that
describe YOUR specific idea. Do NOT list every field you know about set to
false - that wastes space and will be rejected.

Respond with ONLY one JSON object (no array, no markdown fences, no
commentary). Replace EVERY placeholder value below with your own real
content - copying this example's literal field names/values is wrong:
{{
  "name": "short scenario name",
  "techniques": ["3-6 short keyword phrases"],
  "capability_primitives": ["CP-01"],
  "mitre_atlas": ["Defense Evasion"],
  "fixture": {{"<a real field name>": true, "<another real field name>": false}},
  "speculative": false,
  "rationale": "one short sentence on the regulatory gap this exposes"
}}

Reminder: <a real field name> is a placeholder showing you the SHAPE only -
your answer must use an actual field name, never that literal text."""

    @staticmethod
    def _parse_json_scenarios(raw: str) -> list[dict]:
        text = raw.strip()
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip(), flags=re.IGNORECASE)
        # A single-object response (what this prompt asks for) needs no
        # special handling; a model that ignores instructions and wraps its
        # object in an array, or returns several, is still handled below.
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            # Second attempt: the model may have prefixed/suffixed the JSON
            # with commentary despite instructions - try extracting the
            # first {...} or [...] block.
            match = re.search(r"(\{.*\}|\[.*\])", text, re.S)
            candidate_text = match.group(1) if match else text
            try:
                data = json.loads(candidate_text)
            except (json.JSONDecodeError, ValueError):
                # Third attempt: the response was cut off mid-generation by
                # the token budget (confirmed happening in practice - see
                # _build_single_scenario_prompt docstring). Try to recover a
                # usable object from the truncated text rather than
                # discarding a response that was 90% of the way there.
                repaired = SimulationAgent._attempt_repair_truncated_json(candidate_text)
                if repaired is None:
                    return []
                data = repaired
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            return []
        return [item for item in data if isinstance(item, dict)]

    @staticmethod
    def _attempt_repair_truncated_json(text: str) -> Optional[dict]:
        """Best-effort recovery for a JSON object cut off mid-stream by the
        model's token budget. Trims back to the last complete field (the
        last top-level comma), then closes whatever brackets/braces are
        still open, and retries parsing. Returns None if recovery isn't
        possible - callers must still handle that as a genuine failure."""
        text = text.strip()
        if not text.startswith("{"):
            return None
        cut = text.rfind(",")
        if cut == -1:
            return None
        candidate = text[:cut]
        stack: list[str] = []
        in_string = False
        escape = False
        for ch in candidate:
            if escape:
                escape = False
                continue
            if ch == "\\":
                escape = True
                continue
            if ch == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch in "{[":
                stack.append(ch)
            elif ch in "}]":
                if stack:
                    stack.pop()
        closers = {"{": "}", "[": "]"}
        candidate += "".join(closers[c] for c in reversed(stack))
        try:
            return json.loads(candidate)
        except (json.JSONDecodeError, ValueError):
            return None

    @staticmethod
    def _sanitize_scenario(item: dict, existing_rule_names: list[str]) -> Optional[dict]:
        """Validate and clean one LLM-proposed scenario. Returns None if it
        cannot be turned into something the deterministic engine can use, OR
        if it matches a confirmed failure mode below - NEVER defaults a
        missing/invalid fixture to {}, and never lets a template-copy or
        restated-rule slip through as if it were a genuine novel finding."""
        name = item.get("name")
        if not isinstance(name, str) or not name.strip():
            return None
        name = name.strip()[:120]

        # Reject: name is a near-restatement of an existing rule's name.
        name_norm = name.lower()
        for existing in existing_rule_names:
            ratio = difflib.SequenceMatcher(None, name_norm, existing.lower()).ratio()
            if ratio >= _NAME_SIMILARITY_REJECT_THRESHOLD:
                return None

        techniques = item.get("techniques")
        if not isinstance(techniques, list) or not techniques:
            return None
        techniques = [str(t)[:60] for t in techniques if isinstance(t, (str, int, float))][:8]
        if not techniques:
            return None

        raw_fixture = item.get("fixture")
        if not isinstance(raw_fixture, dict) or not raw_fixture:
            return None

        # Reject: fixture is exactly the unfilled prompt template (either
        # known placeholder set, or the general field_<letter> pattern).
        fixture_key_set = set(k.strip() for k in raw_fixture.keys() if isinstance(k, str))
        if fixture_key_set in (_PLACEHOLDER_FIXTURE_KEYS, _PLACEHOLDER_FIXTURE_KEYS_ALT):
            return None
        if fixture_key_set and all(_PLACEHOLDER_FIELD_PATTERN.match(k) for k in fixture_key_set):
            return None

        fixture: dict[str, Any] = {}
        for k, v in raw_fixture.items():
            if not isinstance(k, str) or not k.strip():
                continue
            if not isinstance(v, _ALLOWED_FIXTURE_VALUE_TYPES):
                continue
            if isinstance(v, str) and len(v) > 200:
                continue
            fixture[k.strip()] = v
        if not fixture:
            return None

        # Only accept capability primitive IDs that actually exist.
        raw_cps = item.get("capability_primitives")
        cps = []
        if isinstance(raw_cps, list):
            cps = [cp for cp in raw_cps if isinstance(cp, str) and cp in _KNOWN_CP_IDS]

        # Strip the literal placeholder ATLAS value rather than rejecting
        # the whole scenario over it - ATLAS tagging is supplementary
        # metadata, not load-bearing for whether a gap is real.
        raw_atlas = item.get("mitre_atlas")
        atlas = []
        if isinstance(raw_atlas, list):
            atlas = [
                str(a)[:60] for a in raw_atlas
                if isinstance(a, (str, int, float)) and str(a).strip().lower() != _PLACEHOLDER_ATLAS_VALUE
            ][:5]

        speculative = bool(item.get("speculative", False))

        return {
            "name": name,
            "techniques": techniques,
            "capability_primitives": cps,
            "mitre_atlas": atlas,
            "fixture": fixture,
            "speculative": speculative,
        }

    # -- Deterministic fallback (used per-slot when the LLM path fails) --

    @staticmethod
    def _fallback_scenarios() -> list[dict]:
        """Fixed, hand-authored scenarios with real (non-empty) fixtures.
        Used per-slot when the model is unavailable, or fails validation
        for that slot after GENERATION_ARM_ATTEMPTS_PER_SLOT tries - each
        still represents a genuine, checkable gap, never an empty fixture
        guaranteed to evade everything."""
        return [
            {
                "name": "AI-negotiated OTC settlement structuring",
                "techniques": [
                    "unregistered exchange", "structuring", "ai negotiation",
                    "otc settlement", "high-value", "pacing",
                ],
                "capability_primitives": ["CP-05", "CP-10"],
                "mitre_atlas": ["TA0007 Evasion", "T1071 Layer"],
                "fixture": {
                    "high_value": True,
                    "quick_succession": False,
                    "below_threshold": False,
                    "otc_settlement": True,
                    "ai_paced_negotiation": True,
                },
            },
            {
                "name": "Deepfake board-resolution corporate onboarding",
                "techniques": [
                    "forged documents", "identity fraud", "corporate onboarding",
                    "deepfake board resolution", "new account", "profile mismatch",
                ],
                "capability_primitives": ["CP-01", "CP-03"],
                "mitre_atlas": ["TA0005 ML Development", "T1592 Gather Victim Org Info"],
                "fixture": {
                    "new_account": True,
                    "customer_profile_consistent": True,
                    "rapid_withdrawal": False,
                    "forged_document_provided": False,
                    "edited_id_photograph_provided": False,
                    "deepfake_video_evidence_provided": True,
                },
            },
            {
                "name": "AI-fabricated Travel Rule originator/beneficiary data",
                "techniques": [
                    "travel rule", "originator", "beneficiary", "cross-border",
                    "ai-scripted multi-hop settlement", "identifying information",
                ],
                "capability_primitives": ["CP-03"],
                "mitre_atlas": ["TA0007 Evasion"],
                "fixture": {
                    "qualifying_transfer": True,
                    "travel_rule_info_transmitted": True,
                    "travel_rule_info_ai_fabricated": True,
                },
            },
        ]

    @staticmethod
    def _speculative_probe_scenario() -> dict:
        """Fixed candidate with no published/STR evidence, always appended
        so the critic's plausibility guardrail has a guaranteed rejectable
        case every run - proof the guardrail runs, not just exists in code.
        See agents/critic_agent.py and agents/probe.py."""
        return {
            "name": "Prompt-poisoned global settlement reroute",
            "techniques": ["structuring", "multiple accounts", "model prompt injection"],
            "capability_primitives": ["CP-10"],
            "mitre_atlas": ["TA0005 ML Development"],
            "fixture": {"multiple_accounts": True, "model_prompt_injection": True},
            "speculative": True,
            "_fixed_probe": True,
        }