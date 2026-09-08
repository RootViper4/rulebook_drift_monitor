from __future__ import annotations

import difflib
import json
import re
import textwrap
from typing import Any, Callable, Optional

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
    ("CP-11", "AI-orchestrated structuring - transfer amounts computed to sit just under the reporting threshold"),
    ("CP-12", "AI-automated mule-network / bulk account generation fanning funds in from many bulk-created accounts sharing device/IP fingerprints, then consolidating"),
]
_KNOWN_CP_IDS = {cp_id for cp_id, _ in CP_LIBRARY_SUMMARY}

GENERATION_ARM_TARGET_COUNT = 5  # how many novel scenarios per run
GENERATION_ARM_ATTEMPTS_PER_SLOT = 3  # LLM attempts before falling back for THAT slot only
# Local Ollama on CPU-only hardware is ~1 token/sec, so an extra attempt costs
# a full generation's worth of wall-clock. One attempt only on the local path
# (the hosted path is fast enough to justify the full attempt budget). If the
# local model answers in time it still contributes; a slow/stuck answer fails
# fast and falls back to the varied canned pool instead of stalling the run.
LOCAL_OLLAMA_ATTEMPTS_PER_SLOT = 1
# Cap the answer size on the local path to a bit less than the client's own
# cap so the prompt asks the model for a snippet the CPU can actually finish.
LOCAL_OLLAMA_MAX_TOKENS = 300
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
# The prompt's live template shows its fixture example as {"<a real field
# name>": true, "<another real field name>": false} - a model that copies
# the template instead of substituting real field names returns keys that
# STILL contain angle-bracket placeholders. Neither exact-match set above
# nor the field_<letter> pattern catches that shape, so reject any fixture
# whose keys look like template placeholders, whatever the prompt words.
_PLACEHOLDER_KEY_PATTERN = re.compile(r"[<>]")

# The exact placeholder ATLAS entry from the prompt's JSON template.
_PLACEHOLDER_ATLAS_VALUE = "resource development"

# The canonical MITRE ATLAS tactic names (atlas.mitre.org). A generated
# scenario's mitre_atlas entries used to be accepted as free text, so a
# model could return an ATT&CK tactic that ATLAS does not have (confirmed
# 2026-09-08: "Obfuscation" came back from a hosted model) and it would
# flow untouched into the gap report as though it were a real mapping.
# Entries matching this set are kept in `mitre_atlas`; anything else is
# kept SEPARATELY as `unverified_atlas` so an unverified label is never
# presented as a verified mapping. Matching is case-insensitive and
# tolerates a leading "TAxxxx " id prefix.
_ATLAS_TACTICS = {
    "reconnaissance",
    "resource development",
    "initial access",
    "ml model access",
    "execution",
    "persistence",
    "privilege escalation",
    "defense evasion",
    "credential access",
    "discovery",
    "collection",
    "ml attack staging",
    "exfiltration",
    "impact",
}
# Optional "TA0043 " / "TA0002" style id prefix on a tactic name.
_ATLAS_ID_PREFIX = re.compile(r"^ta\d{4}\s*", re.IGNORECASE)

# A proposed scenario whose name is this similar (0.0-1.0, difflib ratio) to
# an EXISTING rule's name is treated as "copied the rule back, not a novel
# gap" and rejected - confirmed happening in practice: the same local model
# run restated DS-39 and DS-40 nearly verbatim as if they were undetected
# gaps, despite the prompt explicitly saying not to.
_NAME_SIMILARITY_REJECT_THRESHOLD = 0.82

# A candidate which shares this fraction of its technique vocabulary with an
# already-accepted scenario is treated as the same idea under a different
# name, and rejected (0.0-1.0 containment ratio). Set at majority-overlap
# >0.5: a real variation keeps most of its content novel, while a rehash
# largely reuses an earlier slot's vocabulary. Measured against the concrete
# near-duplicate it exists to catch, this is the cleanest separating line
# (that pair scored 0.56 on shared tokens).
_TECHNIQUE_OVERLAP_REJECT_THRESHOLD = 0.5
# Deliberately LOWER than the rejection threshold above. This one does not
# reject anything - it only groups accepted scenarios that appear to be
# arguing the same underlying rulebook blind spot, so the convergence can
# be reported. See _detect_convergence().
_CONVERGENCE_OVERLAP_THRESHOLD = 0.25


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
        """Reconciliation arm over documented typologies (backwards-compatible wrapper)."""
        return self.run_scan(typologies, rulebook, mode="reconciliation")

    def run_scan(self, typologies: list[Typology], rulebook: list[Rule],
                 mode: str = "documented") -> list[dict]:
        """Return a list of gap candidates, one per fixture that evades >=1 relevant rule.

        `mode` tags the origin of the pool: "documented"/"reconciliation" for the
        known-typology arm, "generated" for the generated (novel) arm.

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
                    is_generated = mode == "generated"
                    d = {
                        "typology_id": typology.id,
                        "typology_name": typology.name,
                        "source": typology.source,
                        "fixture_index": idx,
                        "fired_rules": sorted(fired),
                        "evaded_rules": evaded,
                        "mitre_atlas": typology.mitre_atlas,
                        "techniques": typology.techniques,
                        "mode": mode,
                        "novel": is_generated,
                        "speculative": False,
                    }
                    if is_generated:
                        d["evidential_basis"] = (
                            "self-generated from AI capability primitives (novel, unverified)"
                        )
                    findings.append(d)
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

    def run_capability_primitive_reconciliation(self, rulebook: list[Rule], fixtures_path: str,
                                                abort_check: Optional[Callable[[], bool]] = None) -> list[dict]:
        """Reconciliation arm, capability-primitive edition - the 'Known Attacks'
        tab's data source.

        Rewritten in the generation-arm rework: instead of iterating the old
        hardcoded typology corpus, every finding here is derived per AI
        capability primitive (CP-01..CP-12) from the curated fixture set at
        data/fixtures.capability_primitives.json - each primitive's fixture
        scenarios are run through the same deterministic rule engine, the
        union of fired rules is counted, and the gap profile is the relevant
        rules that stay silent. CP-09/CP-10 (recon/tooling) are upstream
        aggravators, not control surfaces, and are deliberately excluded from
        findings."""
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
            if abort_check and abort_check():
                break
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

    def run_generation(self, rulebook: list[Rule],
                       abort_check: Optional[Callable[[], bool]] = None) -> list[dict]:
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
        scenarios = self._llm_compose_scenarios(rulebook, abort_check=abort_check)
        scenarios = scenarios + [self._speculative_probe_scenario()]

        findings = []
        for idx, prim in enumerate(scenarios, 1):
            if abort_check and abort_check():
                break
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
            unmodeled_fields = prim.get("unmodeled_fields") or []
            basis = (
                "speculative self-generated novel path; no published evidence "
                "yet and no supporting STR material" if prim.get("speculative")
                else f"{'model-proposed' if source == 'llm' else 'self-generated from AI capability primitives'} "
                     f"(novel, unverified); composes {', '.join(prim.get('capability_primitives', []) or ['unspecified'])}"
            )
            if unmodeled_fields:
                basis += (
                    f"; NOTE: also references field(s) not modelled anywhere in the "
                    f"rulebook ({', '.join(unmodeled_fields)}) - those describe a "
                    f"coverage idea the corpus can't test yet, not a verified evasion "
                    f"of an existing rule"
                )
            unverified_atlas = prim.get("unverified_atlas") or []
            if unverified_atlas:
                basis += (
                    f"; ATLAS CAUTION: proposed tactic label(s) "
                    f"{', '.join(unverified_atlas)} are not recognised MITRE ATLAS "
                    f"tactics and are recorded as unverified, not as a mapping"
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
                "unverified_atlas": unverified_atlas,
                "mode": "generation",
                "novel": True,
                "speculative": prim.get("speculative", False),
                "generation_source": source,
                "fixture": fixture,
                "unmodeled_fields": unmodeled_fields,
                "dropped_mismatched_fields": prim.get("dropped_mismatched_fields") or [],
            })
        return findings

    # -- LLM path: one scenario per call, per-slot fallback --------------

    def _llm_compose_scenarios(self, rulebook: list[Rule],
                               abort_check: Optional[Callable[[], bool]] = None) -> list[dict]:
        """Return GENERATION_ARM_TARGET_COUNT scenario dicts, each tagged
        with "_source": "llm" or "deterministic_fallback". If no model is
        available at all, every slot uses the fallback immediately (no
        wasted attempts).

        Each candidate is checked against BOTH the rulebook's existing rule
        names (via _sanitize_scenario) AND every name already accepted in an
        earlier slot THIS run (via _name_too_similar below) AND every
        technique profile already accepted in an earlier slot (via
        _techniques_too_similar - catches the "same idea, different wording"
        that name similarity alone misses). The prompt asks
        the model not to repeat a previous slot's idea, but that is only an
        instruction - a small model can and did ignore it in practice
        (confirmed 2026-09-07: two slots returned the identical scenario
        name verbatim, and a later pair returned the same evasion profile
        under names only 0.681-similar). This is the enforced check that
        instruction was missing; a duplicate is treated as a failed attempt
        for that slot, exactly like an unparseable or template-copy
        response, and retried or -ultimately- filled by the deterministic
        fallback."""
        fallback = self._fallback_scenarios()
        if not self.llm or not self.llm.available():
            return [dict(fb, _source="deterministic_fallback") for fb in fallback]

        known_fields_set = self._collect_known_fields(rulebook)
        known_fields = sorted(known_fields_set)
        field_domains = self._collect_field_domains(rulebook)
        existing_rule_names = [r.name for r in rulebook]
        scenarios: list[dict] = []
        proposed_names: list[str] = []
        proposed_scenarios: list[dict] = []
        # Local CPU inference is orders of magnitude slower than a hosted API,
        # so don't spend the full attempt budget (or ask for a huge answer) on
        # the local path - it's the difference between "stalls for 30 min" and
        # "finishes in a couple of minutes".
        is_hosted = bool(getattr(self.llm, "is_hosted", False))
        attempts_per_slot = GENERATION_ARM_ATTEMPTS_PER_SLOT if is_hosted else LOCAL_OLLAMA_ATTEMPTS_PER_SLOT
        max_tokens = 650 if is_hosted else LOCAL_OLLAMA_MAX_TOKENS

        def _aborted() -> bool:
            return bool(abort_check and abort_check())

        for i in range(GENERATION_ARM_TARGET_COUNT):
            # Abort must cut in INSIDE the long generation arm, not only at
            # orchestrator phase boundaries - otherwise a slow local model
            # keeps grinding through every slot before the abort is honoured.
            if _aborted():
                break
            cleaned = None
            for _attempt in range(attempts_per_slot):
                if _aborted():
                    break
                prompt = self._build_single_scenario_prompt(rulebook, known_fields, proposed_scenarios)
                raw = self.llm.complete(prompt, temperature=0.55, max_tokens=max_tokens)
                if not raw:
                    continue
                parsed = self._parse_json_scenarios(raw)
                if not parsed:
                    continue
                candidate = self._sanitize_scenario(
                    parsed[0], existing_rule_names, known_fields_set, field_domains
                )
                if not candidate:
                    continue
                if self._name_too_similar(candidate["name"], proposed_names):
                    continue
                # Same idea under a different name: overlapping technique
                # vocabulary with an earlier slot is also a duplicate, even if
                # the name check passed (name-only similarity is too weak).
                if self._techniques_too_similar(candidate.get("techniques") or [],
                                                proposed_scenarios):
                    continue
                cleaned = candidate
                break
            if cleaned:
                cleaned["_source"] = "llm"
                scenarios.append(cleaned)
                proposed_names.append(cleaned["name"])
                proposed_scenarios.append(cleaned)
            else:
                # Per-slot fallback also needs to avoid duplicating a name
                # or technique profile already used this run (fallback[i %
                # len(fallback)] could collide with an earlier LLM-accepted
                # scenario in principle).
                fb = None
                for candidate_fb in fallback[i:] + fallback[:i]:
                    if self._name_too_similar(candidate_fb["name"], proposed_names):
                        continue
                    if self._techniques_too_similar(candidate_fb.get("techniques") or [],
                                                    proposed_scenarios):
                        continue
                    fb = dict(candidate_fb)
                    break
                fb = fb or dict(fallback[i % len(fallback)])
                fb["_source"] = "deterministic_fallback"
                scenarios.append(fb)
                proposed_names.append(fb["name"])
                proposed_scenarios.append(fb)
        return scenarios

    @staticmethod
    def _detect_convergence(scenarios: list[dict],
                            threshold: float = _CONVERGENCE_OVERLAP_THRESHOLD) -> list[dict]:
        """Group accepted generation-arm scenarios that share enough
        technique vocabulary to be arguing the same underlying blind spot,
        and return one entry per group of 2 or more.

        WHY THIS EXISTS: `_techniques_too_similar` is a REJECTION gate at a
        deliberately high bar (_TECHNIQUE_OVERLAP_REJECT_THRESHOLD) - it
        stops a slot that is a near-verbatim repeat. It is intentionally
        not sensitive enough to catch scenarios that are worded quite
        differently while attacking the same control weakness; measured
        2026-09-08, three slots describing forged travel-rule attestations,
        forged invoices and forged bank statements shared only ~10-20% of
        their technique tokens and all three passed the gate.

        That looser similarity is worth REPORTING even though it is not
        worth rejecting. When several independently-generated scenarios
        converge on one mechanism, that is evidence about the rulebook -
        a blind spot broad enough that the generator keeps rediscovering
        it from different starting points - and it is a stronger finding
        than the same scenarios presented as N unrelated novelties. So
        this runs at a LOWER threshold than the rejection gate, and its
        output is a signal attached to the run, never a filter.

        Returns a list of {"shared_terms", "scenario_names", "size"},
        largest group first. Empty list when nothing converges.
        """
        groups: list[dict] = []
        used: set[int] = set()
        token_sets = [SimulationAgent._technique_tokens(s.get("techniques") or [])
                      for s in scenarios]

        for i, tokens_i in enumerate(token_sets):
            if i in used or not tokens_i:
                continue
            members = [i]
            shared = set(tokens_i)
            for j in range(i + 1, len(token_sets)):
                if j in used:
                    continue
                tokens_j = token_sets[j]
                if not tokens_j:
                    continue
                overlap = len(tokens_i & tokens_j) / min(len(tokens_i), len(tokens_j))
                if overlap >= threshold:
                    members.append(j)
                    shared &= tokens_j
            if len(members) >= 2:
                used.update(members)
                groups.append({
                    "shared_terms": sorted(shared),
                    "scenario_names": [scenarios[k].get("name", "(unnamed)") for k in members],
                    "size": len(members),
                })
        groups.sort(key=lambda g: g["size"], reverse=True)
        return groups

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
    def _stem(token: str) -> str:
        """Light suffix normalisation so plural/tense variants of the same
        concept count as the same technique token ("amount"/"amounts",
        "mixer"/"mixers", "flagged"/"flagging"). Deliberately simple - just
        the most common English suffixes, no dictionary, applied greedily."""
        t = token
        for suffix in ("ing", "tion", "ness", "s", "es", "ed", "ying"):
            if len(t) > 5 and t.endswith(suffix):
                return t[:-len(suffix)]
        return t

    @staticmethod
    def _technique_tokens(techniques: list[str]) -> set[str]:
        """Lower-cased, lightly-stemmed word set from a scenario's technique
        phrases, minus stopword-y short tokens. Two scenarios describing the
        same attack with different prose share most of these tokens, even when
        their displayed names read quite differently (name-only similarity can
        miss that)."""
        stop = {"the", "and", "with", "using", "from", "into", "over",
                "under", "via", "for", "that", "this", "are", "to"}
        tokens: set[str] = set()
        for t in techniques:
            for _t in re.split(r"[^a-z0-9]+", str(t).lower()):
                if _t and len(_t) >= 4 and _t not in stop:
                    tokens.add(SimulationAgent._stem(_t))
        return tokens

    @staticmethod
    def _techniques_too_similar(candidate_techniques: list[str], accepted_scenarios: list[dict]) -> bool:
        """True if `candidate_techniques` overlap an already-accepted
        scenario's technique vocabulary so heavily that the two are the same
        idea (a near-duplicate of an earlier slot in this run), not a distinct
        novel gap. Name similarity alone is deliberately NOT relied on here -
        two different-looking names can share an identical technique set, and
        an identical-looking name can be paired with a genuinely different
        attack profile (confirmed 2026-09-07: SequenceMatcher 0.681 slipped
        past the 0.82 name threshold while the evasion profiles overlapped).
        Uses containment - the docstrings describe the same moves - so a
        short candidate is judged by how much of ITS vocabulary is already
        claimed, keeping high-recall against the small technique sets the
        model is asked to produce."""
        c = SimulationAgent._technique_tokens(candidate_techniques)
        if not c:
            return False
        for acc in accepted_scenarios:
            a = SimulationAgent._technique_tokens(acc.get("techniques") or [])
            if not a:
                continue
            overlap = len(c & a) / len(c)
            if overlap >= _TECHNIQUE_OVERLAP_REJECT_THRESHOLD:
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
    def _collect_field_domains(rulebook: list[Rule]) -> dict[str, dict]:
        """Walk every rule's trigger_schema and build a lightweight type/value
        profile per field: which ops it's ever compared with, and (for
        eq/in against string literals) which specific string values are
        actually valid.

        This exists because a field name matching the rulebook's vocabulary
        is not enough on its own - e.g. counterparty_jurisdiction is only
        ever compared against string categories ('sanctioned', 'high_risk',
        'grey_list') via eq/in; a generated fixture setting it to the
        Python bool True passes the plain field-name check but will never
        match any of those, so the rule silently never fires and the
        "gap" that gets reported didn't actually test anything. Checking
        the field's real domain here catches that before it reaches a
        finding.
        """
        domains: dict[str, dict] = {}

        def _note(field: Any, op: Any, value: Any) -> None:
            if not isinstance(field, str):
                return
            d = domains.setdefault(field, {"ops": set(), "string_values": set()})
            if isinstance(op, str):
                d["ops"].add(op)
            if op in ("eq", "in"):
                values = value if isinstance(value, list) else [value]
                for v in values:
                    if isinstance(v, str):
                        d["string_values"].add(v.strip().lower())

        def _walk(node: Any) -> None:
            if not isinstance(node, dict):
                return
            if "field" in node:
                _note(node["field"], node.get("op"), node.get("value"))
            for key in ("all", "any"):
                for child in node.get(key, []) or []:
                    _walk(child)
            if "not" in node:
                _walk(node["not"])

        for rule in rulebook:
            _walk(rule.trigger_schema or {})
        return domains

    @staticmethod
    def _field_value_matches_domain(value: Any, domain: Optional[dict]) -> bool:
        """True if `value` is a shape the rulebook could actually match for
        a field with this domain profile. No domain (field genuinely
        unknown) is handled by the caller separately, not here."""
        if not domain:
            return True
        ops = domain["ops"]
        string_values = domain["string_values"]
        # Field is only ever compared against specific string categories
        # (eq/in), never checked for plain truthiness/existence - a bool
        # or number here can never match and the rule would silently stay
        # dark on this field regardless of intent.
        if string_values and not (ops & {"truthy", "exists"}):
            return isinstance(value, str) and value.strip().lower() in string_values
        # Field is only ever compared numerically (gte/lte) - a bool
        # (Python bool is technically an int subclass, so exclude it
        # explicitly) or string can't be meaningfully compared.
        if ops and ops <= {"gte", "lte"}:
            return isinstance(value, (int, float)) and not isinstance(value, bool)
        return True

    @staticmethod
    def _build_single_scenario_prompt(rulebook: list[Rule], known_fields: list[str],
                                      avoid_scenarios: list[dict]) -> str:
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
        test slots was truncated mid-JSON this way. The instruction below
        is therefore explicit and repeated about keeping the fixture to a
        handful of fields.

        ANCHOR REQUIREMENT (2026-09-08): the earlier version of this prompt
        showed only a 24-field sample and told the model to "invent a short
        new field name of your own" whenever nothing fit. Measured against
        a hosted model, 2 of 3 slots then invented fields the rulebook has
        never heard of, and one slot invented ALL of them - meaning the
        deterministic engine tested nothing at all and the "gap" was
        vacuous (that slot is now rejected outright by _sanitize_scenario).
        Two changes: the FULL vocabulary is shown (the truncation failure
        above was on a 1B local model with a 300-token budget; the fix for
        it is the fixture SIZE cap below, not hiding two-thirds of the
        vocabulary from the model), and invention is still allowed - it is
        how a genuinely unmodelled coverage gap gets surfaced, which is the
        generation arm's whole point - but only ON TOP of at least two real
        anchor fields, so every scenario is partly testable against the
        real rulebook rather than free-floating.
        """
        rule_lines = "\n".join(f"- {r.id} [{r.category}]: {r.name}" for r in rulebook)
        cp_lines = "\n".join(f"- {cp_id}: {desc}" for cp_id, desc in CP_LIBRARY_SUMMARY)
        cp_range = f"{CP_LIBRARY_SUMMARY[0][0]} to {CP_LIBRARY_SUMMARY[-1][0]}" if CP_LIBRARY_SUMMARY else "none"
        # Full vocabulary, wrapped across lines so it reads as a reference
        # list rather than a template to copy line-by-line.
        fields_block = textwrap.fill(", ".join(known_fields), width=88)

        # CONVERGENCE, NOT DIVERSITY (2026-09-08): a previous revision of
        # this prompt carried a long "DIVERSITY REQUIREMENT" block naming
        # the repetition failure mode and listing alternative lifecycle
        # stages to attack. Measured against a hosted model over two
        # revisions it did NOT work - slots kept returning the same
        # underlying mechanism (AI fabricates a supporting document or
        # narrative that an authenticity-blind control accepts) under
        # different names. That block was removed because:
        #   1. It didn't change behaviour, and
        #   2. It grew the prompt with every accepted slot (measured
        #      8.8k -> 9.1k -> 9.3k chars across three slots), which on a
        #      rate-limited free tier contributed to a slot failing
        #      outright - so it made runs less reliable for no benefit.
        # The convergence is now treated as a measurement rather than a
        # defect: see _detect_convergence() below. Repeated independent
        # arrival at the same blind spot is evidence about the RULEBOOK
        # (it checks presence, consistency, thresholds and keywords, but
        # never authenticity), not a failure of the generator. The
        # avoid-list is kept, but compact - enough to stop verbatim
        # repetition without unbounded prompt growth.
        if avoid_scenarios:
            avoid_lines = []
            for s in avoid_scenarios:
                techniques = ", ".join((s.get("techniques") or [])[:3]) or "(none given)"
                avoid_lines.append(f"- {s.get('name', '(unnamed)')} ({techniques})")
            avoid = "\n".join(avoid_lines)
        else:
            avoid = "(nothing yet - you're first)"

        return f"""You are assisting a financial regulator's horizon-scanning system.
Propose exactly ONE novel crypto-AML evasion scenario that is NOT already
named by any rule below, and NOT similar to anything in the avoid-list.
Combine AI capability primitives in a new way. Stay at the level of a
regulatory indicator gap - describe WHAT pattern would evade detection and
WHY, never step-by-step attacker instructions or exploit code.

EXISTING RULE NAMES (do not restate or paraphrase any of these as a "gap"):
{rule_lines}

ALREADY PROPOSED THIS RUN (do not repeat or rephrase these):
{avoid}

AI CAPABILITY PRIMITIVES ({cp_range} ONLY - never invent another number):
{cp_lines}

THE COMPLETE LIST OF FIELD NAMES THE RULEBOOK UNDERSTANDS - this is a
reference list to choose from, NOT a checklist to fill in:
{fields_block}

HOW TO BUILD THE FIXTURE - this is the part that matters most:
1. Your fixture MUST include AT LEAST TWO field names taken exactly from
   the list above. These anchor your scenario to rules that can actually
   be tested. A fixture with no real field names from that list tests
   nothing and will be rejected outright.
2. You MAY then add ONE or TWO invented field names for aspects of your
   scenario the rulebook genuinely cannot express yet - that is useful, it
   is how we find coverage gaps. Only invent where nothing in the list
   fits; check the list properly first.
3. Most fields above are true/false flags. A few expect a specific text
   value instead (for example a jurisdiction field expects a category
   like "sanctioned" or "high_risk", not true) - if you use one of those,
   give it a sensible text value, not a boolean.
4. Keep the whole fixture to 3-5 fields total. Do NOT list every field you
   know about set to false - that wastes space and will be rejected.

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
    def _sanitize_scenario(item: dict, existing_rule_names: list[str],
                           known_fields: set[str], field_domains: dict[str, dict]) -> Optional[dict]:
        """Validate and clean one LLM-proposed scenario. Returns None if it
        cannot be turned into something the deterministic engine can use, OR
        if it matches a confirmed failure mode below - NEVER defaults a
        missing/invalid fixture to {}, and never lets a template-copy or
        restated-rule slip through as if it were a genuine novel finding.

        Fixture fields are split three ways against the rulebook's real
        vocabulary (known_fields/field_domains, from
        _collect_known_fields/_collect_field_domains):
          - kept fields: in the rulebook's vocabulary AND value-shape-valid
            for that field (e.g. a string category field gets a string in
            its known value set, not a bare bool) - these are the only
            fields that can actually make a rule fire or evade.
          - unmodeled_fields: field name genuinely not in the rulebook at
            all. The prompt explicitly allows inventing a field for a
            coverage idea no rule models yet, so this isn't rejected
            outright, but it's kept SEPARATE from `fixture` and surfaced
            on the returned dict so a finding built from it can be labelled
            as an unmodelled-coverage note rather than a verified gap.
          - dropped_mismatched_fields: field name IS in the rulebook, but
            the value doesn't match what that field is ever compared
            against (wrong type/shape) - these are silently useless to the
            engine, so they're dropped rather than kept as if meaningful.

        If NOTHING is left in `fixture` after this split, the candidate is
        rejected (None) exactly like an unparseable response - a finding
        with zero real, testable fields isn't a gap, it's a fixture bug.
        """
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
        # known placeholder set, the general field_<letter> pattern, or the
        # <a real field name>-style template copy).
        fixture_key_set = set(k.strip() for k in raw_fixture.keys() if isinstance(k, str))
        if fixture_key_set in (_PLACEHOLDER_FIXTURE_KEYS, _PLACEHOLDER_FIXTURE_KEYS_ALT):
            return None
        if fixture_key_set and all(_PLACEHOLDER_FIELD_PATTERN.match(k) for k in fixture_key_set):
            return None
        if fixture_key_set and any(_PLACEHOLDER_KEY_PATTERN.search(k) for k in fixture_key_set):
            return None

        fixture: dict[str, Any] = {}
        unmodeled_fields: list[str] = []
        dropped_mismatched_fields: list[str] = []
        for k, v in raw_fixture.items():
            if not isinstance(k, str) or not k.strip():
                continue
            key = k.strip()
            if not isinstance(v, _ALLOWED_FIXTURE_VALUE_TYPES):
                continue
            if isinstance(v, str) and len(v) > 200:
                continue
            if key not in known_fields:
                # Not a fixture-format problem - a field the rulebook has
                # never heard of. Keep it visible as a coverage note, not
                # as something that drove a "verified" evasion.
                unmodeled_fields.append(key)
                continue
            if not SimulationAgent._field_value_matches_domain(v, field_domains.get(key)):
                dropped_mismatched_fields.append(key)
                continue
            fixture[key] = v

        if not fixture:
            # Nothing left that the deterministic engine can actually test
            # against - reject outright rather than let a "verified gap"
            # through that never exercised a real rule. Treated exactly
            # like an unparseable response: the caller retries this slot
            # or, failing that, falls back.
            return None

        # Only accept capability primitive IDs that actually exist.
        raw_cps = item.get("capability_primitives")
        cps = []
        if isinstance(raw_cps, list):
            cps = [cp for cp in raw_cps if isinstance(cp, str) and cp in _KNOWN_CP_IDS]

        # Split ATLAS entries into recognised tactics and unverified ones
        # rather than accepting all of them as free text. The placeholder
        # value from the prompt template is dropped entirely. Anything else
        # that isn't a real ATLAS tactic is preserved separately as
        # `unverified_atlas` - not silently discarded (the model's intent
        # may still be informative to a reviewer) but never mixed into
        # `mitre_atlas`, which downstream code and the UI treat as a
        # verified mapping.
        raw_atlas = item.get("mitre_atlas")
        atlas: list[str] = []
        unverified_atlas: list[str] = []
        if isinstance(raw_atlas, list):
            for a in raw_atlas[:8]:
                if not isinstance(a, (str, int, float)):
                    continue
                text = str(a).strip()[:60]
                if not text:
                    continue
                normalised = _ATLAS_ID_PREFIX.sub("", text).strip().lower()
                if normalised == _PLACEHOLDER_ATLAS_VALUE and len(raw_atlas) == 1:
                    # Sole entry is the untouched prompt placeholder - drop it.
                    continue
                if normalised in _ATLAS_TACTICS:
                    if text not in atlas:
                        atlas.append(text)
                elif text not in unverified_atlas:
                    unverified_atlas.append(text)
            atlas = atlas[:5]
            unverified_atlas = unverified_atlas[:5]

        speculative = bool(item.get("speculative", False))

        return {
            "name": name,
            "techniques": techniques,
            "capability_primitives": cps,
            "mitre_atlas": atlas,
            "unverified_atlas": unverified_atlas,
            "fixture": fixture,
            "speculative": speculative,
            "unmodeled_fields": unmodeled_fields,
            "dropped_mismatched_fields": dropped_mismatched_fields,
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
            {
                "name": "AI-nudged micro-deposit smurfing via dormant accounts",
                "techniques": [
                    "dormant accounts", "micro-deposits", "ai nudging",
                    "sub-threshold", "long accumulation", "pattern avoidance",
                ],
                "capability_primitives": ["CP-09", "CP-11"],
                "mitre_atlas": ["TA0007 Evasion", "T1071 Layer"],
                "fixture": {
                    "small_consistent_deposits": True,
                    "ai_computed_rhythm": True,
                    "dormant_then_active": True,
                    "rapid_succession": False,
                },
            },
            {
                "name": "AI-tailored PEP-adjacent corporate veil",
                "techniques": [
                    "pep connections", "corporate veil", "ai-tailored structure",
                    "beneficial ownership", "sanctions evasion", "opaque nominee",
                ],
                "capability_primitives": ["CP-04", "CP-10"],
                "mitre_atlas": ["TA0006 Evasion", "T1592 Gather Victim Org Info"],
                "fixture": {
                    "related_to_pep": True,
                    "beneficial_ownership_concealed": True,
                    "newly_formed_entity": True,
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