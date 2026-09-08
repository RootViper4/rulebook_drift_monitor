"""Diagnostic only - prints the raw LLM response for ONE generation-arm
slot (matching the current per-scenario design), so we can see why it
failed to parse/validate (if it did). Does not modify any application
state. Run from rulebook_drift_monitor/:
    python -m scripts.debug_llm_generation
"""
from __future__ import annotations

from agents.loader import load_rulebook
from agents.llm_client import LocalLLMClient
from agents.simulation_agent import SimulationAgent


def main() -> None:
    rulebook = load_rulebook()
    llm = LocalLLMClient()

    backend = "hosted" if getattr(llm, "is_hosted", False) else "local Ollama"
    print(f"LLM backend: {backend} ({llm.model} @ {llm.url})")
    print(f"available(): {llm.available()}")
    if not llm.available():
        print("LLM endpoint is not reachable / credentials rejected / model not "
              "pulled - nothing more to check.")
        return

    known_fields_set = SimulationAgent._collect_known_fields(rulebook)
    known_fields = sorted(known_fields_set)
    # Per-field type/value profile from the rulebook, used to reject a
    # fixture value that could never match the field it's set on (e.g. a
    # bool on a field only ever compared against string categories).
    field_domains = SimulationAgent._collect_field_domains(rulebook)
    existing_rule_names = [r.name for r in rulebook]

    # Simulate 3 slots, exactly like a real run: each prompt sees the names
    # already accepted in earlier slots.
    proposed_names: list[str] = []
    proposed_scenarios: list[dict] = []
    for slot in range(3):
        print(f"\n===== SLOT {slot + 1} =====")
        prompt = SimulationAgent._build_single_scenario_prompt(rulebook, known_fields, proposed_scenarios)
        print(f"(prompt length: {len(prompt)} chars)")

        raw = llm.complete(prompt, temperature=0.55, max_tokens=500)
        print("----- RAW MODEL RESPONSE -----")
        if raw is None:
            reason = getattr(llm, "last_error", None) or "(no reason recorded)"
            print(f"(None - request failed) reason: {reason}")
            if "429" in str(reason) or "rate" in str(reason).lower():
                print("  → rate limit. On a free tier this is expected when slots run "
                      "back-to-back; a real run retries and then falls back for that slot.")
            continue
        print(raw)
        parsed = SimulationAgent._parse_json_scenarios(raw)
        print(f"----- PARSED: {len(parsed)} object(s) -----")
        if not parsed:
            print("Could not parse any JSON object from this response.")
            continue
        cleaned = SimulationAgent._sanitize_scenario(
            parsed[0], existing_rule_names, known_fields_set, field_domains
        )
        if not cleaned:
            print("REJECTED by _sanitize_scenario (bad name, restated rule name, "
                  "empty/placeholder fixture, or no usable fields left after "
                  "checking every field against the rulebook's real vocabulary).")
            continue
        if SimulationAgent._name_too_similar(cleaned["name"], proposed_names):
            print(f"REJECTED: too similar to an earlier slot's name ({proposed_names})")
            continue
        if SimulationAgent._techniques_too_similar(cleaned.get("techniques") or [],
                                                   proposed_scenarios):
            print("REJECTED: same technique profile as an earlier slot (duplicate idea "
                  "under a different name)")
            continue

        print(f"ACCEPTED: {cleaned['name']!r}")
        # Show how much of this scenario the rulebook can actually test.
        print(f"  testable fixture fields (in the rulebook): {cleaned['fixture']}")
        unmodeled = cleaned.get("unmodeled_fields") or []
        dropped = cleaned.get("dropped_mismatched_fields") or []
        if unmodeled:
            print(f"  ⚠ unmodelled field(s) - NOT in the rulebook at all, so nothing "
                  f"tested them: {', '.join(unmodeled)}")
            print("    → this finding will be flagged 'partial coverage' by the critic, "
                  "not a fully verified gap.")
        if dropped:
            print(f"  ⚠ dropped field(s) - real rulebook field but the value's type/shape "
                  f"could never match it: {', '.join(dropped)}")
        if not unmodeled and not dropped:
            print("  ✓ every field is real and value-shape-valid - fully testable gap.")

        unverified_atlas = cleaned.get("unverified_atlas") or []
        if unverified_atlas:
            print(f"  ⚠ ATLAS: {', '.join(unverified_atlas)} is not a real MITRE ATLAS "
                  f"tactic - recorded as unverified, not as a mapping.")
            print(f"    kept as verified mapping: {cleaned.get('mitre_atlas') or '(none)'}")

        proposed_names.append(cleaned["name"])
        proposed_scenarios.append(cleaned)


if __name__ == "__main__":
    main()