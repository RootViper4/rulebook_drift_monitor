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

    print(f"Ollama available(): {llm.available()}")
    if not llm.available():
        print("Ollama is not reachable/model not pulled - nothing more to check.")
        return

    known_fields = sorted(SimulationAgent._collect_known_fields(rulebook))
    existing_rule_names = [r.name for r in rulebook]

    # Simulate 3 slots, exactly like a real run: each prompt sees the names
    # already accepted in earlier slots.
    proposed_names = []
    for slot in range(3):
        print(f"\n===== SLOT {slot + 1} =====")
        prompt = SimulationAgent._build_single_scenario_prompt(rulebook, known_fields, proposed_names)
        print(f"(prompt length: {len(prompt)} chars)")

        raw = llm.complete(prompt, temperature=0.55, max_tokens=500)
        print("----- RAW MODEL RESPONSE -----")
        print(raw if raw is not None else "(None - request failed or timed out)")

        if not raw:
            continue
        parsed = SimulationAgent._parse_json_scenarios(raw)
        print(f"----- PARSED: {len(parsed)} object(s) -----")
        if not parsed:
            print("Could not parse any JSON object from this response.")
            continue
        cleaned = SimulationAgent._sanitize_scenario(parsed[0], existing_rule_names)
        if not cleaned:
            print("REJECTED by _sanitize_scenario (see reasons in that function: bad name, "
                  "restated rule name, empty/placeholder fixture, etc.)")
            continue
        if SimulationAgent._name_too_similar(cleaned["name"], proposed_names):
            print(f"REJECTED: too similar to an earlier slot's name ({proposed_names})")
            continue
        print(f"ACCEPTED: {cleaned['name']!r}")
        proposed_names.append(cleaned["name"])


if __name__ == "__main__":
    main()