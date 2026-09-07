"""Diagnostic only - prints the raw LLM response for the generation-arm
prompt, so we can see why it failed to parse (if it did). Does not modify
any application state. Run from rulebook_drift_monitor/:
    python -m scripts.debug_llm_generation
"""
from __future__ import annotations

from agents.loader import load_rulebook
from agents.llm_client import LocalLLMClient
from agents.simulation_agent import SimulationAgent

RULEBOOK_PATH = "data/rulebook.json"


def main() -> None:
    rulebook = load_rulebook(RULEBOOK_PATH)
    llm = LocalLLMClient()

    print(f"Ollama available(): {llm.available()}")
    if not llm.available():
        print("Ollama is not reachable/model not pulled - nothing more to check.")
        return

    known_fields = sorted(SimulationAgent._collect_known_fields(rulebook))
    prompt = SimulationAgent._build_prompt(rulebook, known_fields)

    print("\n----- PROMPT SENT -----")
    print(prompt)

    raw = llm.complete(prompt, temperature=0.4, max_tokens=900)
    print("\n----- RAW MODEL RESPONSE -----")
    print(raw if raw is not None else "(None - request failed or timed out)")

    if raw:
        parsed = SimulationAgent._parse_json_scenarios(raw)
        print(f"\n----- PARSE RESULT: {len(parsed)} scenario(s) parsed -----")
        for item in parsed:
            cleaned = SimulationAgent._sanitize_scenario(item)
            print(f" - {item.get('name', '?')!r}: {'OK' if cleaned else 'REJECTED by sanitize_scenario'}")


if __name__ == "__main__":
    main()