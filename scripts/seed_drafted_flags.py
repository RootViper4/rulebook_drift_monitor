#!/usr/bin/env python3
"""Optional pre-seeded 'drafted candidate red flags' cache.

A full 37-finding run performs one LLM completion per verified gap. On a local
llama3.2:1b this serialises to ~2-3 minutes per run, which is poor for a live
demo. Like run_history.json / live_run.json, the drafted flags are demo-data:
they are produced by the SAME LLM call the pipeline would make (never hand-typed),
then cached by typology so replay is instant and byte-identical.

The pipeline still drafts live whenever an id is missing from the cache, so a
fresh clone of the repo degrades gracefully to live generation.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from concurrent.futures import ThreadPoolExecutor, as_completed

from agents.loader import load_rulebook, load_typologies
from agents.retrieval_agent import RetrievalAgent
from agents.llm_client import LocalLLMClient
from agents.draft_cache import CACHE_PATH, load_cache, save_cache, cache_draft


def main() -> int:
    rulebook = load_rulebook()
    typologies = load_typologies()
    llm = LocalLLMClient()
    retrieval = RetrievalAgent(rulebook, typologies, llm)
    cache = load_cache()

    # A typology's red flag depends only on its own evaded rule set; draft in
    # parallel to cut wall-clock. Skip ids already cached or without a fixture.
    todo = [t for t in typologies if t.id not in cache]
    if not todo:
        print(f"nothing to do · {len(cache)} flags already cached")
        return 0
    print(f"drafting {len(todo)} flags (live LLM)…")

    def _draft(t) -> tuple[str, str]:
        vocab = " ".join(t.techniques + [t.name]).lower()
        from agents.rule_engine import RuleEvaluationEngine
        from agents.simulation_agent import SimulationAgent
        relevant = [r for r in rulebook if SimulationAgent._rule_relevant(r, vocab)]
        results = RuleEvaluationEngine().evaluate(rulebook, t.test_fixtures[0])
        fired = {r.rule_id for r in results if r.fired}
        evaded_objs = [r for r in relevant if r.id not in fired]
        flag = retrieval.draft_candidate_red_flag(t, evaded_objs)
        return t.id, flag

    done = 0
    with ThreadPoolExecutor(max_workers=8) as pool:
        futs = {pool.submit(_draft, t): t for t in todo}
        for fut in as_completed(futs):
            tid, flag = fut.result()
            cache_draft(tid, flag)
            done += 1
            print(f"  [{done}/{len(todo)}] {tid}: {flag[:72]}")
    print(f"wrote {len(load_cache())} flags to {CACHE_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())