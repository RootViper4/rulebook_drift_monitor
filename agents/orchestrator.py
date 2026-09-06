from __future__ import annotations

import html
import json
import threading
import uuid
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from typing import Optional

from agents.models import GapFinding, Rule, RunState, Typology
from agents.llm_client import LocalLLMClient
from agents.retrieval_agent import RetrievalAgent
from agents.rule_engine import RuleEvaluationEngine
from agents.simulation_agent import SimulationAgent
from agents.critic_agent import CriticAgent
from agents.loader import load_generated


class Orchestrator:
    """Hierarchical planner-worker orchestrator.

    Decomposes a run, routes tasks to the worker agents, co-ordinates the
    parallel reconciliation and generation arms, hands verified findings to the
    critic, and produces a ranked gap report for a named analyst.
    """

    def __init__(self, rulebook: list[Rule], typologies: list[Typology]):
        self.rulebook = rulebook
        self.typologies = typologies
        self.llm = LocalLLMClient()
        self.engine = RuleEvaluationEngine()
        self.retrieval = RetrievalAgent(rulebook, typologies, self.llm)
        self.simulation = SimulationAgent(self.engine, self.llm)
        self.critic = CriticAgent(self.engine, self.llm)

    def run(self, trigger: str = "scheduled", analyst: str = "A. Analyst",
            on_progress=None, abort_check=None, mode: str = "both",
            generated_typologies: Optional[list[Typology]] = None) -> RunState:
        """Run the pipeline. `on_progress` is an optional callback
        (phase: str, message: str) fired at each stage for live progress UI.
        `abort_check` is an optional zero-arg callable; when it returns True
        the run stops cleanly at the next phase boundary (status='aborted').

        `mode` selects which arms to execute: "documented" (known typologies),
        "generated" (novel catalogue), or "both". `generated_typologies` is the
        pool of GEN-* typologies used by the generation arm when supplied; when
        empty the legacy primitive-based generation runs instead."""
        def _progress(phase: str, message: str):
            if on_progress:
                on_progress(phase, message)

        def _aborted() -> bool:
            return bool(abort_check and abort_check())

        run_id = f"run-{uuid.uuid4().hex[:8]}"
        state = RunState(
            run_id=run_id,
            rulebook_version=f"{self.rulebook[0].id}..{self.rulebook[-1].id} · {len(self.rulebook)} rules" if self.rulebook else "unknown",
        )
        state.rulebook = self.rulebook
        state.typologies = self.typologies
        state.append_log("orchestrator", f"Run {run_id} triggered by '{trigger}'·{mode}. LLM backend available: {self.llm.available()}")
        _progress("ingest", f"Run {run_id} triggered · loading rulebook & corpora")
        if _aborted():
            return self._abort(state)

        do_documented = mode in ("documented", "both")
        do_generated = mode in ("generated", "both")

        # Build a map of fixtures by typology for the critic's re-run.
        fixtures_by_typology = {
            t.id: t.test_fixtures for t in self.typologies if t.test_fixtures
        }
        gen_pool = generated_typologies or self._legacy_generation_pool()
        for t in gen_pool:
            if t.test_fixtures:
                fixtures_by_typology[t.id] = t.test_fixtures

        rec_findings: list[dict] = []
        gen_findings: list[dict] = []
        if do_documented:
            _progress("reconcile", "Reconciliation arm · stepping documented typologies through the rulebook")
            rec_findings = self.simulation.run_reconciliation(self.typologies, self.rulebook)
            if _aborted():
                return self._abort(state)
        if do_generated:
            _progress("generate", "Generation arm · testing invented (novel) evasions against the rulebook")
            gen_findings = (self.simulation.run_scan(gen_pool, self.rulebook, mode="generated")
                            if gen_pool else self.simulation.run_generation(self.rulebook))
            if _aborted():
                return self._abort(state)
        msg_bits = [f"Reconciliation produced {len(rec_findings)} gap candidates" if do_documented else None,
                    f"Generation produced {len(gen_findings)} novel candidate(s)" if do_generated else None]
        state.append_log("simulation",
                         "; ".join(b for b in msg_bits if b) + ".",
                         reconciliation=len(rec_findings), generation=len(gen_findings))
        _progress("generate_meta",
                  f"{'Known-fraud scan → ' + str(len(rec_findings)) + ' candidates' if do_documented else ''}"
                  f"{' · ' if do_documented and do_generated else ''}"
                  f"{'Invented-fraud scan → ' + str(len(gen_findings)) + ' novel' if do_generated else ''}")

        all_candidates = rec_findings + gen_findings

        # --- Critic independently re-tests every claim (granular progress) ---
        _progress("critic", "Critic verifying every claimed gap · discarding non-reproducible findings")
        confirmed = []
        discarded = []
        for i, cand in enumerate(all_candidates, 1):
            if _aborted():
                return self._abort(state)
            _progress("critic", f"Verifying claim {i}/{len(all_candidates)} · {cand.get('typology_name', cand['typology_id'])}")
            verified = self.critic.verify(
                cand,
                self.rulebook,
                fixtures_by_typology=fixtures_by_typology,
                known_gaps=[t.id for t in self.typologies],
            )
            if verified["verified"]:
                confirmed.append(verified)
            else:
                discarded.append(verified)
            name = cand.get("typology_name", cand["typology_id"])
            state.append_log(
                "critic",
                f"Verified '{name}' independently: "
                f"reproduced={verified['reproduced']}, plausible={verified['plausible']}"
                f" → {'confirmed' if verified['verified'] else 'discarded'}",
                typology_id=cand["typology_id"],
            )

        state.discarded = discarded
        state.append_log("critic",
                         f"Critic confirmed {len(confirmed)} of {len(all_candidates)} candidates; "
                         f"{len(discarded)} discarded.",
                         confirmed=len(confirmed), discarded=len(discarded))
        _progress("critic_meta",
                  f"Critic confirmed {len(confirmed)} of {len(all_candidates)} · {len(discarded)} discarded")

        # --- Draft candidate red flags (retrieval/LLM assist) for confirmed gaps ---
        # Independent per-finding, so drafted in parallel to keep wall-clock down
        # even on a slow local model. Progress counter + abort check.
        _progress("draft", "Drafting candidate red flags for verified gaps")

        def _draft(cand: dict) -> None:
            t = self._find_typology(cand["typology_id"])
            if t:
                evaded_rule_objs = [r for r in self.rulebook if r.id in cand.get("evaded_rules", [])]
                cand["drafted_candidate_red_flag"] = self.retrieval.draft_candidate_red_flag(t, evaded_rule_objs)
            else:
                # Generation-arm novelty: draft from the self-description.
                name = cand.get("typology_name", "novel evasion")
                evaded_rule_objs = [r for r in self.rulebook if r.id in cand.get("evaded_rules", [])]
                cand["drafted_candidate_red_flag"] = (
                    f"Novel pattern '{name}' evades existing indicators "
                    f"({'; '.join(r.id for r in evaded_rule_objs)}); candidate indicator: "
                    f"flag activity exhibiting {', '.join(cand.get('techniques', [])[:3])} "
                    f"which current rules do not explicitly detect. Submit for expert plausibility review."
                )

        draft_counter = {"done": 0}
        draft_lock = threading.Lock()
        total_drafts = len(confirmed)

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = {pool.submit(_draft, cand): cand for cand in confirmed}
            pending = list(futures)
            while pending:
                if _aborted():
                    for fut in pending:
                        fut.cancel()
                    return self._abort(state)
                done, _ = wait(pending, timeout=0.5, return_when=FIRST_COMPLETED)
                if not done:
                    continue
                for fut in done:
                    fut.result()
                    pending.remove(fut)
                    with draft_lock:
                        draft_counter["done"] += 1
                    _progress("draft",
                              f"Drafting flag {draft_counter['done']}/{total_drafts}")
        _progress("draft", f"Drafted {len(confirmed)} candidate red flags")

        # --- Build ranked gap report, handed to the analyst (human approval gate) ---
        for cand in confirmed:
            trace = self._build_trace(cand)
            funding = GapFinding(
                typology_id=cand["typology_id"],
                typology_name=cand["typology_name"],
                evaded_rules=cand.get("evaded_rules", []),
                fired_rules=cand.get("fired_rules", []),
                mitre_atlas=cand.get("mitre_atlas", []),
                evidential_basis=cand.get("evidential_basis", "documented typology"),
                drafted_candidate_red_flag=cand.get("drafted_candidate_red_flag", ""),
                verified=True,
                trace=trace,
                mode=cand.get("mode", "documented"),
            )
            state.results.append(funding)

        state.status = "awaiting_human_approval"
        state.append_log(
            "report",
            f"Ranked gap report of {len(state.results)} verified finding(s) delivered to analyst '{analyst}' "
            f"for acceptance/amendment/rejection (human approval gate).",
            analyst=analyst,
        )
        _progress("report",
                  f"Ranked gap report of {len(state.results)} verified findings delivered to {analyst}")
        return state

    def _abort(self, state: RunState) -> RunState:
        state.status = "aborted"
        state.append_log("orchestrator", "Run aborted by analyst before completion.")
        return state

    def _find_typology(self, typology_id: str) -> Optional[Typology]:
        for t in self.typologies:
            if t.id == typology_id:
                return t
        return None

    def _legacy_generation_pool(self) -> list[Typology]:
        """Fallback generation pool from data/generated_typologies.json (GEN-*)."""
        return load_generated()

    def _build_trace(self, cand: dict) -> list[dict]:
        """The 'what the agent did' replayable story for one confirmed finding."""
        name = cand.get("typology_name", cand.get("typology_id", "this scam"))
        fired = cand.get("fired_rules", [])
        evaded = cand.get("evaded_rules", [])
        novel = cand.get("novel") or cand.get("mode") in ("generation", "generated")
        vocab = " ".join(cand.get("techniques", []) + [name]).lower()
        relevant = sum(
            1 for r in self.rulebook
            if SimulationAgent._rule_relevant(r, vocab)
        )
        return [
            {
                "agent": "retriever",
                "msg": (f"Looked through the rulebook for the rules that should cover '<b>{html.escape(name)}</b>' "
                        f"by matching this scam's methods against each rule's language — {relevant} rule(s) "
                        f"were in scope and tracked closely."),
            },
            {
                "agent": "simulator",
                "msg": (f"Ran a realistic simulation of this scam through every rule. "
                        f"<b>{len(fired)}</b> rule(s) fired and sounded an alarm, but <b>{len(evaded)}</b> "
                        f"did not notice it — the scam walked straight past them."
                        if not novel else
                        f"Imagined this attack from raw AI-fraud building blocks (no published report has "
                        f"named it yet) and ran it through every rule. <b>{len(fired)}</b> rule(s) fired, "
                        f"<b>{len(evaded)}</b> let it through."),
            },
            {
                "agent": "critic",
                "msg": ("Re-tested the exact same scenario from scratch, independently. "
                        "The missed rules genuinely missed — so this is treated as a real, "
                        "reproducible gap rather than a fluke."),
            },
            {
                "agent": "drafter",
                "msg": "Wrote the candidate red-flag indicator below for you to accept, amend or reject.",
            },
        ]
