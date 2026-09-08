from __future__ import annotations

import json
import os
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

CAPABILITY_PRIMITIVES_FIXTURES_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "fixtures.capability_primitives.json",
)


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
            on_progress=None, abort_check=None) -> RunState:
        """Run the pipeline. `on_progress` is an optional callback
        (phase: str, message: str) fired at each stage for live progress UI.
        `abort_check` is an optional zero-arg callable; when it returns True
        the run stops cleanly at the next phase boundary (status='aborted')."""
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
        state.append_log("orchestrator", f"Run {run_id} triggered by '{trigger}'. LLM backend available: {self.llm.available()}")
        _progress("ingest", f"Run {run_id} triggered · loading rulebook & corpora")
        if _aborted():
            return self._abort(state)

        # Build a map of fixtures by typology for the critic's re-run.
        fixtures_by_typology = {
            t.id: t.test_fixtures for t in self.typologies if t.test_fixtures
        }

        # --- Two arms run in parallel: reconciliation + generation ---
        # Reconciliation arm = "Known Attacks" tab: the 12 documented AI
        # capability-primitive attacks stepped through the rulebook (not the
        # legacy 35-typology corpus - kept in data/typologies.json and
        # SimulationAgent.run_reconciliation for other tooling, but no longer
        # the review UI's reconciliation data source).
        _progress("reconcile", "Reconciliation arm · stepping the 12 capability-primitive attacks through the rulebook")
        rec_findings = self.simulation.run_capability_primitive_reconciliation(
            self.rulebook, CAPABILITY_PRIMITIVES_FIXTURES_PATH, abort_check=_aborted
        )
        if _aborted():
            return self._abort(state)
        _progress("generate", "Generation arm · spawning novel AI evasion paths")
        gen_findings = self.simulation.run_generation(self.rulebook, abort_check=_aborted)
        if _aborted():
            return self._abort(state)
        gen_source_counts: dict[str, int] = {}
        for f in gen_findings:
            src = f.get("generation_source") or "unknown"
            gen_source_counts[src] = gen_source_counts.get(src, 0) + 1
        gen_source_summary = ", ".join(
            f"{count} {src}" for src, count in sorted(gen_source_counts.items())
        ) or "none"
        state.append_log("simulation",
                         f"Reconciliation produced {len(rec_findings)} gap candidates; "
                         f"generation produced {len(gen_findings)} novel candidate(s) "
                         f"({gen_source_summary}).",
                         reconciliation=len(rec_findings), generation=len(gen_findings),
                         generation_sources=gen_source_counts)

        # If every slot fell back, "available: True" at the top of the log
        # reads as a contradiction unless the reason is stated here too - it
        # is otherwise only visible per-row on the review page. De-duplicated
        # because the same cause (e.g. one bad model name) typically hits
        # every slot identically, and repeating it per-slot would just be
        # noise.
        fallback_reasons = sorted({
            f.get("fallback_reason") for f in gen_findings
            if f.get("generation_source") == "deterministic_fallback" and f.get("fallback_reason")
        })
        if fallback_reasons:
            state.append_log(
                "simulation",
                "Generation slot(s) fell back to hand-authored scenarios because: "
                + "; ".join(fallback_reasons),
            )
        _progress("generate_meta",
                  f"Reconciliation → {len(rec_findings)} candidates · generation → {len(gen_findings)} novel")

        # Convergence signal: when several independently-generated scenarios
        # argue the same underlying blind spot, that is evidence about the
        # RULEBOOK's coverage, not a fault in the generator - and it is a
        # stronger finding than the same scenarios read as unrelated
        # novelties. Measured across model-authored scenarios only; the
        # deterministic fallback pool is hand-authored to be distinct, so
        # including it would report a convergence that says nothing.
        llm_scenarios = [
            {"name": f.get("typology_name", ""), "techniques": f.get("techniques", [])}
            for f in gen_findings if f.get("generation_source") == "llm"
        ]
        convergence = self.simulation._detect_convergence(llm_scenarios)
        state.convergence = convergence
        if convergence:
            top = convergence[0]
            terms = ", ".join(top["shared_terms"][:6]) or "(no shared vocabulary)"
            state.append_log(
                "simulation",
                f"CONVERGENCE SIGNAL: {top['size']} of {len(llm_scenarios)} model-authored "
                f"scenarios independently describe the same blind spot (shared terms: "
                f"{terms}). Repeated independent arrival at one weakness is evidence about "
                f"the rulebook's coverage, not a duplicate finding - review these together.",
                convergence=convergence)
            _progress("generate_meta",
                      f"Convergence: {top['size']} scenarios point at one blind spot")

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

        state.discarded = discarded
        fully_verified_count = sum(1 for c in confirmed if c.get("fully_verified", True))
        partial_count = len(confirmed) - fully_verified_count
        partial_note = f" ({partial_count} flagged as partial-coverage - references fields not in the rulebook)" if partial_count else ""
        state.append_log("critic",
                         f"Critic confirmed {len(confirmed)} of {len(all_candidates)} candidates"
                         f"{partial_note}; {len(discarded)} discarded.",
                         confirmed=len(confirmed), discarded=len(discarded),
                         partial_coverage=partial_count)
        _progress("critic_meta",
                  f"Critic confirmed {len(confirmed)} of {len(all_candidates)} · {len(discarded)} discarded")

        # --- Draft candidate red flags (retrieval/LLM assist) for confirmed gaps ---
        # Independent per-finding, so drafted in parallel to keep wall-clock down
        # even on a slow local model. Progress counter + abort check.
        _progress("draft", "Drafting candidate red flags for verified gaps")

        def _draft(cand: dict) -> None:
            t = self._find_typology(cand["typology_id"])
            evaded_rule_objs = [r for r in self.rulebook if r.id in cand.get("evaded_rules", [])]
            if t:
                cand["drafted_candidate_red_flag"] = self.retrieval.draft_candidate_red_flag(t, evaded_rule_objs)
            elif cand.get("mode") == "reconciliation":
                # Capability-primitive reconciliation candidate: a documented
                # attack (CP-XX), not a typology-corpus entry and not a
                # self-generated novelty - word the draft accordingly.
                name = cand.get("typology_name", cand["typology_id"])
                if evaded_rule_objs:
                    cand["drafted_candidate_red_flag"] = (
                        f"Documented attack '{name}' is not adequately detected because the "
                        f"following indicator(s) do not fire: {'; '.join(r.name for r in evaded_rule_objs)}. "
                        f"Draft indicator: assess transactions/onboarding exhibiting this pattern, "
                        f"currently outside explicit coverage of the existing rulebook."
                    )
                else:
                    cand["drafted_candidate_red_flag"] = (
                        f"Documented attack '{name}' has no rule in the current corpus addressing it, "
                        f"even partially. Draft indicator: this needs a new, dedicated red flag - "
                        f"there is nothing existing to amend."
                    )
            else:
                # Generation-arm novelty: draft from the self-description.
                name = cand.get("typology_name", "novel evasion")
                cand["drafted_candidate_red_flag"] = (
                    f"Novel pattern '{name}' evades existing indicators covering "
                    f"{'; '.join(r.name for r in evaded_rule_objs)}; candidate indicator: "
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
            funding = GapFinding(
                typology_id=cand["typology_id"],
                typology_name=cand["typology_name"],
                evaded_rules=cand.get("evaded_rules", []),
                fired_rules=cand.get("fired_rules", []),
                mitre_atlas=cand.get("mitre_atlas", []),
                evidential_basis=cand.get("evidential_basis", ""),
                drafted_candidate_red_flag=cand.get("drafted_candidate_red_flag", ""),
                verified=True,
                mode=cand.get("mode", "reconciliation"),
                generation_source=cand.get("generation_source", ""),
                fallback_reason=cand.get("fallback_reason") or "",
                capability_primitives=cand.get("capability_primitives", []),
                fully_verified=cand.get("fully_verified", True),
                unmodeled_fields=cand.get("unmodeled_fields", []),
                unverified_atlas=cand.get("unverified_atlas", []),
                # Reconciliation candidates carry "fixtures" (one per
                # capability-primitive scenario); generation candidates carry a
                # single "fixture". Normalise to a list so the finding keeps the
                # evidence it was verified against.
                test_fixtures=[fx for fx in (cand.get("fixtures")
                                             or ([cand["fixture"]] if cand.get("fixture") else []))
                               if isinstance(fx, dict)],
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