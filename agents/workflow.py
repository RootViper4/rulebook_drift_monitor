from __future__ import annotations

from typing import Any, TypedDict

from agents.models import Rule, RunState, Typology
from agents.rule_engine import RuleEvaluationEngine
from agents.retrieval_agent import RetrievalAgent
from agents.simulation_agent import SimulationAgent
from agents.critic_agent import CriticAgent


class GraphState(TypedDict, total=False):
    rulebook: list[Rule]
    typologies: list[Typology]
    run_state: RunState
    candidates: list[dict]
    confirmed: list[dict]


def build_graph():
    """Build a LangGraph workflow for the Rulebook Drift Monitor.

    Nodes: ingest -> reconcile (parallel) -> generate -> critic -> draft -> report.
    This mirrors the orchestrator but as an explicit graph, demonstrating the
    agentic orchestration and the human-in-the-loop reporting boundary.
    """
    from langgraph.graph import END, START, StateGraph

    from agents.models import GapFinding

    def node_ingest(state: GraphState) -> GraphState:
        rs = state["run_state"]
        rs.append_log("graph.ingest", f"Loaded {len(state['rulebook'])} rules, {len(state['typologies'])} typologies.")
        return {"candidates": [], "confirmed": []}

    def node_reconcile(state: GraphState) -> GraphState:
        rs = state["run_state"]
        sim = SimulationAgent(RuleEvaluationEngine())
        from agents.llm_client import LocalLLMClient
        sim.llm = LocalLLMClient()
        candidates = sim.run_reconciliation(state["typologies"], state["rulebook"])
        rs.append_log("graph.reconcile", f"Reconciliation produced {len(candidates)} candidate(s).")
        return {"candidates": candidates}

    def node_generate(state: GraphState) -> GraphState:
        rs = state["run_state"]
        sim = SimulationAgent(RuleEvaluationEngine())
        gen = sim.run_generation(state["rulebook"])
        rs.append_log("graph.generate", f"Generation produced {len(gen)} novel candidate(s).")
        existing = state.get("candidates", [])
        return {"candidates": existing + gen}

    def node_critic(state: GraphState) -> GraphState:
        rs = state["run_state"]
        engine = RuleEvaluationEngine()
        critic = CriticAgent(engine)
        confirmed = []
        for cand in state.get("candidates", []):
            verified = critic.verify(cand, state["rulebook"],
                                     fixtures_by_typology={
                                         t.id: t.test_fixtures for t in state["typologies"] if t.test_fixtures
                                     },
                                     known_gaps=[t.id for t in state["typologies"]])
            if verified["verified"]:
                confirmed.append(verified)
        rs.append_log("graph.critic", f"Critic confirmed {len(confirmed)}/{len(state.get('candidates', []))}.")
        return {"confirmed": confirmed}

    def node_draft(state: GraphState) -> GraphState:
        rs = state["run_state"]
        from agents.llm_client import LocalLLMClient
        retrieval = RetrievalAgent(state["rulebook"], state["typologies"], LocalLLMClient())
        for cand in state.get("confirmed", []):
            t = next((x for x in state["typologies"] if x.id == cand["typology_id"]), None)
            if t:
                evaded_objs = [r for r in state["rulebook"] if r.id in cand.get("evaded_rules", [])]
                cand["drafted_candidate_red_flag"] = retrieval.draft_candidate_red_flag(t, evaded_objs)
        return {"confirmed": state.get("confirmed", [])}

    def node_report(state: GraphState) -> GraphState:
        rs = state["run_state"]
        findings = [
            GapFinding(
                typology_id=c["typology_id"], typology_name=c["typology_name"],
                evaded_rules=c.get("evaded_rules", []), fired_rules=c.get("fired_rules", []),
                mitre_atlas=c.get("mitre_atlas", []), evidential_basis=c.get("evidential_basis", ""),
                drafted_candidate_red_flag=c.get("drafted_candidate_red_flag", ""), verified=True,
            )
            for c in state.get("confirmed", [])
        ]
        rs.results = findings
        rs.status = "awaiting_human_approval"
        rs.append_log("graph.report", f"Ranked gap report of {len(findings)} verified finding(s) delivered.")
        return {"run_state": rs}

    g = StateGraph(GraphState)
    g.add_node("ingest", node_ingest)
    g.add_node("reconcile", node_reconcile)
    g.add_node("generate", node_generate)
    g.add_node("critic", node_critic)
    g.add_node("draft", node_draft)
    g.add_node("report", node_report)

    from langgraph.graph import END, START
    g.add_edge(START, "ingest")
    g.add_edge("ingest", "reconcile")
    g.add_edge("reconcile", "generate")
    g.add_edge("generate", "critic")
    g.add_edge("critic", "draft")
    g.add_edge("draft", "report")
    g.add_edge("report", END)

    return g.compile()
