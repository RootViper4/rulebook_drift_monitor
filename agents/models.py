from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Optional


@dataclass
class Rule:
    id: str
    source: str
    category: str
    name: str
    text: str
    keywords: list[str] = field(default_factory=list)
    # Professional Drift Sentinel schema fields (optional for backwards-compat).
    rule_type: str = "indicator"            # indicator | obligation | mixed
    trigger: str = ""                        # natural-language trigger/condition
    source_ref: str = ""                     # FATF 2020 p.xx / FIC Directive 9 para / FIC Act s.
    mitre_atlas: list[str] = field(default_factory=list)
    capability_primitives: list[str] = field(default_factory=list)
    risk_severity: str = "medium"            # low | medium | high | critical
    ai_relevant: bool = False                # whether the rule maps to AI-orchestrated evasion
    signal_signature: dict = field(default_factory=dict)   # (key,value) pairs; institutionalised rules
    trigger_schema: dict = field(default_factory=dict)     # structured all/any/not trigger tree; see agents/trigger_schema.py
    institutionalised: bool = False          # auto-generated from an approved review finding
    source_finding: str = ""                 # provenance: finding id / typology id


@dataclass
class Typology:
    id: str
    name: str
    source: str
    description: str
    techniques: list[str] = field(default_factory=list)
    mitre_atlas: list[str] = field(default_factory=list)
    test_fixtures: list[dict] = field(default_factory=list)
    risk_severity: str = "medium"
    expected_gap: str = ""


@dataclass
class TestCase:
    """A single synthetic transaction under test."""
    fixture: dict = field(default_factory=dict)


@dataclass
class RuleResult:
    rule_id: str
    fired: bool = False
    confidence: float = 0.0
    matched_keywords: list[str] = field(default_factory=list)
    rationale: str = ""
    evaded: bool = False


@dataclass
class GapFinding:
    typology_id: str
    typology_name: str
    evaded_rules: list[str] = field(default_factory=list)
    fired_rules: list[str] = field(default_factory=list)
    mitre_atlas: list[str] = field(default_factory=list)
    evidential_basis: str = ""
    drafted_candidate_red_flag: str = ""
    plausible: bool = True
    verified: bool = False
    trace: list = field(default_factory=list)
    # "reconciliation" (documented capability-primitive attacks stepped through
    # the rulebook) or "generation" (novel, unverified, self-generated evasion
    # hypotheses). Drives the two-tab split in the review UI - the two modes
    # must never be displayed as one merged list.
    mode: str = "reconciliation"
    # Provenance for generation-mode findings only: "llm" (the local model
    # composed this scenario), "deterministic_fallback" (model unavailable or
    # its output didn't parse), or "fixed_probe" (the always-appended
    # speculative case used to prove the critic's rejection path runs).
    # Blank for reconciliation-mode findings, where it doesn't apply.
    generation_source: str = ""
    # Why this slot fell back to a hand-authored scenario instead of a
    # model-written one — e.g. "model 'x' not found at this provider (404)".
    # Blank when generation_source is "llm" or "fixed_probe", where the
    # question does not apply.
    fallback_reason: str = ""
    # Which capability primitive(s) (CP-01..10) this finding composes, where
    # known. Blank list if not applicable/not identified.
    capability_primitives: list[str] = field(default_factory=list)
    # False when the critic downgraded this finding because its fixture
    # referenced field(s) not modelled anywhere in the rulebook
    # (SimulationAgent._sanitize_scenario's unmodeled_fields) - the finding
    # still reached the human gate (verified=True), but should be presented
    # as a coverage idea, not a fully rulebook-tested gap. True for every
    # reconciliation-mode finding and for generation findings with no
    # unmodelled fields.
    fully_verified: bool = True
    unmodeled_fields: list[str] = field(default_factory=list)
    # Tactic labels a generation-arm scenario proposed that are NOT
    # recognised MITRE ATLAS tactics (e.g. an ATT&CK-only term). Kept
    # separate from mitre_atlas so an unverified label is never rendered
    # as a real mapping. Empty for reconciliation findings.
    unverified_atlas: list[str] = field(default_factory=list)
    # The fixture(s) this finding was actually reproduced against, carried
    # through from the candidate dict. Reconciliation findings carry one entry
    # per capability-primitive fixture; generation findings carry the single
    # scenario fixture the critic re-ran.
    #
    # Without this, a finding arriving at the human gate had no evidence
    # attached, so institutionalising it could not run the deterministic
    # self-check that is supposed to prove the gap is closed - the fixtures
    # existed only inside the run and were discarded when the GapFinding was
    # built. Keeping them here is what lets the analyst act on a finding
    # later, including after the run has been rehydrated from disk.
    test_fixtures: list[dict] = field(default_factory=list)


@dataclass
class RunState:
    """Shared, structured state store for inter-agent communication."""
    run_id: str
    rulebook_version: str
    rulebook: list[Rule] = field(default_factory=list)
    typologies: list[Typology] = field(default_factory=list)
    results: list[GapFinding] = field(default_factory=list)
    discarded: list[dict] = field(default_factory=list)
    log: list[dict] = field(default_factory=list)
    status: str = "created"
    audit: list[dict] = field(default_factory=list)
    # Groups of generation-arm scenarios that independently converged on the
    # same underlying rulebook blind spot (see
    # SimulationAgent._detect_convergence). Each entry:
    # {"shared_terms", "scenario_names", "size"}. Empty when the run's novel
    # scenarios were genuinely distinct.
    convergence: list[dict] = field(default_factory=list)

    def append_log(self, node: str, message: str, **extra: Any) -> None:
        entry = {"node": node, "message": message, **extra}
        self.log.append(entry)
        self.audit.append({**entry, "ts": f"ts-{len(self.audit)+1}"})

    def dict(self) -> dict:
        return asdict(self)