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
    # Which capability primitive(s) (CP-01..10) this finding composes, where
    # known. Blank list if not applicable/not identified.
    capability_primitives: list[str] = field(default_factory=list)


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

    def append_log(self, node: str, message: str, **extra: Any) -> None:
        entry = {"node": node, "message": message, **extra}
        self.log.append(entry)
        self.audit.append({**entry, "ts": f"ts-{len(self.audit)+1}"})

    def dict(self) -> dict:
        return asdict(self)