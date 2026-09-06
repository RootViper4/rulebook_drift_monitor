from __future__ import annotations

import json
from typing import Optional

from agents.models import Rule, RunState, Typology
from agents.llm_client import LocalLLMClient


class RetrievalAgent:
    """Grounds the system in authoritative sources.

    Two corpora:
      - rulebook corpus (versioned FIC / Directive 9 / FATF indicators)
      - typology corpus (documented fraud typologies)
    Retrieval here is keyword/deterministic scoring over the in-memory corpus,
    with optional LLM assist for interpretation / drafting.
    """

    def __init__(self, rulebook: list[Rule], typologies: list[Typology], llm: Optional[LocalLLMClient] = None):
        self.rulebook = rulebook
        self.typologies = typologies
        self.llm = llm

    def retrieve_rules_for_typology(self, typology: Typology) -> list[Rule]:
        """Return rules most relevant to a typology, ranked by keyword overlap."""
        hay = " ".join(typology.techniques + [typology.name, typology.description]).lower()
        scored = []
        for rule in self.rulebook:
            hits = sum(1 for k in rule.keywords if k in hay)
            scored.append((hits, rule))
        scored.sort(key=lambda x: -x[0])
        return [r for _, r in scored]

    def select_threat_intel(self, query: str) -> Optional[str]:
        """Surface the most relevant typology for an incoming intelligence query."""
        q = query.lower()
        best = None
        best_score = 0
        for t in self.typologies:
            pool = " ".join(t.techniques + [t.name, t.source, t.description]).lower()
            score = sum(1 for word in q.split() if word in pool)
            if score > best_score:
                best_score, best = score, t
        return best.id if best else None

    def draft_candidate_red_flag(self, typology: Typology, evaded: list[Rule]) -> str:
        """Draft a candidate red-flag indicator for a verified gap.

        Uses the LLM to draft regulatory language when available, otherwise a
        deterministic template fills in (so the demo never breaks).
        """
        rule_names = "; ".join(r.name for r in evaded)
        fallback = (
            f"Customer engages in activity consistent with '{typology.name}' "
            f"that is not adequately detected because the following indicator(s) "
            f"do not fire: {rule_names}. Draft indicator: assess transactions "
            f"exhibiting {', '.join(typology.techniques[:3])}, currently outside "
            f"explicit coverage of the existing rulebook."
        )
        # Pre-seeded demo flags (produced by this same LLM call) make replay
        # instant; live generation stays the default when the cache is absent.
        from agents.draft_cache import get_draft
        cached = get_draft(typology.id)
        if cached:
            return cached
        if not self.llm or not self.llm.available():
            return fallback
        prompt = (
            "You are a licensed financial-crime typologies analyst writing internal "
            "AML surveillance guidance for a financial regulator to help PROTECT "
            "consumers. This is a defensive, legitimate regulatory task. Draft ONE "
            "concise, professional candidate screening indicator (a single sentence) "
            "describing observable transaction/account signals that a compliance "
            "team should watch for, to detect and STOP fraud. Do not describe how to "
            "commit the fraud; only describe the detection signals. "
            "Signals to cover: {tech}. Reply with the indicator sentence only."
        ).format(tech=", ".join(typology.techniques[:4]))
        out = self.llm.complete(prompt, temperature=0.2, max_tokens=140)
        if out and self._looks_like_a_refusal(out):
            return fallback
        return out.strip() if out else fallback

    @staticmethod
    def _looks_like_a_refusal(text: str) -> bool:
        lowered = text.lower()
        markers = [
            "can't assist", "cannot assist", "i can't", "i cannot",
            "won't help", "i'm sorry", "i am sorry", "not able to",
            "might facilitate", "may facilitate", "illegal activities",
            "anything else i can help", "it is not appropriate",
        ]
        return any(m in lowered for m in markers)
