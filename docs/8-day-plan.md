# Rulebook Drift Monitor — 8-Day Build Plan

**Submission deadline:** 8 September, 23:59 AOE (presentation deck + ≤3-min video demo + testable prototype on NayaOne GitLab).
**Demo Days:** 15–16 Sep (4-min pitch + 3-min video + 2-min Q&A). **Judging:** 17 Sep.

Today (31 Aug) we already have a **working end-to-end slice**: orchestrator → reconciliation + generation → critic → drafted red flags → human approval gate, with CLI + web demo. This plan hardens it into a submission-ready prototype.

---

## Current state (done today)
- ✅ Machine-readable rulebook (18 rules: FIC red flags, Directive 9, FATF indicators)
- ✅ Documented typology dataset (Ponzi, pig-butchering, mules, AI-voice phishing, synthetic identity, stablecoin structuring)
- ✅ Deterministic rule-evaluation engine (reproducible, auditable)
- ✅ LangGraph orchestration graph + orchestrator (parallel reconciliation/generation arms)
- ✅ Independent critic that discards non-reproducible/implausible findings
- ✅ MITRE ATLAS mapping
- ✅ LLM-assisted red-flag drafting via local Ollama (falls back deterministically)
- ✅ CLI report + web demo with human-in-the-loop approvals + audit trail
- ✅ Docs: README + architecture diagrams (Mermaid)

---

## Why this matters for the rubric (0–4 per dimension)
| Rubric dimension | How we score |
|---|---|
| Innovation & Approach | Novel: rulebook stress-testing against *self-generated* AI typologies, not just detection. |
| Policy, Regulatory & Supervisory Fit | Named workflow (market monitoring/horizon scanning → policy), named users (FIC/FSCA analyst), sector fit (SA crypto AML, Directive 9, FATF grey-list exit). |
| Technical Plausibility | Real LangGraph agents + deterministic engine + local LLM; deployable in short time. |
| Adoption Readiness & Guardrails | Live human-in-the-loop, audit trail, safety controls, cyber risk — all demonstrated in the demo. |

---

## Day-by-day plan

### Day 1 — Tue 1 Sep (Kick-off)
- **Team alignment** on roles; finalise the plan.
- **Expand rulebook** to the 30–40 rule bounded slice (add more FIC red-flag indicators + full Directive 9 obligations). Assign 1 person.
- **Init git repo** on NayaOne GitLab; add README, `.gitignore`, `requirements.txt`. Assign 1 person.
- **Shake out the demo** end-to-end; record a rough cut of the video.

### Day 2 — Wed 2 Sep (Knowledge clinic: AI in regulatory context)
- **Add more typologies** (target 12–15 documented) with richer test fixtures. Assign 1–2 people.
- **Embedding/RAG**: add a real vector store (ChromaDB/FAISS, free, local) over the two corpora for retrieval, replacing pure keyword scoring. Assign 1 person.
- **MITRE ATLAS mapper**: systematise technique→ATLAS mapping lookup. Assign 1 person.

### Day 3 — Thu 3 Sep (Knowledge clinic: Agentic AI)
- **Strengthen critic**: add back-testing (re-discover seeded historical gaps) + plausibility scoring. 
- **Evaluation harness**: seeded known-gap rulebook → measure recall & false-positive rate; detection lead-time vs manual baseline.
- **Safety & governance**: prompt-injection red-team on poisoned typology docs; add provenance/allow-list controls.

### Day 4 — Fri 4 Sep
- **Integration**: wire vector store + ATLAS mapper + evaluation harness into the workflow.
- **Guardrail hardening**: full audit trail schema; human-in-the-loop wired to a persisted decisions store.
- Interim demo checkpoint: `python3 -m demo.run` must still pass.

### Day 5 — Mon 7 Sep (Pitch clinic)
- **Presentation deck** (4-min template from NayaOne Resources): problem → solution → architecture → live demo → guardrails → impact.
- **Refine demo script** for the video (realistic scenario, input → agents → output → guardrails).
- Book/attend a **mentor session** (mandatory ≥1).

### Day 6 — Tue 8 Sep (Pitch clinic + SUBMISSION DEADLINE)
- **Record 3-min video demo** (end-to-end, guardrails in operation, downloadable, login-free).
- **Finalise prototype + README** (setup/run, architecture, third-party components + licences).
- **Submit ALL three deliverables** to NayaOne (Documents / Media / Sandpit→GitLab) before 23:59 AOE.

### Buffer / stretch (Sep 9–16, before Demo Day)
- Polish visuals, rehearse the 4-min pitch to the clock.
- Load-test demo reliability (degrade gracefully if the model or net is slow).
- Prepare answers for Q&A (data sources, dual-use, next steps to a supervised pilot).

---

## Task ownership (suggested)
| Owner | Responsibilities |
|---|---|
| **Dev A (you)** | Core engine, agents, workflow, integration lead. |
| **Dev B** | Data: rulebook + typology expansion, fixtures, vector store. |
| **Dev C** | MITRE ATLAS mapping + evaluation harness + back-testing. |
| **Dev D** | Web app polish, video demo, deployment to NayaOne Sandpit. |
| **Pitch/Product** | Presentation deck + demo narrative + guardrails story. |

Adjust ownership to your actual team size (you can combine roles for a smaller team).

---

## Risks & mitigations
| Risk | Mitigation |
|---|---|
| Local model too weak for polished drafting | Deterministic fallback + swap to hosted API key if available; keep generation at indicator level. |
| Disk/network constraints on build machines | All dep tooling is lightweight + local; document pinned versions. |
| Scope creep | We deliberately do NOT build live blockchain analytics, entity supervision, or fine-tuning. |
| Demo reliability on the day | Deterministic core is the source of truth; demo never depends on model availability. |
| Guardrail "checkboxes" not convincing | Every guardrail is demonstrated live in the video (human approval step + audit trail). |
