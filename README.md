# Rulebook Drift Monitor

A horizon-scanning **agentic system** for the Financial Intelligence Centre (FIC) and the Financial Sector Conduct Authority (FSCA) that continuously **stress-tests the crypto AML/KYC rulebook** against both documented and self-generated fraud typologies, and hands each **verified detection gap** to a named analyst as a **drafted candidate red flag**.

> Hackathon demo (CDIR Global 'Agentic Regulator' Hackathon). Bounded slice: a machine-readable extract of the CASP rulebook (FIC red-flag indicators, Directive 9, FATF virtual-asset indicators) plus a curated set of documented crypto typologies. Not legal advice.
>
> **All data is synthetic/illustrative** — the DS rulebook is a paraphrased demonstration schema (verify against source before production use); fixtures contain no personal data.

---

## What it does (one run)

1. A run is triggered (scheduled / event / manual).
2. **Reconciliation arm**: a retrieval agent grounds the run in authoritative sources; a simulation agent instantiates each documented typology as a structured synthetic scenario and steps it through the rulebook rule by rule, recording which indicators **fire** and which are **evaded**.
3. **Generation arm**: the same simulation agent reasons from AI capability primitives to spawn candidate evasion paths that no published report has yet named.
4. **Critic agent** (independent — no agent marks its own work) re-tests every claimed gap with the deterministic engine and **discards** what it cannot reproduce or judges implausible.
5. A **ranked gap report** is delivered to a named analyst, each entry citing its evidential basis, the specific rule it defeats, its MITRE ATLAS mapping, and a **drafted candidate red flag**.
6. **Human approval gate**: nothing is promoted into guidance without a named analyst accepting / amending / rejecting.

---

## Agent architecture

| Role | Responsibility |
|------|----------------|
| **Orchestrator** | Decomposes the run, routes tasks, co-ordinates the two parallel arms, produces the report. |
| **Retrieval agent** | Grounds the system: surfaces relevant rules for each typology, selects threat intel, drafts candidate red flags. |
| **Simulation agent** | Two modes: reconciliation (documented typologies) + generation (novel evasion paths). |
| **Critic agent** | Independent verifier; re-runs every claim deterministically, discards non-reproducible / implausible findings. |

The **rule-evaluation engine** is the deterministic core: it steps a synthetic transaction fixture through each rule and records firing/evasion. This gives reproducible, auditable results independent of LLM output.

---

## Repository layout

```
rulebook_drift_monitor/
├── data/
│   ├── rulebook.json         # Drift Sentinel DS-01..DS-40 rulebook (FATF / FIC / Directive 9 / TFS)
│   ├── rulebook.base.json    # shipped-baseline snapshot for one-click rollback of amendments
│   ├── typologies.json       # 35 documented fraud typologies (TYP-001..035) with fixtures + sources
│   ├── run_history.json      # recorded drift checkpoints (auto per run + manual) → measured forecast
│   ├── instituted.json       # institutionalised indicators + covered typologies (created on first institute)
│   └── drafted_flags.json    # pre-seeded red-flag cache (LLM-produced, makes replay instant)
├── agents/
│   ├── models.py             # shared state store + data models (Rule/Typology/RunState)
│   ├── llm_client.py         # local Ollama OR hosted OpenAI-compatible endpoint
│   ├── rule_engine.py        # deterministic predicate-based rule-evaluation engine (per-rule triggers)
│   ├── retrieval_agent.py    # retrieval + red-flag drafting
│   ├── simulation_agent.py   # reconciliation + generation arms
│   ├── critic_agent.py       # independent verifier / discard logic
│   ├── rule_amendment.py     # the institute loop: generate DS-{41+} indicator, cover gaps, rollback
│   ├── probe.py              # adversarial red-team probe (poisoned-typology injection test)
│   ├── draft_cache.py        # seeded drafted-flags cache (demo-data, LLM-produced)
│   ├── forecaster.py         # drift analytics: library scan, drift index, measured-history projection + backtest
│   ├── orchestrator.py       # hierarchical planner-worker orchestration (live progress hooks, abort support)
│   ├── workflow.py           # LangGraph state-graph build
│   └── loader.py             # JSON data loading
├── demo/
│   ├── run.py                # CLI report (python3 -m demo.run)
│   ├── web.py                # Flask API + async background run worker (threaded, aborts cleanly)
│   └── static/
│       ├── index.html        # Run Console (animated pipeline, live trace, review tabs, diff badges, institute button, probe, dossier export)
│       ├── dashboard.html    # Dashboard (KPIs, rulebook profile, evasion heatmap, amendments, forecast snapshot, reset)
│       ├── rules.html        # Rules Catalog (search/filter browse + detail drawer, ✦ badges for instituted rules)
│       ├── forecast.html     # Forecast (measured-history projection + band/backtest, checkpoint recording)
│       ├── css/app.css       # professional light-enterprise stylesheet (sidebar shell)
│       └── js/app.js         # shared nav/status/toast/API helper + chart helpers (incl. chart + heatmap)
├── scripts/
│   ├── export_live.py        # export the current run to live_run.json (for the handout PDF)
│   ├── seed_history.py       # seed data/run_history.json with 7 measured prior review states
│   └── seed_drafted_flags.py # produce data/drafted_flags.json via the live LLM (slow, one-off)
├── docs/
│   ├── make_handout.py       # builds the meeting-handout PDF (incl. live output + forecast section)
│   └── Rulebook_Drift_Monitor_Meeting_Handout.pdf
└── live_run.json             # exported latest run (findings + discarded)
```

---

## Setup

Requires **Python 3.9+**. A local LLM is optional but recommended for drafted red flags.

```bash
# 1. Local LLM (Ollama) — optional, free, runs offline
brew install ollama
ollama serve &
ollama pull llama3.2:1b        # or a bigger model if you have RAM/disk

# 2. Python dependencies
pip install langgraph langchain langchain-openai langchain-community flask
```

The system degrades gracefully: if no model is available it uses deterministic drafting templates, so the demo never breaks.

### Hosted LLM for serverless deployments (Vercel)

On Vercel there is no local Ollama, so the generation arm would silently fall back to
hardcoded scenarios. To give the deployed site a real LLM, set these environment
variables in **Vercel → Project → Settings → Environment Variables** (using a hosted
OpenAI-compatible endpoint; a free Groq key works):

```
LLM_BASE_URL=https://api.groq.com/openai/v1
LLM_MODEL=groq/compound-mini
LLM_API_KEY=<your key>
```

Locally (Ollama) requires no env vars — it uses `http://localhost:11434` / `llama3.2:1b`
by default, and if that model isn't installed the client automatically picks the
smallest available one so local just works. Set `LLM_BACKEND=ollama` to force the
local backend even when hosted credentials are present in `.env` (fully offline demo).
The hosted endpoint is only used when `LLM_BASE_URL` **and** `LLM_API_KEY` are both set
and `LLM_BACKEND` is not `ollama`.

**Speed note:** on CPU-only machines (e.g. Intel Macs) the local `llama3.2:1b`
generates at ~1 token/sec, so a full run can take several minutes and often
times out against the default 45s local ceiling. For fast, genuinely
AI-generated threats use the hosted path instead — copy `.env.example` to
`.env`, fill in `LLM_API_KEY` (and `LLM_BASE_URL` / `LLM_MODEL` if needed), and
the app picks it up automatically on import. The local path fails fast and
falls back to the varied scenario pool when the model can't keep up.

---

## Run

From `rulebook_drift_monitor/`:

```bash
# CLI ranked gap report
python3 -m demo.run
python3 -m demo.run --audit        # include full audit trail
python3 -m demo.run --json         # raw JSON state
python3 -m demo.run --analyst "N. Analyst" --trigger event

# Web demo with human-in-the-loop approval workflow
python3 -m demo.web                # open http://127.0.0.1:5000
```

## Web platform (professional UI)

Four pages, single Flask server, professional light-enterprise design (sidebar nav, no gradients):

| Page | Route | Purpose |
|------|-------|---------|
| Dashboard | `/dashboard.html` | KPIs (coverage, drift index, verified gaps, AI-evasion pressure), rulebook profile, rule-mix & AI break-downs, **typology × category evasion heatmap**, institutionalised-indicator strip, forecast snapshot, architecture strip, reset state |
| Run Console | `/index.html` | Animated async pipeline with per-claim/per-finding live progress, findings tabs (All/Accepted/Amended/Rejected/Undecided), **NEW/REPEAT diff vs last run**, Accept/Amend/Reject, **Institute rule** (the amendment loop), **red-team probe panel**, **compliance dossier export (JSON/PDF)**, decision-aware status, reset + clean abort |
| Rules Catalog | `/rules.html` | Search/filter browse of all DS rules with the full schema in a detail drawer + **✦ instituted** badges and amendments banner |
| Forecast | `/forecast.html` | Drift-index projection (dates + cycle labels), confidence band, hold-out backtest, at-risk typologies, coverage by category, record-checkpoint button |

API: `/api/state`, `/api/run`, `/api/decide`, `/api/institute`, `/api/reset` (idle clear, baseline rollback, or clean abort of a live run), `/api/record` (manual forecast checkpoint), `/api/probe` (red-team injection test), `/api/dossier` + `/api/dossier.pdf` (compliance export), `/api/rules`, `/api/dashboard`, `/api/forecast`. Runs execute in a background thread; the UI polls and animates the genuine pipeline stages as the agents work. A typical run reconciles all 35 typologies + novel-generation candidates (~37 findings) in well under a minute when red flags are pre-seeded (`data/drafted_flags.json`); without the cache it takes ~2–4 min on a local 1B model (parallel drafting, 8 workers).

---

## The amendment loop (institutionalising approved findings)

Closing a verified gap is the whole point of the platform, so an approved finding can be **institutionalised** with one click:

1. The analyst approves a finding and clicks **Institute rule**.
2. `agents/rule_amendment.py` derives the typology's behavioural signature — the `(field, value)` pairs common to **all** of its synthetic fixtures — and generates a dedicated **DS-{41+} indicator** whose trigger predicate fires when that exact signature is present.
3. A deterministic **self-check** re-runs the new indicator over the typology's fixtures; if it fails to reproduce on ≥ half of them, the amendment is rejected and never committed.
4. Committed amendments persist to `data/rulebook.json` + `data/instituted.json`. The typology is **covered**: its freed pairs now count as *fired*, so **coverage rises and Drift Index falls**, and a **post-amendment checkpoint** is appended to the forecast history so the projection re-measures immediately (measured here: closing 6 gaps moved Drift 54.6 → 51.2).
5. Covered typologies are **excluded from the next reconciliation scan** (gap backlog reduced), so follow-up runs report the remaining live gaps — visible as the diff running down.
6. **Reset** restores the shipped DS-01..DS-40 baseline (`data/rulebook.base.json`) and removes instituted indicators in one shot (demo idempotency).

The same affordance demonstrates governance: no rule enters the rulebook without an analyst decision, a reproduction check, and an audit-trail entry naming the adjudicating analyst.

---

## Mandatory guardrails (demonstrated)

| Guardrail | How it is implemented |
|-----------|----------------------|
| **Human-in-the-loop** | Hard approval gate: analyst accepts / amends / rejects every drafted red flag; web UI implements this. |
| **Auditability & traceability** | Structured state store + append-only audit trail linking each gap to its evidence, rules, ATLAS mapping and the adjudicating analyst. |
| **Safety & governance controls** | Independent critic discards implausible/non-reproducible findings; institutionalisation requires an analyst decision + deterministic reproduction self-check; generation held at the level of regulatory indicators, not operational attack detail. |
| **Cyber risk management** | Permissioned tool access; confined to the rulebook/typology corpora; all data public or synthetic (no personal data). **Live adversarial probe** (`agents/probe.py`) injects a poisoned typology (prompt-injection payload + over-claimed evasion set) and shows the critic rejecting the attack in the Run Console. |

---

## Evaluation approach

- **Seeded rulebook** with known gaps (extend `data/rulebook.json` + `data/typologies.json`) to measure recall / false-positive rate.
- **Back-testing**: generator re-discovers known historical gaps it was not shown.
- **Expert plausibility review** for novel generation-arm findings.
- **Adversarial red-team**: run a live probe in the Run Console — the platform is handed a poisoned typology that smuggles a prompt-injection payload and over-claims its evasion set; the critic re-runs the engine and unreproducible claims are rejected on screen.
- **Forecast overlay** (`agents/forecaster.py` + `/api/forecast`): deterministic library scan → Drift Index, AI-evasion pressure share, at-risk ranking. The projection is **measured-history-driven**: every completed run (and manual checkpoint) is recorded to `data/run_history.json`; with 3+ points a damped trend fits the real drift series (least-squares slope combined with the measured AI-evasion rate), with a confidence band and rolling-origin hold-out backtest (MAD/MAPE/bias). Below 3 points it falls back to a clearly-labelled library-scan baseline.
