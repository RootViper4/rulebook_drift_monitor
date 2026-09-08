# Rulebook Drift Monitor — Architecture

## Component / agent view

```mermaid
flowchart LR
    subgraph Trigger
        S[Schedule / Threat report / STR cluster] --> O[Orchestrator]
    end

    O --> RA[Retrieval agent]
    O --> SA[Simulation agent]

    subgraph "Rulebook corpus"
        R1[FIC red-flag indicators]
        R2[FIC Directive 9]
        R3[FATF virtual-asset indicators]
    end

    subgraph "Typology corpus"
        T1[FATF / Chainalysis / INTERPOL]
        T2[Sanitised STR material]
    end

    RA --> R1 & R2 & R3
    RA --> T1 & T2

    SA -->|"Mode A · reconciliation"| FIX[Documented typologies]
    SA -->|"Mode B · generation"| GEN[AI capability primitives]

    SA --> E[Rule-evaluation engine]
    SA --> AT[MITRE ATLAS mapper]

    RA & SA --> CRIT[Critic / verifier]
    CRIT -->|discard implausible| X[discarded]
    CRIT -->|verified gaps| DRAFT[Drafted candidate red flags]

    DRAFT --> AUTH[/Sign-in gate: role + session/]
    AUTH --> GATE{Human approval gate}
    GATE -->|accept / amend / reject| ANALYST[Named FIC / FSCA analyst]
    ANALYST --> TRAIL[(Append-only audit trail:<br/>who, role, session, timestamp, rationale)]
    ANALYST --> GUIDANCE[(Policy & guidance)]

    style GATE fill:#b3124a,color:#fff
    style AUTH fill:#fdf4e1
    style TRAIL fill:#eef2ff
    style CRIT fill:#eef2ff
    style E fill:#e9f7f0
```

## Detection-gap workflow (current vs proposed)

```mermaid
sequenceDiagram
    participant L as Criminals
    participant V as Victims
    participant P as Police / FATF / Interpol
    participant R as Regulator
    participant B as Banks (AML rules)
    participant M as Rulebook Drift Monitor

    Note over L,B: CURRENT (reactive) - months of lag
    L->>V: new AI-driven scam
    L->>B: loss occurs
    V->>P: report
    P-->>R: guidance notes (weeks/months)
    R-->>B: updated expectations
    B-->>B: manually update rules
    Note over B: protection improves, months later

    Note over L,M: PROPOSED (horizon-scanning) - compresses the lag
    L->>V: new AI-driven scam
    M->>M: reconciliation arm (documented typologies)
    M->>M: generation arm (novel evasion paths) + critic verify
    M->>R: ranked gap report + drafted candidate red flags (days)
    R->>R: analyst accepts / amends / rejects (human-in-the-loop)
    R-->>B: updated rulebook reflecting the gap
```

## LangGraph orchestration graph

```mermaid
flowchart LR
    START --> ingest
    ingest --> reconcile
    reconcile --> generate
    generate --> critic
    critic --> draft
    draft --> report
    report --> END
```

## Access control

The findings surface is an attack map, so it sits behind a sign-in. Only the landing page and the
sign-in page are public; every other page redirects and every API route returns 401 without a
session.

```mermaid
flowchart LR
    V[Visitor] --> HOME[home.html - public]
    HOME --> LOGIN[login.html]
    LOGIN -->|PBKDF2 verify + lockout| SESS[(Session: user, role, session id, CSRF token)]
    SESS -->|role = analyst| ACT[Run / accept / amend / reject / institute]
    SESS -->|role = observer| READ[Read findings and paper trail]
    ACT --> LOG[(decisions_log.json + audit.json:<br/>name, username, role, org, session, timestamps)]
    READ -.->|blocked action| DENY[access_denied written to the trail]
```
