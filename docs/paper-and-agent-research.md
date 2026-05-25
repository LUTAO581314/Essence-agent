# Paper And Agent Research Synthesis

This document summarizes the research doctrine behind ESSENCE's agent design.
The source material is a mix of paper-inspired notes, upstream system studies,
and first-principles analysis of what LLM-native agent infrastructure needs.

## Core Claim

An agent should not give an LLM unconstrained freedom. It should give the model
a body, memory, boundary, rhythm, and feedback loop.

The goal is to translate:

- the world into structured state, signals, relations, risks, and missing
  information;
- human intent into contracts, constraints, success criteria, and reversible
  deltas;
- model output into proposed actions, approvals, sandboxed execution, proofs,
  ledger events, and recoverable state.

## Research-Derived Primitives

| Primitive | Meaning | Current or future location |
| --- | --- | --- |
| `Intent` | structured human desire, constraints, taste, success criteria, owner | current `moxi-contracts::Intent`, future richer compiler |
| `WorldDelta` | proposed world change with evidence, risk, and rollback shape | current `moxi-contracts::WorldDelta` |
| `Capability` | affordance with schema, permission, cost, and failure mode | current `CapabilityContract`, future plugin/capability packs |
| `RunContract` | bounded execution agreement with budget and required capabilities | current `RunContract` |
| `ExecutionTicket` | kernel-issued authority to execute one approved action | current `ExecutionTicket` |
| `Proof` | external evidence that a claim/result is valid | current `Proof` |
| `LedgerEvent` | append-only record of what happened and why | current `LedgerEvent` |
| `Heartbeat` | resumable execution window: restore, orient, act, verify, persist, sleep | partial through heartbeats/budgets; future scheduler runtime |
| `MemoryCrystal` | source-tracked memory with fact, relation, confidence, decay, and recall path | future memory runtime |
| `SwarmPlan` | bounded decision to use single, star, hierarchy, graph, or debate topology | future swarm contract |
| `AgentMessage` | typed agent-to-agent message: claim, evidence, instruction, tool proposal, risk, or review | future swarm contract |
| `MergeEvidence` | evidence bundle required before parent-run merge | future swarm contract |

## Design Principles

### World Membrane

The agent should sit between the model and the world. External data is treated
as untrusted input and normalized into state, relations, risk, affordances, and
gaps. Model output is treated as a proposal and must pass policy, approval,
execution, verification, and ledger stages before it changes the world.

### Structured Intent

Natural language is not enough for production execution. Soft goals must be
compiled into explicit constraints, capabilities, permission mode, budget,
success criteria, and ownership boundaries.

### Action As Delta

Tool calls should be interpreted as proposed world changes. Each action should
have preconditions, expected effect, blast radius, reversibility, observer, and
rollback shape. The current kernel expresses the first version of this through
`WorldDelta`, `PolicyDecision`, `ExecutionTicket`, `SandboxResult`, `Proof`, and
`LedgerEvent`.

### Proof Before Trust

An agent cannot rely on model confidence. Code tasks need tests and diffs;
research needs evidence and uncertainty; UI work needs screenshots; long tasks
need replayable logs. ESSENCE encodes this by requiring successful commits to
reference recorded proofs.

### Heartbeat Instead Of Infinite Autonomy

Long-running agents should wake up, restore state, act within a budget, persist
facts, record blockers, and sleep. This avoids pretending that the model has a
continuous mind while still enabling resumable work.

### Layered Memory

Memory should separate raw facts, topic/entity indexes, relation graphs,
timelines, preferences, failure scars, and reusable skills. Memory writes
should be tied to source and ledger facts so future recall can explain where a
claim came from.

### Human As Reality Anchor

Humans should see state, risk, approvals, memory writes, active tools, and
blocked runs. The UI is not merely decorative; it is a projection of audit and
control facts that lets humans calibrate the system.

### Swarm As Verifiable Collaboration

Multi-agent research supports swarm-native systems, but only when collaboration
has a protocol. ESSENCE should treat subagents as bounded workers, not trusted
peers. A swarm run needs a topology, explicit handoffs, typed messages,
sidechain records, reviewers or inspectors for high-risk merges, and evidence
gates before the parent run accepts any result. More agents can improve
coverage and review, but they also add coordination cost, latency, and error
propagation, so swarm use must be budgeted and evaluated against single-agent
baselines.

## Production Readiness Themes

The research notes repeatedly point to the same red lines:

- default-deny sandboxing for files, network, shell, and subprocesses;
- zero-trust permissions across tenant, user, session, agent, plugin, tool, and
  resource;
- prompt-injection defense by treating external content as data;
- schema validation for every tool/capability input;
- secret redaction before model calls, logs, plugin calls, and audit records;
- hard budgets for time, tool calls, heartbeats, output, and future resource
  controls;
- subagent budgets, allowlists, typed messages, sidechains, and parent-merge
  evidence gates;
- fault-injection and malicious-input tests for multi-agent runs;
- append-only ledger and proof-backed recovery;
- explicit rollback/correction events instead of silent mutation.

## Current Implementation Fit

The Rust workspace already implements the first trusted slice:

```text
EntryRequest
-> NormalizedEntry
-> TrustedEntry
-> CompiledIntent
-> Intent
-> RunContract
-> WorldDelta
-> PolicyDecision
-> ExecutionTicket
-> SandboxResult
-> Proof
-> LedgerEvent
```

This is enough to validate the doctrine: the model-facing/product-facing
surface is separate from the trusted kernel, and every external action is
channeled through contracts, tickets, proofs, and ledger events.

Future work should add richer model-backed understanding, planning, memory,
retrieval, workflow, swarm, and UI surfaces without weakening this closure.
