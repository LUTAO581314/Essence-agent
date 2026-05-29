# Dual-Chain Architecture Map

This document summarizes the broader ESSENCE architecture notes into a
publishable map for the Rust kernel repository. It is not an implementation
status document. Current shipped behavior is tracked in `docs/status.md` and
`docs/v0-architecture.md`.

## Core Idea

ESSENCE uses a dual-chain knowledge model:

1. The architecture chain explains what the runtime is made of and how its
   components close the trusted loop.
2. The research chain explains why those components exist, which references
   shaped them, and which product constraints they answer.

The two chains are connected by navigation and synthesis notes. Research can
justify a runtime component, and runtime components can point back to research,
but research notes do not become runtime components by being linked.

## Chain One: Runtime Architecture

The runtime architecture chain is the implementation target. Its stable center
is the small trusted kernel:

```text
Entry
-> Gateway
-> Intent compiler
-> Kernel
-> Policy
-> Run contract
-> Capability contract
-> Execution ticket
-> Sandbox result
-> Proof
-> Ledger event
```

The current Rust workspace implements the P0 trusted closure around this path:

- `moxi-entry` normalizes host/channel requests.
- `moxi-gateway` performs deterministic trust checks and redaction.
- `moxi-intent` compiles trusted ingress into kernel intents.
- `moxi-contracts` defines protocol objects and schemas.
- `moxi-core` owns admission, policy, ticketing, execution orchestration,
  verification, proof production, and ledger commits.
- `moxi-sandbox` provides the v0 local file sandbox and process-sandbox JSON
  protocol boundary.
- `moxi-store` persists run state, tickets, results, proofs, hash-chained
  ledger events, and schema migrations.

The broader architecture also reserves places for scheduler/runtime heartbeat,
model gateway, planner, context manager, plugins, memory, code graph, retrieval,
workflow runtime, triggers, credentials, remote bridge, observability, approval,
compliance, delivery, and marketplace surfaces. Those remain P1-P4 product
layers until they integrate through the P0 contracts.

## Chain Two: Research And Rationale

The research chain holds design pressure and evidence. It includes:

- competitive research across agent runtimes, workflow platforms, code-graph
  systems, memory systems, prompt/skill operating layers, and visual shells;
- paper/source research about agent loops, heartbeat execution, memory,
  retrieval, proof, and auditability;
- production-readiness requirements for sandboxing, zero-trust permissions,
  prompt-injection resistance, data safety, compliance, observability, and
  recoverability.

The research chain is deliberately outside the trusted runtime. It informs
design choices, but it should not expand the kernel.

## Connection Rules

- Runtime components can cite research to explain why a boundary exists.
- Research can point to runtime components to show where an idea should land.
- Bidirectional links express support, explanation, or navigation; they do not
  change ownership.
- Anything that affects execution must land in a numbered runtime component,
  protocol type, crate, or test.
- Anything that is explanatory, comparative, visual, or speculative stays in
  the research chain.

## Current Mapping

| Architecture area | Current Rust location | Status |
| --- | --- | --- |
| Entry | `moxi-entry` | Implemented v0 inbound normalization |
| Gateway | `moxi-gateway` | Implemented v0 trust checks and redaction |
| Intent compiler | `moxi-intent`, `moxi-contracts::Intent` | Implemented deterministic v0 compiler |
| Kernel | `moxi-core` | Implemented trusted admission/policy/ticket/proof/ledger loop |
| Policy | `moxi-core::PolicyEngine`, `PolicyConfig` | Implemented configurable v0 rules |
| State store | `moxi-store` | Implemented SQLite state, budgets, tickets, approvals, migrations |
| Capability contracts | `moxi-contracts`, `moxi-core` | Implemented schema validation and registry |
| Sandbox | `moxi-sandbox` | Implemented file sandbox and v0 process protocol |
| Proof and ledger | `moxi-core`, `moxi-store` | Implemented proof binding, append-only ledger, audit replay |
| Scheduler | `moxi-core`, `moxi-store` | Partial through run state, heartbeats, and budgets |
| Event bus | `moxi-store` ledger facts | Partial; no standalone streaming EventBus yet |
| Memory, swarm, model gateway, workflows, triggers, credentials, bridge, UI | None | Architecture/research only |

## Product Boundary

This repository branch intentionally publishes the Rust trusted kernel first.
CLI, desktop, plugin hub, memory runtime, swarm runtime, workflow runtime, and
delivery surfaces should compose around this kernel rather than merging into
it.

The practical stage label is still P0+ / P0 hardening: the trusted kernel loop
is real and tested, while the broader dual-chain architecture remains a product
roadmap.
