# Optimized Core Architecture

This document is the architecture target for growing MOXI Essence Agent from a
trusted execution kernel into a commercial Agent Core without letting fast
runtime features dilute the auditable kernel.

## Core Position

ESSENCE is an interface-first trusted Agent Core.

The kernel should stay small enough to audit, while intelligent behavior grows
around it through explicit manifests and capability contracts. The guiding
rule is simple:

```text
P1/P2 may understand, plan, delegate, remember, render, and suggest.
Only P0 may authorize, ticket, execute, verify, and commit.
```

## Layer Model

### P0 Trusted Core

P0 owns the authority chain:

```text
Entry
-> Gateway
-> Intent compiler
-> RunContract
-> WorldDelta
-> PolicyDecision
-> ExecutionTicket
-> SandboxResult
-> Proof
-> LedgerEvent
```

P0 responsibilities:

- normalize ingress and preserve the trust boundary;
- perform deterministic gateway checks and redaction;
- compile trusted ingress into deterministic v0 intent values;
- define stable contracts, schemas, policies, tickets, proofs, and ledger
  events;
- register capability contracts and executor manifests;
- persist policy decisions as append-only authority records;
- issue single-use execution tickets only after policy allow or approval;
- validate executor identity, input/output schema, and result bindings;
- produce proofs and append hash-chained ledger events;
- replay audit facts from persisted policy decisions, approval grants, tickets,
  results, proofs, and events.
- keep credential use reference-only, bind secret-use decisions to evidence,
  verify executor signature metadata against tenant trust roots, and export
  redacted audit records without persisting raw secret material.
- evaluate production readiness fail-closed before credentialed or executable
  production enablement, covering production auth, external secret management,
  cryptographic verification, hardened sandboxing, secret injection, rotation,
  tenant policy, executor trust roots, and compliance audit export evidence.
- evaluate P1 execution readiness fail-closed before a P1 runtime task can
  enter the P0 ticket/proof/ledger chain. This readiness gate is separate from
  production readiness: local read-only execution may be allowed for bounded
  capabilities, while credentialed, high-risk, or production execution still
  requires production-ready P0 evidence.
- seal tenant policy packs into hash-bound records, seal P1 execution-readiness
  profiles against those tenant policy record references, reload them with
  policy/profile hash validation, and export redacted P1 readiness audit records
  plus typed P1 execution audit bundles. Bundles bind the runtime request,
  sealed profile record, readiness decision, optional production readiness ref,
  redaction profile, and evidence refs. This makes the P0/P1 execution interlock
  reviewable without turning P0 into a runtime profile database or granting P1
  direct ticket/execution authority.
- package redacted compliance export bundles from audit export records and P1
  execution audit bundles under a sealed tenant policy record/hash. The bundle is
  review evidence only; external compliance storage/delivery remains an adapter
  responsibility.
- require production or credential-capable P1 execution profiles to attach a
  ready production-readiness decision before they can be sealed. Local read-only
  profiles remain bounded local records and do not imply production authority.

P0 must not become a model gateway, planner, memory database, plugin host,
workflow engine, product database, or UI runtime.

### P1 Intelligent Runtime

P1 owns intelligence, orchestration, and adaptation. It can be implemented as
future crates such as `moxi-runtime`, `moxi-skills`, `moxi-swarm`,
`moxi-memory`, and `moxi-model-gateway`, but these crates must compose through
P0 contracts.

P1 responsibilities:

- model-backed intent clarification and strategy planning;
- task graph creation and checkpoint/resume decisions;
- subagent delegation, review, monitoring, and sidechain summaries;
- skill loading, validation, routing, and lifecycle management;
- memory retrieval, memory write proposals, source tracking, and forgetting;
- model provider routing, fallback, cost policies, and context compression;
- workflow scheduling, retries, and trigger handling;
- event projection and UI-readable state streams.

P1 may propose `WorldDelta` values and request capabilities. It may execute only
by passing the P0 P1-execution-readiness gate and then using the normal P0
policy, ticket, sandbox, proof, and ledger chain. It must not issue execution
tickets, consume credentials, mutate resources, verify outputs, or commit ledger
events directly.

### P2 Shells And Product Surfaces

P2 owns user experience and distribution surfaces:

- CLI;
- IDE;
- HTTP API and SDK;
- MCP server;
- desktop app;
- web app;
- mobile approval surface;
- digital human or avatar shell.

P2 translates user interaction into entry requests and renders projections from
runtime/core facts. It must not bypass gateway, policy, ticket, proof, or ledger
contracts.

## Manifest Contract Surface

`moxi-contracts` now reserves additive manifest types for extension layers:

- `ModuleManifest`: declares a package of related core, runtime, shell,
  connector, memory, model, policy, or skill behavior.
- `SkillManifest`: declares a callable skill, its invocation mode, schemas,
  permission mode, risk, proof, and approval needs.
- `SubagentManifest`: declares a bounded worker role, allowed capabilities,
  skills, memory scopes, parallelism, and ledger scope.
- `MemoryProviderManifest`: declares memory access modes, scopes, storage,
  source tracking, ledger binding, and retention policy.
- `ModelGatewayManifest`: declares model provider refs, capability kinds,
  fallback, cost, and redaction policy refs.
- `ShellAdapterManifest`: declares a shell surface, entry channels, supported
  permission modes, projections, and approval surface.
- `AgentPersonaManifest`: declares persona role, allowed modules/skills,
  memory scopes, and policy profile.

These manifests do not grant authority by themselves. They are descriptors used
by future runtime loaders and policy tooling. Real resource access still
requires `CapabilityContract`, policy evaluation, `ExecutionTicket`, proof, and
ledger commit.

## Swarm-Native Design

ESSENCE should become swarm-native at P1, not by putting a swarm runtime inside
`moxi-core`, but by making each subagent auditable. Recent multi-agent and
swarm-agent research sharpens this requirement: swarm support is not "more
agents chatting"; it is a verifiable collaboration runtime with topology,
typed communication, bounded roles, sidechains, review gates, and merge
evidence.

```text
Planner
-> TaskGraph
-> SwarmPlan
-> SubagentManifest[]
-> HandoffContract[]
-> AgentMessage[]
-> Subagent sidechains
-> ReviewGate / Inspector
-> MergeEvidence
-> ParentMerge proposal
-> P0 ticket/proof/ledger when external effects are needed
```

Each subagent should have:

- a bounded role and capability allowlist;
- a memory scope rather than full memory access;
- a sidechain ledger for intermediate reasoning, tool proposals, and review;
- explicit evidence requirements before parent-run merge;
- a budget and max parallelism limit.

The parent run should only trust subagent outputs after they are bound to
proofs, artifacts, review notes, or replayable sidechain summaries.

The future `AgentMessage` contract should distinguish claims, evidence,
instructions, tool proposals, risk notices, and review decisions. External web
pages, files, email, papers, and other untrusted content should enter swarm
runs as data, not as instructions. Any tool proposal from a subagent still has
to become a capability request that goes through P0 policy, ticketing, proof,
and ledger.

Default topology should stay conservative:

- low-risk small tasks stay single-agent;
- medium tasks use a star or hierarchy around the parent orchestrator;
- high-risk tasks require a reviewer or inspector before parent merge;
- exploratory research can use graph/debate patterns with hard budgets;
- decentralized swarm modes are advanced P1/P3 features and never replace the
  P0 authority chain.

Swarm evaluation should cover topology regressions, faulty-agent injection,
malicious input as data-only, reviewer/inspector catch rate, parent-merge
evidence gates, cost, latency, token budget, and replayability.

## Intent Understanding

P0 keeps deterministic v0 intent compilation for safety. P1 should add a
model-backed understanding layer that produces structured proposals:

- user goal normalization;
- missing-context questions;
- task decomposition;
- capability request proposals;
- risk hints;
- expected proof requirements;
- memory recall requests;
- clarifying assumptions.

The model-backed layer should be treated as advisory. Its output becomes a
proposal that gateway, policy, and kernel contracts still validate.

## Memory Architecture

Memory is not a fact source by default. It is a context service with provenance.

Memory writes should include:

- source ref;
- author or agent ref;
- confidence;
- scope;
- retention policy;
- recall path;
- consent or policy ref when personal or external data is involved;
- ledger binding for high-impact memory changes.

Memory reads can enrich planning, but high-risk actions must still depend on
current evidence, policy, approval, ticket, proof, and ledger facts.

## Commercial Readiness Gates

Before credentialed or executable production actions, the architecture needs:

- production credential/key store; the current `moxi-vault` MVP models
  reference-only credential use, quorum approvals, trust roots, signature
  verification decisions, break-glass decisions, redacted audit records, a P1
  execution-readiness gate, production adapter evidence, and a fail-closed
  production readiness decision, but not live KMS/HSM calls;
- OS-level process sandbox hardening; the readiness gate can require a hardened
  sandbox profile ref before production enablement, but does not implement the
  OS/container runtime itself;
- cryptographic executor signature verification against trust roots; current
  verification is a control-plane decision over tenant-bound metadata and
  evidence refs;
- compliance-grade redaction and audit export; current audit export records and
  local compliance export bundles carry redaction profile refs and hashes without
  raw secret material, and the readiness gate requires compliance export
  evidence before production enablement;
- bounded hot-path control for ack/deny/route/cache-hit first packets, with
  measured p50/p95/p99 facts and no tool execution authority;
- model gateway cost controls and fallback;
- memory consent ledger and retention controls;
- hardened observability export, trace sinks, and eval/adaptive promotion gates
  beyond the current runtime and R1 store/ledger fact projections;
- regression tests for manifest schema compatibility.

## Build Order

1. Keep the current P0 policy/ticket/proof/ledger closure stable.
2. Treat the new manifest structs as the stable extension vocabulary.
3. Add schema and validation tests for manifests as they become loader inputs.
4. Build `moxi-runtime` as the first P1 crate for planning and task graph
   orchestration.
5. Build `moxi-observability` as the first P1.5 read-only fact layer for
   `RuntimeFact`, `EvidenceRef`, `RunTimeline`, `RunMetric`, and
   `ProjectionSnapshot`.
6. Build `moxi-eval` as the first P1.5 regression gate for `EvalSuite`,
   `EvalCase`, `ReplayProfile`, `EvalRun`, `EvalScore`, `RegressionReport`,
   and `SafetyFinding` over observability facts.
7. Build `moxi-skills` as the first skill package/lint/eval-binding layer over
   `SkillManifest`, while routing all executable effects through
   `CapabilityContract` and P0.
8. Build `moxi-swarm` as the first multi-agent orchestration control plane for
   `SwarmPlan`, typed `AgentMessage`, `HandoffContract`,
   `SubagentSidechain`, `ReviewGate`, `MergeEvidence`, `ParentMerge`,
   safety findings, and evidence-gated parent merge proposals.
9. Add persistent subagent sidechains, real reviewer assignment policy, and
   evaluator coverage for topology regressions, faulty agents, and malicious
   input.
10. Build `moxi-adaptive` and `moxi-governance` as the first eval-gated
   self-improvement loop for reflection reports, optimization deltas,
   experiments, promotion decisions, rollout/rollback plans, and evolution
   ledger events.
11. Build `moxi-model-gateway` as the first model-routing control plane for
   provider selection, fallback lists, structured-output attempts,
   cost/latency facts, and non-authorizing `UnderstandingProposal` records.
12. Build `moxi-memory` as the first memory control plane for
   source-tracked `MemoryCrystal` records, write proposals, consent/ledger
   gates, contamination findings, recall citations, working-memory
   projections, and forget audit events.
13. Build `moxi-vault` as the first P0 production-hardening control plane for
   credential references, secret-use decisions, trust roots, signature
   verification decisions, tenant policy packs, quorum approval, break-glass,
   audit export records, tenant policy pack records, P1 execution-readiness
   profile records, P1 execution audit bundles, compliance export bundles,
   production adapter evidence, and fail-closed production readiness gates.
14. Build `moxi-hotpath` as the first low-latency control plane for ack,
   early-deny, route, exact/template cache hit, degrade plans, latency samples,
   p50/p95/p99 snapshots, and hot-path facts.
15. Add cache-plane persistence, serving-plane adapters, queue/backpressure
   integration, and SLO eval gates.
16. Build `moxi-shells` as the first P2 shell control plane for shell request
    drafts, entry normalization, adapter manifests, runtime profile
    compatibility, approval-display hints, and runtime event/query projections.
17. Build `moxi-cli` as the first CLI binary over `moxi-shells` for JSON
    admission, adapter-manifest output, read-only runtime event-feed/query
    projection, a file-backed snapshot watch preview, a read-only Ratatui TUI
    skeleton with scriptable pane-focus/task-selection/filter/refresh/quit replay including graph focus, a raw-mode
    read-only snapshot loop and compact projection-only Task Detail preview
    behind `tui --interactive`, and a verified minimal REPL loop only. Task
    Detail may show selected-task state, stage, progress, capability, skill,
    blocker, and message, and the approvals/blockers pane may summarize
    awaiting approvals as display-only. Graph Summary may show compact
    task/done/running/waiting/blocking/failure counts from the same projection,
    but no TUI pane may expose action controls.
18. Add a full runtime-control CLI TUI, MCP, API/SDK, IDE, desktop, web,
    mobile approval, and digital-human transports on top of the shell control
    plane.

## Non-Negotiable Invariants

- No runtime layer issues its own execution ticket.
- No skill, plugin, model, memory provider, or shell mutates external resources
  without a capability contract.
- No subagent expands its own capability, memory scope, budget, or permission
  mode.
- No parent run merges subagent output without evidence.
- No untrusted external content becomes an agent instruction without an
  explicit trusted handoff path.
- No high-risk action completes without policy allow or approval.
- No raw secret material is stored in model context, ordinary logs, durable
  memory, or audit exports.
- No high-risk executor is promoted to production without a tenant trust-root
  verification decision.
- No break-glass action proceeds without bounded scope, evidence, quorum when
  required, and audit export coverage.
- No "5ms" claim covers complete LLM answers or external effects; it only
  covers bounded first-packet ack/deny/route/cache-hit decisions.
- No hot-path cache hit is served without scope, freshness, risk, and evidence
  gates.
- No successful action commits without proof.
- No ledger event mutates in place; correction is another event.
- No private memory leaves local scope unless a policy and consent path allow it.



