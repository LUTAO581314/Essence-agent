# MOXI Essence Agent v0.2.0

Rust-only trusted ingress, intent, and kernel foundation for MOXI/ESSENCE Agent.

This branch intentionally contains only the core framework. It does not include
CLI command parsing, desktop UI, web UI, plugin marketplace, model providers,
swarm runtime, remote bridge, long-term memory runtime, or auto-evolution.
The first P1 runtime crate is now present, but it remains a thin orchestration
layer over the trusted P0 kernel. The first P1.5 observability crate is also
present as a read-only fact/projection layer.

## Core crates

- `moxi-entry`: inbound entry adapter primitives for CLI, desktop, web,
  HTTP API, SDK, MCP server, and automation channels. It normalizes external
  requests into an intent candidate plus entry metadata, without authenticating,
  issuing tickets, or touching tool capabilities.
- `moxi-gateway`: first trusted ingress boundary for deterministic tenant/user
  checks, rate limiting, blocked input scanning, and secret redaction.
- `moxi-intent`: deterministic v0 intent compiler that turns trusted ingress
  records into kernel `Intent` values.
- `moxi-contracts`: stable protocol types for `Intent`, `RunContract`,
  `CapabilityContract`, `WorldDelta`, `PolicyDecision`, `ExecutionTicket`,
  `SandboxResult`, `Proof`, `LedgerEvent`, configurable `PolicyConfig`, and
  structured errors. It also reserves extension manifest contracts for future
  modules, skills, subagents, memory providers, model gateways, shell adapters,
  and personas.
- `moxi-core`: trusted kernel API for admission, policy checks, ticket issuing,
  heartbeat accounting, registered capability execution, verification, and
  ledger commits. Policy evaluation is configurable for declared-capability,
  risk, capability, resource, and approval rules.
- `moxi-runtime`: first P1 orchestration layer for deterministic task planning,
  `SkillManifest` routing, multi-step `TaskGraph` execution, runtime task
  projections, event cursors, optional JSONL journal replay, resume planning,
  running-checkpoint policy, ready-task resume execution, simple fast-path file
  reads, and trusted execution through the P0 kernel. It cannot issue tickets
  or execute tools directly.
- `moxi-observability`: first P1.5 fact layer. It converts runtime graph/query
  snapshots into `RuntimeFact`, `EvidenceRef`, `RunTimeline`, `RunMetric`, and
  `ProjectionSnapshot` DTOs for shells, evaluation, adaptive control, and audit
  explanations. It is read-only and cannot mutate runtime state, issue tickets,
  execute capabilities, verify results, or commit ledger events.
- `moxi-sandbox`: first local read-only file sandbox with workspace root lock
  and path escape protection, plus v0 process-sandbox JSON protocol execution.
- `moxi-store`: SQLite state store, append-only audit ledger, persisted
  capability contract, executor manifest, policy decision, ticket, result, and
  proof payloads, and ledger replay/audit verification.

## Kernel path

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

The trusted kernel path starts at `Intent`; `EntryRequest` belongs to the
inbound adapter boundary and does not expand permissions. Gateway and intent
compiler stages sit before the kernel and must not issue execution tickets or
call tools directly.

```text
Intent
-> RunContract
-> WorldDelta
-> PolicyDecision
-> ExecutionTicket
-> SandboxResult
-> Proof
-> LedgerEvent
```

## P1 runtime path

```text
Intent
-> SkillRegistry / PlannerPlan / ExecutionPlan
-> TaskGraph
-> TaskNode
-> RuntimeTaskStore / RuntimeEventStream
-> optional RuntimeJournal JSONL replay
-> RuntimeResumePlan
-> RuntimeResumeReport
-> RuntimeEvent
-> P0 Kernel path
-> RuntimeRunReport
```

`moxi-runtime` may plan, emit progress, and call the kernel. It does not own
policy authority, ticket issuing, execution, verification, or ledger commits.
High-risk tasks stop at approval rather than silently issuing tickets.
`PlannerPlan` is the P1 planner IR: it records plan source, constraints,
rationales, steps, dependencies, targets, and risk before the runtime compiles
it into a `TaskGraph`. `RuntimePlannerRecord` binds that IR to a graph id and
stable `plan_hash`, so shells can explain why a graph exists and replay the
planning fact without trusting transient memory.
The v0 runtime keeps an in-memory task projection and cursor-readable event
stream so shells can poll graph status, task state, current stage, messages,
and progress without reading kernel internals.
`RuntimeEventFeedSnapshot` turns that event stream into a shell-facing
subscription payload: callers pass a cursor and optional graph id, then receive
incremental events plus the latest stage, message, progress, current task, and
blocker summary.
It also exposes read-only query DTOs: `RuntimeGraphListItem`,
`RuntimeTaskView`, and `RuntimeQuerySnapshot`, so shells can render graph
lists and detail pages without depending on internal store layout.
`RuntimeProjectionSnapshot` can be written as JSON and read back later, giving
shells a lightweight durable projection cache separate from the P0 audit store.
`RuntimeTaskIndexSnapshot` is a shell-facing indexed read model that persists
graph list rows plus task rows and supports graph lookup, graph-task lookup,
and state-filtered task lookup after live runs or journal replay.
`RuntimeSqliteStore` is the first database-backed P1 runtime store. It keeps
schema metadata, persists planner records, graphs, tasks, events, attempts,
retry leases, and adoption-probe records with query indexes, and can hydrate
the same query, index, and event-feed views without touching the P0 audit
ledger.
`RuntimeSession::with_sqlite_store` can now use that store as a live backend:
planner records, task graphs, runtime events, attempts, retry-lease
transitions, and adoption-probe evidence are written during execution and can
be restored by a later runtime session.
SQLite-backed retry leases are acquired through an immediate transaction, so a
second runtime session cannot claim the same active, unexpired task lease until
the first lease is released or expires.
`RuntimePolicyProfile` lets a shell choose a conservative runtime envelope,
including allowed capabilities, fast/task/trusted path switches, skill enablement,
running-checkpoint retry permission, and maximum tasks per graph.
`RuntimeProfileRegistry` persists named profiles as JSON and resolves parent
inheritance conservatively, so shell-specific profiles can only narrow the
effective runtime envelope.
`RuntimeShellProfilePack::standard()` provides conservative built-in profiles
for CLI fast-path, IDE read-only, digital-human read-only, and trusted-review
shells; `RuntimeProfileRegistry::with_standard_shell_profiles()` loads them
without changing P0 authority.
`RuntimeManifestRegistry` persists `ModuleManifest` and `SkillManifest` values
as JSON, deduplicates by id, validates module references, module dependency
graphs, module profile references, and skill/module capability bindings, then
loads only skills allowed by the active runtime profile.
When opened with a journal path, the runtime appends task graphs and runtime
events to JSONL so a later process can replay graph snapshots and continue
appending events. Journal writers use a sibling `.lock` file created with an
atomic create-new operation, so a second runtime fails closed while another
process owns the same journal. Lock files include metadata, and callers may
explicitly inspect or clear age-qualified stale locks; cleanup is not automatic.
Replay can also produce a `RuntimeResumePlan` that classifies completed tasks,
ready-to-resume tasks, dependency-blocked tasks, approval-blocked tasks, and
failed tasks. The plan includes per-task `RuntimeAdoptionRecommendation`
entries so a shell or supervisor can see whether an interrupted side-effect is
already committed, retry-ready, or inspection-required. `resume_ready_tasks`
can execute only the ready tasks and keeps each resumed task inside the P0
chain for policy, tickets, proof, and ledger commits.
Each task execution records a `RuntimeTaskAttempt` with a stable idempotency
key derived from graph, task, target, input, and capability-contract hash.
`RuntimeAdoptionProbe` is the P1 contract for provider-specific recovery
checks: adapters may report idempotency-key observations such as not found,
pending, committed, failed, or unknown. `RuntimeAdoptionProbeRecord` stores
that observation in the runtime journal or SQLite store, and replay uses the
recorded evidence before any fresh provider probe. The runtime folds that
evidence into resume recommendations, but it still cannot issue tickets,
bypass verification, or commit ledger events outside P0.
`RuntimeAdoptionProbeRegistry` lets a runtime register probes by exact
capability id or by provider fallback inferred from the capability prefix, so
provider-specific recovery can be selected automatically before building the
resume plan.
The runtime now acquires a `RuntimeRetryLease` before trusted execution,
persists lease transitions through the journal/store surface, blocks duplicate
retry-ready resumes while a lease is active, and releases the lease after a
successful attempt. `SandboxInput` carries optional runtime metadata so external
providers can receive the stable idempotency key without polluting the
capability input payload that P0 validates.
If replay finds a task that was still running at the crash boundary, the
default `RunningTaskPolicy::RequireInspection` blocks automatic re-execution;
callers must explicitly select `RetryReady` before such a task becomes
resumable. Even then, the runtime only retries running checkpoints whose latest
attempt is marked retry-safe. Failed attempts are retry-ready only when the
latest attempt is retry-safe and no ticket was issued, or when a provider probe
confirms no committed side effect. Ticket evidence, ledger evidence, pending
provider state, or unknown side-effect state stays inspection/adoption-bound
instead of blind retry.
When a graph has multiple tasks, the current v0 runtime opens an independent
P0 run per task and aggregates the outcomes in one `RuntimeRunReport`; this
keeps P0's completed-run semantics intact while P1 scheduling evolves.

## P1.5 observability path

```text
RuntimeGraphSnapshot / RuntimeQuerySnapshot
-> RuntimeFact
-> EvidenceRef
-> RunTimeline
-> RunMetric
-> ProjectionSnapshot
-> eval / adaptive control / shells
```

`moxi-observability` is the first independent fact surface for the bionic/core
design. It turns planner records, graph/task state, runtime events, attempts,
adoption probes, and resume recommendations into citeable facts. Every fact
must carry at least one `EvidenceRef`, and projection consumers only read these
facts. Store/ledger-backed ingestion, export metrics, and eval/adaptive
promotion gates are still future work.

## Research docs

Broader ESSENCE architecture and research notes have been condensed into these
publishable docs:

- [`docs/dual-chain-architecture.md`](docs/dual-chain-architecture.md):
  architecture-chain and research-chain boundaries.
- [`docs/reference-synthesis.md`](docs/reference-synthesis.md): upstream
  agent-system lessons and implementation implications.
- [`docs/paper-and-agent-research.md`](docs/paper-and-agent-research.md):
  paper/source-inspired agent doctrine and production readiness themes.
- [`docs/optimized-core-architecture.md`](docs/optimized-core-architecture.md):
  optimized P0/P1/P2 architecture, extension manifests, swarm-native runtime
  boundaries, memory rules, and commercial readiness gates.

## Safety defaults

- Entry only normalizes host/channel differences.
- Gateway can deny untrusted tenants/users, apply per-principal request limits,
  block risky input terms, and redact obvious secret markers.
- Intent compilation is deterministic in v0 and preserves gateway-approved
  permission mode.
- Default permission mode is read-only.
- Network and shell are denied by default.
- Policy defaults preserve the v0 safety posture, while `PolicyConfig` can
  adjust declared-capability enforcement, risk approval/deny thresholds,
  capability deny/approval rules, resource deny/approval patterns, and approval
  policy/ref metadata.
- Policy decisions are persisted append-only before ticket issuing. A caller
  supplied policy decision must exactly match the kernel-recorded policy
  authority before approval or ticket issuing can continue.
- External action requires an `ExecutionTicket`.
- Capability execution is dispatched through registered executors; `file.read`
  is the default built-in executor, not a hard-coded kernel path.
- Capability contracts and executor manifests are persisted append-only at
  registration time. Re-registering the same authority is idempotent; changing
  a registered capability or executor identity is rejected instead of silently
  swapping the trusted execution target.
- The current runtime accepts `in_process_trusted` and `process_sandbox`
  executor manifests. `process_sandbox` starts a configured executable directly,
  sends JSON on stdin, reads JSON on stdout, and enforces a timeout. Remote,
  browser, model-gateway, and plugin-host isolation modes are protocol values,
  not enabled runtime paths yet.
- Executor manifests must match the registered capability contract hash,
  provider identity, sandbox profile, artifact hash, signature ref, and signing
  key ref before ticket issuing or execution.
- Execution tickets bind the policy decision, capability contract hash,
  executor id/version, executor artifact hash, executor signature ref, executor
  signing key ref, executor manifest hash, executor isolation, and the
  capability retry policy snapshot.
- Execution uses the persisted ticket payload as the authority; a caller-supplied
  ticket must exactly match the ticket recorded by the kernel before it can be
  consumed.
- Executor results must match the issued ticket, run, and capability before
  output schema validation and proof collection.
- The kernel recomputes canonical output hashes from structured output instead
  of trusting executor-supplied hashes.
- Executor failures, result-binding mismatches, and output schema failures mark
  the run as failed after the ticket has been consumed.
- Sandbox results are persisted after output validation, and verification only
  accepts the recorded result for the ticket.
- Proofs and ledger events carry the policy, capability, executor, gateway,
  input, and output hashes/refs used for the execution.
- Ledger/proof bindings include executor artifact identity fields, so audit
  replay can detect executor code identity drift.
- Successful ledger commits must reference recorded proofs whose binding fields
  match the ledger event.
- Execution tickets are issued by the kernel and can be consumed only once.
- Capability contract, executor manifest, policy decision, execution ticket,
  sandbox result, and proof payloads are persisted for audit replay.
- Ledger audit replay validates the hash chain and re-checks successful events
  against persisted capability contracts, executor manifests, policy decisions,
  approval grants when required, tickets, sandbox results, proofs, output
  hashes, and proof evidence hashes.
- SQLite stores track schema version in `store_meta` and run ordered migrations
  for compatibility with older audit databases.
- Run budgets track steps, heartbeats, tool calls, and timeout limits.
- Successful ledger commits require at least one `Proof`.
- Ledger events are append-only and hash-chained; correction must be a new
  event.

## P0 boundary

This branch treats P0 as the small trusted-kernel closure, not the full product
runtime. Production auth providers, distributed rate limiting, compliance-grade
redaction, model-backed understanding, standalone scheduler/EventBus runtimes,
model/tool gateways, plugins, memory, swarm, workflow, and product surfaces are
P1-P4 layers. They must integrate through the P0 contracts instead of expanding
the trusted kernel.

P1/P2 extension surfaces are described through manifest contracts such as
`ModuleManifest`, `SkillManifest`, `SubagentManifest`,
`MemoryProviderManifest`, `ModelGatewayManifest`, `ShellAdapterManifest`, and
`AgentPersonaManifest`. These descriptors do not grant authority by themselves:
resource access still requires a registered `CapabilityContract`, policy
evaluation, a kernel-issued `ExecutionTicket`, proof collection, and a ledger
commit.

`process_sandbox` is a runnable v0 JSON protocol boundary. It is not yet
production OS isolation; enabling executable external actions in production is
blocked on OS-level sandbox hardening and credential/key-store integration.

## Verify

```text
cargo fmt --all --check
cargo test
cargo clippy --all-targets -- -D warnings
```

Current end-to-end acceptance scenario: `EntryRequest` passes gateway checks,
compiles into an `Intent`, executes authorized `file.read` inside the workspace,
and produces a sandbox result, proof, ledger event, and completed run state.
