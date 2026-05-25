# Project Status

Updated: 2026-05-25

## Current State

MOXI Essence Agent is in v0 trusted-kernel buildout. The current repository is
a Rust workspace with nine library crates:

- `moxi-entry`: inbound entry adapter primitives. Converts external channel
  requests into an intent candidate plus entry metadata and requested
  `PermissionMode`.
- `moxi-gateway`: first trusted ingress boundary for deterministic tenant/user
  checks, per-principal request limiting, blocked input scanning, and obvious
  secret redaction.
- `moxi-intent`: deterministic v0 intent compiler. Converts trusted ingress
  records into kernel `Intent` values.
- `moxi-contracts`: protocol and data contracts for intents, runs,
  capabilities, deltas, policy decisions, tickets, sandbox results, proofs,
  ledger events, configurable policy, structured errors, and additive extension
  manifests for modules, skills, subagents, memory providers, model gateways,
  shell adapters, and personas.
- `moxi-core`: trusted kernel API for admission, policy checks, ticket issuing,
  heartbeat accounting, registered capability execution, verification, and
  ledger commits. The policy engine is configurable while preserving safe v0
  defaults.
- `moxi-runtime`: first P1 orchestration layer. It creates deterministic
  `PlannerPlan` IR and compiled `TaskGraph` values, registers read-only
  `SkillManifest` descriptors, emits cursor-readable `RuntimeEvent` progress,
  maintains an in-memory task projection, can append/replay optional JSONL
  runtime journals, builds resume plans from replayed task state, applies a
  running-checkpoint policy, resumes ready tasks through the trusted P0 kernel,
  runs simple file-read fast paths and multi-step read-only skill graphs
  through P0, and stops high-risk tasks at approval.
- `moxi-observability`: first P1.5 read-only fact layer. It turns runtime
  graph/query snapshots into `RuntimeFact`, `EvidenceRef`, `RunTimeline`,
  `RunMetric`, and `ProjectionSnapshot` DTOs so shells, eval, adaptive control,
  and audits can cite planner, task, event, attempt, adoption-probe, and resume
  evidence without mutating runtime or kernel state.
- `moxi-sandbox`: local read-only file sandbox with workspace-root locking and
  path escape protection, plus v0 process-sandbox JSON protocol execution.
- `moxi-store`: SQLite-backed run state, budget counters, append-only
  capability contracts, executor manifests, policy decisions and approval
  grants, execution tickets, persisted sandbox results/proofs, append-only
  hash-chained ledger events, ledger replay/audit verification, and schema
  migrations.

The current end-to-end implemented path is:

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

`EntryRequest` belongs to the inbound adapter boundary. Gateway and intent
compiler stages now make the pre-kernel path explicit. The trusted kernel path
still starts at `Intent`.

## Progress Against P0-P4

The current code is best described as **P0+ with a narrow P1 runtime and P1.5
observability start**.
The trusted kernel loop is implemented end to end, and several P0 concerns have
moved beyond "minimal" into replayable/auditable behavior. P1 now has a
deterministic planner IR and task runtime, but model-backed planning, model
gateway, context manager, verifier-as-a-separate-runtime, rollback manager,
code graph, and retrieval engine are not implemented as current Rust workspace
runtime modules. P1.5 now has a read-only runtime fact projection, but
store/ledger-backed fact ingestion, metrics export, eval suites, and adaptive
promotion governance are not implemented yet.

P1 has started with a narrow `moxi-runtime` v0 skeleton. It is not a full agent
runtime yet: it covers deterministic `PlannerPlan` creation, planner hash
binding through `RuntimePlannerRecord`, read-only `SkillManifest` routing,
dependency ordering, progress events, in-memory task projection, optional JSONL
journal replay, live SQLite-backed runtime persistence, ready-task resume
execution, approval stop, and file-read execution through P0. Running tasks
found during journal or SQLite replay are
inspection-blocked by default and become retryable only through an explicit
runtime policy. Failed/interrupted side-effect tasks now expose adoption
recommendations and can consult provider probes before retry. Multi-task graphs
currently open one P0 run per task and aggregate outcomes at the runtime layer.

P1.5 has started with `moxi-observability`. It is intentionally not an event
bus or control authority: it converts runtime graph/query snapshots into
citeable facts and timelines. The first surface covers planner binding, graph
planning, task state, runtime events, task attempts, adoption probes, resume
recommendations, graph completion, and aggregate run metrics. It does not
write runtime state, issue tickets, execute capabilities, verify outputs, or
commit ledger events.

P0 coverage in current code:

- Implemented: entry boundary, gateway v0 trust checks, deterministic intent
  compiler, kernel admission, configurable policy engine, approval grants,
  capability registry, run contract, capability contract, state store, local
  file sandbox, v0 process-sandbox protocol, proof collection, append-only
  ledger, schema migrations, and ledger replay/audit verification.
- Partial: scheduler is represented by kernel-driven run status transitions and
  heartbeat/budget accounting, but not an independent scheduler runtime.
- Partial: execution event bus is represented by persisted ledger/state facts,
  but no separate streaming event bus exists yet.
- Production gates before enabling credentialed or executable external actions:
  credential/key store and production-grade OS sandbox hardening.

P0 boundary decisions:

- Production authentication providers, distributed rate limiting, and
  compliance-grade redaction are production gateway work, not blockers for the
  P0 trusted kernel loop. The current deterministic gateway checks are the P0
  boundary.
- Model-backed intent understanding and strategy-driven planning are P1 agent
  runtime work. P0 intentionally uses deterministic intent compilation.
- A standalone scheduler runtime and streaming execution EventBus are not P0
  blockers. P0 is covered by kernel run-state transitions, heartbeat/budget
  counters, persisted state facts, and hash-chained ledger events.
- Model gateway, tool gateway, plugin host, memory runtime, swarm runtime,
  workflow runtime, and product surfaces remain P1-P4 runtime layers. They
  must integrate through P0 contracts instead of expanding the trusted kernel.
- `process_sandbox` is a v0 protocol/runtime boundary, not production OS
  isolation. Production exposure of executable external actions is blocked on
  OS-level sandbox hardening.

## Implemented

- Entry-layer request normalization for CLI, desktop, web, HTTP API, SDK, MCP
  server, and automation channels.
- Gateway trust checks for tenant allowlists, blocked users, per-principal
  request limits, blocked input terms, and secret-marker redaction.
- Deterministic intent compilation from gateway-approved ingress records into
  kernel `Intent` values, including conservative `file.read` inference for
  read-like goals.
- Stable contract structs and JSON schema generation.
- Extension manifest structs for future modules, skills, subagents, memory
  providers, model gateways, shell adapters, and personas. These are descriptor
  contracts only; they do not bypass capability contracts, policy, tickets,
  proof, or ledger commits.
- Capability registration with input/output/error schema validation.
- Append-only capability contract and executor manifest persistence at
  registration time, with immutable re-registration checks.
- Run admission with read-only default permission mode and budget
  initialization.
- Deterministic policy checks for declared capabilities, permission modes,
  high-risk approval escalation, and denied network/shell resources.
- Configurable `PolicyConfig` support for declared-capability enforcement,
  capability deny/approval rules, resource deny/approval patterns, risk
  approval/deny thresholds, approval policy, and approval refs.
- Append-only policy decision persistence before approval or ticket issuing.
- Stored policy authority enforcement before approval or ticket issuing:
  caller-supplied policy decisions must exactly match the kernel-recorded
  `PolicyDecision` payload.
- Human approval grants for high-risk policy decisions.
- Single-use execution tickets issued only after policy allow or approval.
- Generic capability executor dispatch in `moxi-core`, with `file.read`
  registered as the default built-in executor.
- Runtime acceptance for `in_process_trusted` and `process_sandbox` executor
  manifests. `process_sandbox` executes a configured child process with a JSON
  stdin/stdout protocol and timeout enforcement.
- Executor manifest validation against capability contract hash, provider
  identity, sandbox profile, artifact hash, signature ref, and signing key ref
  before ticket issuing and execution.
- Single-use execution tickets bound to policy decision, capability contract
  hash, executor id/version, executor artifact hash, executor signature ref,
  executor signing key ref, executor manifest hash, executor isolation, and the
  capability retry policy snapshot.
- Stored ticket enforcement before execution: caller-supplied tickets must match
  the kernel-recorded ticket payload exactly before consumption.
- Executor result binding checks for ticket id, run id, and capability id before
  output schema validation and proof collection.
- Kernel-owned canonical output hashing from structured executor output.
- Failed run transitions after ticket-consuming executor failures, result
  mismatches, and output schema failures.
- Persisted sandbox results after output validation, with verification requiring
  the recorded result for the ticket.
- Local `file.read` capability through the read-only sandbox.
- Workspace path escape protection.
- Sandbox input/output schema validation.
- Proof collection from successful sandbox results, including policy,
  capability, executor, gateway, input, and output hashes/refs.
- Successful ledger commits requiring recorded proof references that match the
  ledger event binding fields, including executor artifact identity.
- Ledger replay/audit verification that validates the hash chain and replays
  successful events against persisted capability contracts, executor manifests,
  policy decisions, approval grants when required, execution tickets, sandbox
  results, proofs, output hashes, and proof evidence hashes.
- SQLite run state transitions, budget counters, append-only capability
  contracts, executor manifests, policy decisions, approval grants, full
  execution ticket payload persistence, append-only sandbox result persistence,
  append-only proof payload persistence, execution ticket consumption, and
  append-only hash-chained ledger events.
- Store schema versioning through `store_meta`, ordered migrations, rejection of
  newer unsupported schemas, and v1-to-current compatibility coverage.
- P1 runtime skeleton with `RuntimeSession`, `TaskGraph`, `TaskNode`,
  `RuntimeEvent`, and `RuntimeRunReport`.
- Runtime `SkillRegistry` and read-only `SkillManifest` registration checks.
- Runtime `RuntimeManifestRegistry` for persisted JSON `ModuleManifest` and
  `SkillManifest` records, id-based deduplication, skill-module reference
  validation, module dependency graph validation, module profile reference
  validation, skill/module capability binding checks, profile-aware skill
  filtering, and session loading.
- Runtime `PlannerPlan` IR and `ExecutionPlan` with deterministic dependency
  ordering for simple multi-step graphs.
- Runtime `RuntimePlannerRecord` binds planner IR to graph id, source,
  step count, and stable plan hash for live query, journal replay, and SQLite
  store recovery.
- Runtime `RuntimePolicyProfile` for shell-specific orchestration limits:
  allowed capabilities, fast/task/trusted path switches, skill enablement,
  running-checkpoint retry permission, and maximum tasks per graph.
- Runtime `RuntimeProfileRegistry` for persisted JSON runtime profiles,
  conservative parent-profile inheritance, cycle detection, and session
  application by profile id.
- Runtime standard shell profile pack for conservative CLI fast-path, IDE
  read-only, digital-human read-only, and trusted-review runtime envelopes.
- Runtime fast-path execution for simple `file.read` tasks, routed through
  `admit -> propose_delta -> issue_ticket -> execute -> verify -> commit`.
- Runtime task-path execution for multiple read-only skill tasks, each routed
  through an independent P0 run and aggregated in one runtime report.
- Runtime approval stop for high-risk tasks before ticket issuing.
- Runtime in-memory task store with graph snapshots, task projections, current
  stage/message/progress fields, and event cursors for shell/UI polling.
- Runtime event feed snapshots: `RuntimeEventFeedSnapshot` gives shells a
  cursor-based subscription payload with incremental events, latest stage,
  message, progress, current task, blocker summary, and completion state.
- Runtime read-only query DTOs: `RuntimeGraphListItem`, `RuntimeTaskView`, and
  `RuntimeQuerySnapshot`, available from live sessions and replayed journals
  for CLI/IDE/UI graph list and detail rendering.
- Runtime projection snapshots: `RuntimeProjectionSnapshot` serializes task
  store, event stream, runtime profile, and running-task policy to JSON for a
  lightweight shell-facing durable cache.
- Runtime task index snapshots: `RuntimeTaskIndexSnapshot` persists graph-list
  rows and task rows as a shell-facing indexed read model with graph lookup,
  graph-task lookup, and state-filtered task lookup after live runs or journal
  replay.
- Runtime SQLite store v4: `RuntimeSqliteStore` persists runtime planner
  records, graphs, tasks, events, attempts, retry leases, and adoption-probe
  records with schema
  metadata and query indexes, then hydrates the same graph-list, query,
  task-index, and event-feed views without mixing P1 runtime state into the P0
  audit ledger.
- Runtime SQLite live backend: `RuntimeSession::with_sqlite_store` restores
  prior runtime projections from SQLite and writes planner, graph, event,
  attempt, retry-lease, and adoption-probe records during execution.
- Optional runtime JSONL journal that appends planner, graph, event, attempt,
  retry-lease, and adoption-probe records, replays graph snapshots, and lets a
  later runtime continue appending to the same journal file.
- Runtime journal writers now create a sibling `.lock` file atomically and
  fail closed when another writer or replay-and-append session is active.
- Runtime journal locks now persist owner metadata and expose explicit
  age-guarded stale-lock inspection/cleanup APIs; cleanup is never automatic.
- Runtime resume plans that classify completed, ready, dependency-blocked,
  approval-blocked, and failed tasks from replayed graph state, with per-task
  `RuntimeAdoptionRecommendation` evidence for interrupted side effects.
- Runtime ready-task resume execution that advances resumable tasks through
  `admit -> propose_delta -> issue_ticket -> execute -> verify -> commit`
  without bypassing P0.
- Running checkpoint policy: replayed running tasks are blocked for inspection
  by default; explicit retry policy can return retry-safe tasks to the ready
  queue.
- Runtime task attempts now persist stable idempotency keys and retry-safety
  metadata. A running checkpoint with non-idempotent/latest-unsafe attempt
  evidence remains blocked even when `RetryReady` is selected.
- Runtime side-effect adoption contract: `RuntimeAdoptionProbe` lets a
  provider adapter report not-found, pending, committed, failed, or unknown
  observations for an attempt/idempotency key. The runtime folds that evidence
  into resume recommendations only; ticket issuing, execution, verification,
  and ledger commits remain inside P0.
- Runtime adoption probe registry: `RuntimeAdoptionProbeRegistry` registers
  recovery probes by exact capability id or by provider fallback inferred from
  the capability prefix, then `RuntimeSession` can automatically probe matching
  tasks before building a resume plan.
- Runtime adoption probe evidence: `RuntimeAdoptionProbeRecord` records
  provider observations in journal/SQLite, exposes them through graph/query
  snapshots, and lets replay or a restored SQLite session use recorded evidence
  before any fresh provider probe.
- Runtime observability facts: `moxi-observability` projects
  `RuntimeGraphSnapshot` and `RuntimeQuerySnapshot` into `RuntimeFact`,
  `EvidenceRef`, `RunTimeline`, `RunMetric`, and `ProjectionSnapshot` records.
  Every generated fact carries evidence back to a runtime graph, planner, task,
  event, attempt, adoption probe, or resume plan record.
- Failed attempt recovery now distinguishes retry-safe/no-ticket attempts from
  attempts with ticket, ledger, pending provider, or unknown side-effect
  evidence. Only the former can be made retry-ready automatically; the latter
  stays inspection/adoption-bound.
- Runtime retry leases: `RuntimeRetryLease` records active/released lease
  state, blocks duplicate retry-ready resumes while a live lease exists, and is
  persisted through journal replay and RuntimeSqliteStore v4.
- SQLite-backed retry lease acquisition now uses an immediate transaction as a
  local database arbitration boundary, so competing runtime sessions cannot
  claim the same active, unexpired task lease.
- External idempotency propagation: `SandboxInput` now carries optional runtime
  metadata, letting external executors/providers receive the stable runtime
  idempotency key without changing or weakening P0 payload schema validation.
- Unit and end-to-end tests for contracts, kernel policy, approvals, sandbox,
  ticket reuse, budgets, ledger hash chains, entry normalization, gateway
  checks, intent compilation, configurable policy rules, ledger replay/audit,
  and the trusted ingress-to-execution path.

## Not Yet Built

- Production gateway integration for external authentication providers,
  cryptographic tenant/session trust, distributed rate limiting, and compliance
  grade redaction.
- Model-backed or policy-backed intent compilation beyond the current
  deterministic v0 compiler.
- Model-backed/strategy-backed P1 planner beyond deterministic and skill-registry
  plans, cross-host distributed locking beyond local SQLite arbitration,
  concrete provider-specific adoption adapter implementations against real idempotency APIs,
  ledger-backed adoption of already-committed external effects, profile schema
  migrations, and packaged profile distribution.
- Store/ledger-backed observability ingestion beyond the current runtime
  snapshot/query projection, metrics export, trace sinks, eval-case generation,
  and adaptive-control promotion gates.
- Concrete CLI, HTTP API, SDK, MCP server, desktop UI, or web UI transports.
- Model provider adapters, model gateway, tool gateway, plugin host, browser
  daemon, remote bridge, swarm runtime, workflow runtime, and long-term memory
  runtime.
- Swarm runtime contracts beyond the current `SubagentManifest`: `SwarmPlan`,
  typed `AgentMessage`, `HandoffContract`, `SubagentSidechain`, `ReviewGate`,
  `MergeEvidence`, topology evaluation, faulty-agent injection, and malicious
  input regression coverage.
- Advanced manifest registry features: schema migrations, signatures, signed
  trust roots, and concrete packaged registries.
- Concrete production executors beyond the current built-in `file.read`,
  process-sandbox protocol harness, and test-only custom executor.
- OS-level process sandbox hardening beyond direct child-process execution,
  protocol checks, and timeout kill.
- Cryptographic executor signature verification against production trust roots.
- Production transcript/WAL hardening, database-backed durable projections,
  concrete push transports such as WebSocket/SSE/IPC, GitNexus harness, release
  binaries, and package-manager installers.

## Verification

Current proof command:

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Expected result: formatting, lint, and all workspace tests pass.

## Architecture Direction

The current code keeps the trusted kernel small and auditable. Fast-changing
product surfaces should stay outside `moxi-core`:

- Inbound host differences belong under `01-入口层` and `moxi-entry`.
- Authentication, tenant/session trust, rate limits, risk scanning, and
  redaction belong under `02-网关层` and `moxi-gateway`.
- Trusted understanding and intent shaping belong under `03-意图编译器` and
  `moxi-intent`.
- Tool, model, plugin, browser, workflow, memory, and remote integrations
  should remain capability-bound and policy-checked before execution.

See [v0-architecture.md](v0-architecture.md) for the implementation-facing
architecture summary.

See [optimized-core-architecture.md](optimized-core-architecture.md) for the
target P0/P1/P2 boundary, extension manifest surface, swarm-native runtime
shape, memory rules, and commercial readiness gates.

Swarm-specific architecture is research-backed but not implemented yet. The
current direction is P1-native, evidence-gated swarm orchestration: subagents
may plan, review, and propose, but they cannot expand authority or merge into a
parent run without sidechain evidence and P0-controlled execution for external
effects.
