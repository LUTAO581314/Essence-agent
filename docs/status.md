# Project Status

Updated: 2026-05-26

Note: the latest R10 `moxi-cli` pass is verified locally. The CLI `admit`,
`manifest`, `status`, `watch`, `tui`, `boundary`, and minimal `repl` commands
pass formatting, tests, clippy, and real command/REPL checks. `status --text`
now renders the same read-only shell projection in a readable status view,
`status --panel` renders a static terminal panel preview, `watch --input
<snapshot.json>` refreshes the same file-backed projection preview,
`tui --input <snapshot.json>` renders a read-only Ratatui dashboard skeleton,
`tui --keys tab,o,g,t,a,b,?,j,k,/filter,r,q` can replay a bounded read-only
pane/task-selection/filter/refresh/quit sequence, `tui --interactive` starts
a raw-mode read-only snapshot dashboard that accepts only Tab, o/O, g/G, t/T, a/A,
b/B, ?, j/J, k/K, Up/Down, r/R, q/Q, and Esc. Task Detail remains
projection-only and compactly shows selected-task state, stage, progress,
capability, skill, blocker, and message. The approvals/blockers pane now
summarizes awaiting approvals as display-only and states that shell approval
actions are unavailable. Graph Summary now shows compact task/done/running/
waiting/blocking/failure counts from the same projection. `--limit` can cap
rendered rows without truncating JSON projection output, and `boundary` renders the
shell-vs-P0 authority split.
`moxi-cli` remains a
submit/projection/approval-display shell only; it cannot execute, approve,
issue tickets, verify results, or commit ledger events.

## Current State

MOXI Essence Agent is in v0 trusted-kernel buildout. The current repository is
a Rust workspace with twenty library crates:

- `moxi-entry`: inbound entry adapter primitives. Converts external channel
  requests into an intent candidate plus entry metadata and requested
  `PermissionMode`.
- `moxi-cli`: first CLI shell binary. It exposes `admit`, `manifest`,
  `status`, file-backed snapshot `watch`, read-only snapshot `tui`,
  `boundary`, and minimal `repl` commands over `moxi-shells`; it cannot
  execute, approve, issue tickets, verify, or commit ledger events.
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
  through P0, asks `moxi-vault` for P1 execution readiness before ticket
  issuance, and stops high-risk tasks at approval or the readiness gate.
- `moxi-observability`: first P1.5 read-only fact layer. It turns runtime
  graph/query snapshots into `RuntimeFact`, `EvidenceRef`, `RunTimeline`,
  `RunMetric`, and `ProjectionSnapshot` DTOs so shells, eval, adaptive control,
  and audits can cite planner, task, event, attempt, adoption-probe, and resume
  evidence without mutating runtime or kernel state.
- `moxi-eval`: first P1.5 regression gate. It turns observability facts and
  store/ledger projections into `EvalSuite`, `EvalCase`, `ReplayProfile`,
  `EvalRun`, `EvalScore`, `RegressionReport`, and `SafetyFinding` records, and
  blocks adaptive promotion when required P0 evidence is missing.
- `moxi-skills`: first P1 skill package layer. It loads and writes
  `SkillPackage` manifests, lints read-only `SkillManifest` packages, checks
  package-root entrypoints, builds trigger/non-trigger eval cases through
  `SkillEvalBinding`, and hands valid packages to `RuntimeManifestRegistry`
  without executing skill code.
- `moxi-model-gateway`: first P1 model gateway control plane. It defines
  provider descriptors, `ModelRouteRequest`, `ModelRouteDecision`,
  `StructuredOutputAttempt`, and `ModelGatewayFact`, selects local/cloud model
  providers under risk, cost, latency, structured-output, and fallback
  constraints, validates structured outputs, and emits non-authorizing
  `UnderstandingProposal` records.
- `moxi-memory`: first P1 memory control plane. It defines `MemoryCrystal`,
  `MemoryWriteDraft`, `MemoryWriteProposal`, `MemoryReadQuery`,
  `MemoryCitation`, `WorkingMemoryProjection`, `ForgetRequest`,
  `MemoryAuditEvent`, and `MemoryContaminationFinding`, enforcing provider
  scopes, source tracking, consent/ledger gates, contamination checks, recall
  citations, and soft-delete/forget audit events without letting models write
  durable memory directly.
- `moxi-swarm`: first P1 multi-agent orchestration control plane. It defines
  `SwarmPlan`, `SwarmTask`, typed `AgentMessage`, `HandoffContract`,
  `SubagentSidechain`, `ReviewGate`, `MergeEvidence`, `ParentMerge`,
  `SwarmMetric`, and `SwarmSafetyFinding`, enforcing subagent capability
  bounds, memory-scope bounds, data-only messages, review gates, and evidence
  requirements before parent merges.
- `moxi-adaptive`: first P1.5 self-improvement proposal layer. It defines
  `ReflectionReport`, `RootCauseHypothesis`, `OptimizationDelta`,
  `ExperimentPlan`, and `ExperimentResult`, deriving optimization proposals
  from regression reports and requiring eval evidence for every delta.
- `moxi-governance`: first P1.5 promotion and evolution ledger layer. It
  defines `PromotionDecision`, `RolloutPlan`, `RollbackPlan`,
  `EvolutionEvent`, and `EvolutionLedger`, requiring passed experiments,
  evidence refs, and human approval for protected or high-risk deltas before
  rollout planning.
- `moxi-vault`: first P0 production-hardening control plane. It defines
  credential references, secret-use requests/decisions, tenant trust roots,
  executor signature verification decisions, tenant policy packs, sealed tenant
  policy records, quorum approvals, break-glass decisions, and redacted audit
  export records without storing raw secret material. It now also defines P1
  execution-readiness profiles, tenant-policy-record-bound profile records,
  requests, decisions, redacted P1 readiness audit exports, typed P1 execution
  audit bundles, and redacted compliance export bundles so bounded P1 runtime
  tasks can enter the P0 execution chain only when explicitly allowed and later
  review the request/profile/decision evidence.
  Production or
  credential-capable P1 profile records must attach a ready
  `ProductionReadinessDecision`.
- `moxi-hotpath`: first low-latency control plane. It defines latency budgets,
  hot-path requests, cache entries, hot-path decisions, degrade plans, latency
  samples, latency snapshots, and hot-path facts for ack/deny/route/cache-hit
  first-packet paths without executing tools or authorizing actions.
- `moxi-shells`: first P2 shell control plane. It defines shell request
  drafts, admissions, approval prompts, adapter manifests, graph/task
  projection DTOs, and runtime-profile compatibility checks for CLI/MCP/API
  style shells. It normalizes requests through `moxi-entry` and renders
  runtime snapshots, but cannot authorize, execute, issue tickets, verify
  results, or commit ledger events.
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
deterministic planner IR, task runtime, and a non-authorizing model-proposal to
planner bridge plus an R4 model-gateway control plane MVP, but richer
model-backed strategy planning, real provider adapters, streaming model
calls, context manager, verifier-as-a-separate-runtime, rollback manager,
code graph, and retrieval engine are not implemented as current Rust workspace
runtime modules. P1.5 now has a read-only runtime fact projection, an R1
store/ledger ingestion MVP for persisted P0 run facts, and an R2 `moxi-eval`
MVP for fact-derived regression reports. Metrics export, trace sinks, concrete
benchmark fixtures, and adaptive promotion governance are not implemented yet.
P1 now also has an R3 `moxi-skills` package/lint/eval-binding MVP, an R4
`moxi-model-gateway` routing/proposal MVP, and an R5 `moxi-memory` control
plane MVP, and an R6 `moxi-swarm` orchestration-control MVP. P1.5 now has an
R7 `moxi-adaptive` + `moxi-governance` self-improvement governance MVP, but
signed package trust, registry install/publish, quarantine, rollback, MCP risk
scanning, real model provider adapters, streaming, cache safety policy, quality
facts, persistent memory storage, retrieval ranking, memory eval history,
memory consent ledger integration, real subagent execution, distributed
scheduling, swarm topology benchmarks, persistent evolution ledgers, and live
rollout controllers are not implemented yet.

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
bus or control authority: it converts runtime graph/query snapshots and
read-only store observations into citeable facts and timelines. The runtime
surface covers planner binding, graph planning, task state, runtime events,
task attempts, adoption probes, resume recommendations, graph completion, and
aggregate run metrics. The R1 store surface covers persisted run status, policy
decisions, approval grants, execution tickets, sandbox results, proofs, ledger
events, and store-derived completion metrics. It does not write runtime state,
issue tickets, execute capabilities, verify outputs, or commit ledger events.

R2 has started with `moxi-eval`. It is also read-only: it consumes
observability facts/projections, builds replay/regression cases, runs local
case checks, emits scores and safety findings, and marks adaptive promotion as
blocked when required P0 evidence is missing. It does not execute tasks, call
models, issue tickets, verify outputs, or mutate the store/ledger.

R3 has started with `moxi-skills`. It keeps skill packaging separate from
execution: packages can be loaded, linted, converted into runtime manifests,
and bound to eval cases, but actual task execution still flows through
`moxi-runtime` and P0 capability/ticket/proof/ledger boundaries.

R4 has started with `moxi-model-gateway`. It keeps model selection and
understanding advisory: provider descriptors can be routed against risk,
capability, structured-output, cost, latency, local/cloud, and fallback
constraints; route decisions can become cost/latency facts; structured output
attempts are schema-validated with retry delay hints; and
`UnderstandingProposal` is explicitly marked as unable to authorize. It does
not call providers, stream tokens, execute actions, or issue tickets.

R5 has started with `moxi-memory`. It keeps long-term memory proposal-based
and evidence-bound: write requests become `MemoryWriteProposal` records with
source, scope, confidence, retention, risk, consent, ledger, tags, and evidence
refs; provider scope and access modes are enforced; contamination findings can
block instruction-like content; accepted `MemoryCrystal` records carry source,
consent, and ledger refs; recall returns citations; working-memory projections
stay read-only; and forget requests produce auditable soft-delete or forget
events. It does not provide a production vector store, ranking engine, consent
ledger, or memory persistence backend yet.

R6 has started with `moxi-swarm`. It keeps multi-agent orchestration
evidence-gated: plans list bounded `SubagentManifest` records and tasks,
handoffs constrain allowed capabilities and memory scopes, typed messages
distinguish claims/evidence/instructions/tool proposals/risk/review decisions,
sidechains collect message and evidence ids, review gates approve or reject
sidechains, merge evidence is required before parent merge proposals, and
parent merges are explicitly unable to commit ledger events. It does not run
subagents, open tool tickets, replace P0 proof, or implement production swarm
scheduling yet.

R7 has started with `moxi-adaptive` and `moxi-governance`. Adaptive converts
regression reports into `ReflectionReport` records, root-cause hypotheses,
evidence-bound `OptimizationDelta` proposals, and experiment plans/results.
Governance converts passed experiments into promotion decisions, rollout
plans, rollback plans, and evolution ledger events. Protected
`PolicyPack`/`Capability` deltas and high-risk deltas require human approval,
and every promotion or rollback must carry eval evidence. These crates do not
modify P0 policy, issue tickets, execute rollouts, or persist a production
evolution ledger yet.

R8 has locally completed the P0 production-hardening control-plane closure with
`moxi-vault`. It models the first P0 production-hardening
control plane for credential references, secret-use boundaries, tenant trust
roots, executor signature verification decisions, tenant policy packs,
quorum approvals, break-glass decisions, redacted audit exports, production
adapter evidence, a P1 execution-readiness gate, and a fail-closed production
readiness gate. The P1 execution-readiness gate lets the default local profile
admit only bounded read-only `file.read` tasks into the P0 execution chain, and
blocks unlisted capabilities, credentialed tasks, and high-risk tasks without
production-ready P0 evidence. The production gate records missing production
auth, external secret-manager/KMS/HSM, cryptographic verifier, hardened sandbox,
secret injection, rotation, tenant policy, executor trust-root, and compliance
audit-export evidence before credentialed or executable production enablement.
Production adapter evidence is now verified into tenant-bound
`ProductionAdapterVerificationDecision` records, and production readiness
requires every adapter evidence item to bind to its matching verified decision.
P1 execution audit bundles now bind the runtime request, sealed profile record,
readiness decision, optional production readiness ref, redaction profile, and
evidence refs for review without granting ticket, execution, verification, or
ledger authority to P1.
Compliance export bundles now aggregate redacted audit export records and P1
execution audit bundles under a sealed tenant policy record/hash for review,
without persisting raw secrets or calling an external compliance backend.
It keeps raw secrets out of model, log, and durable payload paths. It does not
yet integrate concrete KMS/HSM/secret-manager adapters, perform real
cryptographic verification, inject credentials into OS sandboxes, or generate
externally persisted compliance export bundles.

R9 has started with `moxi-hotpath`. It turns the 5ms claim into a bounded
first-packet contract for ack, early deny, route, and exact/template cache-hit
decisions. It also records degrade plans, latency samples, p50/p95/p99
snapshots, and hot-path facts. It does not execute tools, authorize actions,
serve semantic cache entries as trusted facts, or claim that complete LLM
answers can be produced in 5ms.

R10 has started with `moxi-shells`. It makes product shells explicit as
submit-only, projection-only, and approval-display-only surfaces. The MVP
supports shell request drafts, entry normalization, shell adapter manifests,
runtime shell profile compatibility, event-feed projection, query-snapshot
projection, and high-risk approval hints. `moxi-cli` now adds the first CLI
binary with verified `admit`, `manifest`, `status`, `watch`, `tui`, `boundary`,
and minimal `repl` commands. `status` renders runtime event-feed and query
snapshots as shell projections without executing or authorizing work,
including readable `--text` output and a static ASCII `--panel` preview.
`watch` repeats that same rendering from an explicit snapshot file for bounded
ticks, so it is a preview loop rather than live runtime control. `tui` renders
a Ratatui snapshot dashboard with overview, graph summary, tasks,
approvals/blockers, task detail, boundary, and key-hint panes. Its `--keys`
replay model covers `tab`,
`o`, `g`, `t`, `a`, `b`, `?`, `j`, `k`, `/filter`, `r`, and `q`, allowing pane
cycling/focus, task selection, filtering, refresh count, and quit state to be
verified without opening a terminal. `tui --interactive` starts a crossterm
raw-mode event-loop skeleton for the same explicit snapshot file and only
accepts Tab, o/O, g/G, t/T, a/A, b/B, ?, j/J, k/K, Up/Down, r/R, q/Q, and Esc. Its
Task Detail pane follows the selected task and compactly shows state, stage,
progress, capability, skill, blocker, and message without action controls; it
also renders awaiting-approval counts as display-only in the approvals/blockers
pane, shows compact graph task counters, and still has no live runtime polling.
`--limit` only caps rendered blocker/graph/task rows for text or panel output;
JSON projection output remains complete. `boundary` renders the
no-execution/no-authority contract. It does not include a full runtime-control
TUI, MCP server, SDK, HTTP
transport, desktop UI, web UI, mobile approval app, or digital-human shell yet.

P0 coverage in current code:

- Implemented: entry boundary, gateway v0 trust checks, deterministic intent
  compiler, kernel admission, configurable policy engine, approval grants,
  capability registry, run contract, capability contract, state store, local
  file sandbox, v0 process-sandbox protocol, proof collection, append-only
  ledger, schema migrations, ledger replay/audit verification, reference-only
  credential-use decisions, tenant trust-root signature verification decisions,
  quorum approvals, break-glass decision records, redacted audit export records,
  and a P0-controlled P1 execution-readiness gate for bounded runtime execution.
- Partial: scheduler is represented by kernel-driven run status transitions and
  heartbeat/budget accounting, but not an independent scheduler runtime.
- Partial: execution event bus is represented by persisted ledger/state facts,
  but no separate streaming event bus exists yet.
- Production gates before enabling credentialed or executable external actions:
  `moxi-vault` now exposes a fail-closed readiness decision for auth,
  credential/key-store, cryptographic verifier, hardened sandbox, secret
  injection, rotation, tenant policy, executor trust-root, and compliance export
  evidence. Concrete adapters for these gates remain required before production
  exposure.
- P1 execution gates before runtime task execution: `moxi-runtime` now asks
  `moxi-vault` for `P1ExecutionReadinessDecision` before ticket issuing. Ready
  local read-only tasks still execute through
  `admit -> propose_delta -> issue_ticket -> execute -> verify -> commit`;
  blocked tasks stop before ticket issuance and P1 never gains direct authority.

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
- Runtime model-proposal bridge: `RuntimeSession::planner_plan_from_understanding`
  converts evidence-bound, non-authorizing `UnderstandingProposal` task
  decompositions into `PlannerSource::ModelProposed` plans, rejects capability
  expansion, and still compiles through profile validation before any P0 action.
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
- Runtime P1 execution readiness: before ticket issuing, `RuntimeSession`
  builds a `P1ExecutionReadinessRequest` and requires `moxi-vault` to return a
  ready `P1ExecutionReadinessDecision`. The default profile permits bounded
  local read-only `file.read` execution through P0, while disallowed
  capabilities stop before ticket issuance.
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
- Store/ledger observability facts: `moxi-store::StoredRunObservation` exposes
  a read-only run observation spanning persisted run state, policy decisions,
  approval grants, execution tickets, sandbox results, proofs, and ledger
  events; `moxi-observability::StoreProjectionSnapshot` converts it into
  citeable `RuntimeFact`, `EvidenceRef`, `RunTimeline`, and `StoreRunMetric`
  records without issuing tickets, executing capabilities, verifying outputs,
  or committing ledger events.
- Eval regression gate: `moxi-eval` exposes `EvalSuite`, `EvalCase`,
  `ReplayProfile`, `EvalRun`, `EvalScore`, `RegressionReport`, and
  `SafetyFinding`, can build a P0 replay/audit suite from
  `StoreProjectionSnapshot`, and blocks adaptive promotion if required policy,
  ticket, sandbox result, proof, or ledger facts are missing.
- Skill package MVP: `moxi-skills` exposes `SkillPackage`,
  `SkillTriggerTest`, `SkillEvalBinding`, `SkillLintReport`, and
  `SkillLintFinding`; it loads/writes package manifests, rejects package-root
  path escapes, lints read-only skill manifests, converts valid packages into
  `RuntimeManifestRegistry`, and generates trigger/non-trigger eval cases.
- Model gateway MVP: `moxi-model-gateway` exposes provider descriptors,
  `ModelRouteRequest`, `ModelRouteDecision`, `StructuredOutputAttempt`, and
  `ModelGatewayFact`; it routes local/cloud providers with fallback lists,
  records cost/latency estimates, rejects high-risk downgrade to insufficient
  providers, validates structured outputs, and creates non-authorizing
  `UnderstandingProposal` records.
- Memory control-plane MVP: `moxi-memory` exposes `MemoryCrystal`,
  `MemoryWriteDraft`, `MemoryWriteProposal`, `MemoryReadQuery`,
  `MemoryCitation`, `WorkingMemoryProjection`, `ForgetRequest`,
  `MemoryAuditEvent`, and `MemoryContaminationFinding`; it enforces provider
  scopes, source refs, consent/ledger gates, contamination blocking, recall
  citations, working-memory projections, and auditable forget events.
- Swarm orchestration-control MVP: `moxi-swarm` exposes `SwarmPlan`,
  `SwarmTask`, typed `AgentMessage`, `HandoffContract`, `SubagentSidechain`,
  `ReviewGate`, `MergeEvidence`, `ParentMerge`, `SwarmMetric`, and
  `SwarmSafetyFinding`; it blocks subagent capability expansion, enforces
  memory scopes, treats untrusted content as data, requires review-backed merge
  evidence, and keeps parent merge proposals unable to commit ledger events.
- Adaptive/governance MVP: `moxi-adaptive` exposes `ReflectionReport`,
  `RootCauseHypothesis`, `OptimizationDelta`, `ExperimentPlan`, and
  `ExperimentResult`; `moxi-governance` exposes `PromotionDecision`,
  `RolloutPlan`, `RollbackPlan`, `EvolutionEvent`, and `EvolutionLedger`. The
  loop requires eval evidence, passed experiments, and human approval for
  protected/high-risk deltas before rollout planning.
- P0 production-hardening MVP: `moxi-vault` exposes `CredentialRef`,
  `SecretUseRequest`, `SecretUseDecision`, `TrustRoot`, `ExecutorSignature`,
  `SignatureVerificationDecision`, `TenantPolicyPack`,
  `TenantPolicyPackRecord`, `QuorumApproval`, `BreakGlassRequest`,
  `BreakGlassDecision`, `AuditExportRecord`,
  `ProductionHardeningEvidence`, `ProductionAdapterEvidence`,
  `ProductionAdapterVerificationDecision`, and `ProductionReadinessDecision`,
  plus `P1ExecutionReadinessProfile`, `P1ExecutionReadinessProfileRecord`,
  `P1ExecutionReadinessRequest`, and `P1ExecutionReadinessDecision`,
  `P1ExecutionAuditBundle`, and `ComplianceExportBundle`. It rejects raw
  secret-looking references, requires
  quorum for high-risk secret use, checks executor signatures against tenant
  trust-root metadata, binds signature decisions to tenant ids, exports redacted
  audit records, P1 execution audit bundles, and local compliance export
  bundles, rejects placeholder adapter evidence, verifies adapter evidence into
  tenant-bound decisions, blocks production readiness until all P0 hardening
  gates have tenant-bound adapter evidence and matching verified decisions,
  seals tenant policy packs with stable hashes, seals P1 execution
  profiles against tenant policy record refs and policy/profile hashes,
  requires ready production readiness before sealing production or
  credential-capable P1 profiles, and blocks P1 runtime tasks before ticket
  issuance unless the P1 execution profile allows them into the P0 chain.
- Low-latency control-plane MVP: `moxi-hotpath` exposes `LatencyBudget`,
  `HotPathRequest`, `CacheEntry`, `HotPathDecision`, `DegradePlan`,
  `LatencySample`, `LatencySnapshot`, and `HotPathFact`. It enforces cache
  scope/freshness/risk gates, early-denies unsafe capabilities, defers
  high-risk work to trusted execution, and reports p50/p95/p99 first-packet
  latency snapshots.
- Shell control-plane MVP: `moxi-shells` exposes `ShellRequestDraft`,
  `ShellAdmission`, `ApprovalPrompt`, `ShellProjection`, `ShellGraphView`,
  and `ShellTaskView`. It binds shell surfaces to compatible
  `RuntimePolicyProfile` values, normalizes shell requests through
  `moxi-entry`, and renders runtime event/query snapshots without granting any
  execution or approval authority.
- CLI shell MVP: `moxi-cli` exposes `admit`, `manifest`, `status`, `watch`,
  `tui`, `boundary`, and `repl` commands that emit JSON shell contracts. The latest
  R10 verification passed for formatting, workspace tests, workspace clippy,
  real `admit`/`manifest`/`boundary` runs, and piped REPL input. `status`
  reads event-feed or query-snapshot JSON from stdin or a file and projects it
  through `moxi-shells`, either as JSON, a readable `--text` status view, or a
  static ASCII `--panel` preview. `watch` rereads an explicit snapshot file
  and rerenders the same projection for bounded ticks; it does not add runtime
  polling, execution, approval, ticket, verification, or ledger authority.
  `tui` renders the same snapshot as a Ratatui multi-pane dashboard and remains
  read-only; `--keys` can replay `tab`, `o`, `t`, `a`, `b`, `?`, `j`, `k`, `/filter`, `r`, and `q` for deterministic
  tests, while `--interactive` starts a raw-mode snapshot dashboard that accepts
  only Tab, o/O, t/T, a/A, b/B, ?, j/J, k/K, Up/Down, r/R, q/Q, and Esc. It is still not an interactive runtime
  controller.
  `--limit` is a render-only row cap for text and panel output and does not
  truncate JSON projection output. `boundary` reports supported and forbidden
  shell commands plus the P0-owned authority fields. It intentionally rejects
  unknown commands such as `execute`, preserving the shell-vs-kernel boundary.
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
- Production vault integration beyond the current R8 adapter evidence gate:
  concrete KMS/HSM/secret-manager calls, real cryptographic signature
  verification, secret injection into hardened sandboxes, tenant trust-root
  persistence, and external compliance export bundle storage/delivery. Adapter
  evidence and rotation/compliance requirements are now modeled as fail-closed
  readiness gates, and local redacted compliance bundles can be assembled, but
  live external infrastructure still needs to be connected.
- P1 execution readiness beyond the default local read-only profile: production
  profiles, credentialed execution, and high-risk runtime tasks still require
  production-ready P0 evidence and concrete external adapters.
- Low-latency hardening beyond the current R9 control-plane MVP: real
  benchmark harnesses, latency fact ingestion into observability/eval,
  model-serving adapters, queue/backpressure integration, exact/template cache
  storage, semantic cache safety eval, and per-tenant p50/p95/p99 SLO reports.
- Model-backed or policy-backed intent compilation beyond the current
  deterministic v0 compiler.
- P1 planner hardening beyond deterministic, skill-registry, and the current
  non-authorizing model-proposal bridge: richer strategy planning, plan repair,
  cross-host distributed locking beyond local SQLite arbitration,
  concrete provider-specific adoption adapter implementations against real idempotency APIs,
  ledger-backed adoption of already-committed external effects, profile schema
  migrations, and packaged profile distribution.
- Observability export metrics, trace sinks, concrete benchmark fixtures,
  persisted eval history, failure-to-eval-case generation, and adaptive-control
  promotion gates beyond the current runtime/R1 facts and R2 eval MVP.
- Signed skill package metadata, trust roots, registry publish/install,
  quarantine/disable/rollback lifecycle, and MCP server risk scanner beyond the
  current R3 skill package/lint/eval-binding MVP.
- Full CLI TUI, HTTP API transport, SDK package, MCP server, desktop UI, web
  UI, mobile approval app, and digital-human shell.
- Real model provider adapters, streaming model calls, model cache safety
  policy, gateway-to-observability export, model quality facts, persistent
  memory storage, memory retrieval ranking, consent ledger integration, real
  subagent execution adapters, distributed swarm scheduling, topology
  benchmark suites, persistent evolution ledger storage, live rollout/rollback
  executor, governance approval UI, tool gateway, plugin host, browser daemon,
  remote bridge, and workflow runtime.
- Adaptive/governance hardening beyond the current R7 MVP: durable experiment
  history, real rollout controllers, rollback execution, policy-pack review
  workflows, audit export integration, and longitudinal promotion metrics.
- Swarm hardening beyond the current R6 MVP: real sidechain persistence,
  reviewer assignment policy, topology evaluation, faulty-agent injection,
  malicious input regression coverage, budget enforcement, and latency/token
  accounting.
- Advanced manifest registry features: schema migrations, signatures, signed
  trust roots, and concrete packaged registries.
- Concrete production executors beyond the current built-in `file.read`,
  process-sandbox protocol harness, and test-only custom executor.
- OS-level process sandbox hardening beyond direct child-process execution,
  protocol checks, and timeout kill.
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

Latest targeted R10 recovery verification:

```powershell
cargo fmt --all --check
cargo test -p moxi-cli --locked --target-dir C:\MOXI-Essence-agent\MOXI-Essence-agent\target-codex-r10-repl-verify
cargo test -p moxi-shells --locked --target-dir C:\MOXI-Essence-agent\MOXI-Essence-agent\target-codex-r10-repl-verify
cargo clippy -p moxi-cli --all-targets --locked --target-dir C:\MOXI-Essence-agent\MOXI-Essence-agent\target-codex-r10-repl-verify -- -D warnings
cargo run -p moxi-cli --locked --target-dir C:\MOXI-Essence-agent\MOXI-Essence-agent\target-codex-r10-repl-verify -- admit --tenant local --user codex --workspace C:\MOXI-Essence-agent\MOXI-Essence-agent --goal "read project status" --capability file.read
cargo run -p moxi-cli --locked --target-dir C:\MOXI-Essence-agent\MOXI-Essence-agent\target-codex-r10-repl-verify -- manifest --surface cli
```

Result: passed. Later full-workspace verification also passed after extending
the read-only `status` projection command to both event-feed and query-snapshot
inputs. The piped REPL checks passed for `admit`, `manifest`, `status`,
`execute` as `unknown command`, and `exit`. The latest `moxi-cli` focused test
run covers 41 tests after adding file-backed `watch` preview coverage,
read-only Ratatui `tui` skeleton, compact Graph Summary coverage, compact Task
Detail coverage, approval display-only panel coverage, scriptable `tui --keys`
pane/task-selection/filter/refresh/quit coverage, graph-pane focus replay,
raw-mode key mapping,
pane-focus key replay, task-selection key replay, and `--poll-ms` validation,
boundary reporting, PowerShell/Windows UTF-8 BOM handling for REPL commands
and piped status JSON, and render-only `--limit` coverage for text/panel output
and JSON non-truncation. The latest graph-focus pass used
`target-codex-r10-tui-graph-focus`, with `moxi-cli` at 41 passed and
`moxi-shells` at 7 passed.

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

Swarm-specific architecture now has a P1 control-plane MVP in `moxi-swarm`.
The current direction remains evidence-gated: subagents may plan, review, and
propose, but they cannot expand authority or merge into a parent run without
sidechain evidence and P0-controlled execution for external effects. Real
subagent execution, sidechain persistence, topology eval, and production budget
enforcement are still future hardening work.







