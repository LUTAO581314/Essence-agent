# MOXI Essence Agent v0.2.0

Rust-only trusted ingress, intent, and kernel foundation for MOXI/ESSENCE Agent.

This branch intentionally contains only the core framework plus a minimal
contract-checking CLI shell. It does not include a full TUI, desktop UI,
web UI, plugin marketplace, model providers, swarm runtime, remote bridge,
long-term memory runtime, or auto-evolution.
The first P1 runtime crate is now present, but it remains a thin orchestration
layer over the trusted P0 kernel. The first P1.5 observability crate is also
present as a read-only fact/projection layer, `moxi-eval` now provides the
first regression gate over those facts, `moxi-skills` adds the first skill
package/lint/eval-binding surface, `moxi-model-gateway` adds the first
model-routing control plane without calling real providers or granting
authority, and `moxi-memory` adds the first source-tracked memory control
surface without letting models write durable memory directly. `moxi-swarm`
adds the first evidence-gated multi-agent orchestration control plane without
letting subagents expand authority. `moxi-adaptive` and `moxi-governance` add
the first eval-gated self-improvement control loop without letting adaptive
logic modify P0 directly. `moxi-vault` adds the first P0 production-hardening
control plane for credential references, secret-use decisions, tenant trust
roots, executor signature verification decisions, quorum approvals,
break-glass decisions, redacted audit export records, redacted P1 execution
audit bundles, redacted compliance export bundles, and compliance export
delivery decisions without storing raw
secret material, plus a P1 execution-readiness gate for bounded local runtime execution and a production
readiness gate that blocks credentialed or
executable production enablement until production auth, real external secret
management, cryptographic verification, hardened sandboxing, secret injection,
rotation enforcement, tenant policy, executor trust roots, and compliance audit
export evidence are all present. `moxi-hotpath` adds the first low-latency control plane for
5ms-class ack/deny, 10ms route decisions, bounded cache-hit decisions,
degrade plans, latency samples, and percentile snapshots without executing
tools or authorizing actions. `moxi-shells` adds the first shell control
plane for CLI/MCP/API/IDE-style admission, runtime projection, and approval
display contracts without executing tools, authorizing actions, issuing
tickets, or committing ledger events. `moxi-cli` adds the first CLI shell over
that control plane for JSON admission, adapter manifest output, read-only
runtime event-feed/query projection, a readable `status --text` view, an
ASCII `status --panel` preview, a read-only Ratatui snapshot `tui` dashboard
with scriptable pane-focus/task-selection/filter/refresh/quit keys, an
approval display-only blockers pane, a compact projection-only Graph Summary
pane, and a compact projection-only Task Detail pane, a read-only `tui --interactive`
raw-mode skeleton for the same snapshot projection, an explicit `boundary`
report, and a minimal REPL loop. It also provides a
snapshot-file `watch` preview that repeatedly renders the same read-only
status projection without polling P0 directly; the targeted R10 checks for
`admit`, `manifest`, `status`, `watch`, `tui`, `boundary`, and REPL behavior
now pass locally.

## Core crates

- `moxi-entry`: inbound entry adapter primitives for CLI, desktop, web,
  HTTP API, SDK, MCP server, and automation channels. It normalizes external
  requests into an intent candidate plus entry metadata, without authenticating,
  issuing tickets, or touching tool capabilities.
- `moxi-cli`: first CLI shell binary. It exposes `admit`, `manifest`,
  `status`, `watch`, `tui`, `boundary`, and `repl` commands that call
  `moxi-shells` and write JSON shell contracts; `status --text` renders the
  same projection in a readable status view, `status --panel` renders a static
  terminal panel preview, `watch --input <snapshot.json>` refreshes that same
  file-backed projection preview, `tui --input <snapshot.json>` renders a
  read-only Ratatui dashboard with overview, graph summary, tasks,
  approvals/blockers, task detail, boundary, and key-hint panes, and `tui --keys
  tab,o,g,t,a,b,?,j,k,/filter,r,q` can replay a bounded read-only pane/task-
  selection/filter/refresh/quit sequence for tests and scripts.
  `tui --interactive` starts the same read-only snapshot dashboard in raw
  terminal mode; it accepts only Tab, o/O, g/G, t/T, a/A, b/B, ?, j/J, k/K,
  Up/Down, r/R, q/Q, and Esc, and still only rereads the explicit snapshot
  file. Task Detail is compact and projection-only, summarizing selected task
  state, stage, progress, capability, skill, blocker, and message without
  action controls. The approvals/blockers pane summarizes awaiting approvals as
  display-only and shows that shell approval actions are unavailable. Graph
  Summary shows task/done/running/waiting/blocking/failure counts from the same
  projection. `--limit`
  can cap rendered rows without truncating JSON projection
  output, and `boundary` reports the shell-vs-P0 authority split. It has no
  execute, approve, ticket, verify, or ledger commands.
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
  reads, model-proposed planner plans from non-authorizing
  `UnderstandingProposal` task decompositions, and trusted execution through the
  P0 kernel. Before ticket issuance it now asks the P0 vault control plane for a
  `P1ExecutionReadinessDecision`, so the default local profile can run bounded
  low-risk `file.read` tasks through P0 while blocking disallowed capabilities,
  credential use, and high-risk tasks without production-ready P0 evidence. It
  cannot issue tickets or execute tools directly.
- `moxi-observability`: first P1.5 fact layer. It converts runtime graph/query
  snapshots into `RuntimeFact`, `EvidenceRef`, `RunTimeline`, `RunMetric`, and
  `ProjectionSnapshot` DTOs for shells, evaluation, adaptive control, and audit
  explanations. It is read-only and cannot mutate runtime state, issue tickets,
  execute capabilities, verify results, or commit ledger events.
- `moxi-eval`: first P1.5 evaluation gate. It builds `EvalSuite`, `EvalCase`,
  `ReplayProfile`, `EvalRun`, `EvalScore`, `RegressionReport`, and
  `SafetyFinding` records from observability facts, including P0 store/ledger
  projections. It can block adaptive promotion when required policy, ticket,
  sandbox, proof, or ledger evidence is missing, but it cannot execute or
  authorize actions.
- `moxi-skills`: first P1 skill package layer. It defines `SkillPackage`,
  `SkillTriggerTest`, `SkillEvalBinding`, and lint reports, can load/write
  package manifests, verify entrypoints stay inside the package root, convert
  valid packages into `RuntimeManifestRegistry`, and generate eval suites for
  trigger/non-trigger cases. It never executes skill code directly.
- `moxi-model-gateway`: first P1 model gateway control plane. It defines
  provider descriptors, `ModelRouteRequest`, `ModelRouteDecision`,
  `StructuredOutputAttempt`, and `ModelGatewayFact`, performs local/cloud
  provider selection with fallback lists and cost/latency estimates, validates
  structured output attempts, and produces non-authorizing
  `UnderstandingProposal` records. It does not call real model providers,
  execute actions, issue tickets, or authorize model output.
- `moxi-memory`: first P1 memory control plane. It defines `MemoryCrystal`,
  `MemoryWriteDraft`, `MemoryWriteProposal`, `MemoryReadQuery`,
  `MemoryCitation`, `WorkingMemoryProjection`, `ForgetRequest`,
  `MemoryAuditEvent`, and `MemoryContaminationFinding`. It enforces provider
  scopes, source tracking, consent/ledger gates, contamination checks, recall
  citations, and soft-delete/forget audit events; model output can propose
  memory, but cannot write durable memory directly.
- `moxi-swarm`: first P1 multi-agent orchestration control plane. It defines
  `SwarmPlan`, `SwarmTask`, typed `AgentMessage`, `HandoffContract`,
  `SubagentSidechain`, `ReviewGate`, `MergeEvidence`, `ParentMerge`, and
  `SwarmMetric`, enforcing subagent capability and memory-scope bounds,
  data-only message treatment, review gates, and evidence requirements before
  parent merges. It does not execute subagents or authorize tool use.
- `moxi-adaptive`: first P1.5 self-improvement proposal layer. It defines
  `ReflectionReport`, `RootCauseHypothesis`, `OptimizationDelta`,
  `ExperimentPlan`, and `ExperimentResult`, generating optimization proposals
  from regression reports and binding every delta to eval evidence. It cannot
  modify P0 policy or capability contracts directly.
- `moxi-governance`: first P1.5 promotion and evolution ledger layer. It
  defines `PromotionDecision`, `RolloutPlan`, `RollbackPlan`,
  `EvolutionEvent`, and `EvolutionLedger`, requiring passed experiments,
  evidence refs, and human approval for protected/high-risk deltas before
  rollout planning.
- `moxi-vault`: first P0 production-hardening control plane. It defines
  `CredentialRef`, `SecretUseRequest`, `SecretUseDecision`,
  `SecretInjectionEvidence`, `SecretInjectionDecision`, `TrustRoot`,
  `TrustRootRecord`, `ExecutorSignature`, `SignatureVerificationDecision`,
  `TenantPolicyPack`, `QuorumApproval`, `BreakGlassRequest`,
  `BreakGlassDecision`, and `AuditExportRecord`, plus sealed
  `TenantPolicyPackRecord` values, enforcing reference-only secrets, quorum
  gates, tenant trust-root checks, hash-bound trust-root records,
  trust-root external storage evidence decisions, redacted audit export
  metadata, and a
  fail-closed `P1ExecutionReadinessDecision` gate plus
  `ProductionAdapterEvidence`, `ProductionAdapterVerificationDecision`,
  `ProductionAuthEvidence`, `ProductionAuthDecision`,
  `ExternalSecretManagerEvidence`, `ExternalSecretManagerDecision`,
  `CryptographicVerifierEvidence`, `CryptographicVerifierDecision`,
  `HardenedSandboxEvidence`, `HardenedSandboxDecision`,
  `RotationEnforcementDecision`, `ComplianceExportDeliveryDecision`, and
  `ProductionHardeningDecisionSet` / `ProductionReadinessDecision` gates over
  production auth, external secret manager, crypto verifier, hardened sandbox,
  secret injection, rotation, tenant policy, executor trust roots, and
  compliance export evidence. It
  verifies adapter evidence into tenant-bound decisions and requires production
  readiness to bind every adapter evidence item to the matching verified
  decision; when rotation refs are configured it also requires every credential
  to bind to a verified rotation-enforcement decision, optionally bound to a
  verified RotationEnforcement adapter decision. It verifies production
  auth evidence into tenant-bound decisions that bind the configured auth
  provider, issuer/JWKS/token/session policy refs, and a verified AuthProvider
  adapter decision; it verifies external secret-manager evidence into
  tenant-bound decisions that bind credential refs, external secret refs,
  KMS/HSM/access-policy/rotation refs, and a verified ExternalSecretManager
  adapter decision; it verifies cryptographic verifier evidence into
  tenant-bound decisions that bind signature decisions, sealed trust-root
  records and hashes, configured verifier refs, verifier policy,
  transparency-log, algorithm-suite, attestation refs, and a verified
  CryptographicVerifier adapter decision; it verifies hardened sandbox evidence
  into tenant-bound decisions that bind the configured sandbox profile,
  isolation, filesystem, network, syscall, resource policy, attestation refs,
  and a verified HardenedSandbox adapter decision; it also verifies secret injection receipts as tenant-bound
  decisions that bind an allowed `SecretUseDecision`, an executor-injected
  credential, hardened sandbox and injection profiles, and a verified
  SecretInjection adapter decision. It can seal tenant policy packs with stable
  hashes, then seal P1 execution-readiness profiles into
  tenant-policy-record-bound `P1ExecutionReadinessProfileRecord` values, reload
  them with policy/profile hash validation, and export redacted P1 readiness audit records
  plus `P1ExecutionAuditBundle` values binding the runtime request, profile
  record, readiness decision, optional production readiness ref, redaction
  profile, and evidence refs for review. It can also package redacted
  `ComplianceExportBundle` values that aggregate audit exports and P1 execution
  bundles under one tenant policy record/hash for review.
  Production or credential-capable P1 profiles must be sealed through a ready
  `ProductionReadinessDecision`; blocked or missing production readiness fails
  closed. It records decisions and evidence refs only; it never stores raw
  secrets or performs real cryptographic signing in this MVP.
- `moxi-hotpath`: first low-latency control plane. It defines
  `LatencyBudget`, `HotPathRequest`, `CacheEntry`, `HotPathDecision`,
  `DegradePlan`, `LatencySample`, `LatencySnapshot`, and `HotPathFact`,
  making ack, early deny, route, exact/template cache hit, task-path deferral,
  and trusted-execution deferral measurable. It cannot execute tools or
  authorize actions.
- `moxi-shells`: first P2 shell control plane. It defines `ShellRequestDraft`,
  `ShellAdmission`, `ApprovalPrompt`, `ShellProjection`, `ShellGraphView`,
  and `ShellTaskView`, selects compatible runtime shell profiles, normalizes
  shell requests through `moxi-entry`, converts runtime event/query snapshots
  into shell-facing projections, and keeps shells submit-only,
  projection-only, and approval-display-only.
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
`RuntimeSession::planner_plan_from_understanding` can now accept an
evidence-bound, non-authorizing `UnderstandingProposal` task decomposition and
turn it into a `PlannerSource::ModelProposed` plan. The runtime rejects
proposals that belong to another intent, lack evidence, claim authorization, or
suggest capabilities outside the original intent; compiled graphs still pass
profile validation and any external action still returns to P0.
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
facts. R1 now also adds a read-only store/ledger ingestion MVP:
`moxi-store::StoredRunObservation` collects persisted P0 run state, policy
decisions, approvals, tickets, sandbox results, proofs, and ledger events, and
`moxi-observability::StoreProjectionSnapshot` turns that observation into
citeable P0 facts, a timeline, and run metrics. Export metrics, trace sinks,
concrete benchmark fixtures, and adaptive/governance promotion gates are still
future work. R2 adds `moxi-eval` as the first regression surface over these
facts: a store projection can become an eval suite, a regression run, and a
report whose score controls whether adaptive promotion is allowed.

## R9 low-latency path

```text
HotPathRequest
-> cache scope/freshness/risk gate
-> ack / early deny / route / cache-hit / defer decision
-> DegradePlan
-> LatencySample
-> LatencySnapshot p50/p95/p99
-> HotPathFact
```

`moxi-hotpath` makes the 5ms goal concrete: it only applies to first-packet
ack/deny and bounded hot-route/cache-hit decisions. Normal LLM answers remain
measured by TTFT, TPOT, queue wait, prefill/decode, and tool latency. High-risk
requests are deferred to the trusted execution path, unsafe capabilities can be
early-denied, and semantic cache entries need task-path review instead of
silently serving as facts.

## R10 shell control plane

```text
ShellRequestDraft
-> EntryRequest
-> NormalizedEntry
-> RuntimePolicyProfile compatibility check
-> ShellAdmission
-> RuntimeEventFeedSnapshot / RuntimeQuerySnapshot
-> ShellProjection
```

`moxi-shells` is the first shell-facing contract layer. `moxi-cli` is the
first CLI binary on top of it, with verified `admit`, `manifest`, `status`,
`watch`, `tui`, `boundary`, and minimal `repl` commands. `status` reads a runtime
event-feed or query snapshot JSON payload from stdin or a file and renders the
shell projection as JSON or a readable `--text` view through `moxi-shells`;
`--panel` renders the same projection as a static terminal panel preview, and
`--limit` only caps rendered blocker/graph/task rows for text or panel output.
`watch` is a file-backed snapshot preview that repeats the same text/panel/JSON
projection rendering for a bounded number of ticks. `tui` is the first
read-only Ratatui dashboard skeleton over the same snapshot projection, using
overview, graph summary, tasks, approvals/blockers, task detail, boundary, and
key-hint panes.
Task Detail is compact and high-signal: it follows the selected task and shows
state, stage, progress, capability, skill, blocker, and message while remaining
projection-only. The approvals/blockers pane summarizes awaiting approvals as
display-only and repeats that shell approval actions are unavailable. Graph
Summary shows compact task/done/running/waiting/blocking/failure counts without
adding a new data source. It also has a scriptable `--keys` replay model for
`tab`, `o`, `g`, `t`, `a`, `b`, `?`,
`j`, `k`, `/filter`, `r`, and `q` so pane selection, task selection, filtering,
refresh count, and quit state can be verified without starting a terminal.
`tui --interactive` starts a crossterm raw-mode
event-loop skeleton for the same read-only snapshot projection; accepted live
keys are Tab, o/O, g/G, t/T, a/A, b/B, ?, j/J, k/K, Up/Down, r/R, q/Q, and Esc. JSON
projection output remains complete.
`boundary` renders the same no-execution/no-authority
contract for humans or scripts. It does not execute work or read the P0 ledger
directly; `watch` and `tui` only reread an explicit snapshot file. It is not a
full runtime-control TUI or MCP server yet. The product-shell
boundary is explicit: shells can submit normalized requests, render runtime
projections, and display approval state, but they cannot execute capabilities,
approve their own requests, issue execution tickets, verify results, or commit
ledger events.
CLI fast mode is kept to a read-only `shell.cli.fast` profile; high-risk or
privileged work is marked for the trusted execution path.

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
- Credential use is represented by vault references and evidence-bound
  decisions. `moxi-vault` rejects raw secret-looking references, requires
  quorum for high-risk secret use, and marks raw secrets as invisible to
  models, ordinary logs, and durable payloads.
- The 5ms path is limited to ack, early-deny, route, and bounded cache-hit
  decisions. `moxi-hotpath` cannot execute tools, cannot authorize actions,
  and sends high-risk work to the trusted execution path.
- Shells are submit/projection/approval-display surfaces only. `moxi-shells`
  cannot approve, execute, verify, issue tickets, or commit ledger events.
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
- High-risk executor hardening now has a control-plane decision model:
  `moxi-vault` seals tenant trust roots into hash-bound `TrustRootRecord`
  values, reloads them with tenant/hash checks, and verifies executor
  signatures against those tenant trust-root records before a future ticket gate
  can require signed executors. It also verifies external trust-root storage
  receipts into tenant-bound `TrustRootStorageDecision` records that bind the
  storage evidence to the sealed trust-root record hash.
- Production enablement now has a fail-closed readiness model:
  `moxi-vault` produces `ProductionAdapterEvidence`, verifies it into
  tenant-bound `ProductionAdapterVerificationDecision` records, verifies
  cryptographic verifier evidence into `CryptographicVerifierDecision` records
  bound to signature decisions, trust-root records and hashes, configured
  verifier refs, verifier policy, transparency-log, algorithm-suite,
  attestation refs, and verified CryptographicVerifier adapter decisions,
  verifies hardened sandbox evidence into `HardenedSandboxDecision` records
  bound to the configured sandbox profile, isolation, filesystem, network,
  syscall, resource policy, attestation refs, and verified HardenedSandbox
  adapter decisions,
  credential rotation refs into `RotationEnforcementDecision` records that can
  bind the configured rotation policy to a verified RotationEnforcement adapter
  decision, verifies
  compliance export bundle delivery evidence into
  `ComplianceExportDeliveryDecision` records that can bind bundle-hash delivery
  receipts to verified ComplianceAuditExport adapter decisions, and then produces
  `ProductionReadinessDecision` records only when each adapter evidence item and
  configured credential rotation ref is precisely bound to its matching verified
  decision. The stricter `ProductionHardeningDecisionSet` path also requires
  verified auth, external secret-manager, cryptographic verifier, hardened
  sandbox, rotation, secret-injection, compliance-delivery, and trust-root
  storage decisions before readiness can cite the full P0 hardening set. It
  blocks production readiness whenever production auth, real
  secret-manager/KMS/HSM references, cryptographic verifier evidence, hardened
  sandbox profiles, secret injection, rotation enforcement, tenant quorum/audit
  policy, verified executor trust roots, or compliance export profiles are
  missing.
- P1 runtime enablement now has a separate P0-controlled readiness model:
  `moxi-vault` produces `P1ExecutionReadinessDecision` records. The default
  local profile permits only bounded read-only `file.read` requests to enter the
  P0 execution chain, rejects unlisted capabilities, credentialed tasks, and
  high-risk work without production-ready P0 evidence, and explicitly never
  grants P1 direct ticketing or execution authority.
- P1 execution-readiness profiles can be sealed against tenant policy pack refs
  and sealed `TenantPolicyPackRecord` refs as
  `P1ExecutionReadinessProfileRecord` values, reloaded with policy/profile hash
  and tenant checks, and included in redacted audit exports and typed
  `P1ExecutionAuditBundle` records for P0/P1 execution interlock review.
  Bundles bind the runtime request, profile record, readiness decision, optional
  production readiness ref, redaction profile, and evidence refs, while still
  denying P1 direct ticket, execution, verification, or ledger authority.
- Production or credential-capable P1 execution profiles can only be sealed when
  a tenant-bound `ProductionReadinessDecision::Ready` is attached. Local
  read-only profiles do not gain production authority from this record.
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

`moxi-vault` is a control-plane MVP, not a production HSM or secret manager. It
keeps raw secret material out of the model/log/ledger path, can assemble
redacted local compliance export bundles, verifies compliance export delivery
evidence against the bundle hash and optionally a verified ComplianceAuditExport
adapter decision, verifies secret injection evidence into a
decision bound to an allowed `SecretUseDecision`, an executor-injected
credential, hardened sandbox and injection profiles, a verified injection
adapter decision, executor ref, and receipt, verifies production auth evidence
into a decision bound to the configured auth provider, issuer/JWKS/token/session
policy refs, and a verified AuthProvider adapter decision, verifies external
secret-manager evidence into a decision bound to the credential ref, external
secret ref, KMS/HSM/access-policy/rotation refs, and a verified
ExternalSecretManager adapter decision, verifies cryptographic verifier
evidence into a decision bound to signature decisions, sealed trust-root
records and hashes, configured verifier refs, verifier policy, transparency-log,
algorithm-suite, attestation refs, and a verified CryptographicVerifier adapter
decision, verifies hardened sandbox evidence into a decision bound to the
configured sandbox profile, isolation, filesystem, network, syscall, resource
policy, attestation refs, and a verified HardenedSandbox adapter decision, and
now evaluates a fail-closed P1
execution-readiness decision plus production readiness decisions over
trust-root, quorum, break-glass, audit-export, auth, secret-manager,
crypto-verifier, sandbox, secret-injection, and rotation evidence. Production
adapter evidence, production auth evidence, external secret-manager evidence,
cryptographic verifier evidence, hardened sandbox evidence, credential rotation refs, secret injection receipts, and compliance export delivery receipts are verified into
tenant-bound decisions before readiness or review can cite them. The strict P0
hardening decision-set readiness path requires those verified decisions as one
typed set and fails closed on any missing, rejected, cross-tenant, or mismatched
decision. P1 may only enter the P0 execution
chain when that readiness decision is ready; it still cannot issue tickets,
execute without P0, verify, or commit. Real OIDC/SSO authentication, real
cryptographic verification, OS credential injection, HSM/KMS/secret-manager integration,
production secret rotation adapters, and real external trust-root/compliance
storage backends still require concrete external adapters before production
exposure.

`process_sandbox` is a runnable v0 JSON protocol boundary. It is not yet
production OS isolation; enabling executable external actions in production is
still blocked on OS-level sandbox hardening and real credential-store
integration.

## Verify

```text
cargo fmt --all --check
cargo test
cargo clippy --all-targets -- -D warnings
```

Current end-to-end acceptance scenario: `EntryRequest` passes gateway checks,
compiles into an `Intent`, executes authorized `file.read` inside the workspace,
and produces a sandbox result, proof, ledger event, and completed run state.

Targeted R10 recovery verification also passes for `moxi-cli` tests,
`moxi-shells` tests, targeted `moxi-cli` clippy, real `admit`, `manifest`,
`boundary --text`, `status --text`, `status --panel`, file-backed `watch`, and
read-only Ratatui `tui --keys` runs including compact Task Detail selection,
approval display-only plus Graph Summary panel rendering, and graph-pane focus
with `g`, and piped REPL input where `execute` is rejected as an unknown
command.





