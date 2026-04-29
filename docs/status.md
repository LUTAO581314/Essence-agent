# Project Status

Updated: 2026-04-29

## Current State

MOXI Essence Agent is in v0 trusted-kernel buildout. The current repository is
a Rust workspace with seven library crates:

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
  ledger events, configurable policy, and structured errors.
- `moxi-core`: trusted kernel API for admission, policy checks, ticket issuing,
  heartbeat accounting, registered capability execution, verification, and
  ledger commits. The policy engine is configurable while preserving safe v0
  defaults.
- `moxi-sandbox`: local read-only file sandbox with workspace-root locking and
  path escape protection, plus v0 process-sandbox JSON protocol execution.
- `moxi-store`: SQLite-backed run state, budget counters, approval grants,
  execution tickets, persisted sandbox results/proofs, append-only
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

The current code is best described as **P0+ / P0 hardening**. The trusted kernel
loop is implemented end to end, and several P0 concerns have moved beyond
"minimal" into replayable/auditable behavior. It is not P1 yet: planner, model
gateway, context manager, verifier-as-a-separate-runtime, rollback manager,
code graph, and retrieval engine are not implemented as current Rust workspace
runtime modules.

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
- Capability registration with input/output/error schema validation.
- Run admission with read-only default permission mode and budget
  initialization.
- Deterministic policy checks for declared capabilities, permission modes,
  high-risk approval escalation, and denied network/shell resources.
- Configurable `PolicyConfig` support for declared-capability enforcement,
  capability deny/approval rules, resource deny/approval patterns, risk
  approval/deny thresholds, approval policy, and approval refs.
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
  successful events against persisted execution tickets, sandbox results,
  proofs, output hashes, and proof evidence hashes.
- SQLite run state transitions, budget counters, approval grants, full execution
  ticket payload persistence, append-only sandbox result persistence,
  append-only proof payload persistence, execution ticket consumption, and
  append-only hash-chained ledger events.
- Store schema versioning through `store_meta`, ordered migrations, rejection of
  newer unsupported schemas, and v1-to-current compatibility coverage.
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
- Concrete CLI, HTTP API, SDK, MCP server, desktop UI, or web UI transports.
- Model provider adapters, model gateway, tool gateway, plugin host, browser
  daemon, remote bridge, swarm runtime, workflow runtime, and long-term memory
  runtime.
- Concrete production executors beyond the current built-in `file.read`,
  process-sandbox protocol harness, and test-only custom executor.
- OS-level process sandbox hardening beyond direct child-process execution,
  protocol checks, and timeout kill.
- Cryptographic executor signature verification against production trust roots.
- JSONL transcript/WAL, projections, task store, UI event stream, GitNexus
  harness, release binaries, and package-manager installers.

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
