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
  ledger events, and structured errors.
- `moxi-core`: trusted kernel API for admission, policy checks, ticket issuing,
  heartbeat accounting, registered capability execution, verification, and
  ledger commits.
- `moxi-sandbox`: local read-only file sandbox with workspace-root locking and
  path escape protection.
- `moxi-store`: SQLite-backed run state, budget counters, approval grants,
  execution tickets, and append-only hash-chained ledger events.

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
- Human approval grants for high-risk policy decisions.
- Single-use execution tickets issued only after policy allow or approval.
- Generic capability executor dispatch in `moxi-core`, with `file.read`
  registered as the default built-in executor.
- Runtime acceptance limited to `in_process_trusted` executor manifests. Other
  isolation modes remain protocol values until separate runtimes exist.
- Executor manifest validation against capability contract hash, provider
  identity, and sandbox profile before ticket issuing and execution.
- Single-use execution tickets bound to policy decision, capability contract
  hash, executor id/version, executor manifest hash, executor isolation, and the
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
  ledger event binding fields.
- SQLite run state transitions, budget counters, approval grants, full execution
  ticket payload persistence, append-only sandbox result persistence,
  append-only proof payload persistence, execution ticket consumption, and
  append-only hash-chained ledger events.
- Unit and end-to-end tests for contracts, kernel policy, approvals, sandbox,
  ticket reuse, budgets, ledger hash chains, entry normalization, gateway
  checks, intent compilation, and the trusted ingress-to-execution path.

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
- Concrete production executors beyond the current built-in `file.read` and
  test-only custom executor.
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
