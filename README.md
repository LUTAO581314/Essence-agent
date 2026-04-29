# MOXI Essence Agent v0.2.0

Rust-only trusted ingress, intent, and kernel foundation for MOXI/ESSENCE Agent.

This branch intentionally contains only the core framework. It does not include
CLI command parsing, desktop UI, web UI, plugin marketplace, model providers,
swarm runtime, remote bridge, long-term memory runtime, or auto-evolution.

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
  structured errors.
- `moxi-core`: trusted kernel API for admission, policy checks, ticket issuing,
  heartbeat accounting, registered capability execution, verification, and
  ledger commits. Policy evaluation is configurable for declared-capability,
  risk, capability, resource, and approval rules.
- `moxi-sandbox`: first local read-only file sandbox with workspace root lock
  and path escape protection, plus v0 process-sandbox JSON protocol execution.
- `moxi-store`: SQLite state store, append-only audit ledger, persisted
  ticket/result/proof payloads, and ledger replay/audit verification.

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
- External action requires an `ExecutionTicket`.
- Capability execution is dispatched through registered executors; `file.read`
  is the default built-in executor, not a hard-coded kernel path.
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
- Execution ticket, sandbox result, and proof payloads are persisted for audit
  replay.
- Ledger audit replay validates the hash chain and re-checks successful events
  against persisted tickets, sandbox results, proofs, output hashes, and proof
  evidence hashes.
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
