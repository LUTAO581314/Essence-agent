# MOXI Essence Agent v0 Architecture

This document is the implementation-facing summary for the current Rust
workspace. Broader research and long-term architecture notes live in the
Obsidian-style architecture graph under `MOXI-ESSENCE-agent/ESSENCE/`.

## Current Kernel Decision

The v0 implementation keeps the trusted path explicit and the trusted kernel
small:

1. External host requests enter as `EntryRequest`.
2. Entry normalizes them into `NormalizedEntry`.
3. Gateway trust checks produce `TrustedEntry`.
4. Intent compilation produces `CompiledIntent` and kernel `Intent`.
5. The trusted kernel path starts at `Intent`.
6. Runs are admitted into `RunContract`.
7. External actions must be proposed as `WorldDelta`.
8. Policy produces `PolicyDecision`.
9. The kernel issues single-use `ExecutionTicket` bound to the current
   capability contract, executor manifest, isolation mode, and retry policy.
10. Execution requires the caller-supplied ticket to exactly match the stored
   ticket payload before ticket consumption.
11. The sandbox returns `SandboxResult`.
12. The kernel validates result binding, recomputes the canonical output hash
   from structured output, and validates output schema.
13. Valid sandbox results are persisted, and verification only accepts the
   recorded result for the ticket.
14. Successful results produce `Proof` carrying policy, capability, executor,
   gateway, input, and output hashes/refs.
15. Successful commits require recorded proof refs whose binding fields match
   the `LedgerEvent`, then append the event carrying the same execution-binding
   refs for audit replay.

The current durable store is SQLite through `moxi-store`. It owns run state,
budget counters, approval grants, execution tickets, and append-only
hash-chained ledger events. JSONL transcript/WAL and projection stores remain
future design work, not current code.

## Crate Map

- `moxi-entry`: inbound adapter boundary for CLI, desktop, web, HTTP API, SDK,
  MCP server, and automation channel normalization.
- `moxi-gateway`: first trusted ingress boundary for tenant/user checks, rate
  limiting, blocked input scanning, and secret redaction.
- `moxi-intent`: deterministic v0 intent compiler from trusted ingress records
  to kernel `Intent`.
- `moxi-contracts`: shared protocol structs and JSON schema generation.
- `moxi-core`: trusted kernel orchestration across admission, policy, approval,
  ticket issuing, registered capability execution, verification, and ledger
  commits.
- `moxi-sandbox`: first local read-only file sandbox.
- `moxi-store`: SQLite state store and append-only audit ledger.

## Entry Boundary

The inbound adapter layer is `01-入口层`, not a separate architecture plane.
Concrete transports can have their own modules later, but conceptually they all
live under Entry.

`moxi-entry` converts external channel requests into a normalized intent
candidate plus entry metadata and requested `PermissionMode`. It must not
authenticate users, evaluate policy, issue execution tickets, call tools, or
expand requested capabilities. Those responsibilities stay with the Gateway,
Intent, Policy, Kernel, and Capability planes.

## Gateway Boundary

`02-网关层` is defined in the architecture notes as the first trusted boundary
after Entry. It is responsible for authentication, tenant identification,
session identification, rate limiting, input risk scanning, and sensitive-data
pre-redaction.

`moxi-gateway` consumes `NormalizedEntry` and produces `TrustedEntry` when
deterministic trust checks pass. The current v0 implementation supports tenant
allowlists, blocked users, per-principal request limits, blocked input terms,
and secret-marker redaction. Production authentication providers, distributed
rate limits, and compliance-grade redaction remain future work.

Gateway may reject ingress, sanitize the request, and attach a gateway decision.
It must not issue `ExecutionTicket`, call tools, or bypass kernel policy.

## Intent Boundary

`moxi-intent` consumes `TrustedEntry` and produces `CompiledIntent`, which wraps
the kernel `Intent`, gateway decision reference, and gateway-approved
`PermissionMode`. The current v0 compiler is deterministic: it preserves
requested capabilities, conservatively infers `file.read` for read-like goals,
normalizes budgets, and escalates risk for obvious write, shell, or network
language.

Model-backed intent understanding, planner handoff, success criteria extraction,
and richer constraints remain future work.

## Current Implemented Path

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
-> SandboxInput
-> SandboxResult
-> Proof
-> LedgerEvent
```

The shipped end-to-end scenario is `file.read` inside the workspace:

1. Normalize an `EntryRequest`.
2. Pass gateway trust checks into `TrustedEntry`.
3. Compile the trusted entry into an `Intent`.
4. Register `file.read` capability.
5. Admit a read-only run that declares `file.read`.
6. Propose a matching `WorldDelta`.
7. Receive an allow policy decision.
8. Issue a ticket.
9. Execute through the read-only sandbox.
10. Verify the result into proof.
11. Commit a hash-chained ledger event.
12. Complete the run state.

## Safety Defaults

- Default permission mode is read-only.
- Entry does only channel normalization.
- Gateway can deny or sanitize ingress before intent compilation.
- Intent compilation is deterministic in v0.
- Network and shell are denied by default.
- Capabilities must be registered before use.
- Requested capabilities must be declared in the run contract.
- High-risk and critical actions require human approval before ticket issuing.
- Execution dispatch is capability-based. `file.read` is registered as a
  default executor, but the kernel path can run any registered executor whose
  capability passed contract, policy, ticket, schema, and result-binding checks.
- The current runtime only accepts `in_process_trusted` executors. Process,
  remote, browser, model-gateway, and plugin-host isolation modes are reserved
  protocol values until their runtimes are implemented.
- Executor manifests must match the registered capability contract hash,
  provider identity, and sandbox profile.
- Execution tickets bind the policy decision, capability contract hash,
  executor id/version, executor manifest hash, executor isolation, and the
  capability retry policy snapshot.
- The persisted ticket payload is the execution authority. A supplied ticket
  must exactly match the stored ticket before it can be consumed.
- The kernel recomputes output hashes from structured executor output; executor
  supplied output hashes are not trusted.
- After ticket consumption, executor failures, result-binding mismatches, and
  output schema failures transition the run to `failed`.
- Valid sandbox results are persisted and append-only; proof generation rejects
  unrecorded or tampered results.
- Execution tickets are single-use.
- Execution ticket, sandbox result, and proof payloads are persisted for audit
  replay.
- Successful ledger commits require recorded proof references matching the
  ledger event binding fields.
- Ledger events are append-only and hash-chained.

## Future Work

- Production gateway integrations for auth, tenant/session trust, distributed
  rate limits, risk scanning, and compliance-grade redaction.
- Intent compiler beyond deterministic v0 heuristics.
- Concrete CLI, HTTP API, SDK, MCP server, desktop, and web transports.
- Model gateway, tool gateway, plugin system, browser daemon, remote bridge,
  workflow runtime, swarm runtime, and long-term memory runtime.
- Process, remote, browser, model-gateway, and plugin-host executor isolation
  runtimes beyond the current `in_process_trusted` path.
- Production capability executors beyond the current built-in `file.read`.
- JSONL transcript/WAL and replayable projections.
- Production release packaging beyond source bundles.

## Verification

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
```
