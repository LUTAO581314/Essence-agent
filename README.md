# MOXI Essence Agent v0.2.0

Rust-only trusted kernel for MOXI/ESSENCE Agent.

This branch intentionally contains only the core framework. It does not include
CLI command parsing, desktop UI, web UI, plugin marketplace, model providers,
swarm runtime, remote bridge, long-term memory runtime, or auto-evolution.

## Core crates

- `moxi-contracts`: stable protocol types for `Intent`, `RunContract`,
  `CapabilityContract`, `WorldDelta`, `PolicyDecision`, `ExecutionTicket`,
  `SandboxResult`, `Proof`, `LedgerEvent`, and structured errors.
- `moxi-core`: trusted kernel API for admission, policy checks, ticket issuing,
  heartbeat accounting, policy checks, ticket issuing, sandbox execution,
  verification, and ledger commits.
- `moxi-sandbox`: first local read-only file sandbox with workspace root lock
  and path escape protection.
- `moxi-store`: SQLite state store and append-only audit ledger.

## Kernel path

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

- Default permission mode is read-only.
- Network and shell are denied by default.
- External action requires an `ExecutionTicket`.
- Execution tickets are issued by the kernel and can be consumed only once.
- Run budgets track steps, heartbeats, tool calls, and timeout limits.
- Successful ledger commits require at least one `Proof`.
- Ledger events are append-only and hash-chained; correction must be a new
  event.

## Verify

```text
cargo fmt
cargo test
cargo clippy --all-targets -- -D warnings
```

Current end-to-end acceptance scenario: authorized `file.read` inside the
workspace produces a sandbox result, proof, ledger event, and completed run
state.
