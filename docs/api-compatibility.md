# API Compatibility

Essence Agent is still in v0. Public Rust APIs exported from the `moxi-*`
crates should still be treated as compatibility commitments once they are
documented or used by downstream tools.

## Version Boundary Rules

- Patch releases (`0.1.x`) should be backward compatible.
- Breaking exported API changes before `1.0` require a minor version boundary
  such as `0.1` to `0.2`.
- Breaking exported API changes after `1.0` require a major version boundary.
- Future CLI or server output contracts should follow the same rule for stable
  JSON or JSONL fields.

## Public Type Changes

Before changing public enum or struct shapes:

1. Check whether the type is exported from a crate `src/lib.rs`.
2. Check whether serialized output, MCP descriptors, or plugin manifests depend
   on the shape.
3. Prefer additive fields or new wrapper types when downstream code can keep
   compiling.
4. If a lint suggests reshaping a public type, document the compatibility
   tradeoff and prefer a local allow/expect when the current shape is the API.

## Current Policy

The v0 kernel may still evolve, but compatibility-breaking changes should be
intentional and grouped into explicit release-boundary work rather than mixed
into formatting, lint, or CI-only commits.

The 02/03 ingress update intentionally moves final `Intent` construction out of
`moxi-entry` and into `moxi-intent`. `moxi-entry::NormalizedEntry` now carries an
intent candidate, while `moxi-gateway::TrustedEntry` and
`moxi-intent::CompiledIntent` represent the pre-kernel trust and understanding
steps.

`moxi-core::CapabilityExecutor` is the v0 extension point for capability
runtime execution. New executors should preserve the kernel-owned safety chain:
capability contract registration, policy decision, execution ticket, input
schema validation, single-use ticket consumption, result binding validation,
output schema validation, proof collection, and ledger commit.

`moxi-contracts::PolicyConfig` and `moxi-core::PolicyEngine` are now the v0
policy configuration surface. Defaults preserve the original safety behavior:
registered capabilities must be declared in the run contract, and high/critical
risk requires approval. Changes to serialized `PolicyConfig` fields should be
treated as compatibility work because policy packs, deployment profiles, and
future admin tooling will depend on them.

The additive extension descriptors in `moxi-contracts` are the vocabulary for
future P1/P2 growth: `ModuleManifest`, `SkillManifest`, `SubagentManifest`,
`MemoryProviderManifest`, `ModelGatewayManifest`, `ShellAdapterManifest`, and
`AgentPersonaManifest`. These manifest shapes should be evolved as serialized
API contracts. They describe modules and runtimes, but they do not grant
execution authority; executable effects still require `CapabilityContract`,
policy evaluation, `ExecutionTicket`, proof collection, and ledger commit.

Execution-facing serialized contracts now include capability contract hashes,
executor artifact hashes, executor signature refs, executor signing key refs,
executor manifest hashes, executor isolation, retry policy snapshots, and
proof/ledger binding refs. Treat changes to these fields as compatibility work,
because downstream auditors, replay tools, and future runtimes will rely on
them to prove which capability and executor were authorized.

`SandboxResult.output_hash` is kernel-owned. Executors may populate the field,
but the kernel recomputes it from structured output before validation,
proofing, or ledger commit. Execution also requires the caller-supplied ticket
to exactly match the persisted ticket payload before consumption.

The store persists full execution ticket, sandbox result, and proof payloads so
audit/replay tools are not limited to index columns. Verification is bound to
the recorded sandbox result, and successful ledger commits are bound to
recorded proofs whose policy, capability, executor, gateway, input, output, and
ticket refs match the event.

`moxi-store::Store::replay_ledger_audit` is the current read-time audit verifier.
It first validates the append-only hash chain, then replays successful ledger
events against persisted tickets, sandbox results, proofs, canonical output
hashes, and proof evidence hashes. Adding fields to the ticket/result/proof
binding set should update this replay verifier in the same compatibility unit.

SQLite schema changes must move through `moxi-store` ordered migrations and bump
the recorded `store_meta.schema_version`. Newer on-disk schemas are rejected
rather than silently opened by older code.

The current v0 executor identity check requires `sha256:<hex>` artifact refs,
signature refs, and signing key refs. It does not yet verify cryptographic
signatures against a real trust root; that remains future runtime work.

The current executable runtime accepts `in_process_trusted` and
`process_sandbox` executor manifests. `process_sandbox` is a stable v0 JSON
protocol boundary: stdin receives `{ ticket, input }`, stdout returns
`{ success, output, error }`, and the kernel still owns result binding,
hashing, proofing, and ledger commit. Other `ExecutorIsolation` variants are
reserved protocol surface and should not be documented as runnable until their
runtime checks exist.
