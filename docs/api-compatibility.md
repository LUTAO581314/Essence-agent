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

Execution-facing serialized contracts now include capability contract hashes,
executor manifest hashes, executor isolation, retry policy snapshots, and
proof/ledger binding refs. Treat changes to these fields as compatibility
work, because downstream auditors, replay tools, and future runtimes will rely
on them to prove which capability and executor were authorized.

`SandboxResult.output_hash` is kernel-owned. Executors may populate the field,
but the kernel recomputes it from structured output before validation,
proofing, or ledger commit. Execution also requires the caller-supplied ticket
to exactly match the persisted ticket payload before consumption.

The store persists full execution ticket, sandbox result, and proof payloads so
audit/replay tools are not limited to index columns. Verification is bound to
the recorded sandbox result, and successful ledger commits are bound to
recorded proofs whose policy, capability, executor, gateway, input, output, and
ticket refs match the event.

The current executable runtime accepts only `in_process_trusted` executor
manifests. Other `ExecutorIsolation` variants are reserved protocol surface and
should not be documented as runnable until their runtime checks exist.
