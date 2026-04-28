# API Compatibility

Essence Agent is still in v0. Public Rust APIs exported from `essence_core`
should still be treated as compatibility commitments once they are documented
or used by downstream tools.

## Version Boundary Rules

- Patch releases (`0.1.x`) should be backward compatible.
- Breaking exported API changes before `1.0` require a minor version boundary
  such as `0.1` to `0.2`.
- Breaking exported API changes after `1.0` require a major version boundary.
- CLI output contracts should follow the same rule for `--json` and
  `--output jsonl` fields.

## Public Type Changes

Before changing public enum or struct shapes:

1. Check whether the type is exported from `src/lib.rs`.
2. Check whether JSON output, MCP descriptors, or plugin manifests depend on
   the shape.
3. Prefer additive fields or new wrapper types when downstream code can keep
   compiling.
4. If a lint suggests reshaping a public type, document the compatibility
   tradeoff and prefer a local allow/expect when the current shape is the API.

## Current Policy

The v0 kernel may still evolve, but compatibility-breaking changes should be
intentional and grouped into explicit release-boundary work rather than mixed
into formatting, lint, or CI-only commits.
