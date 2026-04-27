# Project Status

Updated: 2026-04-27

## State

Essence Agent is in v0 kernel buildout. The current repository is a Rust
workspace with one crate, `essence-core`.

The implemented layer is the durable local kernel:

- append-only JSONL WAL events
- replayable projections
- file-backed control plane
- session and run lifecycle records
- tool call and approval records
- task, artifact, and memory events
- local saved-memory store queries by kind and text
- native subagent metadata and sidechain transcripts
- deterministic tool registry and permission policy
- plugin manifest host
- CLI harness metadata, command rendering, and execution result capture
- policy-bound CLI harness runner for allow, approval, and deny outcomes
- ControlPlane recording for policy-bound CLI harness executions, approvals,
  and denials
- approved CLI harness replay after approval resolution
- pending approval queue queries by session, run, and tool call
- CLI commands for listing and resolving approvals
- session-level approval reuse for `approve-session` and `approve-always`
- cross-session approval reuse for `approve-always`
- indexed approval grant cache for reusable approval lookup
- GitNexus harness plugin
- minimal model execution loop abstraction
- task scheduler primitives for claiming queued work
- JSON projection snapshots for persistent replay checkpoints
- local Control API adapter primitives for future HTTP/MCP servers
- minimal `essence` CLI for session creation, message append, and event tailing

## Verification

Current proof command:

```bash
cargo test --workspace
```

Expected result: all library and CLI tests pass.

## Not Yet Built

- full SwarmRuntime scheduler
- MCP/API server adapters
- memory embedding/index backend
- browser daemon plugin
- research radar plugins
- visual multi-agent workspace shell
- evolution asset store

## Architecture Direction

The system should take the spirit of the reference systems without cloning their
surface shape:

- Claude Code for core loop, WAL, control planes, AgentTool, and permissions.
- Agency Agents for role/workflow quality contracts.
- Hermes for simple tool/approval/gateway patterns.
- GStack for browser daemon isolation.
- Paperclip for heartbeat/adapters/plugin guardrails.
- Evolver for later evolution assets.

See [reference-synthesis.md](reference-synthesis.md) for the condensed design
mapping.
