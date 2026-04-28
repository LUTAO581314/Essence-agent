# Project Status

Updated: 2026-04-28

## State

Essence Agent is in v0 kernel buildout. The current repository is a Rust
workspace with one crate, `essence-core`.

The implemented layer is the durable local kernel:

- append-only JSONL WAL events
- replayable projections
- file-backed control plane
- session and run lifecycle records
- tool call and approval records
- Claude/Codex/Hermes-shaped built-in tools for safe file reads/search,
  approval-gated patch/shell/web calls, ledger-backed todo/subagent operations,
  and denied-by-default gateway exec
- task, artifact, and memory events
- local saved-memory store queries by kind and text
- native subagent metadata and sidechain transcripts
- subagent steering, cancellation, budget, and result records
- deterministic tool registry and permission policy
- plugin manifest host
- selectable bundled plugin catalog with installable memory, browser, research,
  code-intelligence, and UI shell plugins
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
- minimal SwarmRuntime facade with WAL-backed agent registration, projection
  restore, heartbeat/presence records, queued task dispatch, subagent spawn,
  scheduler ticks, turn/tool-call budget checks, completion, and cancellation
- background scheduler loop handle for repeated session ticks
- deterministic local memory index/search layer
- Control API facade methods for swarm registration, heartbeat, ticks, memory
  search, and MCP manifest discovery
- MCP adapter manifest descriptors and core tool dispatcher for future
  stdio/HTTP servers
- browser daemon plugin boundary and workspace shell projection helpers
- JSON projection snapshots for persistent replay checkpoints
- local Control API adapter primitives for future HTTP/MCP servers
- minimal `essence` CLI for session creation, message append, event tailing,
  interactive chat, Star Office-style terminal workspace watching, agent/task
  heartbeat commands, model config get/set, doctor checks, shell completions,
  completion install, global dry-run previews, non-interactive chat detection,
  and bounded model-command chat adapters
- split CLI implementation modules for args, chat/model adapters, control
  commands, workspace rendering, shared support, and tests

## Verification

Current proof command:

```bash
cargo test --workspace
```

Expected result: all library and CLI tests pass.

Latest local proof for the CLI/built-in-tools polish:

```bash
cargo fmt --check
cargo test -p essence-core
cargo build -p essence-core --bin essence
```

Core-only proof:

```bash
cargo test -p essence-core --no-default-features
```

## Not Yet Built

- durable SwarmRuntime scheduler with production supervision and concurrent lane
  worker execution
- token budget enforcement
- concrete MCP/API server transports
- production memory embedding backend
- executable browser daemon plugin
- research radar plugins
- visual multi-agent workspace shell UI
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
