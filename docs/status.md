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
- v0 `essence` CLI control surface for session, run, message, event,
  approval, tool, agent, task, artifact, memory, subagent, snapshot, plugin,
  MCP manifest, harness, config, doctor, completion, and theme commands
- one-shot `ask` model turns plus interactive chat, both writing assistant
  replies back to the ledger through the same bounded model adapters
- built-in tool execution from the CLI with policy decisions, reusable
  approvals, and approval-resolution replay for built-in tools and CLI
  harness tools
- pixel/plain theme selection for human text output while `--json`,
  `--output jsonl`, and `--quiet` remain machine-readable
- three-platform CI gate over Ubuntu, Windows, and macOS for formatting,
  strict clippy, and tests
- tag-driven release workflow that publishes Linux, Windows, macOS Intel, and
  macOS Apple Silicon portable CLI binary archives with SHA-256 checksums
- documented v0 API compatibility policy for public Rust and structured CLI
  output changes
- split CLI implementation modules for args, chat/model adapters, control
  commands, workspace rendering, shared support, and tests

## Verification

Current proof command:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

Expected result: all formatting, lint, library, and CLI tests pass. CI runs the
same gate on `ubuntu-latest`, `windows-latest`, and `macos-latest`.

Latest local proof for the CLI/built-in-tools polish:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
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
- native package-manager installers such as MSI, Homebrew, Debian, or RPM
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
