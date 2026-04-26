# Essence Agent

Swarm-native agent kernel research and implementation.

Essence Agent is being built as a trusted control plane plus an append-only
event ledger for multi-agent work. The first implementation target is a small
Rust core that defines the stable protocol:

- sessions and runs
- append-only JSONL transcript/WAL events
- tool calls and tool results
- approvals and permission decisions
- subagents and lanes
- replayable projections for memory, tasks, artifacts, and UI streams

Current Rust crate status:

- `essence-core::protocol`: durable event and metadata types
- `essence-core::wal`: append/replay JSONL WAL primitives
- `essence-core::projection`: in-memory replay views for sessions, runs, tasks,
  artifacts, approvals, subagents, and messages
- `essence-core::control`: minimal file-backed control plane for creating
  sessions, appending events, submitting messages, tracking session/run
  lifecycle, and recording approvals, tool calls, tasks, artifacts, and
  subagents

The long-term shape is:

- Rust core for the durable kernel
- Python adapters for memory, research, and fast experimentation
- TypeScript UI/plugin SDK for dashboards, office views, and product shells

See [docs/v0-architecture.md](docs/v0-architecture.md) for the current v0
architecture draft.
