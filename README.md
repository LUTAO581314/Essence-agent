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
- `essence-core::policy`: minimal tool permission policy decisions for allow,
  approval, and deny flows
- `essence-core::registry`: deterministic tool metadata registry with capability
  filtering and policy generation
- `essence-core::subagent`: native subagent sidechain transcript helper for
  append/replay of per-lane WAL files
- memory hooks: candidate and saved memory events projected from the WAL
- `essence-core::task_store`: task projection queries by status, lane, and
  assignee
- `essence-core::stream`: cursor-based UI event stream over ledger events
- `essence-core::approval_index`: indexed reusable approval grants by subject
- `essence-core::plugin`: minimal plugin manifest host that registers plugin
  tools into the core tool registry
- `essence-core::harness`: CLI harness metadata for external tool adapters
- `essence-core::gitnexus`: first code-intelligence harness plugin for
  GitNexus graph search, context, impact, diff detection, and indexing

The long-term shape is:

- Rust core for the durable kernel
- Python adapters for memory, research, and fast experimentation
- TypeScript UI/plugin SDK for dashboards, office views, and product shells

## CLI

There is now a minimal `essence` CLI over the local control plane. It writes
runtime data to `.essence/` by default and can be pointed elsewhere with
`--root`.

```bash
cargo run -- session create --title "First session"
cargo run -- message send --session-id <session-id> --text "Build the next layer"
cargo run -- events tail --session-id <session-id> --user-visible
cargo run -- approval pending --session-id <session-id>
cargo run -- approval resolve --session-id <session-id> --approval-id <approval-id> --decision deny
```

## Project Notes

- [Current status](docs/status.md)
- [Reference synthesis](docs/reference-synthesis.md)
- [v0 architecture draft](docs/v0-architecture.md)
