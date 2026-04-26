# Essence Agent v0 Architecture

This document is the implementation-facing summary of the current research.
The full working research notes live under `.omx/`.

## Core Decision

The v0 source of truth is an append-only JSONL Transcript/WAL:

1. The first line is `session_meta`.
2. Every later line is an event envelope.
3. Every event has `event_id`, `seq`, `ts`, `type`, `session_id`, and `schema_version`.
4. SQLite/Postgres tables, UI streams, memory indexes, and task views are projections.
5. Subagents write sidechain WAL files linked to the parent session/run.

This keeps the first kernel small, replayable, and auditable.

## Minimal Protocol

- `Session`: long-lived conversation/work container.
- `Run` / `Turn`: one execution in a session.
- `EventEnvelope`: the unified message/event record.
- `ToolCall` / `ToolResult`: tool boundary records.
- `ApprovalRequest`: permission decision boundary.
- `Subagent`: parallel execution actor.
- `Lane`: scheduling/workflow track.

## Stores

The v0 storage model is split into three layers:

- `MemoryStore`: long-term memory, facts, summaries, embeddings, source tracking.
- `TaskStore`: tasks, steps, progress, threads, checkpoints, artifacts.
- `Ledger projections`: indexed views over the JSONL WAL, including outbox/audit fields.

## Plugin Boundary

Core owns manifest validation, capability enforcement, tool registration, UI slots,
secret references, health checks, and execution policy.

Plugins own external sources and fast-changing integrations:

- RSS/news/search/social sources
- notification channels
- browser, Zotero, n8n, Obsidian, Office, GitHub, Linear harnesses
- research radar packs
- role packs and product shells

## First Build Order

1. Core Rust protocol types. Done in `essence-core::protocol`.
2. JSONL WAL append/replay. Done in `essence-core::wal`.
3. Replayable in-memory ledger projections. Done in `essence-core::projection`.
4. Minimal file-backed control plane. Done in `essence-core::control`.
5. Control plane API for submit prompt, stream events, cancel, approve.
6. Tool registry and permission policy.
7. Native subagent runtime with sidechain transcripts.
8. Memory hooks.
9. Task store and UI event stream.
10. Plugin host and one CLI harness plugin.

## Projection Contract

The first projection layer is intentionally in-memory. It consumes ordered
`EventEnvelope` records and folds them into the views that later stores and UIs
will index:

- latest session metadata
- run metadata by run id
- subagent metadata by agent id
- approvals by approval id
- tasks by task id
- artifacts by artifact id
- user-facing message payloads

Projection errors include the source sequence number and event type so corrupt
or incompatible WAL lines can be diagnosed without losing the rest of the design.

## Control Plane Contract

The first control plane is a synchronous file-backed facade over the WAL. It is
small on purpose:

- `create_session` creates a session id, writes the first `session_meta` event,
  and returns the durable `SessionMeta`.
- `submit_user_message` and `append_assistant_message` append user-visible
  message events.
- `start_run`, `complete_run`, and `fail_run` append auditable run lifecycle
  events.
- `append_event` is the escape hatch for typed protocol work that has not earned
  a dedicated helper yet.
- `projection` replays a session WAL into the current `LedgerProjection`.

This keeps higher layers from needing to know transcript paths or sequence
numbers while the kernel is still stabilizing.
