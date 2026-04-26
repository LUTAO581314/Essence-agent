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
6. Minimal permission policy. Done in `essence-core::policy`.
7. Tool registry. Done in `essence-core::registry`.
8. Native subagent runtime with sidechain transcripts. In progress:
   `essence-core::subagent` now provides sidechain WAL append/replay helpers.
9. Memory hooks. Done for the first WAL layer: memory candidates and saved
   memories are durable events and projection entries.
10. Task store and UI event stream. Done for the first projection layer:
    `TaskStore` exposes task queries and `UiEventStream` exposes cursor-based
    UI refresh events.
11. Plugin host and one CLI harness plugin. In progress:
    `PluginHost` registers plugin manifests and exposes their tools through the
    deterministic tool registry. `essence-core::gitnexus` is the first CLI
    harness manifest for external code-intelligence tools.

## GitNexus Integration

GitNexus is integrated at the plugin boundary, not copied into the kernel. The
first bridge is a CLI harness manifest that registers graph-aware tools:

- `gitnexus.query`
- `gitnexus.context`
- `gitnexus.impact`
- `gitnexus.detect_changes`
- `gitnexus.api_impact`
- `gitnexus.tool_map`
- `gitnexus.analyze`

Read-only graph queries are allow-listed tool specs. Repository indexing writes
`.gitnexus/` state and therefore requires approval. Future runners can execute
the harness commands while the control plane records tool calls, memory
candidates, artifacts, and approvals in the WAL.

## Permission Policy Contract

The first policy layer is deliberately deterministic and local. It receives a
tool name, tool input, optional cwd, and the active `PermissionMode`, then
returns one of three decisions:

- allow
- require approval
- deny

Explicit deny rules win over every mode. `Readonly` denies tool execution,
`Plan` requires approval, `Auto` allows unless a tool is configured for
approval, and `Default` requires an allow rule or approval rule.

## Tool Registry Contract

The first registry stores tool metadata only. It does not execute tools. Each
tool has:

- name
- description
- permission class
- optional provider
- optional input schema
- capability tags

The registry supports deterministic lookup, duplicate detection, capability
filtering, and conversion into a `ToolPolicy`.

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
- `update_session_state`, `cancel_session`, and `events_after` support lifecycle
  state changes and cursor-based UI refresh.
- `submit_user_message` and `append_assistant_message` append user-visible
  message events.
- `start_run`, `complete_run`, `fail_run`, and `cancel_run` append auditable run
  lifecycle events.
- `request_approval` and `resolve_approval` record permission boundaries and
  their user decisions.
- `start_tool_call`, `complete_tool_call`, and `fail_tool_call` record tool
  execution boundaries.
- `create_task`, `update_task`, `complete_task`, and `create_artifact` connect
  work tracking and artifacts to the WAL.
- `spawn_subagent`, `update_subagent_progress`, `complete_subagent`, and
  `fail_subagent` record parallel actor lifecycle metadata.
- `propose_memory` and `save_memory` record memory extraction boundaries before
  a future `MemoryStore` indexes the saved records.
- `task_store` returns the current task projection as queryable task views.
- `ui_events_after` returns user-visible event stream entries after a cursor.
- `append_event` is the escape hatch for typed protocol work that has not earned
  a dedicated helper yet.
- `projection` replays a session WAL into the current `LedgerProjection`.

This keeps higher layers from needing to know transcript paths or sequence
numbers while the kernel is still stabilizing.
