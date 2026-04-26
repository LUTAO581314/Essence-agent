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

1. Core Rust protocol types.
2. JSONL WAL append/replay.
3. Control plane API for create session, submit prompt, stream events, cancel, approve.
4. Tool registry and permission policy.
5. Native subagent runtime with sidechain transcripts.
6. Memory hooks.
7. Task store and UI event stream.
8. Plugin host and one CLI harness plugin.

