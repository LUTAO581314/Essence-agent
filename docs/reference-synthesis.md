# Reference Synthesis

This project uses upstream agent systems as design references, not as code to
copy. Claude Code is the primary backbone reference; the other projects are
secondary references for narrower boundaries such as browser isolation, memory,
research adapters, and visual workspaces. The goal is to take the durable ideas
and reshape them into the Essence kernel.

## Principle

Essence Agent should be a swarm-native trusted control plane with a unified
ledger, explicit tool policy, subagent sidechains, and plugin boundaries.

The Claude Code-shaped kernel surface comes first: transcript/WAL, session/run
control, headless CLI, interactive adapters, permission mediation, tool call
records, and AgentTool-style delegated sidechains. Other references should not
pull the kernel away from this small auditable loop.

Reference projects inform the shape of the system, but the Rust kernel remains
small, auditable, and replayable.

## References To Keep

| Reference | Take | Do not take |
| --- | --- | --- |
| Claude Code | Core loop, transcript/WAL, AgentTool-style delegation, control-plane adapters, permission mediation | Product-specific UI/runtime coupling |
| Agency Agents | Role packets, missions, handoffs, quality gates, evidence requirements | Treating role packs as the runtime |
| Hermes | Simple agent loop, tool registry, terminal backends, approval queue, MCP/gateway hooks | Python implementation shape as kernel architecture |
| GStack | Browser daemon, session/tab isolation, health discovery, cross-agent browser pairing | Browser automation as core kernel state |
| Paperclip | Heartbeat runtime, adapters, plugin capability gates, hard plugin limits | Plugins that bypass approvals, budget, auth, checkout, or storage boundaries |
| Evolver | Evolution asset model: gene, candidate, event, capsule | GPL or obfuscated code reuse |
| MemPalace | Local-first memory, layered retrieval, source tracking, wake-up context | Memory as an opaque side database without ledger provenance |
| DeerFlow | Task orchestration, visible task stream, artifact/report workflow | Full LangGraph/FastAPI/Next stack in the core |
| Star Office UI | Presence/status projection and multi-agent office shell | Identity or auth kernel |
| TrendRadar | Source adapters, normalized items, scheduler, radar query surface | Research sources hard-coded into the kernel |

## Current Essence Mapping

- `protocol`: durable session, run, event, task, approval, subagent, and memory
  records.
- `wal`: append-only JSONL session source of truth.
- `projection`: replay views for UI, tasks, approvals, artifacts, messages, and
  subagents.
- `control`: file-backed control plane for session/run/tool/task/subagent
  lifecycle.
- `policy` and `registry`: deterministic tool metadata and permission decisions.
- `subagent`: native sidechain transcript helper for delegated lanes.
- `plugin` and `harness`: manifest and external CLI adapter boundary.
- `gitnexus`: first code-intelligence harness plugin.

## Build Order

1. Keep the JSONL WAL and projection layer as canonical source of truth.
2. Grow the control plane into adapters: CLI, TUI, API, ACP, MCP, and gateway.
3. Add richer subagent spawn, steer, cancel, result, and budget semantics.
4. Add memory store projections with provenance from ledger events.
5. Add plugin-hosted research radar, browser daemon, and external app harnesses.
6. Add Star Office style visual shells over the UI event stream.
7. Add evolution assets after kernel behavior is stable and auditable.

## Guardrails

- Do not make SQLite/Postgres canonical before the WAL is stable; use databases
  as projections.
- Do not put fast-changing product integrations inside the Rust kernel.
- Do not let plugins bypass approvals, budgets, auth, checkout, or storage
  contracts.
- Do not copy incompatible upstream code; reimplement only the needed ideas.
- Keep private memory local and opt-in for external lookup.
