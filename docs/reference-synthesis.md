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

## Current Crate Mapping

- `moxi-entry`: inbound adapter primitives for CLI, desktop, web, HTTP API,
  SDK, MCP server, and automation channel normalization.
- `moxi-contracts`: protocol structs and JSON schema generation for intents,
  runs, capabilities, deltas, policy decisions, tickets, sandbox results,
  proofs, ledger events, and structured errors.
- `moxi-core`: trusted kernel orchestration for admission, policy checks,
  approvals, manifest-bound ticket issuing, registered executor dispatch,
  verification, and ledger commits.
- `moxi-sandbox`: first local read-only file sandbox.
- `moxi-store`: SQLite-backed run state, budgets, tickets, approvals, and
  append-only hash-chained ledger events.

## Build Order

1. Keep the current manifest-bound, proof-bound kernel path stable and
   hash-chained.
2. Revisit JSONL transcript/WAL and projection layers as explicit future
   source-of-truth work, not as current implementation.
3. Implement `moxi-gateway` for authentication, tenant/session trust, rate
   limiting, input risk scanning, and redaction.
4. Grow concrete Entry adapters: CLI, API, SDK, MCP, desktop, and web.
5. Add richer control-plane, projection, subagent, memory, plugin, browser, and
   workflow surfaces only after the trusted path stays small and auditable.
6. Add Star Office style visual shells over event/projection streams.
7. Add evolution assets after kernel behavior is stable and auditable.

## Guardrails

- Do not let the current SQLite ledger grow into a product database without a
  deliberate source-of-truth decision.
- Do not put fast-changing product integrations inside the Rust kernel.
- Do not let plugins bypass approvals, budgets, auth, checkout, or storage
  contracts.
- Do not copy incompatible upstream code; reimplement only the needed ideas.
- Keep private memory local and opt-in for external lookup.
