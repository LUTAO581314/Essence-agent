# Competitive Research Synthesis

This document condenses the outer ESSENCE competitive research vault into a
GitHub-readable reference for the Rust kernel repository. It records design
patterns to learn from, not upstream code to copy.

## Thesis

The strongest agent systems separate six layers:

1. runtime kernel;
2. gateway and channel adapters;
3. skill, prompt, and tool operating layer;
4. memory, index, and retrieval substrate;
5. evaluation, proof, and harness layer;
6. ambient UI, approval, and product operations.

ESSENCE should keep the Rust kernel small and auditable while letting these
outer layers compose through explicit contracts.

## Reference Groups

| Group | Useful references | What to absorb |
| --- | --- | --- |
| Agent runtime shell | Claude Code-style runtimes, Hermes, OpenClaw | streaming loop, tool registry, permissions, approvals, bridge boundaries |
| Workflow platform | AutoGPT Platform, DeerFlow, Paperclip | graph/block execution, heartbeat runs, scheduler, webhooks, visible task streams |
| Code context substrate | GitNexus, Graphify, Sonic | code graph, BM25/semantic retrieval, impact analysis, MCP query surfaces |
| Memory substrate | MemPalace and related local-first memory systems | drawers for verbatim facts, hybrid retrieval, graph memory, source tracking |
| Skill/prompt OS | Superpowers, skills-main, agency-agent style role packs | skill triggering discipline, reusable role packets, quality gates |
| Product shell | Star Office UI, visual status surfaces | agent presence, queues, approvals, memory writes, and risk states as readable projections |
| Evolution loop | Evolver-style systems | gene/capsule/event assets, validation before adoption, rollbackable evolution |

## Project-Level Lessons

### Claude Code-Style Runtimes

The durable lesson is the runtime shell shape: an interactive loop, resumable
state, permission mediation, tool records, bridge/session control, and
observability. For ESSENCE, this maps to:

- `moxi-core` as the trusted admission/policy/ticket/proof/ledger authority;
- CLI and desktop shells as adapters, not owners of policy;
- future approval and observability layers that subscribe to structured events;
- delegated sidechains only after tickets, proofs, and ledger boundaries are
  stable.

Do not copy product-specific UI/runtime coupling into the kernel.

### AutoGPT-Style Workflow Platforms

The durable lesson is block/graph productization. Blocks are not just functions;
they carry schemas, tests, credentials, sensitive-action flags, execution
context, and marketplace metadata.

For ESSENCE, capability contracts should eventually grow similar product
metadata while preserving the current small kernel:

- input/output schemas;
- test inputs and mocks;
- risk and sensitivity markers;
- credential requirements;
- cost and retry policy;
- audit/proof requirements.

Do not pull the full SaaS stack into the Rust kernel.

### GitNexus-Style Code Context Systems

The durable lesson is index-time intelligence. Agents need code structure,
relations, ownership, impact, and search surfaces before they act.

For ESSENCE, code graph and retrieval should become outer runtime services that
feed intent compilation, planning, and proof. They should not bypass policy or
ledger rules.

### Memory Systems

The durable lesson is that memory is not just embeddings. A production agent
needs source-preserving drawers, temporal history, relations, preferences,
failure scars, and recall paths.

For ESSENCE, memory writes must be auditable and reversible. Long-term memory
should reference ledger/proof facts instead of becoming an opaque side
database.

### Skill And Prompt Operating Layers

The durable lesson is that prompts and skills can be tested product assets.
They should have trigger rules, scope, quality gates, and evidence
requirements.

For ESSENCE, this belongs outside the trusted kernel but inside the capability
and workflow ecosystem.

## Implementation Implications

- Keep `moxi-core` focused on trust, state, policy, ticketing, execution
  orchestration, verification, and ledger commits.
- Express outer capabilities through contracts, manifests, schemas, budgets,
  proofs, and approval policies.
- Treat CLI, desktop, MCP, web, plugins, memory, workflow, and swarm surfaces
  as replaceable shells over the same contracts.
- Use competitive research to shape interfaces and tests, not to import
  incompatible upstream code.

## Build Order

1. Stabilize the P0 kernel closure.
2. Add explicit projection/event surfaces without making them source of truth.
3. Grow CLI/API/MCP adapters over entry/gateway/intent boundaries.
4. Add capability-pack/plugin metadata and tests.
5. Add memory, retrieval, code graph, workflow, and swarm services through
   capability contracts and ledger-backed evidence.
6. Add product shells for approvals, observability, and delivery.

## Guardrails

- Do not let product UX own trust decisions.
- Do not let plugins bypass tickets, approval, budget, proof, or ledger.
- Do not treat vector memory as source of truth.
- Do not copy code from incompatible upstream licenses.
- Do not turn the P0 Rust kernel into a marketplace, workflow engine, or UI.
