<p align="center">
  <img src="assets/logo/silver-snow-wolf-pixel.png" alt="Essence Agent silver snow wolf pixel logo" width="180" />
</p>

# Essence Agent

**不止单智能体助手，而是多智能体协作的典范。**

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
- subagent control records: spawn, steer, progress, cancel, complete, fail,
  budgets, and results
- memory hooks: candidate and saved memory events projected from the WAL
- `essence-core::memory_store`: local saved-memory queries by kind and text
- `essence-core::memory_index`: deterministic local memory search/index layer
- `essence-core::task_store`: task projection queries by status, lane, and
  assignee
- `essence-core::stream`: cursor-based UI event stream over ledger events
- `essence-core::approval_index`: indexed reusable approval grants by subject
- `essence-core::builtin_tools`: Claude/Codex/Hermes-shaped built-in tool
  specs and executor for safe file reads/search, approval-gated patch/shell/web,
  ledger-backed todo/subagent operations, and denied-by-default gateway exec
- `essence-core::plugin`: minimal plugin manifest host that registers plugin
  tools into the core tool registry, plus a catalog for selectable plugin
  installation
- `essence-core::mcp`: MCP adapter manifest descriptors and core tool
  dispatcher for future stdio/HTTP transports
- `essence-core::harness`: CLI harness metadata for external tool adapters
- `essence-core::gitnexus`: first code-intelligence harness plugin for
  GitNexus graph search, context, impact, diff detection, and indexing
- `essence-core::model_loop`: minimal model execution loop abstraction over
  the control plane
- `essence-core::scheduler`: task scheduling primitives for queued work
- `essence-core::swarm`: minimal swarm runtime facade with WAL-backed agent
  registration, heartbeat/presence records, queued task dispatch, subagent
  spawn, scheduler ticks, turn/tool-call budget checks, and work
  completion/cancel
- `essence-core::workspace`: browser daemon descriptor and workspace shell
  projection helpers
- `essence-core::snapshot`: JSON projection snapshots for persistent replay
  checkpoints
- `essence-core::api`: local JSON-friendly Control API façade for future
  HTTP/MCP adapters

The long-term shape is:

- Rust core for the durable kernel
- Python adapters for memory, research, and fast experimentation
- TypeScript UI/plugin SDK for dashboards, office views, and product shells

## Reference Influences

Essence Agent uses other agent systems as architecture references, not as code
to copy. The core idea is to absorb durable patterns, then re-express them as a
small, auditable Rust kernel with an append-only ledger as the source of truth.
The project keeps reference influence explicit so readers can see what was
borrowed as a concept, what was bundled as an asset, and where the boundary is:

| Reference | Upstream | Essence usage | Boundary |
| --- | --- | --- | --- |
| Agency Agents | https://github.com/msitarzewski/agency-agents | Bundled as MIT role-packet prompt templates in `assets/agency-agents/templates.json` for `essence agent templates` and `essence agent define --template`. | Prompt templates only; no upstream runtime code is used as the kernel. |
| Other reference systems | Listed below and expanded in `docs/reference-synthesis.md`. | Design influence for ledgers, subagents, plugin boundaries, memory, research, browser isolation, and visual workspaces. | Ideas are reimplemented behind Essence protocol boundaries; incompatible or tightly coupled code is not copied. |

- Claude Code: the main backbone reference for a query-style execution loop,
  JSONL transcript/session storage, headless and interactive control-plane
  entrypoints, AgentTool-style subagent delegation, sidechain transcripts, and
  permission mediation around tool use.
- OpenClaw and Claw Code: references for swarm/runtime boundaries, session APIs,
  tool catalog and policy pipelines, subagent registry lifecycle, Rust-oriented
  crate boundaries, task packets, lane events, worker lifecycle, and MCP/tool
  registry ideas.
- Hermes: a simpler reference for agent loop shape, tool registry/toolsets,
  terminal or gateway backends, approval queues, MCP exposure, and profile-scoped
  runtime state.
- Agency Agents: inspiration for role packets, missions, workflow contracts,
  handoffs, quality gates, evidence requirements, and agent workbench concepts.
  Essence treats these as role/product-layer assets, not as the kernel itself.
- MemPalace: reference for local-first memory, layered retrieval, source
  tracking, wake-up context, and compaction resilience. Essence keeps memory
  provenance tied back to ledger events.
- DeerFlow: reference for visible task orchestration, subtask streams,
  artifacts/reports, and workflow UI patterns, without importing its full
  LangGraph/FastAPI/Next stack into the Rust core.
- Star Office UI: reference for a visual multi-agent workspace: agent presence,
  status, area/lane placement, avatar/bubble style projections, and an office
  board shell over ledger events.
- GStack: reference for browser daemon isolation, session/tab pairing, health
  discovery, and external browser control as a plugin boundary rather than core
  ledger state.
- Paperclip and TrendRadar: references for heartbeat/adapters, plugin guardrails,
  research source adapters, normalized items, scheduled ingestion, and query
  surfaces.
- Evolver and Edict: references for future evolution assets and structured
  task/state capture. Essence avoids copying incompatible or tightly coupled
  upstream code and keeps these ideas behind explicit ledger/plugin boundaries.

The guiding constraints are:

- JSONL/WAL remains canonical; databases, memory indexes, UI streams, and API
  responses are projections.
- Plugins and external harnesses cannot bypass approvals, budgets, auth,
  checkout, or storage contracts.
- Product shells, browser automation, research radars, and visual workspaces
  live outside the kernel behind stable protocol boundaries.
- Private memory stays local-first and opt-in for external lookup.

## Plugin Model

Plugins are installable capability packages. A plugin can provide tools, an
external CLI harness, a browser daemon boundary, a memory backend, a research
radar, a role pack, or a frontend UI shell. Frontend interfaces are treated as
plugins through `ui_slots`, so a workspace dashboard can be installed and
discovered the same way as a tool provider.

The first bundled plugin catalog includes:

- `gitnexus`: code-intelligence CLI harness plugin.
- `memory-index`: deterministic local memory search plugin.
- `browser-daemon`: browser control boundary plugin.
- `research-radar`: scheduled source-ingestion boundary plugin.
- `workspace-shell`: frontend UI shell plugin with a workspace slot.

Users should be able to browse the catalog, choose which plugins to install,
and let the kernel register only the selected plugins. Installed plugins still
flow through the same registry, policy, approval, budget, and ledger contracts.

## Core Only

The crate supports a core-only build path. Use the kernel without optional
integrations with:

```bash
cargo test -p essence-core --no-default-features
cargo check -p essence-core --no-default-features --features api
```

Feature groups are opt-in:

- `api`: local JSON-friendly Control API facade
- `mcp`: MCP adapter manifest and tool dispatcher
- `swarm`: swarm runtime, budget, registry, and scheduler helpers
- `gitnexus`: bundled code-intelligence plugin
- `workspace`: browser daemon and workspace shell plugin boundary

Default build keeps `full` enabled, so the current repo still ships the whole
kernel by default.

## Installation

From the repository root, install the `essence` CLI into Cargo's binary
directory:

```bash
cargo install --path crates/essence-core --bin essence
```

On Windows this installs:

```powershell
C:\Users\<you>\.cargo\bin\essence.exe
```

If `essence` is not found after installation, open a new terminal so PATH is
reloaded, or run it by full path:

```powershell
C:\Users\<you>\.cargo\bin\essence.exe --help
```

Verify the CLI is available:

```bash
essence --help
```

Release tags named `v*` publish portable `essence` CLI archives for:

- Linux `x86_64-unknown-linux-gnu`
- Windows `x86_64-pc-windows-msvc`
- macOS `x86_64-apple-darwin`
- macOS `aarch64-apple-darwin`

Each archive includes the binary, README, LICENSE, and a SHA-256 checksum file.

## CLI

There is now a v0 `essence` CLI over the local control plane. It writes runtime
data to `.essence/` by default and can be pointed elsewhere with `--root`.

Quick start after installation:

```bash
essence setup --save
essence chat
```

For one-shot prompts instead of interactive chat:

```bash
essence ask --text "Build the next layer"
```

Useful first commands:

```bash
essence session create --title "First session"
essence session list
essence doctor --strict
essence theme set pixel
essence completion powershell
essence completion install powershell
```

When developing from source without installing, prefix commands with
`cargo run -p essence-core --bin essence --`:

```bash
cargo run -p essence-core --bin essence -- session create --title "First session"
cargo run -p essence-core --bin essence -- session list
cargo run -p essence-core --bin essence -- session show --session-id <session-id> --projection --json
cargo run -p essence-core --bin essence -- ask --text "Build the next layer"
cargo run -p essence-core --bin essence -- message send --session-id <session-id> --text "Build the next layer" --json
cargo run -p essence-core --bin essence -- run start --session-id <session-id> --json
cargo run -p essence-core --bin essence -- tool specs --plugins
cargo run -p essence-core --bin essence -- tool run --session-id <session-id> --name essence.fs.list --input-json '{"path":"."}'
cargo run -p essence-core --bin essence -- events tail --session-id <session-id> --user-visible --output jsonl
cargo run -p essence-core --bin essence -- task claim --session-id <session-id> --assignee researcher
cargo run -p essence-core --bin essence -- memory remember --session-id <session-id> --kind decision --text "JSONL is canonical."
cargo run -p essence-core --bin essence -- memory search --session-id <session-id> --query canonical
cargo run -p essence-core --bin essence -- artifact create --session-id <session-id> --uri artifact://notes.md --kind markdown
cargo run -p essence-core --bin essence -- subagent list --session-id <session-id>
cargo run -p essence-core --bin essence -- snapshot write --session-id <session-id>
cargo run -p essence-core --bin essence -- approval pending --session-id <session-id>
cargo run -p essence-core --bin essence -- approval resolve --session-id <session-id> --approval-id <approval-id> --decision deny
cargo run -p essence-core --bin essence -- plugin catalog
cargo run -p essence-core --bin essence -- plugin install --id memory-index
cargo run -p essence-core --bin essence -- mcp manifest --json
cargo run -p essence-core --bin essence -- harness list
cargo run -p essence-core --bin essence -- theme set pixel
cargo run -p essence-core --bin essence -- theme preview pixel
cargo run -p essence-core --bin essence -- config set model your-model-name
cargo run -p essence-core --bin essence -- config get
cargo run -p essence-core --bin essence -- doctor --strict
cargo run -p essence-core --bin essence -- completion powershell
cargo run -p essence-core --bin essence -- completion install powershell
```

The Rust CI gate runs formatting, strict clippy, and tests on Ubuntu, Windows,
and macOS. macOS support is therefore a compatibility target, not only a best
effort path.

By default, data commands print compact human-readable text. Use `--theme
auto|pixel|plain` to choose the text renderer and `--no-color` to disable ANSI
color. `--json`, `--output jsonl`, and `--quiet` remain machine-readable and do
not include pixel UI framing. Mutating commands accept global `--dry-run` to
preview the write without changing `.essence/` state or installing files.

## API Compatibility

The crate is still in v0. Public API type-shape changes, especially enums and
records exported from `essence_core`, should be treated as compatibility
decisions rather than lint cleanup. Prefer additive changes in patch/minor
releases; reserve breaking public type reshapes for an explicit version-boundary
release.

Interactive chat and the Star Office-style agent board are available from the
same CLI:

```bash
cargo run -p essence-core --bin essence -- chat --title "Desk session"
```

Inside chat, type `/office` to render the multi-agent board and `/exit` to
quit. Chat registers itself as the `main` agent, flips to `running` while a turn
is active, and returns to `idle` when ready. `essence chat` refuses to start
when stdin/stdout or common CI variables indicate a non-interactive environment.

The CLI also includes a pixel-styled setup flow for the full path from install
to model configuration, chat, and the live board:

```bash
cargo run -p essence-core --bin essence -- setup --model your-model-name
cargo run -p essence-core --bin essence -- setup --model your-model-name --save
cargo run -p essence-core --bin essence -- setup --model your-model-name \
  --main-agent main \
  --main-agent-role "Main Operator" \
  --main-agent-prompt "You are the custom main Essence agent." \
  --save
```

`--save` writes `.essence/model.json`. The file stores the provider, model,
base URL, and API key environment variable name, but not the secret value.
Later `chat` commands use that saved model configuration unless CLI flags or
environment variables override it.

`setup` can also write a main agent profile to `.essence/agents/<id>.json`.
Use `--main-agent`, `--main-agent-lane`, `--main-agent-role`,
`--main-agent-prompt`, `--main-agent-prompt-file`, or
`--main-agent-template`. A saved profile named `main` is loaded automatically by
plain `essence chat`; other profiles can be selected with
`essence chat --agent <id>`.

The default assistant is local and ledger-backed, so the loop can be tested
without external model credentials. To use an OpenAI-compatible chat
completions endpoint, provide the provider, model, base URL, and API key:

```bash
export ESSENCE_MODEL_PROVIDER=openai-compatible
export ESSENCE_MODEL_BASE_URL='https://api.openai.com/v1'
export OPENAI_API_KEY='sk-...'
export ESSENCE_MODEL='your-model-name'

cargo run -p essence-core --bin essence -- chat --title "Desk session"

cargo run -p essence-core --bin essence -- chat \
  --model-provider openai-compatible \
  --model-base-url 'https://api.openai.com/v1' \
  --model-api-key-env OPENAI_API_KEY \
  --model your-model-name
```

PowerShell:

```powershell
$env:ESSENCE_MODEL_PROVIDER = "openai-compatible"
$env:ESSENCE_MODEL_BASE_URL = "https://api.openai.com/v1"
$env:OPENAI_API_KEY = "sk-..."
$env:ESSENCE_MODEL = "your-model-name"

cargo run -p essence-core --bin essence -- chat --title "Desk session"
```

`ESSENCE_MODEL_API_KEY` is checked before `OPENAI_API_KEY`, and
`--model-api-key-env` can point at another environment variable. The
OpenAI-compatible provider sends a native `POST /chat/completions` request and
uses `--model` as the request's model name.

You can also point chat at any command that reads the rendered transcript from
stdin and writes the assistant reply to stdout:

```bash
export ESSENCE_CHAT_MODEL_CMD='your-model-command'
cargo run -p essence-core --bin essence -- chat --title "Desk session"

cargo run -p essence-core --bin essence -- chat --model-command 'your-model-command'
```

PowerShell:

```powershell
$env:ESSENCE_CHAT_MODEL_CMD = "your-model-command"
cargo run -p essence-core --bin essence -- chat --title "Desk session"
```

For example, the command can be a small wrapper around an LLM CLI or a local
model runner. Non-empty stdout becomes the assistant message and is written back
to the Essence ledger. Model adapters are bounded by default with a 30 second
timeout, a 1 MiB HTTP response cap, a 1 MiB command stdout cap, and a 64 KiB
command stderr cap:

```bash
cargo run -p essence-core --bin essence -- chat \
  --model-command 'your-model-command' \
  --model-timeout-ms 30000 \
  --model-max-response-bytes 1048576 \
  --model-max-stdout-bytes 1048576 \
  --model-max-stderr-bytes 65536
```

To populate the board from another terminal:

```bash
cargo run -p essence-core --bin essence -- agent register --session-id <session-id> --agent-id researcher --lane research --role Research
cargo run -p essence-core --bin essence -- task create --session-id <session-id> --title "Map repo" --lane research
cargo run -p essence-core --bin essence -- agent heartbeat --session-id <session-id> --agent-id researcher --status running --lane research --note "indexing"
cargo run -p essence-core --bin essence -- workspace dashboard --session-id <session-id>
cargo run -p essence-core --bin essence -- workspace watch --session-id <session-id>
```

## Project Notes

- [Current status](docs/status.md)
- [Reference synthesis](docs/reference-synthesis.md)
- [v0 architecture draft](docs/v0-architecture.md)
- [Release process](docs/releasing.md)
- [API compatibility policy](docs/api-compatibility.md)
