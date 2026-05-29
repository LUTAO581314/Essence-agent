# R10 Rich CLI TUI Product Design

This document records the agreed product direction for the `moxi-agent` rich
CLI/TUI. It is a design target and acceptance guide for the R10 shell, not a
claim that every future runtime workflow is already connected.

## Product Position

`moxi-agent` should feel like a modern agent control panel in the terminal:

- Claude-like safety and clarity during daily use.
- Hermes-like visual impact during startup and core information display.
- MOXI-specific agent operating system identity, not a generic dashboard.
- P2 shell experience only: it may render, request, and display approvals; P0
  still owns authorization, execution, verification, and ledger commits.

## Startup Flow

The default `moxi` / `moxi-agent` entry should follow this order:

1. Logo impact page.
2. Workspace Trust risk page, only when needed.
3. First-run Setup page, only when model/API config is missing or incomplete.
4. Agent Core information page.
5. Main working conversation surface.

The risk page should not appear on every launch. It appears when the workspace
is new, the disk/location changes, trust is unknown, core or agent config
changes, permissions are elevated, or the user clears trust state.

The setup page should not appear after configuration is complete. It appears
when `.moxi/config.toml` and supported environment variables do not provide a
provider, endpoint, model, and API-key source. It is guidance-only until the
explicit save/setup flow and `/doctor` connectivity check are implemented.

## Page 1: Logo Impact

Purpose: visual impact and product identity.

Use a large `moxi-agent` wordmark with ANSI color gradients, an optional ASCII
or pixel logo, and a short loading waterfall. This page must represent real
initialization state and must not flash past automatically in the interactive
CLI. It waits for owner input, then advances through trust, Agent Core, and the
workspace.

```text
        MOXI // AGENT      guarded terminal intelligence
        ███╗   ███╗ ██████╗ ██╗  ██╗██╗       █████╗  ██████╗ ███████╗███╗   ██╗████████╗
        ████╗ ████║██╔═══██╗╚██╗██╔╝██║      ██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝
        ██╔████╔██║██║   ██║ ╚███╔╝ ██║█████╗███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║
        ██║╚██╔╝██║██║   ██║ ██╔██╗ ██║╚════╝██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║
        ██║ ╚═╝ ██║╚██████╔╝██╔╝ ██╗██║      ██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║

        SILVER CORE ONLINE | P0 GUARDED | P2 RICH CLI

        moxi-agent  guarded agent operating system  session local-r10-demo-session
        CORE Silver Core  SHELL P2 rich-cli  MODE guarded read-only

  Initialization waterfall
  > Initializing Silver Core  [###################-----]
  + Loading Agent Core profiles
  + Reading configured skills and tools
  > Reading workspace context: C:\MOXI-Essence-agent\MOXI-Essence-agent
  - Checking trust boundary
  - Waiting for owner handoff

  Enter continue startup flow    5 workspace    q quit

  graph demo_graph    context workspace facts ready
```

## Page 2: Workspace Trust Risk Gate

Purpose: safety and user confidence.

Only show this page for new or changed trust situations:

- First launch in a folder.
- New drive, network drive, removable drive, or suspicious location.
- Workspace path is not in the trusted list.
- Agent/core configuration changes, such as `.moxi/agents.toml`.
- Mode changes from read-only to write, shell execution, or Git/GitHub actions.
- Hooks, scripts, sensitive files, or risky environment variables are detected.
- User manually clears trust state.

```text
Workspace Trust

moxi-agent will enter this workspace:
C:\MOXI-Essence-agent\MOXI-Essence-agent

Current safety mode
* Read-only inspection: allowed
o File writes: require owner confirmation
o Shell commands: require owner confirmation
o Git commit / GitHub push: require owner confirmation

Risk note
The rich CLI shell cannot authorize or execute by itself.
High-risk actions must go through the P0 guarded path.

Enter read-only     /trust trust workspace     /deny exit
```

## Page 3: Agent Core Information

Purpose: advanced product feel, configuration transparency, and trust.

This page appears after the risk gate and before the main conversation. It is
the right place for detailed configuration. Do not force all of this into the
main chat surface.

`moxi-agent` does not assume five fixed agents. Agents are loaded from runtime
configuration and should be shown as the active configuration for the current
workspace/session.

```text
moxi-agent core

[ MOXI ]
[AGENT ]
[ CORE ]
[ P0   ]
[ P2   ]

moxi-agent v0.1.0 | Silver Core | guarded rich-cli
cwd: C:\MOXI-Essence-agent\MOXI-Essence-agent
config: .moxi\agents.toml
session: 20260528_154201

Agent Runtime
orchestrator: adaptive
trust: pending
mode: read-only
approval: required for write / shell / git

Loaded Agents
moxi-agent: orchestrator, planning, task routing
ui-agent: rich-cli, terminal-design, ratatui
guard-agent: trust-boundary, approval, risk-review

Agent config source:
`.moxi/agents.toml` may define `[[agents]]` entries with `name`, `role`,
`model`, and `reasoning`. The TUI should show configured active agents first.
If config is missing or incomplete, it may fall back to a small documented
local demo set; the product must not assume a permanent five-agent roster.

Model/API config source:
`.moxi/config.toml` may define `provider`, `endpoint`, `model`, `api_key_env`,
or `api_key`. Environment fallback may use `MOXI_PROVIDER`, `MOXI_ENDPOINT`,
`MOXI_MODEL`, `MOXI_API_KEY`, `OPENAI_API_KEY`, or `OPENROUTER_API_KEY`.
The UI must never print full API keys; `/config` only shows redacted key
sources until a real connectivity check and chat adapter are connected.

Available Tools
file.read | repo.inspect | git.status | test.run
shell.preview | context.trace | command.palette

Available Skills
tui.design | risk.review | docs.prepare | github.prepare
```

## Page 3: First-Run Setup

Purpose: make the API-backed Alpha feel usable instead of silently falling back
to a display-only shell when model/API config is missing.

This page shows the detected provider, endpoint, model, config path/state, and
redacted API-key source. It should offer a copyable `.moxi/config.toml` shape
and environment variable alternatives without ever printing a full key.

```text
MOXI CLI Alpha setup                  read-only model chat preparation

Model/API configuration is required before real chat is connected.
This page is a guide only: it does not write files, print full keys, or call the network.

Detected configuration
provider: openai        model: not-configured
endpoint: https://api.openai.com/v1
config: C:\...\MOXI-Essence-agent\.moxi\config.toml (missing)
api key: missing

Create .moxi/config.toml
[model]
  provider = "openai"
  endpoint = "https://api.openai.com/v1"
  model = "gpt-4o-mini"
  api_key_env = "OPENAI_API_KEY"

Supported providers
openai | openrouter | custom | local

Environment alternative
MOXI_PROVIDER / MOXI_ENDPOINT / MOXI_MODEL
MOXI_API_KEY / OPENAI_API_KEY / OPENROUTER_API_KEY

Enter continue to Agent Core    /config show redacted state    5 workspace
```

## Page 4: Agent Core Information

Purpose: advanced product feel, configuration transparency, and trust.

## Page 5: Main Working Surface

Purpose: daily usability.

The main UI should be cleaner than the startup/core pages. It should behave
like a chat-first reading surface: a light fact header at the top, a flowing
conversation body, a sticky task sidebar on the right, and a bottom input/status
rail. Avoid wrapping the whole workspace in a dashboard frame.

```text
moxi-agent                                      guarded | read-only
cwd: C:\MOXI-Essence-agent\MOXI-Essence-agent
config: .moxi\agents.toml | core: Silver Core | trust: pending

Conversation stream                           Sticky Task Tracking

* moxi-agent [orchestrator]                    Turn 1
I will inspect the workspace first,            * Detect workspace
then prepare a safe plan.                      * Load Agent Core
model: gpt-5.5 | reasoning: high               > Check risk
                                                o Wait for owner
* ui-agent [rich-cli]
The CLI should feel like a safe                 Turn 2
agent control panel, not a dashboard.          > demo_intake
model: code-ui | reasoning: high               o demo_plan
                                                o demo_approval
> guard-agent is checking workspace risk...
model: guard | reasoning: medium

Input Task
> Ask moxi-agent to inspect the current project

? shortcuts | / command menu          context [#######---]72%
```

## Main Surface Rules

- Top header shows hard session facts: `cwd`, config source, core, trust, mode.
- Do not put `context [bar]` in the top header. It belongs under the input box,
  bottom-right.
- The workspace should not have one large enclosing border. Conversation text
  is an unframed stream so the user feels they are talking, not reading a
  dashboard.
- Task Tracking is a sticky sidebar: it stays fixed on the right while the
  conversation scrolls independently. Keep a narrow gap between chat and the
  sidebar so the sidebar feels pinned rather than crowded into the chat.
- The input box is fixed at the bottom. Use a simple bottom rail and keep
  context/mode/model/reasoning metadata in the thin line below it.
- Shortcut commands should not be permanently listed. Default footer is only:
  `? shortcuts | / command menu`.
- Full commands appear only in a popup or command palette.
- Agent model and reasoning are per-message metadata, because different agents
  may use different models and reasoning levels.
- Task Tracking shows all turns, separated by blank space. The active step
  should auto-center when follow mode is enabled.
- Manual scrolling pauses follow mode; `f` or `/follow` can resume it.
- Risk and approval prompts appear near or above the input area, not as a
  permanent dashboard panel.
- Errors and blockers should be explained as conversation messages at the end
  of a turn.

## Command Palette

Commands should be discoverable but not consume permanent vertical space:

```text
Commands
/status    current runtime status
/tasks     open task tracking
/agents    inspect Agent Core
/skills    inspect loaded skills
/context   show context sources
/config    inspect redacted model/API config
/doctor    test model/API readiness
/approve   confirm current risk intent
/deny      reject current risk
/trust     open workspace trust gate
/help      show this menu
```

`/doctor` should classify provider readiness in owner-facing language: setup
missing, invalid key, model not found, quota/rate limit, bad endpoint, network
failure, timeout, unsupported response, or ready. It must keep secrets redacted.
The Alpha implementation probes OpenAI-compatible HTTP/HTTPS endpoints through
`/models/{model}` before model-backed chat is connected.

## Implementation Notes

- Keep Rust + Ratatui. Textual, Rich, Bubble Tea, Claude Code, and Hermes are
  design references only.
- Preserve deterministic `--keys` rendering for snapshot tests.
- The TUI remains P2. It may display `/approve` and `/deny`, but those are
  owner intent signals unless a real P0 authorization path is connected.
- Optional image/logo rendering should be progressive enhancement; ASCII and
  ANSI-color fallbacks must remain good on Windows terminals.
