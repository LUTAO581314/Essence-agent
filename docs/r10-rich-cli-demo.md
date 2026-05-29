# R10 Rich CLI Demo Guide

This guide is the local demo runbook for the `moxi-agent` Rich CLI/TUI. The
demo is intentionally a P2 shell experience: it can render workspace facts,
collect user intent, show risk prompts, persist a local TUI snapshot, and
display read-only backend analysis. It cannot authorize, execute, issue
tickets, verify proofs, push to GitHub, or commit ledger events.

## Quick Start

From the repository root:

```powershell
cargo run -p moxi-cli --bin moxi --locked
```

Preview a safe model/API config:

```powershell
cargo run -p moxi-cli --bin moxi --locked -- init --provider openai --model gpt-4o-mini
```

Create `.moxi/config.toml` only when you explicitly pass `--write`:

```powershell
cargo run -p moxi-cli --bin moxi --locked -- init --provider openai --model gpt-4o-mini --write
```

Or use the helper script:

```powershell
.\scripts\demo-r10-rich-cli.ps1
```

The default entry opens the resident workbench. Use `q` to quit.

## Demo Modes

```powershell
.\scripts\demo-r10-rich-cli.ps1 -Mode interactive
.\scripts\demo-r10-rich-cli.ps1 -Mode boot
.\scripts\demo-r10-rich-cli.ps1 -Mode setup
.\scripts\demo-r10-rich-cli.ps1 -Mode core
.\scripts\demo-r10-rich-cli.ps1 -Mode flow
.\scripts\demo-r10-rich-cli.ps1 -Mode status
```

- `interactive`: opens the normal `moxi` TUI.
- `boot`: renders the startup wordmark and initialization waterfall.
- `setup`: renders the first-run model/API configuration guide.
- `core`: renders the Agent Core information page.
- `flow`: replays a deterministic demo path for screenshots and reviews.
- `status`: renders a read-only status projection.

## Suggested Live Walkthrough

1. Start with `.\scripts\demo-r10-rich-cli.ps1 -Mode boot`.
2. Show that startup waits for owner input instead of flashing by itself.
3. Run `.\scripts\demo-r10-rich-cli.ps1 -Mode setup`.
4. Point out provider, endpoint, model, `api_key_env`, and redacted key rules.
5. Run `.\scripts\demo-r10-rich-cli.ps1 -Mode core`.
6. Point out `cwd`, config, trust, active agents, tools, skills, and snapshot path.
7. Run `.\scripts\demo-r10-rich-cli.ps1`.
8. In the workbench, type `inspect project status` and press Enter.
9. Press `r` repeatedly to advance staged reply rendering until the turn
   completes.
10. Press `?` to open the command palette.
11. Type `/con` and press Enter to show context sources.
12. Type `commit and push current branch` and press Enter to show the risk prompt.
13. Type `/deny` to cancel, or `/approve` to submit only a local planning turn.
14. Type `/save` to write `.moxi/session/tui-session.json`.
15. Type `/resume` to read the snapshot summary without overwriting the session.

## Safe Boundary Talk Track

- The TUI is a shell, not the trusted execution core.
- The default TUI backend is local and read-only; it prepares analysis text from
  workspace facts but does not execute tools.
- Backend output includes a local plan id, suggested plan steps, and blocked
  authority categories so the task tracker can explain what would require a
  real P1/P0 adapter.
- The default backend asks `moxi-runtime` for read-only planner steps before
  falling back to local planning, but it never issues tickets, executes,
  verifies proofs, or commits ledger events.
- Runtime planner steps render as owner-facing agent workflow steps while their
  details keep the original capability/target/risk evidence.
- Task Tracking shows the active turn first, keeping the latest backend plan
  visible before older session turns.
- Read-only workspace facts are collected locally: cwd, Git status, Cargo state,
  docs/config presence, active agents, messages, and task steps.
- First-run setup shows `.moxi/config.toml` and environment variable options,
  but does not save secrets or print full API keys. The top-level `moxi init`
  command previews the same env-only config by default, and writes it only when
  `--write` is explicit.
- `/doctor` classifies model/API readiness without printing secrets. It probes
  OpenAI-compatible HTTP/HTTPS endpoints through the configured
  `/models/{model}` route and reports setup gaps, invalid keys, missing models,
  quota/rate limits, bad endpoints, network failures, timeouts, and unsupported
  response shapes.
- `/models` lists OpenAI-compatible provider model ids through `/models` when
  the configured endpoint supports catalog listing.
- Configured workbench tasks now use the OpenAI-compatible `/chat/completions`
  adapter in read-only mode. If config, network, provider, or response parsing
  fails, the TUI falls back to local read-only analysis and redacts error
  previews. Replies are staged into visible chunks so the conversation feels
  live while the terminal remains read-only.
- Risk prompts are local intent capture only.
- `/approve` inside the TUI does not grant write, shell, Git/GitHub, ticket,
  proof, or ledger authority.
- `/save` writes only a local session JSON snapshot.
- Real execution still belongs behind P0 policy, ticket, sandbox, proof, and
  ledger gates.

## Useful Keys

- `Enter`: submit task or advance startup page.
- `?`: open command palette.
- `Up` / `Down`: move command palette selection, or task selection when the
  palette is closed.
- `PageUp` / `PageDown`: review conversation history.
- `r`: advance startup/loading frames and staged reply chunks.
- `1` / `2` / `3` / `4` / `5`: jump to Boot / Trust / Setup / Agent Core /
  Workspace.
- `q`: quit.

## Deterministic Screenshot Runs

These runs do not require a live terminal session:

```powershell
cargo run -p moxi-cli --bin moxi --locked -- tui --width 120 --height 32 --keys "boot,q"
cargo run -p moxi-cli --bin moxi --locked -- tui --width 120 --height 32 --keys "setup,q"
cargo run -p moxi-cli --bin moxi --locked -- tui --width 132 --height 34 --keys "core,q"
cargo run -p moxi-cli --bin moxi --locked -- tui --width 132 --height 38 --keys "boot,enter,enter,enter,enter,type:i,type:n,type:s,type:p,type:e,type:c,type:t,enter,r,r,r,type:/,type:c,type:o,type:n,enter,type:/,type:s,type:a,type:v,type:e,enter,type:/,type:r,type:e,type:s,type:u,type:m,type:e,enter,q"
```
