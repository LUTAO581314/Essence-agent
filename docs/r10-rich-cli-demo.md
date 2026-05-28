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

Or use the helper script:

```powershell
.\scripts\demo-r10-rich-cli.ps1
```

The default entry opens the resident workbench. Use `q` to quit.

## Demo Modes

```powershell
.\scripts\demo-r10-rich-cli.ps1 -Mode interactive
.\scripts\demo-r10-rich-cli.ps1 -Mode boot
.\scripts\demo-r10-rich-cli.ps1 -Mode core
.\scripts\demo-r10-rich-cli.ps1 -Mode flow
.\scripts\demo-r10-rich-cli.ps1 -Mode status
```

- `interactive`: opens the normal `moxi` TUI.
- `boot`: renders the startup wordmark and initialization waterfall.
- `core`: renders the Agent Core information page.
- `flow`: replays a deterministic demo path for screenshots and reviews.
- `status`: renders a read-only status projection.

## Suggested Live Walkthrough

1. Start with `.\scripts\demo-r10-rich-cli.ps1 -Mode boot`.
2. Show that startup waits for owner input instead of flashing by itself.
3. Run `.\scripts\demo-r10-rich-cli.ps1 -Mode core`.
4. Point out `cwd`, config, trust, active agents, tools, skills, and snapshot path.
5. Run `.\scripts\demo-r10-rich-cli.ps1`.
6. In the workbench, type `inspect project status` and press Enter.
7. Press `r` three times to advance the local streaming demo.
8. Press `?` to open the command palette.
9. Type `/con` and press Enter to show context sources.
10. Type `commit and push current branch` and press Enter to show the risk prompt.
11. Type `/deny` to cancel, or `/approve` to submit only a local planning turn.
12. Type `/save` to write `.moxi/session/tui-session.json`.
13. Type `/resume` to read the snapshot summary without overwriting the session.

## Safe Boundary Talk Track

- The TUI is a shell, not the trusted execution core.
- The default TUI backend is local and read-only; it prepares analysis text from
  workspace facts but does not execute tools.
- Read-only workspace facts are collected locally: cwd, Git status, Cargo state,
  docs/config presence, active agents, messages, and task steps.
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
- `r`: advance the local streaming demo frame.
- `1` / `2` / `3` / `4`: jump to Boot / Trust / Agent Core / Workspace.
- `q`: quit.

## Deterministic Screenshot Runs

These runs do not require a live terminal session:

```powershell
cargo run -p moxi-cli --bin moxi --locked -- tui --width 120 --height 32 --keys "boot,q"
cargo run -p moxi-cli --bin moxi --locked -- tui --width 132 --height 34 --keys "core,q"
cargo run -p moxi-cli --bin moxi --locked -- tui --width 132 --height 38 --keys "boot,enter,enter,enter,type:i,type:n,type:s,type:p,type:e,type:c,type:t,enter,r,r,r,type:/,type:c,type:o,type:n,enter,type:/,type:s,type:a,type:v,type:e,enter,type:/,type:r,type:e,type:s,type:u,type:m,type:e,enter,q"
```
