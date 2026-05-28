# R10 TUI UX Reference Plan

This note turns the current R10 shell direction into an implementation-oriented
TUI plan. The goal is a demo-quality terminal surface that feels usable as soon
as a user types `moxi`, while preserving the P0/P1/P2 authority boundary.

## Product Target

The next minimum demo should show a real product surface, not only a static
snapshot:

- `moxi` opens the full-screen terminal UI by default.
- The first screen is chat-first: the center is a large AI conversation/status
  stream, not a dashboard grid.
- The current graph, task, approval, blocker, and shell boundary state are
  compressed into short inline summaries so they do not cover the chat area.
- The first frame must look branded: MOXI wordmark, high-contrast color badges,
  semantic task colors, visible progress bars, and a polished terminal layout.
- A bottom command/input pane accepts safe shell commands and demo prompts.
  The first command set is intentionally display-only: `/help`, `/status`,
  `/boundary`, `/demo`, `/filter <text>`, `/clear`, and `/quit`.
- Key navigation is visible and consistent: pane focus, task selection,
  command palette, refresh, quit.
- Any executable or credentialed action is rendered as unavailable unless a
  verified P0 path exists.

## Reference Findings

- Claude Code treats `claude` with no subcommand as the primary interactive
  entrypoint, while keeping `-p` and piped input for one-shot automation:
  https://code.claude.com/docs/en/cli-reference
- Claude Code exposes in-session slash commands, theme selection, terminal
  setup, and a `/tui [default|fullscreen]` renderer switch. The useful pattern
  for MOXI is not copying command names, but making product controls discoverable
  in-session:
  https://code.claude.com/docs/en/commands
- Ratatui is an immediate-mode renderer: each frame should be rendered from the
  current app state. This supports a clean split between state, actions, and
  view functions:
  https://docs.rs/ratatui/latest/ratatui/
- Ratatui layouts should be responsive and nested with constraints instead of
  fixed coordinates. This matters for Windows terminals, small panes, and remote
  shells:
  https://ratatui.rs/concepts/layout/
- Crossterm provides the event source for keyboard, resize, mouse, and focus
  events. `poll`/`read` should stay on one event path, and raw mode is required
  for reliable key handling:
  https://docs.rs/crossterm/latest/crossterm/event/index.html
- Ratatui's official templates include event-driven, async, and component
  variants. The component/event-driven shape is the best fit once MOXI adds
  an input pane and live runtime refresh:
  https://github.com/ratatui/templates/
- Ratatui async guidance separates tick, render, key, paste, focus, and quit
  events. MOXI can adopt the event vocabulary without immediately moving all
  shell logic to async:
  https://ratatui.rs/tutorials/counter-async-app/full-async-events/
- Flux-style app architecture maps well to MOXI: user key/input events become
  actions, stores hold shell/runtime projection state, and widgets render only
  from that state:
  https://ratatui.rs/concepts/application-patterns/flux-architecture/

## Recommended UI Shape

Use a Claude-like chat surface with a persistent bottom input pane:

```text
MOXI Essence Agent                         projection shell  high /effort

Welcome back. MOXI is ready for chat-first agent work.
You  Try /help, /status, /boundary, or ask a local read-only task.
MOXI I can show the current projection and explain blockers.

Status  4 tasks  1 approval  progress 62%  [##########......]
Selected demo_plan  Running  runtime.plan 62%

> ask MOXI or type /help
? for shortcuts   esc/q to quit   display-only shell
```

Primary panes:

- Header: product name, profile, graph, mode, refresh/error state.
- Main: AI conversation/status stream and selected-task summary.
- Bottom pane: large editable input, slash commands, command status.
- Status bar: shortcuts, effort/model/profile indicators, boundary reminder.
- Optional overlays later: one-screen key map, task detail, evidence/proof refs.

Visual rules:

- Use a dark-terminal brand feel with cyan, magenta, green, yellow, red, white,
  and gray semantics instead of one-hue decoration.
- Keep status badges short and scannable: running, complete, blocked, approval,
  projection-only.
- Preserve text fallbacks in rendered frames so tests and plain terminals still
  show the core state even when colors are unavailable.
- Treat `assets/logo/silver-snow-wolf-pixel.png` as the current brand asset
  candidate. PNG rendering should be an optional enhanced path later, because
  terminal image protocols vary across Windows terminals.

## Implementation Sequence

1. Extract TUI state and rendering into small modules inside `moxi-cli`.
   Keep command parsing and shell projection separate from rendering.
2. Add an interactive default mode for `moxi` that enters alternate screen
   without requiring `--interactive`.
3. Add a bottom input pane with editing state, history, and command submission.
   Start with safe commands only: `help`, `status`, `boundary`, `demo`, `quit`.
4. Add command palette behavior for `/` so users can discover actions without
   memorizing CLI flags.
5. Add responsive layouts: desktop three-pane, narrow two-pane, very narrow
   stacked mode.
6. Add snapshot tests for rendered frames at common terminal sizes.
7. Connect optional runtime snapshot/journal refresh so the UI can show real
   local read-only runs when available.

## Boundary Rules

- The TUI may submit shell requests, render projections, and display approval
  prompts.
- It must not authorize, approve, issue tickets, execute, verify, or commit
  ledger events directly.
- A future "run" or "read" path must be a visible P0 handoff, not a TUI-owned
  action.
- UI labels should say "request", "blocked", "needs approval", or "P0 path"
  instead of implying direct shell execution.

## Next PR Candidate

Build the display-first TUI shell:

- Replace the current default snapshot print with a real interactive full-screen
  app when the user runs `moxi`.
- Keep the current branded/colorized chat-first view and command input pane,
  then add command history, help overlay, and responsive pane layout.
- Keep `--keys` deterministic replay for tests and non-interactive verification.
- Add tests for key actions and frame snapshots at small and normal terminal
  sizes.
