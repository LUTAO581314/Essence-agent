use std::fmt::Write as FmtWrite;
use std::io::Write;
use std::thread;
use std::time::Duration;

use essence_core::{ControlPlane, LedgerProjection, LifecycleStatus, SessionId};

use super::args::{WorkspaceArgs, WorkspaceCommand};
use super::support::{parse_session_id, CliError};

pub(crate) fn execute_workspace(
    control: &ControlPlane,
    args: WorkspaceArgs,
    writer: &mut impl Write,
) -> Result<(), CliError> {
    match args.command {
        WorkspaceCommand::Dashboard(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let rendered =
                render_workspace_dashboard_from_control(control, &session_id, !args.no_color)?;
            writer.write_all(rendered.as_bytes())?;
            Ok(())
        }
        WorkspaceCommand::Watch(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            watch_workspace_dashboard(
                control,
                &session_id,
                !args.no_color,
                !args.no_clear,
                args.interval_ms,
                args.ticks,
                writer,
            )
        }
    }
}

pub(crate) fn render_workspace_dashboard_from_control(
    control: &ControlPlane,
    session_id: &SessionId,
    color: bool,
) -> Result<String, CliError> {
    let projection = control.projection(session_id)?;
    let shell = CliWorkspaceShell::from_ledger(&projection);
    Ok(render_workspace_dashboard(
        session_id,
        &shell,
        projection.latest_seq,
        projection.tasks.len(),
        projection.pending_approvals().count(),
        color,
    ))
}

fn watch_workspace_dashboard(
    control: &ControlPlane,
    session_id: &SessionId,
    color: bool,
    clear: bool,
    interval_ms: u64,
    ticks: Option<u64>,
    writer: &mut impl Write,
) -> Result<(), CliError> {
    let mut tick = 0;
    loop {
        if clear && color {
            writer.write_all(b"\x1b[2J\x1b[H")?;
        }
        let rendered = render_workspace_dashboard_from_control(control, session_id, color)?;
        writer.write_all(rendered.as_bytes())?;
        writer.flush()?;

        tick += 1;
        if ticks.is_some_and(|limit| tick >= limit) {
            break;
        }
        thread::sleep(Duration::from_millis(interval_ms));
    }
    Ok(())
}

#[derive(Debug, Clone, Default, PartialEq)]
struct CliWorkspaceShell {
    agents: Vec<CliWorkspaceAgentTile>,
}

impl CliWorkspaceShell {
    fn from_ledger(projection: &LedgerProjection) -> Self {
        let mut agents = Vec::new();
        for agent in projection.agents.values() {
            let heartbeat = projection.agent_heartbeats.get(&agent.agent_id);
            let current_task_title = heartbeat
                .and_then(|heartbeat| heartbeat.current_task_id.as_ref())
                .and_then(|task_id| projection.tasks.get(task_id))
                .map(|task| task.title.clone());
            agents.push(CliWorkspaceAgentTile {
                agent_id: agent.agent_id.0.clone(),
                area: heartbeat
                    .and_then(|heartbeat| heartbeat.lane_id.as_ref())
                    .map(|lane_id| lane_id.0.clone())
                    .unwrap_or_else(|| agent.lane_id.0.clone()),
                status: heartbeat
                    .map(|heartbeat| heartbeat.status.clone())
                    .unwrap_or_else(|| agent.status.clone()),
                current_task_title,
            });
        }
        Self { agents }
    }
}

#[derive(Debug, Clone, PartialEq)]
struct CliWorkspaceAgentTile {
    agent_id: String,
    area: String,
    status: LifecycleStatus,
    current_task_title: Option<String>,
}

fn render_workspace_dashboard(
    session_id: &SessionId,
    shell: &CliWorkspaceShell,
    events_applied: u64,
    task_count: usize,
    pending_approvals: usize,
    color: bool,
) -> String {
    let cyan = style(color, "36;1");
    let blue = style(color, "34;1");
    let green = style(color, "32;1");
    let yellow = style(color, "33;1");
    let red = style(color, "31;1");
    let dim = style(color, "2");
    let reset = if color { "\x1b[0m" } else { "" };

    let mut output = String::new();
    let _ = writeln!(
        output,
        "{cyan}+======================================================================+{reset}"
    );
    let _ = writeln!(
        output,
        "{cyan}|{reset} {blue}ESSENCE AGENT // STAR OFFICE{reset}        multi-agent control room      {cyan}|{reset}"
    );
    let _ = writeln!(
        output,
        "{cyan}|{reset} session {dim}{}{reset}",
        session_id.0
    );
    let _ = writeln!(
        output,
        "{cyan}|{reset} events {events_applied:<5} tasks {task_count:<5} pending approvals {pending_approvals:<5}"
    );
    let _ = writeln!(
        output,
        "{cyan}+======================================================================+{reset}"
    );
    let _ = writeln!(
        output,
        "{cyan}|{reset} WOLF SIGNAL  /\\_/\\\\   agents online: {:<3}",
        shell.agents.len()
    );
    let _ = writeln!(
        output,
        "{cyan}|{reset}             ( o.o )  ledger-backed swarm presence"
    );
    let _ = writeln!(output, "{cyan}|{reset}              > ^ <");
    let _ = writeln!(
        output,
        "{cyan}+----------------------+----------------+----------+------------------+{reset}"
    );
    let _ = writeln!(
        output,
        "{cyan}|{reset} agent                lane             status     current work"
    );
    let _ = writeln!(
        output,
        "{cyan}+----------------------+----------------+----------+------------------+{reset}"
    );

    if shell.agents.is_empty() {
        let _ = writeln!(
            output,
            "{cyan}|{reset} {dim}no agents registered yet; use `agent register` to open desks{reset}"
        );
    } else {
        for tile in &shell.agents {
            let status_color = match tile.status {
                LifecycleStatus::Running => green,
                LifecycleStatus::WaitingTool | LifecycleStatus::WaitingApproval => yellow,
                LifecycleStatus::Failed
                | LifecycleStatus::Cancelled
                | LifecycleStatus::TimedOut => red,
                _ => blue,
            };
            let task = tile.current_task_title.as_deref().unwrap_or("standby");
            let _ = writeln!(
                output,
                "{cyan}|{reset} {agent:<20} {lane:<16} {status_color}{status:<10}{reset} {task}",
                agent = truncate(&tile.agent_id, 20),
                lane = truncate(&tile.area, 16),
                status = lifecycle_label(&tile.status),
                task = truncate(task, 28),
            );
        }
    }

    let _ = writeln!(
        output,
        "{cyan}+----------------------+----------------+----------+------------------+{reset}"
    );
    let _ = writeln!(
        output,
        "{dim}tip: `essence agent heartbeat --status running --lane research --note \"indexing\"`{reset}"
    );
    output
}

fn style(enabled: bool, code: &str) -> &'static str {
    if !enabled {
        ""
    } else {
        match code {
            "36;1" => "\x1b[36;1m",
            "34;1" => "\x1b[34;1m",
            "32;1" => "\x1b[32;1m",
            "33;1" => "\x1b[33;1m",
            "31;1" => "\x1b[31;1m",
            "2" => "\x1b[2m",
            _ => "",
        }
    }
}

fn lifecycle_label(status: &LifecycleStatus) -> &'static str {
    match status {
        LifecycleStatus::Queued => "queued",
        LifecycleStatus::Active => "active",
        LifecycleStatus::Idle => "idle",
        LifecycleStatus::Running => "running",
        LifecycleStatus::WaitingTool => "tool",
        LifecycleStatus::WaitingApproval => "approval",
        LifecycleStatus::Completed => "done",
        LifecycleStatus::Failed => "failed",
        LifecycleStatus::Cancelled => "cancelled",
        LifecycleStatus::TimedOut => "timeout",
    }
}

fn truncate(value: &str, width: usize) -> String {
    let mut output = value.chars().take(width).collect::<String>();
    if value.chars().count() > width && width > 1 {
        output.truncate(width - 1);
        output.push('~');
    }
    output
}
