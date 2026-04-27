use std::fmt::Write as FmtWrite;
use std::io::Write;
use std::thread;
use std::time::Duration;

use essence_core::{ControlPlane, LedgerProjection, LifecycleStatus, SessionId};

use super::args::{WorkspaceArgs, WorkspaceCommand};
use super::pixel_ui::{
    brand_header, key_value, mid, reset, row, status_chip, style, tiny_logo, top,
};
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
    let mut output = String::new();
    output.push_str(&brand_header(
        "ESSENCE AGENT // STAR OFFICE",
        "multi-agent control room",
        color,
    ));
    let _ = writeln!(output, "{}", row(color, tiny_logo(color)));
    let _ = writeln!(output, "{}", mid(color));
    let _ = writeln!(
        output,
        "{}",
        row(
            color,
            key_value(color, "session", &session_id.0.to_string())
        )
    );
    let _ = writeln!(
        output,
        "{}",
        row(
            color,
            format!(
                "{}   {}   {}   {}",
                key_value(color, "events", &events_applied.to_string()),
                key_value(color, "tasks", &task_count.to_string()),
                key_value(color, "approvals", &pending_approvals.to_string()),
                key_value(color, "agents", &shell.agents.len().to_string())
            )
        )
    );
    let _ = writeln!(output, "{}", top(color));
    let _ = writeln!(
        output,
        "{}",
        row(
            color,
            "desk                 lane             state        current work"
        )
    );
    let _ = writeln!(output, "{}", mid(color));

    if shell.agents.is_empty() {
        let _ = writeln!(
            output,
            "{}",
            row(
                color,
                format!(
                    "{}no agents registered yet; use `agent register` to open desks{}",
                    style(color, "dim"),
                    reset(color)
                )
            )
        );
    } else {
        for tile in &shell.agents {
            let tone = match tile.status {
                LifecycleStatus::Running => "green",
                LifecycleStatus::WaitingTool | LifecycleStatus::WaitingApproval => "yellow",
                LifecycleStatus::Failed
                | LifecycleStatus::Cancelled
                | LifecycleStatus::TimedOut => "red",
                _ => "moon",
            };
            let task = tile.current_task_title.as_deref().unwrap_or("standby");
            let _ = writeln!(
                output,
                "{}",
                row(
                    color,
                    format!(
                        "{agent:<20} {lane:<16} {status:<12} {task}",
                        agent = truncate(&tile.agent_id, 20),
                        lane = truncate(&tile.area, 16),
                        status = status_chip(color, lifecycle_label(&tile.status), tone),
                        task = truncate(task, 24),
                    )
                )
            );
        }
    }

    let _ = writeln!(output, "{}", mid(color));
    let _ = writeln!(
        output,
        "{}",
        row(
            color,
            format!(
                "{}tip:{} `essence agent heartbeat --status running --lane research --note \"indexing\"`",
                style(color, "dim"),
                reset(color)
            )
        )
    );
    output
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
    super::pixel_ui::truncate(value, width)
}
