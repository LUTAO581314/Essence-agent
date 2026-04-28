use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::{IsTerminal, Write};
use std::thread;
use std::time::Duration;

use essence_core::{
    basic_plugin_catalog, builtin_tool_specs, AgentHeartbeatRequest, AgentId, ApprovalDecision,
    ApprovalRequest, ArtifactRecord, BuiltinToolApprovalOutcome, BuiltinToolExecutor,
    BuiltinToolOutcome, BuiltinToolRequest, CliHarnessManifest, ControlPlane,
    CreateArtifactRequest, CreateSessionRequest, CreateTaskRequest, EventCursor, EventEnvelope,
    LaneId, LedgerProjection, LifecycleStatus, MemoryIndex, MemoryRecord, PermissionMode,
    PluginHost, PluginKind, PluginManifest, PolicyBoundCliHarness, ProposeMemoryRequest,
    RecordedCliHarnessApprovalOutcome, RecordedCliHarnessOutcome, RegisterAgentRequest,
    RequestApprovalRequest, RunMeta, SessionMeta, SessionStatePatch, SpawnSubagentRequest,
    StartRunRequest, StartToolCallRequest, SteerSubagentRequest, SubagentBudget, SubagentMeta,
    SubagentResult, TaskPatch, TaskRecord, ToolCallRecord, UiEvent, WalIntegrityReport,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::agency_templates::{find_agent_template, search_agent_templates, AgencyAgentTemplate};
use super::agent_profile::{list_agent_profiles, write_agent_profile, StoredAgentProfile};
use super::args::{
    AgentArgs, AgentCommand, AgentDefineArgs, AgentTemplatesArgs, ApprovalArgs, ApprovalCommand,
    ArtifactArgs, ArtifactCommand, CliApprovalDecision, CliConfigKey, CliPluginKind, CliTheme,
    ConfigArgs, ConfigCommand, DoctorArgs, EventsArgs, EventsCommand, HarnessArgs, HarnessCommand,
    McpArgs, McpCommand, MemoryArgs, MemoryCommand, MessageArgs, MessageCommand, PluginArgs,
    PluginCommand, RunArgs, RunCommand, SessionArgs, SessionCommand, SnapshotArgs, SnapshotCommand,
    SubagentArgs, SubagentCommand, TaskArgs, TaskCommand, ThemeArgs, ThemeCommand, ToolArgs,
    ToolCommand,
};
use super::model_config::{
    model_config_path, non_empty, read_model_config, write_model_config, StoredModelConfig,
};
use super::pixel_ui::{
    brand_header, error_panel, key_value, mid, panel, reset, row, status_chip, style, table,
};
use super::setup::provider_slug;
use super::support::{
    anchor_key_from_env, emit_events, emit_ui_events, parse_approval_id, parse_artifact_id,
    parse_event_id, parse_memory_id, parse_run_id, parse_session_id, parse_task_id,
    parse_tool_call_id, path_to_string, write_json_line, write_json_pretty, write_text_line,
    CliError, OutputMode,
};

fn write_output<T: Serialize>(
    writer: &mut impl Write,
    output: OutputMode,
    value: &T,
    text: String,
    quiet_text: String,
) -> Result<(), CliError> {
    if output.is_json() {
        write_json_pretty(writer, value)
    } else if output.is_jsonl() {
        write_json_line(writer, value)
    } else if output.quiet {
        write_text_line(writer, quiet_text)
    } else if output.is_pixel() {
        let rendered = if quiet_text == "failed" {
            error_panel(&text, output.color)
        } else {
            panel("ESSENCE CLI", "local control plane", &text, output.color)
        };
        write_text_line(writer, rendered)
    } else {
        write_text_line(writer, text)
    }
}

fn write_dry_run(
    writer: &mut impl Write,
    output: OutputMode,
    action: &str,
    detail: impl Into<String>,
) -> Result<(), CliError> {
    let detail = detail.into();
    let value = json!({
        "dry_run": true,
        "action": action,
        "detail": detail,
    });
    write_output(
        writer,
        output,
        &value,
        format!("dry run: would {detail}"),
        "dry-run".to_string(),
    )
}

fn parse_json_arg(raw: &str, name: &str) -> Result<Value, CliError> {
    serde_json::from_str(raw)
        .map_err(|error| CliError::Usage(format!("{name} must be valid JSON: {error}")))
}

fn parse_optional_json_arg(raw: Option<String>, name: &str) -> Result<Option<Value>, CliError> {
    raw.map(|value| parse_json_arg(&value, name)).transpose()
}

fn write_list_output<T: Serialize>(
    writer: &mut impl Write,
    output: OutputMode,
    values: &[T],
    text: String,
) -> Result<(), CliError> {
    if output.is_pixel() {
        let rows = text
            .lines()
            .map(|line| vec![line.to_string()])
            .collect::<Vec<_>>();
        return write_text_line(
            writer,
            table(
                "ESSENCE CLI",
                "local control plane",
                &["items"],
                &rows,
                output.color,
            ),
        );
    }
    write_output(writer, output, &values, text, values.len().to_string())
}

fn render_session_created(session: &SessionMeta, output: OutputMode) -> String {
    let mut text = format!(
        "created session {}\ncwd: {}\nmode: {}\npermission: {}",
        session.session_id.0,
        session.cwd,
        json_name(&session.mode),
        json_name(&session.permission_mode)
    );
    if let Some(model) = &session.model {
        let _ = write!(text, "\nmodel: {model}");
    }
    if output.verbose > 0 {
        let _ = write!(text, "\ntranscript: {}", session.transcript_uri);
    }
    text
}

fn render_session_summary(session: &SessionMeta) -> String {
    format!(
        "{}  {}  {}",
        session.session_id.0,
        json_name(&session.status),
        session.title.as_deref().unwrap_or("(untitled)")
    )
}

fn render_sessions(sessions: &[SessionMeta]) -> String {
    if sessions.is_empty() {
        return "no sessions".to_string();
    }
    sessions
        .iter()
        .map(render_session_summary)
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_session_state(patch: &SessionStatePatch) -> String {
    let mut text = format!("session is {}", json_name(&patch.status));
    if let Some(title) = &patch.title {
        let _ = write!(text, "\ntitle: {title}");
    }
    text
}

fn render_runs(runs: &[RunMeta]) -> String {
    if runs.is_empty() {
        return "no runs".to_string();
    }
    runs.iter()
        .map(|run| {
            format!(
                "{}  {}  {}",
                run.run_id.0,
                json_name(&run.status),
                json_name(&run.trigger)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_tool_calls(tool_calls: &[ToolCallRecord]) -> String {
    if tool_calls.is_empty() {
        return "no tool calls".to_string();
    }
    tool_calls
        .iter()
        .map(|tool_call| {
            format!(
                "{}  {}  {}",
                tool_call.tool_call_id.0,
                json_name(&tool_call.status),
                tool_call.name
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_tasks(tasks: &[TaskRecord]) -> String {
    if tasks.is_empty() {
        return "no tasks".to_string();
    }
    tasks
        .iter()
        .map(|task| {
            let lane = task
                .lane_id
                .as_ref()
                .map(|lane| lane.0.as_str())
                .unwrap_or("-");
            let assignee = task
                .assignee
                .as_ref()
                .map(|agent| agent.0.as_str())
                .unwrap_or("-");
            format!(
                "{}  {}  {}  {}  {}",
                task.task_id.0,
                json_name(&task.status),
                lane,
                assignee,
                task.title
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_artifacts(artifacts: &[essence_core::ArtifactRecord]) -> String {
    if artifacts.is_empty() {
        return "no artifacts".to_string();
    }
    artifacts
        .iter()
        .map(|artifact| {
            format!(
                "{}  {}  {}",
                artifact.artifact_id.0, artifact.kind, artifact.uri
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_memories(memories: &[MemoryRecord]) -> String {
    if memories.is_empty() {
        return "no memories".to_string();
    }
    memories
        .iter()
        .map(|memory| {
            format!(
                "{}  {}  {}  {}",
                memory.memory_id.0,
                json_name(&memory.status),
                memory.kind,
                super::pixel_ui::truncate(&memory.text, 72)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_subagents(subagents: &[SubagentMeta]) -> String {
    if subagents.is_empty() {
        return "no subagents".to_string();
    }
    subagents
        .iter()
        .map(|subagent| {
            format!(
                "{}  {}  {}  {}",
                subagent.subagent_id.0,
                json_name(&subagent.status),
                subagent.lane_id.0,
                subagent.goal
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn emit_event_summaries(
    writer: &mut impl Write,
    events: &[EventEnvelope],
    quiet: bool,
) -> Result<(), CliError> {
    for event in events {
        if quiet {
            write_text_line(writer, event.seq.to_string())?;
        } else {
            write_text_line(
                writer,
                format!(
                    "#{:<5} {:<24} {}",
                    event.seq,
                    json_name(&event.event_type),
                    json_name(&event.source)
                ),
            )?;
        }
    }
    Ok(())
}

fn emit_ui_event_summaries(
    writer: &mut impl Write,
    events: &[UiEvent],
    quiet: bool,
) -> Result<(), CliError> {
    for event in events {
        if quiet {
            write_text_line(writer, event.seq.to_string())?;
        } else {
            write_text_line(
                writer,
                format!(
                    "#{:<5} {:<24} {}",
                    event.seq,
                    json_name(&event.event_type),
                    json_name(&event.source)
                ),
            )?;
        }
    }
    Ok(())
}

fn render_integrity_report(report: &WalIntegrityReport) -> String {
    if report.findings.is_empty() {
        format!(
            "WAL integrity ok: {} events, latest seq {}",
            report.event_count,
            report
                .latest_seq
                .map(|seq| seq.to_string())
                .unwrap_or_else(|| "none".to_string())
        )
    } else {
        format!(
            "WAL integrity failed: {} finding(s); rerun with --json for details",
            report.findings.len()
        )
    }
}

fn render_pending_approvals(approvals: &[ApprovalRequest]) -> String {
    if approvals.is_empty() {
        return "no pending approvals".to_string();
    }

    let mut text = format!("{} pending approval(s)", approvals.len());
    for approval in approvals {
        let _ = write!(
            text,
            "\n{}  {}  {}",
            approval.approval_id.0, approval.subject, approval.reason
        );
    }
    text
}

fn json_name<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(value)) => value,
        Ok(value) => value.to_string(),
        Err(_) => "unknown".to_string(),
    }
}

fn cli_approval_decision_name(value: CliApprovalDecision) -> &'static str {
    match value {
        CliApprovalDecision::ApproveOnce => "approve_once",
        CliApprovalDecision::ApproveSession => "approve_session",
        CliApprovalDecision::ApproveAlways => "approve_always",
        CliApprovalDecision::Deny => "deny",
    }
}

const THEME_FILE: &str = "theme.json";
const PLUGINS_FILE: &str = "plugins.json";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct StoredTheme {
    theme: Option<CliTheme>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct StoredPlugins {
    #[serde(default)]
    installed: Vec<String>,
}

pub(crate) fn configured_theme(root: &std::path::Path) -> Option<CliTheme> {
    fs::read_to_string(root.join(THEME_FILE))
        .ok()
        .and_then(|raw| serde_json::from_str::<StoredTheme>(&raw).ok())
        .and_then(|stored| stored.theme)
}

fn write_theme(root: &std::path::Path, theme: CliTheme) -> Result<std::path::PathBuf, CliError> {
    fs::create_dir_all(root)?;
    let path = root.join(THEME_FILE);
    let encoded = serde_json::to_vec_pretty(&StoredTheme { theme: Some(theme) })?;
    fs::write(&path, encoded)?;
    Ok(path)
}

fn read_plugins(root: &std::path::Path) -> Result<StoredPlugins, CliError> {
    let path = root.join(PLUGINS_FILE);
    if !path.exists() {
        return Ok(StoredPlugins::default());
    }
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

fn write_plugins(
    root: &std::path::Path,
    plugins: &StoredPlugins,
) -> Result<std::path::PathBuf, CliError> {
    fs::create_dir_all(root)?;
    let path = root.join(PLUGINS_FILE);
    fs::write(&path, serde_json::to_vec_pretty(plugins)?)?;
    Ok(path)
}

fn installed_plugin_manifests(root: &std::path::Path) -> Result<Vec<PluginManifest>, CliError> {
    let catalog = basic_plugin_catalog();
    read_plugins(root)?
        .installed
        .iter()
        .map(|id| catalog.plugin(id).cloned().map_err(CliError::from))
        .collect()
}

fn plugin_kind_matches(plugin: &PluginManifest, kind: CliPluginKind) -> bool {
    matches!(
        (kind, &plugin.kind),
        (CliPluginKind::ToolProvider, PluginKind::ToolProvider)
            | (CliPluginKind::CliHarness, PluginKind::CliHarness)
            | (CliPluginKind::BrowserDaemon, PluginKind::BrowserDaemon)
            | (CliPluginKind::ResearchRadar, PluginKind::ResearchRadar)
            | (CliPluginKind::MemoryBackend, PluginKind::MemoryBackend)
            | (CliPluginKind::UiShell, PluginKind::UiShell)
            | (CliPluginKind::RolePack, PluginKind::RolePack)
    )
}

fn list_sessions(control: &ControlPlane) -> Result<Vec<SessionMeta>, CliError> {
    let sessions_dir = control.root().join("sessions");
    if !sessions_dir.exists() {
        return Ok(Vec::new());
    }

    let mut sessions = Vec::new();
    for entry in fs::read_dir(sessions_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("jsonl") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|value| value.to_str()) else {
            continue;
        };
        let Ok(session_id) = parse_session_id(stem) else {
            continue;
        };
        let projection = control.projection(&session_id)?;
        if let Some(session) = projection.session {
            sessions.push(session);
        }
    }
    sessions.sort_by_key(|session| session.created_at);
    Ok(sessions)
}

fn projection_session(
    projection: &LedgerProjection,
    raw_session_id: &str,
) -> Result<SessionMeta, CliError> {
    projection
        .session
        .clone()
        .ok_or_else(|| CliError::MissingSession(raw_session_id.to_string()))
}

fn projection_run(projection: &LedgerProjection, raw_run_id: &str) -> Result<RunMeta, CliError> {
    let run_id = parse_run_id(raw_run_id)?;
    projection
        .runs
        .get(&run_id)
        .cloned()
        .ok_or_else(|| CliError::MissingRun(raw_run_id.to_string()))
}

fn projection_tool_call(
    projection: &LedgerProjection,
    raw_tool_call_id: &str,
) -> Result<ToolCallRecord, CliError> {
    let tool_call_id = parse_tool_call_id(raw_tool_call_id)?;
    projection
        .tool_calls
        .get(&tool_call_id)
        .cloned()
        .ok_or_else(|| CliError::MissingToolCall(raw_tool_call_id.to_string()))
}

fn projection_task(
    projection: &LedgerProjection,
    raw_task_id: &str,
) -> Result<TaskRecord, CliError> {
    let task_id = parse_task_id(raw_task_id)?;
    projection
        .tasks
        .get(&task_id)
        .cloned()
        .ok_or_else(|| CliError::MissingTask(raw_task_id.to_string()))
}

fn projection_artifact(
    projection: &LedgerProjection,
    raw_artifact_id: &str,
) -> Result<ArtifactRecord, CliError> {
    let artifact_id = parse_artifact_id(raw_artifact_id)?;
    projection
        .artifacts
        .get(&artifact_id)
        .cloned()
        .ok_or_else(|| CliError::MissingArtifact(raw_artifact_id.to_string()))
}

fn projection_memory(
    projection: &LedgerProjection,
    raw_memory_id: &str,
) -> Result<MemoryRecord, CliError> {
    let memory_id = parse_memory_id(raw_memory_id)?;
    projection
        .memories
        .get(&memory_id)
        .cloned()
        .ok_or_else(|| CliError::MissingMemory(raw_memory_id.to_string()))
}

fn projection_subagent(
    projection: &LedgerProjection,
    raw_subagent_id: &str,
) -> Result<SubagentMeta, CliError> {
    projection
        .subagents
        .get(raw_subagent_id)
        .cloned()
        .ok_or_else(|| CliError::MissingSubagent(raw_subagent_id.to_string()))
}

pub(crate) fn execute_session(
    control: &ControlPlane,
    args: SessionArgs,
    output: OutputMode,
    writer: &mut impl Write,
) -> Result<(), CliError> {
    match args.command {
        SessionCommand::Create(args) => {
            let cwd = match args.cwd {
                Some(path) => path,
                None => std::env::current_dir()?,
            };
            let mut request = CreateSessionRequest::interactive(path_to_string(&cwd)?);
            request.mode = args.mode.into();
            request.permission_mode = args.permission_mode.into();
            if let Some(title) = args.title {
                request = request.with_title(title);
            }
            if let Some(model) = args.model {
                request = request.with_model(model);
            }
            if output.dry_run {
                return write_dry_run(
                    writer,
                    output,
                    "session.create",
                    format!("create session for cwd {}", request.cwd),
                );
            }
            let session = control.create_session(request)?;
            write_output(
                writer,
                output,
                &session,
                render_session_created(&session, output),
                session.session_id.0.to_string(),
            )
        }
        SessionCommand::List(args) => {
            let mut sessions = list_sessions(control)?;
            if let Some(status) = args.status {
                let status: LifecycleStatus = status.into();
                sessions.retain(|session| session.status == status);
            }
            write_list_output(writer, output, &sessions, render_sessions(&sessions))
        }
        SessionCommand::Show(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let projection = control.projection(&session_id)?;
            if args.projection {
                write_output(
                    writer,
                    output,
                    &projection,
                    format!(
                        "projection {}: {} messages, {} tasks, {} runs",
                        session_id.0,
                        projection.messages.len(),
                        projection.tasks.len(),
                        projection.runs.len()
                    ),
                    projection.latest_seq.to_string(),
                )
            } else {
                let session = projection_session(&projection, &args.session_id)?;
                write_output(
                    writer,
                    output,
                    &session,
                    render_session_created(&session, output),
                    session.session_id.0.to_string(),
                )
            }
        }
        SessionCommand::Update(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let status: LifecycleStatus = args.status.into();
            if output.dry_run {
                return write_dry_run(
                    writer,
                    output,
                    "session.update",
                    format!("update session {} to {}", session_id.0, json_name(&status)),
                );
            }
            let patch = control.update_session_state(&session_id, status, args.title)?;
            write_output(
                writer,
                output,
                &patch,
                render_session_state(&patch),
                json_name(&patch.status),
            )
        }
        SessionCommand::Cancel(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            if output.dry_run {
                return write_dry_run(
                    writer,
                    output,
                    "session.cancel",
                    format!("cancel session {}", session_id.0),
                );
            }
            let patch = control.cancel_session(&session_id)?;
            write_output(
                writer,
                output,
                &patch,
                render_session_state(&patch),
                json_name(&patch.status),
            )
        }
    }
}

pub(crate) fn execute_message(
    control: &ControlPlane,
    args: MessageArgs,
    output: OutputMode,
    writer: &mut impl Write,
) -> Result<(), CliError> {
    match args.command {
        MessageCommand::Send(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            if output.dry_run {
                return write_dry_run(
                    writer,
                    output,
                    "message.send",
                    format!("record user message for session {}", session_id.0),
                );
            }
            let event = control.submit_user_message(&session_id, args.text)?;
            write_output(
                writer,
                output,
                &event,
                format!(
                    "recorded user message {} at seq {}",
                    event.event_id.0, event.seq
                ),
                event.event_id.0.to_string(),
            )
        }
    }
}

pub(crate) fn execute_run(
    control: &ControlPlane,
    args: RunArgs,
    output: OutputMode,
    writer: &mut impl Write,
) -> Result<(), CliError> {
    match args.command {
        RunCommand::Start(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let mut request = StartRunRequest::user(session_id.clone());
            request.trigger = args.trigger.into();
            request.parent_run_id = args
                .parent_run_id
                .as_deref()
                .map(parse_run_id)
                .transpose()?;
            request.lane_id = args.lane.map(LaneId);
            request.agent_id = args.agent_id.map(AgentId);
            request.model = args.model;
            request.input_message_ids = args
                .input_events
                .iter()
                .map(|event_id| parse_event_id(event_id))
                .collect::<Result<Vec<_>, _>>()?;
            if output.dry_run {
                return write_dry_run(
                    writer,
                    output,
                    "run.start",
                    format!("start run for session {}", session_id.0),
                );
            }
            let run = control.start_run(request)?;
            write_output(
                writer,
                output,
                &run,
                format!("started run {} ({})", run.run_id.0, json_name(&run.trigger)),
                run.run_id.0.to_string(),
            )
        }
        RunCommand::List(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let projection = control.projection(&session_id)?;
            let mut runs = projection.runs.values().cloned().collect::<Vec<_>>();
            if let Some(status) = args.status {
                let status: LifecycleStatus = status.into();
                runs.retain(|run| run.status == status);
            }
            runs.sort_by_key(|run| run.started_at);
            write_list_output(writer, output, &runs, render_runs(&runs))
        }
        RunCommand::Complete(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let projection = control.projection(&session_id)?;
            let run = projection_run(&projection, &args.run_id)?;
            let usage = parse_optional_json_arg(args.usage_json, "--usage-json")?;
            if output.dry_run {
                return write_dry_run(
                    writer,
                    output,
                    "run.complete",
                    format!("complete run {}", run.run_id.0),
                );
            }
            let completed = match args.stop_reason {
                Some(stop_reason) => {
                    control.complete_run_with_stop_reason(&run, usage, stop_reason)?
                }
                None => control.complete_run(&run, usage)?,
            };
            write_output(
                writer,
                output,
                &completed,
                format!("completed run {}", completed.run_id.0),
                json_name(&completed.status),
            )
        }
        RunCommand::Fail(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let run = projection_run(&control.projection(&session_id)?, &args.run_id)?;
            if output.dry_run {
                return write_dry_run(
                    writer,
                    output,
                    "run.fail",
                    format!("fail run {}", run.run_id.0),
                );
            }
            let failed = control.fail_run(&run, args.reason)?;
            write_output(
                writer,
                output,
                &failed,
                format!("failed run {}", failed.run_id.0),
                json_name(&failed.status),
            )
        }
        RunCommand::Cancel(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let run = projection_run(&control.projection(&session_id)?, &args.run_id)?;
            if output.dry_run {
                return write_dry_run(
                    writer,
                    output,
                    "run.cancel",
                    format!("cancel run {}", run.run_id.0),
                );
            }
            let cancelled = control.cancel_run(&run, args.reason)?;
            write_output(
                writer,
                output,
                &cancelled,
                format!("cancelled run {}", cancelled.run_id.0),
                json_name(&cancelled.status),
            )
        }
    }
}

pub(crate) fn execute_events(
    control: &ControlPlane,
    args: EventsArgs,
    output: OutputMode,
    writer: &mut impl Write,
) -> Result<(), CliError> {
    match args.command {
        EventsCommand::Tail(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let mut after_seq = args.after;
            loop {
                if args.user_visible {
                    let events =
                        control.ui_events_after(&session_id, EventCursor::after(after_seq))?;
                    if output.is_structured() {
                        emit_ui_events(writer, &events)?;
                    } else {
                        emit_ui_event_summaries(writer, &events, output.quiet)?;
                    }
                    if let Some(last) = events.last() {
                        after_seq = last.seq;
                    }
                } else {
                    let events = control.events_after(&session_id, after_seq)?;
                    if output.is_structured() {
                        emit_events(writer, &events)?;
                    } else {
                        emit_event_summaries(writer, &events, output.quiet)?;
                    }
                    if let Some(last) = events.last() {
                        after_seq = last.seq;
                    }
                }

                if !args.follow {
                    break;
                }
                thread::sleep(Duration::from_millis(args.interval_ms));
            }
            Ok(())
        }
        EventsCommand::Verify(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let report = control.verify_session_integrity(&session_id)?;
            write_output(
                writer,
                output,
                &report,
                render_integrity_report(&report),
                if report.findings.is_empty() {
                    "ok".to_string()
                } else {
                    "failed".to_string()
                },
            )
        }
        EventsCommand::AnchorWrite(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            if output.dry_run {
                return write_dry_run(
                    writer,
                    output,
                    "events.anchor-write",
                    format!(
                        "write WAL anchor `{}` for session {}",
                        args.key_id, session_id.0
                    ),
                );
            }
            let key = anchor_key_from_env(&args.key_env)?;
            let anchor = control.write_session_anchor(&session_id, args.key_id, key.as_bytes())?;
            write_output(
                writer,
                output,
                &anchor,
                format!(
                    "wrote WAL anchor {} at seq {}",
                    anchor.key_id,
                    anchor
                        .latest_seq
                        .map(|seq| seq.to_string())
                        .unwrap_or_else(|| "none".to_string())
                ),
                anchor.key_id.clone(),
            )
        }
        EventsCommand::AnchorVerify(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let key = anchor_key_from_env(&args.key_env)?;
            let verification = control.verify_session_anchor(&session_id, key.as_bytes())?;
            write_output(
                writer,
                output,
                &verification,
                format!(
                    "anchor verification {}",
                    if verification.is_valid() {
                        "ok"
                    } else {
                        "failed"
                    }
                ),
                if verification.is_valid() {
                    "ok".to_string()
                } else {
                    "failed".to_string()
                },
            )
        }
    }
}

fn builtin_tool_outcome_value(outcome: BuiltinToolOutcome) -> (Value, String, String) {
    match outcome {
        BuiltinToolOutcome::Executed { tool_call, output } => {
            let text = format!("executed tool {}", tool_call.tool_call_id.0);
            (
                json!({"status": "executed", "tool_call": tool_call, "output": output}),
                text,
                "executed".to_string(),
            )
        }
        BuiltinToolOutcome::RequiresApproval {
            tool_call,
            approval,
        } => {
            let text = format!(
                "tool {} requires approval {}",
                tool_call.tool_call_id.0, approval.approval_id.0
            );
            (
                json!({
                    "status": "requires_approval",
                    "tool_call": tool_call,
                    "approval": approval
                }),
                text,
                "requires-approval".to_string(),
            )
        }
        BuiltinToolOutcome::Denied { tool_call, reason } => {
            let text = format!("denied tool {}: {reason}", tool_call.tool_call_id.0);
            (
                json!({"status": "denied", "tool_call": tool_call, "reason": reason}),
                text,
                "denied".to_string(),
            )
        }
        BuiltinToolOutcome::Failed { tool_call, reason } => {
            let text = format!("failed tool {}: {reason}", tool_call.tool_call_id.0);
            (
                json!({"status": "failed", "tool_call": tool_call, "reason": reason}),
                text,
                "failed".to_string(),
            )
        }
    }
}

fn builtin_approval_outcome_value(outcome: BuiltinToolApprovalOutcome) -> (Value, String, String) {
    match outcome {
        BuiltinToolApprovalOutcome::Executed {
            approval,
            tool_call,
            output,
        } => (
            json!({
                "status": "executed",
                "approval": approval,
                "tool_call": tool_call,
                "output": output
            }),
            "resolved approval and executed tool".to_string(),
            "executed".to_string(),
        ),
        BuiltinToolApprovalOutcome::Denied {
            approval,
            tool_call,
            reason,
        } => (
            json!({
                "status": "denied",
                "approval": approval,
                "tool_call": tool_call,
                "reason": reason
            }),
            "resolved approval and denied tool".to_string(),
            "denied".to_string(),
        ),
        BuiltinToolApprovalOutcome::Failed {
            approval,
            tool_call,
            reason,
        } => (
            json!({
                "status": "failed",
                "approval": approval,
                "tool_call": tool_call,
                "reason": reason
            }),
            "resolved approval but tool failed".to_string(),
            "failed".to_string(),
        ),
    }
}

fn cli_harness_outcome_value(outcome: RecordedCliHarnessOutcome) -> (Value, String, String) {
    match outcome {
        RecordedCliHarnessOutcome::Executed {
            tool_call,
            command,
            result,
        } => (
            json!({
                "status": "executed",
                "tool_call": tool_call,
                "command": command,
                "result": result
            }),
            "executed harness tool".to_string(),
            "executed".to_string(),
        ),
        RecordedCliHarnessOutcome::RequiresApproval {
            tool_call,
            approval,
            command,
        } => (
            json!({
                "status": "requires_approval",
                "tool_call": tool_call,
                "approval": approval,
                "command": command
            }),
            "harness tool requires approval".to_string(),
            "requires-approval".to_string(),
        ),
        RecordedCliHarnessOutcome::Denied {
            tool_call,
            command,
            reason,
        } => (
            json!({
                "status": "denied",
                "tool_call": tool_call,
                "command": command,
                "reason": reason
            }),
            "denied harness tool".to_string(),
            "denied".to_string(),
        ),
    }
}

fn cli_harness_approval_outcome_value(
    outcome: RecordedCliHarnessApprovalOutcome,
) -> (Value, String, String) {
    match outcome {
        RecordedCliHarnessApprovalOutcome::Executed {
            approval,
            tool_call,
            command,
            result,
        } => (
            json!({
                "status": "executed",
                "approval": approval,
                "tool_call": tool_call,
                "command": command,
                "result": result
            }),
            "resolved approval and executed harness tool".to_string(),
            "executed".to_string(),
        ),
        RecordedCliHarnessApprovalOutcome::Denied {
            approval,
            tool_call,
            command,
            reason,
        } => (
            json!({
                "status": "denied",
                "approval": approval,
                "tool_call": tool_call,
                "command": command,
                "reason": reason
            }),
            "resolved approval and denied harness tool".to_string(),
            "denied".to_string(),
        ),
    }
}

fn is_builtin_tool_subject(subject: &str) -> bool {
    builtin_tool_specs().iter().any(|tool| tool.name == subject)
}

fn is_gitnexus_tool_subject(subject: &str) -> bool {
    subject.starts_with("gitnexus.")
}

pub(crate) fn execute_tool(
    control: &ControlPlane,
    args: ToolArgs,
    output: OutputMode,
    writer: &mut impl Write,
) -> Result<(), CliError> {
    match args.command {
        ToolCommand::Specs(args) => {
            let mut specs = builtin_tool_specs();
            if args.plugins {
                for plugin in installed_plugin_manifests(control.root())? {
                    specs.extend(plugin.tools);
                }
            }
            write_list_output(
                writer,
                output,
                &specs,
                if specs.is_empty() {
                    "no tool specs".to_string()
                } else {
                    specs
                        .iter()
                        .map(|spec| format!("{}  {:?}", spec.name, spec.permission))
                        .collect::<Vec<_>>()
                        .join("\n")
                },
            )
        }
        ToolCommand::Start(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let input = parse_json_arg(&args.input_json, "--input-json")?;
            let mut request = StartToolCallRequest::new(session_id.clone(), args.name, input);
            if let Some(run_id) = args.run_id {
                let run = projection_run(&control.projection(&session_id)?, &run_id)?;
                request = request.for_run(&run);
            }
            if output.dry_run {
                return write_dry_run(
                    writer,
                    output,
                    "tool.start",
                    format!("start tool call for session {}", session_id.0),
                );
            }
            let tool_call = control.start_tool_call(request)?;
            write_output(
                writer,
                output,
                &tool_call,
                format!(
                    "started tool {} {}",
                    tool_call.name, tool_call.tool_call_id.0
                ),
                tool_call.tool_call_id.0.to_string(),
            )
        }
        ToolCommand::List(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let projection = control.projection(&session_id)?;
            let mut tool_calls = projection.tool_calls.values().cloned().collect::<Vec<_>>();
            if let Some(status) = args.status {
                let status: LifecycleStatus = status.into();
                tool_calls.retain(|tool_call| tool_call.status == status);
            }
            tool_calls.sort_by_key(|tool_call| tool_call.started_at);
            write_list_output(writer, output, &tool_calls, render_tool_calls(&tool_calls))
        }
        ToolCommand::Complete(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let projection = control.projection(&session_id)?;
            let tool_call = projection_tool_call(&projection, &args.tool_call_id)?;
            let value = parse_json_arg(&args.output_json, "--output-json")?;
            if output.dry_run {
                return write_dry_run(
                    writer,
                    output,
                    "tool.complete",
                    format!("complete tool call {}", tool_call.tool_call_id.0),
                );
            }
            let completed = control.complete_tool_call(&tool_call, value)?;
            write_output(
                writer,
                output,
                &completed,
                format!("completed tool call {}", completed.tool_call_id.0),
                json_name(&completed.status),
            )
        }
        ToolCommand::Fail(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let projection = control.projection(&session_id)?;
            let tool_call = projection_tool_call(&projection, &args.tool_call_id)?;
            if output.dry_run {
                return write_dry_run(
                    writer,
                    output,
                    "tool.fail",
                    format!("fail tool call {}", tool_call.tool_call_id.0),
                );
            }
            let failed = control.fail_tool_call(&tool_call, args.error)?;
            write_output(
                writer,
                output,
                &failed,
                format!("failed tool call {}", failed.tool_call_id.0),
                json_name(&failed.status),
            )
        }
        ToolCommand::Run(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let input = parse_json_arg(&args.input_json, "--input-json")?;
            let mut request = BuiltinToolRequest::new(session_id.clone(), args.name, input);
            if let Some(run_id) = args.run_id {
                let run = projection_run(&control.projection(&session_id)?, &run_id)?;
                request = request.for_run(&run);
            }
            if let Some(cwd) = args.cwd {
                request = request.with_cwd(cwd);
            }
            if output.dry_run {
                return write_dry_run(
                    writer,
                    output,
                    "tool.run",
                    format!("run built-in tool for session {}", session_id.0),
                );
            }
            let executor = BuiltinToolExecutor::for_mode(
                control.clone(),
                PermissionMode::from(args.permission_mode),
            );
            let (value, text, quiet) = builtin_tool_outcome_value(executor.run_tool(request)?);
            write_output(writer, output, &value, text, quiet)
        }
    }
}

pub(crate) fn execute_approval(
    control: &ControlPlane,
    args: ApprovalArgs,
    output: OutputMode,
    writer: &mut impl Write,
) -> Result<(), CliError> {
    match args.command {
        ApprovalCommand::Request(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let input = parse_json_arg(&args.input_json, "--input-json")?;
            let mut request =
                RequestApprovalRequest::new(session_id.clone(), args.subject, input, args.reason);
            if let Some(run_id) = args.run_id {
                request = request.for_run(parse_run_id(&run_id)?);
            }
            if let Some(tool_call_id) = args.tool_call_id {
                request = request.for_tool_call(parse_tool_call_id(&tool_call_id)?);
            }
            if let Some(cwd) = args.cwd {
                request = request.with_cwd(cwd);
            }
            if !args.allowed_decisions.is_empty() {
                request = request.with_allowed_decisions(
                    args.allowed_decisions
                        .into_iter()
                        .map(ApprovalDecision::from)
                        .collect(),
                );
            }
            if output.dry_run {
                return write_dry_run(
                    writer,
                    output,
                    "approval.request",
                    format!("request approval for session {}", session_id.0),
                );
            }
            let approval = control.request_approval(request)?;
            write_output(
                writer,
                output,
                &approval,
                format!("requested approval {}", approval.approval_id.0),
                approval.approval_id.0.to_string(),
            )
        }
        ApprovalCommand::Pending(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let approvals = control.pending_approvals(&session_id)?;
            write_output(
                writer,
                output,
                &approvals,
                render_pending_approvals(&approvals),
                approvals.len().to_string(),
            )
        }
        ApprovalCommand::Resolve(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let approval_id = parse_approval_id(&args.approval_id)?;
            if output.dry_run {
                return write_dry_run(
                    writer,
                    output,
                    "approval.resolve",
                    format!(
                        "resolve approval {} as {}",
                        approval_id.0,
                        cli_approval_decision_name(args.decision)
                    ),
                );
            }
            let projection = control.projection(&session_id)?;
            let approval = projection
                .approvals
                .get(&approval_id)
                .ok_or_else(|| CliError::MissingApproval(args.approval_id.clone()))?;
            if is_builtin_tool_subject(&approval.subject) && approval.tool_call_id.is_some() {
                let executor =
                    BuiltinToolExecutor::for_mode(control.clone(), PermissionMode::Default);
                let (value, text, quiet) = builtin_approval_outcome_value(
                    executor.resolve_approval(approval, args.decision.into(), args.resolved_by)?,
                );
                return write_output(writer, output, &value, text, quiet);
            }
            if is_gitnexus_tool_subject(&approval.subject) && approval.tool_call_id.is_some() {
                let (value, text, quiet) =
                    cli_harness_approval_outcome_value(control.resolve_cli_harness_approval(
                        approval,
                        args.decision.into(),
                        args.resolved_by,
                    )?);
                return write_output(writer, output, &value, text, quiet);
            }
            let resolved =
                control.resolve_approval(approval, args.decision.into(), args.resolved_by)?;
            write_output(
                writer,
                output,
                &resolved,
                format!(
                    "resolved approval {} as {}",
                    resolved.approval_id.0,
                    json_name(&resolved.decision)
                ),
                resolved.approval_id.0.to_string(),
            )
        }
    }
}

pub(crate) fn execute_agent(
    control: &ControlPlane,
    args: AgentArgs,
    output: OutputMode,
    writer: &mut impl Write,
) -> Result<(), CliError> {
    match args.command {
        AgentCommand::Register(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let mut request =
                RegisterAgentRequest::new(session_id.clone(), args.agent_id, args.lane, args.role);
            for toolset in args.toolsets {
                request = request.with_toolset(toolset);
            }
            if output.dry_run {
                return write_dry_run(
                    writer,
                    output,
                    "agent.register",
                    format!(
                        "register agent {} for session {}",
                        request.agent_id.0, session_id.0
                    ),
                );
            }
            let agent = control.register_agent(request)?;
            write_output(
                writer,
                output,
                &agent,
                format!(
                    "registered agent {} on lane {}",
                    agent.agent_id.0, agent.lane_id.0
                ),
                agent.agent_id.0.clone(),
            )
        }
        AgentCommand::Heartbeat(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let mut request =
                AgentHeartbeatRequest::new(session_id.clone(), args.agent_id, args.status.into());
            if let Some(lane) = args.lane {
                request = request.with_lane(lane);
            }
            if let Some(run_id) = args.run_id {
                request = request.with_run(parse_run_id(&run_id)?);
            }
            if let Some(task_id) = args.task_id {
                request = request.with_task(parse_task_id(&task_id)?);
            }
            if let Some(note) = args.note {
                request = request.with_note(note);
            }
            if output.dry_run {
                return write_dry_run(
                    writer,
                    output,
                    "agent.heartbeat",
                    format!(
                        "record heartbeat for agent {} in session {}",
                        request.agent_id.0, session_id.0
                    ),
                );
            }
            let heartbeat = control.record_agent_heartbeat(request)?;
            write_output(
                writer,
                output,
                &heartbeat,
                format!(
                    "agent {} is {}",
                    heartbeat.agent_id.0,
                    json_name(&heartbeat.status)
                ),
                heartbeat.agent_id.0.clone(),
            )
        }
        AgentCommand::Define(args) => execute_agent_define(control, args, output, writer),
        AgentCommand::Profiles(args) => {
            let profiles = list_agent_profiles(control.root())?;
            let rendered = render_agent_profiles(&profiles, output.color && !args.no_color);
            writer.write_all(rendered.as_bytes())?;
            Ok(())
        }
        AgentCommand::Templates(args) => {
            let rendered = render_agent_templates(&args, output.color && !args.no_color)?;
            writer.write_all(rendered.as_bytes())?;
            Ok(())
        }
    }
}

fn execute_agent_define(
    control: &ControlPlane,
    mut args: AgentDefineArgs,
    output: OutputMode,
    writer: &mut impl Write,
) -> Result<(), CliError> {
    let color = output.color && !args.no_color;
    let requested_save = args.save;
    if output.dry_run {
        args.save = false;
    }
    let template = resolve_template_for_define(&args)?;
    let role = match &template {
        Some(template) if args.role == "Custom Agent" => template.role.clone(),
        _ => args.role.clone(),
    };
    let lane = match &template {
        Some(template) if args.lane == "main" => template.lane.clone(),
        _ => args.lane.clone(),
    };
    let mut profile = StoredAgentProfile::new(args.agent_id.clone(), role, lane);
    profile.system_prompt = non_empty(args.system_prompt)
        .or_else(|| template.as_ref().map(|template| template.prompt.clone()));
    profile.system_prompt_file = args
        .system_prompt_file
        .as_ref()
        .map(|path| path_to_string(path))
        .transpose()?
        .and_then(|value| non_empty(Some(value)));
    profile.provider = args
        .model_provider
        .map(|provider| provider_slug(provider).to_string());
    profile.model = non_empty(args.model);
    profile.base_url = non_empty(args.model_base_url);
    profile.api_key_env = non_empty(args.model_api_key_env);
    profile.command = non_empty(args.model_command);
    profile.template_id = template.as_ref().map(|template| template.id.clone());

    let saved_path = if args.save {
        Some(write_agent_profile(control.root(), &profile)?)
    } else {
        None
    };
    let rendered = render_agent_profile(&profile, template.as_ref(), saved_path.as_ref(), color);
    writer.write_all(rendered.as_bytes())?;
    if output.dry_run && requested_save {
        write_text_line(writer, "dry run: no agent profile written")?;
    }
    Ok(())
}

fn render_agent_profile(
    profile: &StoredAgentProfile,
    template: Option<&AgencyAgentTemplate>,
    saved_path: Option<&std::path::PathBuf>,
    color: bool,
) -> String {
    let mut output = String::new();
    let ice = style(color, "ice");
    let dim = style(color, "dim");
    let reset = reset(color);
    let prompt_state = if profile.system_prompt.is_some() || profile.system_prompt_file.is_some() {
        status_chip(color, "PROMPT READY", "green")
    } else {
        status_chip(color, "NO PROMPT", "yellow")
    };
    let model = profile.model.as_deref().unwrap_or("global default");
    let provider = profile.provider.as_deref().unwrap_or("global default");

    output.push_str(&brand_header(
        "ESSENCE AGENT PROFILE",
        "custom agent cartridge",
        color,
    ));
    let _ = writeln!(output, "{}", row(color, format!("{ice}identity{reset}")));
    let _ = writeln!(
        output,
        "{}",
        row(color, key_value(color, "agent", &profile.agent_id))
    );
    let _ = writeln!(
        output,
        "{}",
        row(color, key_value(color, "role", &profile.role))
    );
    let _ = writeln!(
        output,
        "{}",
        row(color, key_value(color, "lane", &profile.lane))
    );
    if let Some(template) = template {
        let _ = writeln!(
            output,
            "{}",
            row(color, key_value(color, "template", &template.id))
        );
        let _ = writeln!(
            output,
            "{}",
            row(
                color,
                key_value(color, "source", "Agency Agents bundled library")
            )
        );
    } else if let Some(template_id) = &profile.template_id {
        let _ = writeln!(
            output,
            "{}",
            row(color, key_value(color, "template", template_id))
        );
    }
    let _ = writeln!(output, "{}", mid(color));
    let _ = writeln!(
        output,
        "{}",
        row(color, format!("{ice}behavior{reset} {prompt_state}"))
    );
    if let Some(prompt_file) = &profile.system_prompt_file {
        let _ = writeln!(
            output,
            "{}",
            row(color, key_value(color, "prompt file", prompt_file))
        );
    } else if let Some(prompt) = &profile.system_prompt {
        let preview = super::pixel_ui::truncate(prompt, 54);
        let _ = writeln!(
            output,
            "{}",
            row(color, key_value(color, "prompt", &preview))
        );
    }
    let _ = writeln!(output, "{}", mid(color));
    let _ = writeln!(
        output,
        "{}",
        row(color, format!("{ice}model override{reset}"))
    );
    let _ = writeln!(
        output,
        "{}",
        row(color, key_value(color, "provider", provider))
    );
    let _ = writeln!(output, "{}", row(color, key_value(color, "model", model)));
    if let Some(base_url) = &profile.base_url {
        let _ = writeln!(
            output,
            "{}",
            row(color, key_value(color, "base url", base_url))
        );
    }
    if let Some(api_key_env) = &profile.api_key_env {
        let _ = writeln!(
            output,
            "{}",
            row(color, key_value(color, "api key env", api_key_env))
        );
    }
    if let Some(command) = &profile.command {
        let preview = super::pixel_ui::truncate(command, 54);
        let _ = writeln!(
            output,
            "{}",
            row(color, key_value(color, "command", &preview))
        );
    }
    let _ = writeln!(output, "{}", mid(color));
    if let Some(path) = saved_path {
        let _ = writeln!(
            output,
            "{}",
            row(color, format!("{ice}saved{reset} {}", path.display()))
        );
    } else {
        let _ = writeln!(
            output,
            "{}",
            row(
                color,
                format!("{dim}preview only; add --save to write .essence/agents/<id>.json{reset}")
            )
        );
    }
    let _ = writeln!(
        output,
        "{}",
        row(
            color,
            format!("run: essence chat --agent {}", profile.agent_id)
        )
    );
    output
}

fn render_agent_profiles(profiles: &[StoredAgentProfile], color: bool) -> String {
    let mut output = String::new();
    output.push_str(&brand_header(
        "ESSENCE AGENT PROFILES",
        "saved custom agents",
        color,
    ));
    if profiles.is_empty() {
        let _ = writeln!(
            output,
            "{}",
            row(
                color,
                "no profiles yet; use `essence agent define --agent-id researcher --save`"
            )
        );
        return output;
    }
    let _ = writeln!(
        output,
        "{}",
        row(
            color,
            "agent                lane             role                 template/prompt"
        )
    );
    let _ = writeln!(output, "{}", mid(color));
    for profile in profiles {
        let prompt = if let Some(template_id) = &profile.template_id {
            super::pixel_ui::truncate(template_id, 12)
        } else if profile.system_prompt.is_some() || profile.system_prompt_file.is_some() {
            status_chip(color, "ready", "green")
        } else {
            status_chip(color, "empty", "yellow")
        };
        let _ = writeln!(
            output,
            "{}",
            row(
                color,
                format!(
                    "{agent:<20} {lane:<16} {role:<20} {prompt}",
                    agent = super::pixel_ui::truncate(&profile.agent_id, 20),
                    lane = super::pixel_ui::truncate(&profile.lane, 16),
                    role = super::pixel_ui::truncate(&profile.role, 20),
                )
            )
        );
    }
    output
}

fn render_agent_templates(args: &AgentTemplatesArgs, color: bool) -> Result<String, CliError> {
    let mut templates = search_agent_templates(args.query.as_deref(), args.category.as_deref())?;
    templates.truncate(args.limit);

    let mut output = String::new();
    output.push_str(&brand_header(
        "ESSENCE AGENT TEMPLATES",
        "Agency Agents bundled library",
        color,
    ));
    let _ = writeln!(
        output,
        "{}",
        row(color, format!("showing {} templates", templates.len()))
    );
    let _ = writeln!(
        output,
        "{}",
        row(
            color,
            "use: agent define --agent-id <id> --template <id> --save"
        )
    );
    let _ = writeln!(output, "{}", mid(color));
    let _ = writeln!(
        output,
        "{}",
        row(
            color,
            "template id                         category        name"
        )
    );
    let _ = writeln!(output, "{}", mid(color));
    for template in templates {
        let _ = writeln!(
            output,
            "{}",
            row(
                color,
                format!(
                    "{id:<35} {category:<15} {name}",
                    id = super::pixel_ui::truncate(&template.id, 35),
                    category = super::pixel_ui::truncate(&template.category, 15),
                    name = super::pixel_ui::truncate(&template.name, 22),
                )
            )
        );
    }
    Ok(output)
}

fn resolve_template_for_define(
    args: &AgentDefineArgs,
) -> Result<Option<AgencyAgentTemplate>, CliError> {
    if let Some(template_id) = args.template.as_deref() {
        return find_agent_template(template_id)?
            .map(Some)
            .ok_or_else(|| CliError::MissingAgentTemplate(template_id.to_string()));
    }
    if args.system_prompt.is_none() && args.system_prompt_file.is_none() {
        return Ok(find_agent_template(&args.agent_id)?);
    }
    Ok(None)
}

pub(crate) fn execute_task(
    control: &ControlPlane,
    args: TaskArgs,
    output: OutputMode,
    writer: &mut impl Write,
) -> Result<(), CliError> {
    match args.command {
        TaskCommand::Create(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let mut request = CreateTaskRequest::new(session_id.clone(), args.title)
                .with_status(args.status.into());
            if let Some(lane) = args.lane {
                request = request.with_lane(lane);
            }
            if let Some(assignee) = args.assignee {
                request = request.with_assignee(assignee);
            }
            if output.dry_run {
                return write_dry_run(
                    writer,
                    output,
                    "task.create",
                    format!(
                        "create task `{}` for session {}",
                        request.title, session_id.0
                    ),
                );
            }
            let task = control.create_task(request)?;
            write_output(
                writer,
                output,
                &task,
                format!("created task {}: {}", task.task_id.0, task.title),
                task.task_id.0.to_string(),
            )
        }
        TaskCommand::List(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let store = control.task_store(&session_id)?;
            let mut tasks = store.iter().cloned().collect::<Vec<_>>();
            if let Some(status) = args.status {
                let status: LifecycleStatus = status.into();
                tasks.retain(|task| task.status == status);
            }
            if let Some(lane) = args.lane {
                tasks.retain(|task| task.lane_id.as_ref().is_some_and(|value| value.0 == lane));
            }
            if let Some(assignee) = args.assignee {
                tasks.retain(|task| {
                    task.assignee
                        .as_ref()
                        .is_some_and(|value| value.0 == assignee)
                });
            }
            tasks.sort_by_key(|task| task.created_at);
            write_list_output(writer, output, &tasks, render_tasks(&tasks))
        }
        TaskCommand::Update(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let task_id = parse_task_id(&args.task_id)?;
            let patch = TaskPatch {
                task_id,
                title: args.title,
                status: args.status.map(LifecycleStatus::from),
                updated_at: Some(time::OffsetDateTime::now_utc()),
                assignee: args.assignee.map(AgentId),
                metadata: Default::default(),
            };
            if output.dry_run {
                return write_dry_run(
                    writer,
                    output,
                    "task.update",
                    format!("update task {}", patch.task_id.0),
                );
            }
            let patch = control.update_task(&session_id, patch)?;
            write_output(
                writer,
                output,
                &patch,
                format!("updated task {}", patch.task_id.0),
                patch.task_id.0.to_string(),
            )
        }
        TaskCommand::Complete(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let task = projection_task(&control.projection(&session_id)?, &args.task_id)?;
            if output.dry_run {
                return write_dry_run(
                    writer,
                    output,
                    "task.complete",
                    format!("complete task {}", task.task_id.0),
                );
            }
            let patch = control.complete_task(&task)?;
            write_output(
                writer,
                output,
                &patch,
                format!("completed task {}", patch.task_id.0),
                patch.task_id.0.to_string(),
            )
        }
        TaskCommand::Claim(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            if output.dry_run {
                return write_dry_run(
                    writer,
                    output,
                    "task.claim",
                    format!("claim next task for {}", args.assignee),
                );
            }
            let patch = control.claim_next_task(&session_id, args.assignee)?;
            write_output(
                writer,
                output,
                &patch,
                match &patch {
                    Some(patch) => format!("claimed task {}", patch.task_id.0),
                    None => "no queued tasks".to_string(),
                },
                patch
                    .as_ref()
                    .map(|patch| patch.task_id.0.to_string())
                    .unwrap_or_else(|| "none".to_string()),
            )
        }
    }
}

pub(crate) fn execute_artifact(
    control: &ControlPlane,
    args: ArtifactArgs,
    output: OutputMode,
    writer: &mut impl Write,
) -> Result<(), CliError> {
    match args.command {
        ArtifactCommand::Create(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let mut request = CreateArtifactRequest::new(session_id.clone(), args.uri, args.kind);
            if let Some(task_id) = args.task_id {
                request = request.for_task(parse_task_id(&task_id)?);
            }
            if let Some(run_id) = args.run_id {
                request = request.for_run(parse_run_id(&run_id)?);
            }
            if output.dry_run {
                return write_dry_run(
                    writer,
                    output,
                    "artifact.create",
                    format!("create artifact for session {}", session_id.0),
                );
            }
            let artifact = control.create_artifact(request)?;
            write_output(
                writer,
                output,
                &artifact,
                format!(
                    "created artifact {}: {}",
                    artifact.artifact_id.0, artifact.uri
                ),
                artifact.artifact_id.0.to_string(),
            )
        }
        ArtifactCommand::List(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let projection = control.projection(&session_id)?;
            let mut artifacts = projection.artifacts.values().cloned().collect::<Vec<_>>();
            if let Some(kind) = args.kind {
                artifacts.retain(|artifact| artifact.kind == kind);
            }
            artifacts.sort_by_key(|artifact| artifact.created_at);
            write_list_output(writer, output, &artifacts, render_artifacts(&artifacts))
        }
        ArtifactCommand::Show(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let artifact =
                projection_artifact(&control.projection(&session_id)?, &args.artifact_id)?;
            write_output(
                writer,
                output,
                &artifact,
                format!("artifact {}: {}", artifact.artifact_id.0, artifact.uri),
                artifact.artifact_id.0.to_string(),
            )
        }
    }
}

fn build_memory_request(
    session_id: essence_core::SessionId,
    kind: String,
    text: String,
    run_id: Option<String>,
    source_events: Vec<String>,
    confidence: Option<f32>,
) -> Result<ProposeMemoryRequest, CliError> {
    let mut request = ProposeMemoryRequest::new(session_id, kind, text);
    if let Some(run_id) = run_id {
        request = request.for_run(parse_run_id(&run_id)?);
    }
    for event_id in source_events {
        request = request.with_source_event(parse_event_id(&event_id)?);
    }
    if let Some(confidence) = confidence {
        request = request.with_confidence(confidence);
    }
    Ok(request)
}

pub(crate) fn execute_memory(
    control: &ControlPlane,
    args: MemoryArgs,
    output: OutputMode,
    writer: &mut impl Write,
) -> Result<(), CliError> {
    match args.command {
        MemoryCommand::Propose(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let request = build_memory_request(
                session_id.clone(),
                args.kind,
                args.text,
                args.run_id,
                args.source_events,
                args.confidence,
            )?;
            if output.dry_run {
                return write_dry_run(
                    writer,
                    output,
                    "memory.propose",
                    format!("propose memory for session {}", session_id.0),
                );
            }
            let memory = control.propose_memory(request)?;
            write_output(
                writer,
                output,
                &memory,
                format!("proposed memory {}", memory.memory_id.0),
                memory.memory_id.0.to_string(),
            )
        }
        MemoryCommand::Save(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let memory = projection_memory(&control.projection(&session_id)?, &args.memory_id)?;
            if output.dry_run {
                return write_dry_run(
                    writer,
                    output,
                    "memory.save",
                    format!("save memory {}", memory.memory_id.0),
                );
            }
            let saved = control.save_memory(&memory)?;
            write_output(
                writer,
                output,
                &saved,
                format!("saved memory {}", saved.memory_id.0),
                saved.memory_id.0.to_string(),
            )
        }
        MemoryCommand::Remember(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let request = build_memory_request(
                session_id.clone(),
                args.kind,
                args.text,
                args.run_id,
                args.source_events,
                args.confidence,
            )?;
            if output.dry_run {
                return write_dry_run(
                    writer,
                    output,
                    "memory.remember",
                    format!("save new memory for session {}", session_id.0),
                );
            }
            let candidate = control.propose_memory(request)?;
            let saved = control.save_memory(&candidate)?;
            write_output(
                writer,
                output,
                &saved,
                format!("remembered memory {}", saved.memory_id.0),
                saved.memory_id.0.to_string(),
            )
        }
        MemoryCommand::List(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let store = control.memory_store(&session_id)?;
            let mut memories = if args.saved {
                store.saved().cloned().collect::<Vec<_>>()
            } else {
                store.iter().cloned().collect::<Vec<_>>()
            };
            if let Some(kind) = args.kind {
                memories.retain(|memory| memory.kind == kind);
            }
            memories.sort_by_key(|memory| memory.created_at);
            write_list_output(writer, output, &memories, render_memories(&memories))
        }
        MemoryCommand::Search(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let store = control.memory_store(&session_id)?;
            let index = MemoryIndex::from_store(&store);
            let hits = index.search(&args.query, args.limit);
            let text = if hits.is_empty() {
                "no memory hits".to_string()
            } else {
                hits.iter()
                    .map(|hit| {
                        format!(
                            "{:.3}  {}  {}",
                            hit.score,
                            hit.memory.memory_id.0,
                            super::pixel_ui::truncate(&hit.memory.text, 64)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            write_list_output(writer, output, &hits, text)
        }
    }
}

pub(crate) fn execute_subagent(
    control: &ControlPlane,
    args: SubagentArgs,
    output: OutputMode,
    writer: &mut impl Write,
) -> Result<(), CliError> {
    match args.command {
        SubagentCommand::Spawn(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let run = projection_run(&control.projection(&session_id)?, &args.run_id)?;
            let mut request =
                SpawnSubagentRequest::native(session_id.clone(), &run, args.lane, args.goal)
                    .with_isolation(args.isolation.into());
            if let Some(subagent_id) = args.subagent_id {
                request = request.with_subagent_id(subagent_id);
            }
            for context_ref in args.context_refs {
                request = request.with_context_ref(context_ref);
            }
            for toolset in args.toolsets {
                request = request.with_toolset(toolset);
            }
            if args.max_turns.is_some()
                || args.max_tool_calls.is_some()
                || args.max_tokens.is_some()
            {
                request = request.with_budget(SubagentBudget {
                    max_turns: args.max_turns,
                    max_tool_calls: args.max_tool_calls,
                    max_tokens: args.max_tokens,
                });
            }
            if output.dry_run {
                return write_dry_run(
                    writer,
                    output,
                    "subagent.spawn",
                    format!("spawn subagent for run {}", run.run_id.0),
                );
            }
            let subagent = control.spawn_subagent(request)?;
            write_output(
                writer,
                output,
                &subagent,
                format!("spawned subagent {}", subagent.subagent_id.0),
                subagent.subagent_id.0.to_string(),
            )
        }
        SubagentCommand::List(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let projection = control.projection(&session_id)?;
            let mut subagents = projection.subagents.values().cloned().collect::<Vec<_>>();
            if let Some(status) = args.status {
                let status: LifecycleStatus = status.into();
                subagents.retain(|subagent| subagent.status == status);
            }
            subagents.sort_by_key(|subagent| subagent.subagent_id.clone());
            write_list_output(writer, output, &subagents, render_subagents(&subagents))
        }
        SubagentCommand::Progress(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let subagent =
                projection_subagent(&control.projection(&session_id)?, &args.subagent_id)?;
            if output.dry_run {
                return write_dry_run(
                    writer,
                    output,
                    "subagent.progress",
                    format!("update subagent {}", subagent.subagent_id.0),
                );
            }
            let updated = control.update_subagent_progress(&subagent, args.status.into())?;
            write_output(
                writer,
                output,
                &updated,
                format!(
                    "subagent {} is {}",
                    updated.subagent_id.0,
                    json_name(&updated.status)
                ),
                json_name(&updated.status),
            )
        }
        SubagentCommand::Steer(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let subagent =
                projection_subagent(&control.projection(&session_id)?, &args.subagent_id)?;
            let mut request = SteerSubagentRequest::new();
            if let Some(goal) = args.goal {
                request = request.with_goal(goal);
            }
            for context_ref in args.context_refs {
                request = request.with_context_ref(context_ref);
            }
            for toolset in args.toolsets {
                request = request.with_toolset(toolset);
            }
            if output.dry_run {
                return write_dry_run(
                    writer,
                    output,
                    "subagent.steer",
                    format!("steer subagent {}", subagent.subagent_id.0),
                );
            }
            let steered = control.steer_subagent(&subagent, request)?;
            write_output(
                writer,
                output,
                &steered,
                format!("steered subagent {}", steered.subagent_id.0),
                steered.subagent_id.0.to_string(),
            )
        }
        SubagentCommand::Complete(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let subagent =
                projection_subagent(&control.projection(&session_id)?, &args.subagent_id)?;
            let usage = parse_optional_json_arg(args.usage_json, "--usage-json")?;
            if output.dry_run {
                return write_dry_run(
                    writer,
                    output,
                    "subagent.complete",
                    format!("complete subagent {}", subagent.subagent_id.0),
                );
            }
            let completed =
                if args.summary.is_some() || !args.artifact_refs.is_empty() || usage.is_some() {
                    control.complete_subagent_with_result(
                        &subagent,
                        SubagentResult {
                            summary: args.summary.unwrap_or_default(),
                            artifact_refs: args.artifact_refs,
                            usage,
                            error: None,
                        },
                    )?
                } else {
                    control.complete_subagent(&subagent)?
                };
            write_output(
                writer,
                output,
                &completed,
                format!("completed subagent {}", completed.subagent_id.0),
                json_name(&completed.status),
            )
        }
        SubagentCommand::Fail(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let subagent =
                projection_subagent(&control.projection(&session_id)?, &args.subagent_id)?;
            if output.dry_run {
                return write_dry_run(
                    writer,
                    output,
                    "subagent.fail",
                    format!("fail subagent {}", subagent.subagent_id.0),
                );
            }
            let failed = match args.error {
                Some(error) => control.fail_subagent_with_error(&subagent, error)?,
                None => control.fail_subagent(&subagent)?,
            };
            write_output(
                writer,
                output,
                &failed,
                format!("failed subagent {}", failed.subagent_id.0),
                json_name(&failed.status),
            )
        }
        SubagentCommand::Cancel(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let subagent =
                projection_subagent(&control.projection(&session_id)?, &args.subagent_id)?;
            if output.dry_run {
                return write_dry_run(
                    writer,
                    output,
                    "subagent.cancel",
                    format!("cancel subagent {}", subagent.subagent_id.0),
                );
            }
            let cancelled = control.cancel_subagent(&subagent, args.reason)?;
            write_output(
                writer,
                output,
                &cancelled,
                format!("cancelled subagent {}", cancelled.subagent_id.0),
                json_name(&cancelled.status),
            )
        }
    }
}

pub(crate) fn execute_snapshot(
    control: &ControlPlane,
    args: SnapshotArgs,
    output: OutputMode,
    writer: &mut impl Write,
) -> Result<(), CliError> {
    match args.command {
        SnapshotCommand::Write(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            if output.dry_run {
                return write_dry_run(
                    writer,
                    output,
                    "snapshot.write",
                    format!("write projection snapshot for session {}", session_id.0),
                );
            }
            let snapshot = control.write_projection_snapshot(&session_id)?;
            write_output(
                writer,
                output,
                &snapshot,
                format!("wrote snapshot at seq {}", snapshot.latest_seq),
                snapshot.latest_seq.to_string(),
            )
        }
        SnapshotCommand::Read(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let snapshot = control.read_projection_snapshot(&session_id)?;
            write_output(
                writer,
                output,
                &snapshot,
                snapshot
                    .as_ref()
                    .map(|snapshot| format!("snapshot at seq {}", snapshot.latest_seq))
                    .unwrap_or_else(|| "no snapshot".to_string()),
                snapshot
                    .as_ref()
                    .map(|snapshot| snapshot.latest_seq.to_string())
                    .unwrap_or_else(|| "none".to_string()),
            )
        }
    }
}

fn plugin_text(plugins: &[PluginManifest]) -> String {
    if plugins.is_empty() {
        return "no plugins".to_string();
    }
    plugins
        .iter()
        .map(|plugin| format!("{}  {:?}  {}", plugin.id, plugin.kind, plugin.description))
        .collect::<Vec<_>>()
        .join("\n")
}

pub(crate) fn execute_plugin(
    control: &ControlPlane,
    args: PluginArgs,
    output: OutputMode,
    writer: &mut impl Write,
) -> Result<(), CliError> {
    match args.command {
        PluginCommand::Catalog(args) => {
            let catalog = basic_plugin_catalog();
            let mut plugins = catalog.plugins().cloned().collect::<Vec<_>>();
            if let Some(capability) = args.capability {
                plugins.retain(|plugin| plugin.capabilities.contains(&capability));
            }
            if let Some(kind) = args.kind {
                plugins.retain(|plugin| plugin_kind_matches(plugin, kind));
            }
            plugins.sort_by_key(|plugin| plugin.id.clone());
            write_list_output(writer, output, &plugins, plugin_text(&plugins))
        }
        PluginCommand::List(_) => {
            let mut plugins = installed_plugin_manifests(control.root())?;
            plugins.sort_by_key(|plugin| plugin.id.clone());
            write_list_output(writer, output, &plugins, plugin_text(&plugins))
        }
        PluginCommand::Install(args) => {
            let catalog = basic_plugin_catalog();
            let plugin = catalog.plugin(&args.id)?.clone();
            let mut stored = read_plugins(control.root())?;
            if !stored.installed.contains(&plugin.id) {
                stored.installed.push(plugin.id.clone());
                stored.installed.sort();
            }
            if output.dry_run {
                return write_dry_run(
                    writer,
                    output,
                    "plugin.install",
                    format!("install plugin {}", plugin.id),
                );
            }
            let path = write_plugins(control.root(), &stored)?;
            let value = json!({
                "plugin": plugin,
                "path": path.display().to_string(),
                "installed": stored.installed,
            });
            write_output(
                writer,
                output,
                &value,
                format!("installed plugin {}", args.id),
                args.id,
            )
        }
        PluginCommand::Tools(_) => {
            let plugins = installed_plugin_manifests(control.root())?;
            let tools = plugins
                .iter()
                .flat_map(|plugin| plugin.tools.iter().cloned())
                .collect::<Vec<_>>();
            let text = if tools.is_empty() {
                "no plugin tools".to_string()
            } else {
                tools
                    .iter()
                    .map(|tool| format!("{}  {:?}", tool.name, tool.permission))
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            write_list_output(writer, output, &tools, text)
        }
        PluginCommand::UiSlots(_) => {
            let plugins = installed_plugin_manifests(control.root())?;
            let slots = plugins
                .iter()
                .flat_map(|plugin| plugin.ui_slots.iter().cloned())
                .collect::<Vec<_>>();
            let text = if slots.is_empty() {
                "no plugin ui slots".to_string()
            } else {
                slots
                    .iter()
                    .map(|slot| format!("{}  {:?}  {}", slot.slot_id, slot.kind, slot.entry_ref))
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            write_list_output(writer, output, &slots, text)
        }
    }
}

pub(crate) fn execute_mcp(
    control: &ControlPlane,
    args: McpArgs,
    output: OutputMode,
    writer: &mut impl Write,
) -> Result<(), CliError> {
    match args.command {
        McpCommand::Manifest(_) => {
            #[cfg(feature = "mcp")]
            {
                let api = essence_core::ControlApi::new(control.clone());
                let manifest = api.mcp_manifest();
                write_output(
                    writer,
                    output,
                    &manifest,
                    format!(
                        "mcp manifest {} with {} tools",
                        manifest.server_name,
                        manifest.tools.len()
                    ),
                    manifest.tools.len().to_string(),
                )
            }
            #[cfg(not(feature = "mcp"))]
            {
                let _ = (control, output, writer);
                Err(CliError::Usage(
                    "mcp support is not enabled in this build".to_string(),
                ))
            }
        }
    }
}

fn bundled_harness(id: &str) -> Result<CliHarnessManifest, CliError> {
    match id {
        #[cfg(feature = "gitnexus")]
        "gitnexus" => Ok(essence_core::gitnexus_harness()),
        other => Err(CliError::Usage(format!(
            "harness `{other}` is not available in this build"
        ))),
    }
}

fn installed_harnesses() -> Vec<CliHarnessManifest> {
    let harnesses = Vec::new();
    #[cfg(feature = "gitnexus")]
    let harnesses = {
        let mut harnesses = harnesses;
        harnesses.push(essence_core::gitnexus_harness());
        harnesses
    };
    harnesses
}

pub(crate) fn execute_harness(
    control: &ControlPlane,
    args: HarnessArgs,
    output: OutputMode,
    writer: &mut impl Write,
) -> Result<(), CliError> {
    match args.command {
        HarnessCommand::List(_) => {
            let harnesses = installed_harnesses();
            let text = if harnesses.is_empty() {
                "no bundled harnesses".to_string()
            } else {
                harnesses
                    .iter()
                    .map(|harness| {
                        format!(
                            "{}  {} command(s)",
                            harness.plugin.id,
                            harness.commands.len()
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            write_list_output(writer, output, &harnesses, text)
        }
        HarnessCommand::Run(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let manifest = bundled_harness(&args.harness)?;
            let input = parse_json_arg(&args.input_json, "--input-json")?;
            let mut host = PluginHost::new();
            host.register(manifest.plugin.clone())?;
            let runner = PolicyBoundCliHarness::new(
                manifest,
                host.tools()
                    .to_policy(PermissionMode::from(args.permission_mode)),
            );
            let mut request =
                essence_core::RunCliHarnessToolRequest::new(session_id.clone(), args.tool, input);
            if let Some(run_id) = args.run_id {
                let run = projection_run(&control.projection(&session_id)?, &run_id)?;
                request = request.for_run(&run);
            }
            if let Some(cwd) = args.cwd {
                request = request.with_cwd(cwd);
            }
            if output.dry_run {
                return write_dry_run(
                    writer,
                    output,
                    "harness.run",
                    format!("run harness {} for session {}", args.harness, session_id.0),
                );
            }
            let (value, text, quiet) =
                cli_harness_outcome_value(control.run_cli_harness_tool(&runner, request)?);
            write_output(writer, output, &value, text, quiet)
        }
    }
}

pub(crate) fn execute_theme(
    control: &ControlPlane,
    args: ThemeArgs,
    output: OutputMode,
    writer: &mut impl Write,
) -> Result<(), CliError> {
    match args.command {
        ThemeCommand::Get(_) => {
            let stored = configured_theme(control.root()).unwrap_or(CliTheme::Auto);
            let value = json!({
                "theme": stored,
                "effective": format!("{:?}", output.theme).to_ascii_lowercase(),
                "color": output.color,
            });
            write_output(
                writer,
                output,
                &value,
                format!(
                    "theme: {:?}\neffective: {:?}\ncolor: {}",
                    stored, output.theme, output.color
                ),
                format!("{:?}", stored).to_ascii_lowercase(),
            )
        }
        ThemeCommand::Set(args) => {
            if output.dry_run {
                return write_dry_run(
                    writer,
                    output,
                    "theme.set",
                    format!("set theme to {:?}", args.theme),
                );
            }
            let path = write_theme(control.root(), args.theme)?;
            let value = json!({
                "theme": args.theme,
                "path": path.display().to_string(),
            });
            write_output(
                writer,
                output,
                &value,
                format!("set theme {:?} in {}", args.theme, path.display()),
                format!("{:?}", args.theme).to_ascii_lowercase(),
            )
        }
        ThemeCommand::Preview(args) => {
            let theme = args.theme.unwrap_or(CliTheme::Pixel);
            let color = output.color && !matches!(theme, CliTheme::Plain);
            let rendered = match theme {
                CliTheme::Plain => "ESSENCE CLI\nstatus: ready\ntheme: plain".to_string(),
                CliTheme::Auto | CliTheme::Pixel => panel(
                    "ESSENCE CLI",
                    "theme preview",
                    "status: ready\ntheme: pixel\nmachine output stays clean with --json",
                    color,
                ),
            };
            write_text_line(writer, rendered)
        }
    }
}

pub(crate) fn execute_config(
    control: &ControlPlane,
    args: ConfigArgs,
    output: OutputMode,
    writer: &mut impl Write,
) -> Result<(), CliError> {
    match args.command {
        ConfigCommand::Get(args) => {
            let config = read_model_config(control.root())?.unwrap_or_default();
            if let Some(key) = args.key {
                let value = config_value(&config, key);
                let response = json!({
                    "key": config_key_name(key),
                    "value": value,
                });
                write_output(
                    writer,
                    output,
                    &response,
                    value.clone().unwrap_or_else(|| "(unset)".to_string()),
                    value.unwrap_or_default(),
                )
            } else {
                write_output(
                    writer,
                    output,
                    &config,
                    render_model_config(&config),
                    model_config_path(control.root()).display().to_string(),
                )
            }
        }
        ConfigCommand::Set(args) => {
            validate_config_value(args.key, &args.value)?;
            let mut config = read_model_config(control.root())?.unwrap_or_default();
            set_config_value(&mut config, args.key, args.value);
            if output.dry_run {
                return write_dry_run(
                    writer,
                    output,
                    "config.set",
                    format!(
                        "set config {} in {}",
                        config_key_name(args.key),
                        model_config_path(control.root()).display()
                    ),
                );
            }
            let path = write_model_config(control.root(), &config)?;
            let response = json!({
                "key": config_key_name(args.key),
                "value": config_value(&config, args.key),
                "path": path.display().to_string(),
            });
            write_output(
                writer,
                output,
                &response,
                format!("set {} in {}", config_key_name(args.key), path.display()),
                config_value(&config, args.key).unwrap_or_default(),
            )
        }
    }
}

pub(crate) fn execute_doctor(
    control: &ControlPlane,
    args: DoctorArgs,
    output: OutputMode,
    writer: &mut impl Write,
) -> Result<(), CliError> {
    let report = doctor_report(control);
    write_output(
        writer,
        output,
        &report,
        render_doctor_report(&report),
        if report.ok {
            "ok".to_string()
        } else {
            "failed".to_string()
        },
    )?;
    if args.strict && !report.ok {
        return Err(CliError::Doctor(format!(
            "{} failing check(s)",
            report
                .checks
                .iter()
                .filter(|check| check.status == "error")
                .count()
        )));
    }
    Ok(())
}

fn render_model_config(config: &StoredModelConfig) -> String {
    let fields = [
        ("provider", config.provider.as_deref()),
        ("model", config.model.as_deref()),
        ("base-url", config.base_url.as_deref()),
        ("api-key-env", config.api_key_env.as_deref()),
        ("command", config.command.as_deref()),
    ];
    fields
        .into_iter()
        .map(|(key, value)| format!("{key}: {}", value.unwrap_or("(unset)")))
        .collect::<Vec<_>>()
        .join("\n")
}

fn config_key_name(key: CliConfigKey) -> &'static str {
    match key {
        CliConfigKey::Provider => "provider",
        CliConfigKey::Model => "model",
        CliConfigKey::BaseUrl => "base-url",
        CliConfigKey::ApiKeyEnv => "api-key-env",
        CliConfigKey::Command => "command",
    }
}

fn config_value(config: &StoredModelConfig, key: CliConfigKey) -> Option<String> {
    match key {
        CliConfigKey::Provider => config.provider.clone(),
        CliConfigKey::Model => config.model.clone(),
        CliConfigKey::BaseUrl => config.base_url.clone(),
        CliConfigKey::ApiKeyEnv => config.api_key_env.clone(),
        CliConfigKey::Command => config.command.clone(),
    }
}

fn set_config_value(config: &mut StoredModelConfig, key: CliConfigKey, value: String) {
    let value = non_empty(Some(value));
    match key {
        CliConfigKey::Provider => {
            config.provider = value.map(|value| normalize_provider(&value).unwrap_or(value))
        }
        CliConfigKey::Model => config.model = value,
        CliConfigKey::BaseUrl => config.base_url = value,
        CliConfigKey::ApiKeyEnv => config.api_key_env = value,
        CliConfigKey::Command => config.command = value,
    }
}

fn validate_config_value(key: CliConfigKey, value: &str) -> Result<(), CliError> {
    if matches!(key, CliConfigKey::Provider)
        && non_empty(Some(value.to_string()))
            .as_deref()
            .is_some_and(|value| !supported_provider(value))
    {
        return Err(CliError::ModelConfig(format!(
            "unsupported provider `{value}`; expected local, command, or openai-compatible"
        )));
    }
    Ok(())
}

fn supported_provider(value: &str) -> bool {
    normalize_provider(value).is_some()
}

fn normalize_provider(value: &str) -> Option<String> {
    match value.trim().to_ascii_lowercase().replace('_', "-").as_str() {
        "local" => Some("local".to_string()),
        "command" => Some("command".to_string()),
        "openai" | "openai-compatible" => Some("openai-compatible".to_string()),
        _ => None,
    }
}

#[derive(Debug, Serialize)]
struct DoctorReport {
    ok: bool,
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, Serialize)]
struct DoctorCheck {
    name: String,
    status: &'static str,
    detail: String,
}

fn doctor_report(control: &ControlPlane) -> DoctorReport {
    let mut checks = Vec::new();
    checks.push(doctor_check(
        "cli",
        "ok",
        format!("essence {}", env!("CARGO_PKG_VERSION")),
    ));

    let root = control.root();
    if root.exists() {
        if root.is_dir() {
            checks.push(doctor_check("root", "ok", root.display().to_string()));
        } else {
            checks.push(doctor_check(
                "root",
                "error",
                format!("{} exists but is not a directory", root.display()),
            ));
        }
    } else {
        checks.push(doctor_check(
            "root",
            "warn",
            format!("{} does not exist yet", root.display()),
        ));
    }

    match read_model_config(root) {
        Ok(Some(config)) => add_model_config_checks(root, &config, &mut checks),
        Ok(None) => checks.push(doctor_check(
            "model config",
            "warn",
            format!("{} not found", model_config_path(root).display()),
        )),
        Err(error) => checks.push(doctor_check("model config", "error", error.to_string())),
    }

    let terminal_status = if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
        ("ok", "interactive stdin/stdout detected".to_string())
    } else {
        (
            "warn",
            "non-interactive stdin/stdout detected; `essence chat` will refuse to start"
                .to_string(),
        )
    };
    checks.push(doctor_check(
        "terminal",
        terminal_status.0,
        terminal_status.1,
    ));
    checks.push(doctor_check(
        "completion",
        "ok",
        "completion generate/install commands available",
    ));
    checks.push(doctor_check(
        "dry-run",
        "ok",
        "mutating CLI commands accept global --dry-run",
    ));

    DoctorReport {
        ok: checks.iter().all(|check| check.status != "error"),
        checks,
    }
}

fn add_model_config_checks(
    root: &std::path::Path,
    config: &StoredModelConfig,
    checks: &mut Vec<DoctorCheck>,
) {
    checks.push(doctor_check(
        "model config",
        "ok",
        model_config_path(root).display().to_string(),
    ));

    match config.provider.as_deref() {
        Some(provider) if supported_provider(provider) => {
            checks.push(doctor_check("provider", "ok", provider.to_string()))
        }
        Some(provider) => checks.push(doctor_check(
            "provider",
            "error",
            format!("unsupported provider `{provider}`"),
        )),
        None => checks.push(doctor_check(
            "provider",
            "warn",
            "no provider set; chat will use local mode unless overridden",
        )),
    }

    match config.provider.as_deref().and_then(normalize_provider) {
        Some(provider) if provider == "command" => {
            if config
                .command
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
            {
                checks.push(doctor_check("model command", "ok", "configured"));
            } else {
                checks.push(doctor_check(
                    "model command",
                    "error",
                    "provider is command but no command is configured",
                ));
            }
        }
        Some(provider) if provider == "openai-compatible" => {
            if config
                .model
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
            {
                checks.push(doctor_check("model", "ok", "configured"));
            } else {
                checks.push(doctor_check(
                    "model",
                    "error",
                    "openai-compatible provider requires a model",
                ));
            }
            add_api_key_check(config, checks);
        }
        _ => {}
    }
}

fn add_api_key_check(config: &StoredModelConfig, checks: &mut Vec<DoctorCheck>) {
    let candidates = config
        .api_key_env
        .as_deref()
        .map(|name| vec![name])
        .unwrap_or_else(|| vec!["ESSENCE_MODEL_API_KEY", "OPENAI_API_KEY"]);
    if let Some(name) = candidates.iter().find(|name| {
        std::env::var(name)
            .ok()
            .is_some_and(|value| !value.trim().is_empty())
    }) {
        checks.push(doctor_check("api key env", "ok", format!("{name} is set")));
    } else {
        checks.push(doctor_check(
            "api key env",
            "warn",
            format!("none set from {}", candidates.join(", ")),
        ));
    }
}

fn doctor_check(
    name: impl Into<String>,
    status: &'static str,
    detail: impl Into<String>,
) -> DoctorCheck {
    DoctorCheck {
        name: name.into(),
        status,
        detail: detail.into(),
    }
}

fn render_doctor_report(report: &DoctorReport) -> String {
    let mut text = if report.ok {
        "doctor ok".to_string()
    } else {
        "doctor failed".to_string()
    };
    for check in &report.checks {
        let _ = write!(
            text,
            "\n[{:<5}] {}: {}",
            check.status, check.name, check.detail
        );
    }
    text
}
