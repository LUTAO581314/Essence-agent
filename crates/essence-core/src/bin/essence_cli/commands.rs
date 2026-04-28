use std::fmt::Write as FmtWrite;
use std::io::{IsTerminal, Write};
use std::thread;
use std::time::Duration;

use essence_core::{
    AgentHeartbeatRequest, ApprovalRequest, ControlPlane, CreateSessionRequest, CreateTaskRequest,
    EventCursor, EventEnvelope, RegisterAgentRequest, SessionMeta, UiEvent, WalIntegrityReport,
};
use serde::Serialize;
use serde_json::json;

use super::agency_templates::{find_agent_template, search_agent_templates, AgencyAgentTemplate};
use super::agent_profile::{list_agent_profiles, write_agent_profile, StoredAgentProfile};
use super::args::{
    AgentArgs, AgentCommand, AgentDefineArgs, AgentTemplatesArgs, ApprovalArgs, ApprovalCommand,
    CliApprovalDecision, CliConfigKey, ConfigArgs, ConfigCommand, DoctorArgs, EventsArgs,
    EventsCommand, MessageArgs, MessageCommand, SessionArgs, SessionCommand, TaskArgs, TaskCommand,
};
use super::model_config::{
    model_config_path, non_empty, read_model_config, write_model_config, StoredModelConfig,
};
use super::pixel_ui::{brand_header, key_value, mid, reset, row, status_chip, style};
use super::setup::provider_slug;
use super::support::{
    anchor_key_from_env, emit_events, emit_ui_events, parse_approval_id, parse_run_id,
    parse_session_id, parse_task_id, path_to_string, write_json_line, write_json_pretty,
    write_text_line, CliError, OutputMode,
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

pub(crate) fn execute_approval(
    control: &ControlPlane,
    args: ApprovalArgs,
    output: OutputMode,
    writer: &mut impl Write,
) -> Result<(), CliError> {
    match args.command {
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
            let rendered = render_agent_profiles(&profiles, !args.no_color);
            writer.write_all(rendered.as_bytes())?;
            Ok(())
        }
        AgentCommand::Templates(args) => {
            let rendered = render_agent_templates(&args, !args.no_color)?;
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
    let color = !args.no_color;
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
