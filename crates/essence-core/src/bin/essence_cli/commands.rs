use std::fmt::Write as FmtWrite;
use std::io::Write;
use std::thread;
use std::time::Duration;

use essence_core::{
    AgentHeartbeatRequest, ControlPlane, CreateSessionRequest, CreateTaskRequest, EventCursor,
    RegisterAgentRequest,
};

use super::agency_templates::{find_agent_template, search_agent_templates, AgencyAgentTemplate};
use super::agent_profile::{list_agent_profiles, write_agent_profile, StoredAgentProfile};
use super::args::{
    AgentArgs, AgentCommand, AgentDefineArgs, AgentTemplatesArgs, ApprovalArgs, ApprovalCommand,
    EventsArgs, EventsCommand, MessageArgs, MessageCommand, SessionArgs, SessionCommand, TaskArgs,
    TaskCommand,
};
use super::model_config::non_empty;
use super::pixel_ui::{brand_header, key_value, mid, reset, row, status_chip, style};
use super::setup::provider_slug;
use super::support::{
    anchor_key_from_env, emit_events, emit_ui_events, parse_approval_id, parse_run_id,
    parse_session_id, parse_task_id, path_to_string, write_json_pretty, CliError,
};

pub(crate) fn execute_session(
    control: &ControlPlane,
    args: SessionArgs,
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
            let session = control.create_session(request)?;
            write_json_pretty(writer, &session)
        }
    }
}

pub(crate) fn execute_message(
    control: &ControlPlane,
    args: MessageArgs,
    writer: &mut impl Write,
) -> Result<(), CliError> {
    match args.command {
        MessageCommand::Send(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let event = control.submit_user_message(&session_id, args.text)?;
            write_json_pretty(writer, &event)
        }
    }
}

pub(crate) fn execute_events(
    control: &ControlPlane,
    args: EventsArgs,
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
                    emit_ui_events(writer, &events)?;
                    if let Some(last) = events.last() {
                        after_seq = last.seq;
                    }
                } else {
                    let events = control.events_after(&session_id, after_seq)?;
                    emit_events(writer, &events)?;
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
            write_json_pretty(writer, &report)
        }
        EventsCommand::AnchorWrite(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let key = anchor_key_from_env(&args.key_env)?;
            let anchor = control.write_session_anchor(&session_id, args.key_id, key.as_bytes())?;
            write_json_pretty(writer, &anchor)
        }
        EventsCommand::AnchorVerify(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let key = anchor_key_from_env(&args.key_env)?;
            let verification = control.verify_session_anchor(&session_id, key.as_bytes())?;
            write_json_pretty(writer, &verification)
        }
    }
}

pub(crate) fn execute_approval(
    control: &ControlPlane,
    args: ApprovalArgs,
    writer: &mut impl Write,
) -> Result<(), CliError> {
    match args.command {
        ApprovalCommand::Pending(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let approvals = control.pending_approvals(&session_id)?;
            write_json_pretty(writer, &approvals)
        }
        ApprovalCommand::Resolve(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let approval_id = parse_approval_id(&args.approval_id)?;
            let projection = control.projection(&session_id)?;
            let approval = projection
                .approvals
                .get(&approval_id)
                .ok_or_else(|| CliError::MissingApproval(args.approval_id.clone()))?;
            let resolved =
                control.resolve_approval(approval, args.decision.into(), args.resolved_by)?;
            write_json_pretty(writer, &resolved)
        }
    }
}

pub(crate) fn execute_agent(
    control: &ControlPlane,
    args: AgentArgs,
    writer: &mut impl Write,
) -> Result<(), CliError> {
    match args.command {
        AgentCommand::Register(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let mut request =
                RegisterAgentRequest::new(session_id, args.agent_id, args.lane, args.role);
            for toolset in args.toolsets {
                request = request.with_toolset(toolset);
            }
            let agent = control.register_agent(request)?;
            write_json_pretty(writer, &agent)
        }
        AgentCommand::Heartbeat(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let mut request =
                AgentHeartbeatRequest::new(session_id, args.agent_id, args.status.into());
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
            let heartbeat = control.record_agent_heartbeat(request)?;
            write_json_pretty(writer, &heartbeat)
        }
        AgentCommand::Define(args) => execute_agent_define(control, args, writer),
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
    args: AgentDefineArgs,
    writer: &mut impl Write,
) -> Result<(), CliError> {
    let color = !args.no_color;
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
    writer: &mut impl Write,
) -> Result<(), CliError> {
    match args.command {
        TaskCommand::Create(args) => {
            let session_id = parse_session_id(&args.session_id)?;
            let mut request =
                CreateTaskRequest::new(session_id, args.title).with_status(args.status.into());
            if let Some(lane) = args.lane {
                request = request.with_lane(lane);
            }
            if let Some(assignee) = args.assignee {
                request = request.with_assignee(assignee);
            }
            let task = control.create_task(request)?;
            write_json_pretty(writer, &task)
        }
    }
}
