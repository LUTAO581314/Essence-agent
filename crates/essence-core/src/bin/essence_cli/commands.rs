use std::io::Write;
use std::thread;
use std::time::Duration;

use essence_core::{
    AgentHeartbeatRequest, ControlPlane, CreateSessionRequest, CreateTaskRequest, EventCursor,
    RegisterAgentRequest,
};

use super::args::{
    AgentArgs, AgentCommand, ApprovalArgs, ApprovalCommand, EventsArgs, EventsCommand, MessageArgs,
    MessageCommand, SessionArgs, SessionCommand, TaskArgs, TaskCommand,
};
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
    }
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
