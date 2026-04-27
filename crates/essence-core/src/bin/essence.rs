use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use essence_core::{
    ControlPlane, CreateSessionRequest, EventCursor, EventEnvelope, PermissionMode, SessionId,
    SessionMode, UiEvent,
};
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(
    name = "essence",
    version,
    about = "Minimal v0 CLI for the Essence Agent control plane."
)]
struct Cli {
    #[arg(long, global = true, default_value = ".essence")]
    root: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Session(SessionArgs),
    Message(MessageArgs),
    Events(EventsArgs),
}

#[derive(Debug, Args)]
struct SessionArgs {
    #[command(subcommand)]
    command: SessionCommand,
}

#[derive(Debug, Subcommand)]
enum SessionCommand {
    Create(SessionCreateArgs),
}

#[derive(Debug, Args)]
struct SessionCreateArgs {
    #[arg(long)]
    cwd: Option<PathBuf>,
    #[arg(long)]
    title: Option<String>,
    #[arg(long)]
    model: Option<String>,
    #[arg(long, value_enum, default_value_t = CliSessionMode::Interactive)]
    mode: CliSessionMode,
    #[arg(long, value_enum, default_value_t = CliPermissionMode::Default)]
    permission_mode: CliPermissionMode,
}

#[derive(Debug, Args)]
struct MessageArgs {
    #[command(subcommand)]
    command: MessageCommand,
}

#[derive(Debug, Subcommand)]
enum MessageCommand {
    Send(MessageSendArgs),
}

#[derive(Debug, Args)]
struct MessageSendArgs {
    #[arg(long)]
    session_id: String,
    #[arg(long)]
    text: String,
}

#[derive(Debug, Args)]
struct EventsArgs {
    #[command(subcommand)]
    command: EventsCommand,
}

#[derive(Debug, Subcommand)]
enum EventsCommand {
    Tail(EventsTailArgs),
}

#[derive(Debug, Args)]
struct EventsTailArgs {
    #[arg(long)]
    session_id: String,
    #[arg(long, default_value_t = 0)]
    after: u64,
    #[arg(long)]
    user_visible: bool,
    #[arg(long)]
    follow: bool,
    #[arg(long, default_value_t = 500)]
    interval_ms: u64,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliSessionMode {
    Interactive,
    Headless,
    Acp,
    Gateway,
    Scheduled,
}

impl From<CliSessionMode> for SessionMode {
    fn from(value: CliSessionMode) -> Self {
        match value {
            CliSessionMode::Interactive => SessionMode::Interactive,
            CliSessionMode::Headless => SessionMode::Headless,
            CliSessionMode::Acp => SessionMode::Acp,
            CliSessionMode::Gateway => SessionMode::Gateway,
            CliSessionMode::Scheduled => SessionMode::Scheduled,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliPermissionMode {
    Default,
    Plan,
    Auto,
    Bypass,
    Readonly,
}

impl From<CliPermissionMode> for PermissionMode {
    fn from(value: CliPermissionMode) -> Self {
        match value {
            CliPermissionMode::Default => PermissionMode::Default,
            CliPermissionMode::Plan => PermissionMode::Plan,
            CliPermissionMode::Auto => PermissionMode::Auto,
            CliPermissionMode::Bypass => PermissionMode::Bypass,
            CliPermissionMode::Readonly => PermissionMode::Readonly,
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error(transparent)]
    Control(#[from] essence_core::ControlError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Uuid(#[from] uuid::Error),
    #[error("path is not valid unicode: {0}")]
    InvalidPath(PathBuf),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let stdout = io::stdout();
    let mut writer = stdout.lock();

    match execute(cli, &mut writer) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(io::stderr().lock(), "{error}");
            ExitCode::FAILURE
        }
    }
}

fn execute(cli: Cli, writer: &mut impl Write) -> Result<(), CliError> {
    let control = ControlPlane::new(&cli.root);
    match cli.command {
        Command::Session(args) => execute_session(&control, args, writer),
        Command::Message(args) => execute_message(&control, args, writer),
        Command::Events(args) => execute_events(&control, args, writer),
    }
}

fn execute_session(
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

fn execute_message(
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

fn execute_events(
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
    }
}

fn emit_events(writer: &mut impl Write, events: &[EventEnvelope]) -> Result<(), CliError> {
    for event in events {
        write_json_line(writer, event)?;
    }
    Ok(())
}

fn emit_ui_events(writer: &mut impl Write, events: &[UiEvent]) -> Result<(), CliError> {
    for event in events {
        write_json_line(writer, event)?;
    }
    Ok(())
}

fn write_json_pretty(writer: &mut impl Write, value: &impl Serialize) -> Result<(), CliError> {
    serde_json::to_writer_pretty(&mut *writer, value)?;
    writer.write_all(b"\n")?;
    Ok(())
}

fn write_json_line(writer: &mut impl Write, value: &impl Serialize) -> Result<(), CliError> {
    serde_json::to_writer(&mut *writer, value)?;
    writer.write_all(b"\n")?;
    Ok(())
}

fn parse_session_id(raw: &str) -> Result<SessionId, CliError> {
    Ok(SessionId(Uuid::parse_str(raw)?))
}

fn path_to_string(path: &Path) -> Result<String, CliError> {
    match path.to_str() {
        Some(value) => Ok(value.to_string()),
        None => Err(CliError::InvalidPath(path.to_path_buf())),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use serde_json::Value;
    use uuid::Uuid;

    use super::*;
    use essence_core::{CreateSessionRequest, MessagePayload, MessageRole};

    #[test]
    fn creates_session_via_cli() {
        let root = temp_root("create-session");
        let cwd = root.join("workspace");
        fs::create_dir_all(&cwd).unwrap();

        let cli = Cli {
            root: root.clone(),
            command: Command::Session(SessionArgs {
                command: SessionCommand::Create(SessionCreateArgs {
                    cwd: Some(cwd.clone()),
                    title: Some("First session".to_string()),
                    model: Some("gpt-test".to_string()),
                    mode: CliSessionMode::Interactive,
                    permission_mode: CliPermissionMode::Default,
                }),
            }),
        };

        let mut out = Vec::new();
        execute(cli, &mut out).unwrap();

        let session: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(session["title"], "First session");
        assert_eq!(session["model"], "gpt-test");

        let session_id = session["session_id"].as_str().unwrap();
        let wal_path = root.join("sessions").join(format!("{session_id}.jsonl"));
        assert!(wal_path.exists());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn sends_message_via_cli() {
        let root = temp_root("send-message");
        let control = ControlPlane::new(&root);
        let session = control
            .create_session(CreateSessionRequest::interactive("."))
            .unwrap();

        let cli = Cli {
            root: root.clone(),
            command: Command::Message(MessageArgs {
                command: MessageCommand::Send(MessageSendArgs {
                    session_id: session.session_id.0.to_string(),
                    text: "hello from cli".to_string(),
                }),
            }),
        };

        let mut out = Vec::new();
        execute(cli, &mut out).unwrap();

        let event: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(event["event_type"], "message_user");

        let projection = control.projection(&session.session_id).unwrap();
        let payload: &MessagePayload = &projection.messages[0];
        assert_eq!(payload.role, MessageRole::User);
        assert_eq!(payload.content.len(), 1);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn tails_events_after_cursor() {
        let root = temp_root("tail-events");
        let control = ControlPlane::new(&root);
        let session = control
            .create_session(CreateSessionRequest::interactive("."))
            .unwrap();
        control
            .submit_user_message(&session.session_id, "first")
            .unwrap();
        control
            .submit_user_message(&session.session_id, "second")
            .unwrap();

        let cli = Cli {
            root: root.clone(),
            command: Command::Events(EventsArgs {
                command: EventsCommand::Tail(EventsTailArgs {
                    session_id: session.session_id.0.to_string(),
                    after: 2,
                    user_visible: false,
                    follow: false,
                    interval_ms: 1,
                }),
            }),
        };

        let mut out = Vec::new();
        execute(cli, &mut out).unwrap();

        let lines = String::from_utf8(out).unwrap();
        let events = lines
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["event_type"], "message_user");
        assert_eq!(events[0]["seq"], 3);

        let _ = fs::remove_dir_all(root);
    }

    fn temp_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("essence-cli-{label}-{}", Uuid::new_v4()))
    }
}
