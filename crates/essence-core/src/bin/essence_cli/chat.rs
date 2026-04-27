use std::fmt::Write as FmtWrite;
use std::io::{self, BufRead, Read, Write};
use std::path::Path;
use std::process::{Command as ProcessCommand, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use essence_core::{
    AgentHeartbeatRequest, ContentBlock, ControlPlane, CreateSessionRequest, EventEnvelope,
    LifecycleStatus, MessagePayload, ModelClient, ModelExecutionLoop, ModelRequest, ModelResponse,
    RegisterAgentRequest, SessionId,
};
use uuid::Uuid;

use super::args::ChatArgs;
use super::support::{parse_session_id, path_to_string, CliError};
use super::workspace_view::render_workspace_dashboard_from_control;

pub(crate) fn execute_chat(
    control: &ControlPlane,
    args: ChatArgs,
    reader: &mut impl BufRead,
    writer: &mut impl Write,
) -> Result<(), CliError> {
    let ChatArgs {
        session_id,
        cwd,
        title,
        model,
        model_command,
        model_timeout_ms,
        model_max_stdout_bytes,
        model_max_stderr_bytes,
        agent_id,
        lane,
        role,
        no_agent,
        no_assistant,
        no_color,
    } = args;
    let session_id = match session_id {
        Some(raw) => parse_session_id(&raw)?,
        None => {
            let cwd = match cwd {
                Some(path) => path,
                None => std::env::current_dir()?,
            };
            let mut request = CreateSessionRequest::interactive(path_to_string(&cwd)?);
            if let Some(title) = title {
                request = request.with_title(title);
            }
            if let Some(model) = model {
                request = request.with_model(model);
            }
            control.create_session(request)?.session_id
        }
    };

    let chat_agent = if no_agent {
        None
    } else {
        let agent = ChatAgentConfig {
            agent_id,
            lane,
            role,
        };
        ensure_chat_agent(control, &session_id, &agent)?;
        Some(agent)
    };
    let model_command = model_command.or_else(|| std::env::var("ESSENCE_CHAT_MODEL_CMD").ok());
    let model_limits = ModelCommandLimits {
        timeout: Duration::from_millis(model_timeout_ms),
        max_stdout_bytes: model_max_stdout_bytes,
        max_stderr_bytes: model_max_stderr_bytes,
    };

    writeln!(writer, "Essence chat session: {}", session_id.0)?;
    write_chat_help(writer)?;

    let runtime =
        ModelExecutionLoop::new(control.clone(), ChatModel::new(model_command, model_limits));
    loop {
        writer.write_all(b"you> ")?;
        writer.flush()?;

        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let text = line.trim_end_matches(['\r', '\n']).trim().to_string();
        if text.is_empty() {
            continue;
        }

        match text.as_str() {
            "/exit" | "/quit" => {
                writeln!(writer, "bye")?;
                break;
            }
            "/help" => {
                write_chat_help(writer)?;
            }
            "/office" | "/agents" | "/dashboard" => {
                let rendered =
                    render_workspace_dashboard_from_control(control, &session_id, !no_color)?;
                writer.write_all(rendered.as_bytes())?;
            }
            command if command.starts_with('/') => {
                writeln!(writer, "unknown command: {command}")?;
                write_chat_help(writer)?;
            }
            _ if no_assistant => {
                if let Some(agent) = &chat_agent {
                    record_chat_agent(
                        control,
                        &session_id,
                        agent,
                        LifecycleStatus::Running,
                        &text,
                    )?;
                }
                let event = control.submit_user_message(&session_id, text)?;
                if let Some(agent) = &chat_agent {
                    record_chat_agent(
                        control,
                        &session_id,
                        agent,
                        LifecycleStatus::Idle,
                        "standby",
                    )?;
                }
                writeln!(writer, "recorded seq {}", event.seq)?;
            }
            _ => {
                if let Some(agent) = &chat_agent {
                    record_chat_agent(
                        control,
                        &session_id,
                        agent,
                        LifecycleStatus::Running,
                        &text,
                    )?;
                }
                let turn = match runtime.run_user_turn(session_id.clone(), text) {
                    Ok(turn) => turn,
                    Err(error) => {
                        if let Some(agent) = &chat_agent {
                            record_chat_agent(
                                control,
                                &session_id,
                                agent,
                                LifecycleStatus::Failed,
                                &error.to_string(),
                            )?;
                        }
                        return Err(error.into());
                    }
                };
                if let Some(agent) = &chat_agent {
                    record_chat_agent(
                        control,
                        &session_id,
                        agent,
                        LifecycleStatus::Idle,
                        "standby",
                    )?;
                }
                let reply = event_message_text(&turn.assistant_event)
                    .unwrap_or_else(|| "local assistant: recorded turn".to_string());
                writeln!(writer, "assistant> {reply}")?;
            }
        }
    }

    Ok(())
}

fn write_chat_help(writer: &mut impl Write) -> Result<(), CliError> {
    writeln!(
        writer,
        "commands: /office shows agent board, /help shows this, /exit quits"
    )?;
    Ok(())
}

#[derive(Debug, Clone)]
struct ChatAgentConfig {
    agent_id: String,
    lane: String,
    role: String,
}

fn ensure_chat_agent(
    control: &ControlPlane,
    session_id: &SessionId,
    agent: &ChatAgentConfig,
) -> Result<(), CliError> {
    control.register_agent(RegisterAgentRequest::new(
        session_id.clone(),
        agent.agent_id.clone(),
        agent.lane.clone(),
        agent.role.clone(),
    ))?;
    record_chat_agent(
        control,
        session_id,
        agent,
        LifecycleStatus::Idle,
        "chat ready",
    )
}

fn record_chat_agent(
    control: &ControlPlane,
    session_id: &SessionId,
    agent: &ChatAgentConfig,
    status: LifecycleStatus,
    note: &str,
) -> Result<(), CliError> {
    control.record_agent_heartbeat(
        AgentHeartbeatRequest::new(session_id.clone(), agent.agent_id.clone(), status)
            .with_lane(agent.lane.clone())
            .with_note(note),
    )?;
    Ok(())
}

#[derive(Debug, Clone)]
enum ChatModel {
    Local(LocalChatModel),
    Command(CommandChatModel),
}

impl ChatModel {
    fn new(model_command: Option<String>, limits: ModelCommandLimits) -> Self {
        match model_command {
            Some(command) if !command.trim().is_empty() => {
                Self::Command(CommandChatModel { command, limits })
            }
            _ => Self::Local(LocalChatModel),
        }
    }
}

impl ModelClient for ChatModel {
    fn complete(&self, request: ModelRequest) -> Result<ModelResponse, String> {
        match self {
            Self::Local(model) => model.complete(request),
            Self::Command(model) => model.complete(request),
        }
    }
}

#[derive(Debug, Clone)]
struct LocalChatModel;

impl ModelClient for LocalChatModel {
    fn complete(&self, request: ModelRequest) -> Result<ModelResponse, String> {
        let latest = latest_message_text(&request.messages).unwrap_or("");
        let summary = truncate(latest, 80);
        Ok(ModelResponse::text(format!(
            "local assistant: recorded `{summary}`. Use /office to view the agent board."
        ))
        .with_stop_reason("local"))
    }
}

#[derive(Debug, Clone)]
struct CommandChatModel {
    command: String,
    limits: ModelCommandLimits,
}

impl ModelClient for CommandChatModel {
    fn complete(&self, request: ModelRequest) -> Result<ModelResponse, String> {
        let prompt = render_model_command_prompt(&request);
        let output = execute_model_command(&self.command, prompt.as_bytes(), self.limits)?;
        if output.timed_out {
            return Err(format!(
                "model command timed out after {} ms",
                self.limits.timeout.as_millis()
            ));
        }
        if output.stdout_truncated {
            return Err(format!(
                "model command stdout exceeded {} bytes",
                self.limits.max_stdout_bytes
            ));
        }
        if !output.success {
            let mut stderr = output.stderr.trim().to_string();
            if output.stderr_truncated {
                let _ = write!(
                    stderr,
                    "\n[stderr truncated at {} bytes]",
                    self.limits.max_stderr_bytes
                );
            }
            return Err(if stderr.is_empty() {
                format!("model command exited with {:?}", output.status_code)
            } else {
                format!(
                    "model command exited with {:?}: {stderr}",
                    output.status_code
                )
            });
        }

        let text = output.stdout.trim().to_string();
        if text.is_empty() {
            return Err("model command returned empty output".to_string());
        }

        Ok(ModelResponse::text(text).with_stop_reason("command"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ModelCommandLimits {
    timeout: Duration,
    max_stdout_bytes: usize,
    max_stderr_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ModelCommandOutput {
    status_code: Option<i32>,
    success: bool,
    stdout: String,
    stderr: String,
    timed_out: bool,
    stdout_truncated: bool,
    stderr_truncated: bool,
}

fn execute_model_command(
    command: &str,
    stdin: &[u8],
    limits: ModelCommandLimits,
) -> Result<ModelCommandOutput, String> {
    let temp_id = Uuid::new_v4();
    let stdout_path = std::env::temp_dir().join(format!("essence-model-{temp_id}.stdout"));
    let stderr_path = std::env::temp_dir().join(format!("essence-model-{temp_id}.stderr"));
    let stdout_file = std::fs::File::create(&stdout_path)
        .map_err(|error| format!("could not create model stdout file: {error}"))?;
    let stderr_file = std::fs::File::create(&stderr_path)
        .map_err(|error| format!("could not create model stderr file: {error}"))?;

    let mut process = shell_command(command);
    process
        .stdin(Stdio::piped())
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file));

    let mut child = process
        .spawn()
        .map_err(|error| format!("could not start model command: {error}"))?;

    if let Some(mut child_stdin) = child.stdin.take() {
        child_stdin
            .write_all(stdin)
            .map_err(|error| format!("could not write model prompt: {error}"))?;
    }

    let started = Instant::now();
    let (status, timed_out) = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("model command failed: {error}"))?
        {
            break (status, false);
        }
        if started.elapsed() >= limits.timeout {
            child
                .kill()
                .map_err(|error| format!("could not kill timed-out model command: {error}"))?;
            let status = child
                .wait()
                .map_err(|error| format!("could not wait for timed-out model command: {error}"))?;
            break (status, true);
        }
        thread::sleep(Duration::from_millis(5));
    };

    let (stdout, stdout_truncated) = read_limited_lossy(&stdout_path, limits.max_stdout_bytes)
        .map_err(|error| {
            format!(
                "could not read model command stdout from {}: {error}",
                stdout_path.display()
            )
        })?;
    let (stderr, stderr_truncated) = read_limited_lossy(&stderr_path, limits.max_stderr_bytes)
        .map_err(|error| {
            format!(
                "could not read model command stderr from {}: {error}",
                stderr_path.display()
            )
        })?;
    let _ = std::fs::remove_file(stdout_path);
    let _ = std::fs::remove_file(stderr_path);

    Ok(ModelCommandOutput {
        status_code: if timed_out { None } else { status.code() },
        success: !timed_out && status.success(),
        stdout,
        stderr,
        timed_out,
        stdout_truncated,
        stderr_truncated,
    })
}

fn read_limited_lossy(path: &Path, limit: usize) -> io::Result<(String, bool)> {
    let mut file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    let take = limit.saturating_add(1) as u64;
    Read::by_ref(&mut file).take(take).read_to_end(&mut bytes)?;
    let truncated = bytes.len() > limit;
    if truncated {
        bytes.truncate(limit);
    }
    Ok((String::from_utf8_lossy(&bytes).to_string(), truncated))
}

fn shell_command(command: &str) -> ProcessCommand {
    #[cfg(windows)]
    {
        let mut process = ProcessCommand::new("powershell");
        process.arg("-NoProfile").arg("-Command").arg(command);
        process
    }
    #[cfg(not(windows))]
    {
        let mut process = ProcessCommand::new("sh");
        process.arg("-c").arg(command);
        process
    }
}

fn render_model_command_prompt(request: &ModelRequest) -> String {
    let mut prompt = String::new();
    let _ = writeln!(
        prompt,
        "You are the assistant in an Essence Agent CLI session."
    );
    let _ = writeln!(prompt, "Session: {}", request.session_id.0);
    let _ = writeln!(prompt, "Run: {}", request.run.run_id.0);
    let _ = writeln!(prompt);
    for message in &request.messages {
        let role = serde_json::to_string(&message.role)
            .unwrap_or_else(|_| "\"message\"".to_string())
            .trim_matches('"')
            .to_string();
        for content in &message.content {
            if let ContentBlock::Text { text } = content {
                let _ = writeln!(prompt, "{role}: {text}");
            }
        }
    }
    let _ = writeln!(prompt);
    let _ = writeln!(prompt, "assistant:");
    prompt
}

fn latest_message_text(messages: &[MessagePayload]) -> Option<&str> {
    messages.iter().rev().find_map(|message| {
        message
            .content
            .iter()
            .rev()
            .find_map(|content| match content {
                ContentBlock::Text { text } => Some(text.as_str()),
                _ => None,
            })
    })
}

fn truncate(value: &str, width: usize) -> String {
    let mut output = value.chars().take(width).collect::<String>();
    if value.chars().count() > width && width > 1 {
        output.truncate(width - 1);
        output.push('~');
    }
    output
}

fn event_message_text(event: &EventEnvelope) -> Option<String> {
    let payload = serde_json::from_value::<MessagePayload>(event.payload.clone()).ok()?;
    payload
        .content
        .into_iter()
        .find_map(|content| match content {
            ContentBlock::Text { text } => Some(text),
            _ => None,
        })
}
