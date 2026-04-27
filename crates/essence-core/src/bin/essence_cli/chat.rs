use std::fmt::Write as FmtWrite;
use std::io::{self, BufRead, Read, Write};
use std::path::Path;
use std::process::{Command as ProcessCommand, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use essence_core::{
    AgentHeartbeatRequest, ContentBlock, ControlPlane, CreateSessionRequest, EventEnvelope,
    LifecycleStatus, MessagePayload, MessageRole, ModelClient, ModelExecutionLoop, ModelRequest,
    ModelResponse, RegisterAgentRequest, SessionId,
};
use serde_json::{json, Value};
use uuid::Uuid;

use super::agent_profile::{
    read_agent_profile, read_agent_profile_if_exists, read_prompt_file, StoredAgentProfile,
};
use super::args::{ChatArgs, CliModelProvider};
use super::model_config::{read_model_config, DEFAULT_OPENAI_COMPATIBLE_BASE_URL};
use super::pixel_ui::{brand_header, key_value, mid, reset, row, status_chip, style};
use super::support::{parse_session_id, path_to_string, CliError};
use super::workspace_view::render_workspace_dashboard_from_control;

pub(crate) fn execute_chat(
    control: &ControlPlane,
    args: ChatArgs,
    reader: &mut impl BufRead,
    writer: &mut impl Write,
) -> Result<(), CliError> {
    let ChatArgs {
        agent_profile,
        system_prompt,
        system_prompt_file,
        session_id,
        cwd,
        title,
        model,
        model_provider,
        model_base_url,
        model_api_key_env,
        model_command,
        model_timeout_ms,
        model_max_response_bytes,
        model_max_stdout_bytes,
        model_max_stderr_bytes,
        agent_id,
        lane,
        role,
        no_agent,
        no_assistant,
        no_color,
    } = args;
    let agent_profile = match non_empty(agent_profile) {
        Some(agent_id) => Some(read_agent_profile(control.root(), &agent_id)?),
        None if agent_id == "main" => read_agent_profile_if_exists(control.root(), "main")?,
        None => None,
    };
    let stored_config = read_model_config(control.root())?.unwrap_or_default();
    let configured_model = non_empty(model)
        .or_else(|| env_var_non_empty("ESSENCE_MODEL"))
        .or_else(|| {
            agent_profile
                .as_ref()
                .and_then(|profile| non_empty(profile.model.clone()))
        })
        .or_else(|| non_empty(stored_config.model.clone()));
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
            if let Some(model) = configured_model.clone() {
                request = request.with_model(model);
            }
            control.create_session(request)?.session_id
        }
    };
    let model_name = match configured_model {
        Some(model) => Some(model),
        None => projected_session_model(control, &session_id)?,
    };

    let system_prompt =
        resolve_system_prompt(system_prompt, system_prompt_file, agent_profile.as_ref())?;
    let agent_id = agent_profile
        .as_ref()
        .map(|profile| profile.agent_id.clone())
        .unwrap_or(agent_id);
    let lane = agent_profile
        .as_ref()
        .map(|profile| profile.lane.clone())
        .unwrap_or(lane);
    let role = agent_profile
        .as_ref()
        .map(|profile| profile.role.clone())
        .unwrap_or(role);

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
    let cli_model_command = non_empty(model_command);
    let env_model_command = env_var_non_empty("ESSENCE_CHAT_MODEL_CMD");
    let model_command = cli_model_command
        .clone()
        .or(env_model_command)
        .or_else(|| {
            agent_profile
                .as_ref()
                .and_then(|profile| non_empty(profile.command.clone()))
        })
        .or_else(|| non_empty(stored_config.command.clone()));
    let model_provider = if no_assistant {
        CliModelProvider::Local
    } else {
        resolve_model_provider(
            model_provider,
            cli_model_command.as_deref(),
            agent_profile
                .as_ref()
                .and_then(|profile| profile.provider.as_deref()),
            stored_config.provider.as_deref(),
            model_command.as_deref(),
        )
        .map_err(CliError::ModelConfig)?
    };
    let model_limits = ModelAdapterLimits {
        timeout: Duration::from_millis(model_timeout_ms),
        max_response_bytes: model_max_response_bytes,
        max_stdout_bytes: model_max_stdout_bytes,
        max_stderr_bytes: model_max_stderr_bytes,
    };
    let openai_config = if matches!(model_provider, CliModelProvider::OpenaiCompatible) {
        OpenAiCompatibleConfig {
            model: model_name.clone(),
            base_url: non_empty(model_base_url)
                .or_else(|| env_var_non_empty("ESSENCE_MODEL_BASE_URL"))
                .or_else(|| {
                    agent_profile
                        .as_ref()
                        .and_then(|profile| non_empty(profile.base_url.clone()))
                })
                .or_else(|| non_empty(stored_config.base_url.clone()))
                .unwrap_or_else(|| DEFAULT_OPENAI_COMPATIBLE_BASE_URL.to_string()),
            api_key: resolve_model_api_key(
                model_api_key_env
                    .or_else(|| {
                        agent_profile
                            .as_ref()
                            .and_then(|profile| non_empty(profile.api_key_env.clone()))
                    })
                    .or_else(|| non_empty(stored_config.api_key_env.clone())),
            )
            .map_err(CliError::ModelConfig)?,
        }
    } else {
        OpenAiCompatibleConfig {
            model: None,
            base_url: String::new(),
            api_key: None,
        }
    };

    write_chat_header(
        writer,
        &session_id,
        model_provider,
        model_name.as_deref(),
        chat_agent.as_ref(),
        system_prompt.as_deref(),
        !no_color,
    )?;
    write_chat_help(writer, !no_color)?;

    let runtime = if no_assistant {
        None
    } else {
        Some(ModelExecutionLoop::new(
            control.clone(),
            ChatModel::new(
                model_provider,
                model_command,
                openai_config,
                model_limits,
                system_prompt.clone(),
            )
            .map_err(CliError::ModelConfig)?,
        ))
    };
    loop {
        if no_color {
            writer.write_all(b"you> ")?;
        } else {
            write!(writer, "{}you>{} ", style(true, "moon"), reset(true))?;
        }
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
                write_chat_help(writer, !no_color)?;
            }
            "/office" | "/agents" | "/dashboard" => {
                let rendered =
                    render_workspace_dashboard_from_control(control, &session_id, !no_color)?;
                writer.write_all(rendered.as_bytes())?;
            }
            command if command.starts_with('/') => {
                writeln!(
                    writer,
                    "{}",
                    row(!no_color, format!("unknown command: {command}"))
                )?;
                write_chat_help(writer, !no_color)?;
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
                writeln!(
                    writer,
                    "{}",
                    row(!no_color, format!("recorded seq {}", event.seq))
                )?;
            }
            _ => {
                let runtime = runtime
                    .as_ref()
                    .expect("assistant runtime is initialized unless --no-assistant is set");
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
                write_chat_message(writer, "assistant", &reply, !no_color)?;
            }
        }
    }

    Ok(())
}

fn write_chat_header(
    writer: &mut impl Write,
    session_id: &SessionId,
    provider: CliModelProvider,
    model: Option<&str>,
    agent: Option<&ChatAgentConfig>,
    system_prompt: Option<&str>,
    color: bool,
) -> Result<(), CliError> {
    writer.write_all(brand_header("ESSENCE AGENT CHAT", "snow pixel console", color).as_bytes())?;
    writeln!(
        writer,
        "{}",
        row(color, format!("Essence chat session: {}", session_id.0))
    )?;
    writeln!(
        writer,
        "{}",
        row(
            color,
            key_value(color, "provider", model_provider_label(provider))
        )
    )?;
    writeln!(
        writer,
        "{}",
        row(
            color,
            key_value(color, "model", model.unwrap_or("local ledger"))
        )
    )?;
    if let Some(agent) = agent {
        writeln!(
            writer,
            "{}",
            row(
                color,
                format!(
                    "{}   {}   {}",
                    key_value(color, "agent", &agent.agent_id),
                    key_value(color, "lane", &agent.lane),
                    key_value(color, "role", &agent.role)
                )
            )
        )?;
    }
    let prompt_status = if system_prompt.is_some() {
        status_chip(color, "SYSTEM PROMPT", "green")
    } else {
        status_chip(color, "DEFAULT BEHAVIOR", "yellow")
    };
    writeln!(
        writer,
        "{}",
        row(color, key_value(color, "behavior", &prompt_status))
    )?;
    writeln!(writer, "{}", mid(color))?;
    Ok(())
}

fn write_chat_help(writer: &mut impl Write, color: bool) -> Result<(), CliError> {
    let reset = reset(color);
    let ice = style(color, "ice");
    writeln!(
        writer,
        "{}",
        row(
            color,
            format!("{ice}commands{reset}  /office board   /help commands   /exit quit")
        )
    )?;
    writeln!(writer, "{}", mid(color))?;
    Ok(())
}

fn write_chat_message(
    writer: &mut impl Write,
    role: &str,
    text: &str,
    color: bool,
) -> Result<(), CliError> {
    let tone = if role == "assistant" { "cyan" } else { "moon" };
    let chip = status_chip(color, role, tone);
    for (index, line) in text.lines().enumerate() {
        if index == 0 {
            writeln!(writer, "{role}> {line}")?;
        } else {
            writeln!(writer, "        {line}")?;
        }
    }
    writeln!(
        writer,
        "{}",
        row(color, format!("{chip} response sealed to ledger"))
    )?;
    Ok(())
}

fn model_provider_label(provider: CliModelProvider) -> &'static str {
    match provider {
        CliModelProvider::Local => "local",
        CliModelProvider::Command => "command",
        CliModelProvider::OpenaiCompatible => "openai-compatible",
    }
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

fn projected_session_model(
    control: &ControlPlane,
    session_id: &SessionId,
) -> Result<Option<String>, CliError> {
    Ok(control
        .projection(session_id)?
        .session
        .and_then(|session| non_empty(session.model)))
}

fn resolve_system_prompt(
    cli_prompt: Option<String>,
    cli_prompt_file: Option<std::path::PathBuf>,
    agent_profile: Option<&StoredAgentProfile>,
) -> Result<Option<String>, CliError> {
    if let Some(prompt) = non_empty(cli_prompt) {
        return Ok(Some(prompt));
    }
    if let Some(path) = cli_prompt_file {
        return read_prompt_file(&path).map(Some);
    }
    match agent_profile {
        Some(profile) => profile.system_prompt_text(),
        None => Ok(None),
    }
}

fn resolve_model_provider(
    cli_provider: Option<CliModelProvider>,
    cli_model_command: Option<&str>,
    agent_provider: Option<&str>,
    stored_provider: Option<&str>,
    model_command: Option<&str>,
) -> Result<CliModelProvider, String> {
    if let Some(provider) = cli_provider {
        return Ok(provider);
    }
    if cli_model_command.is_some_and(|command| !command.trim().is_empty()) {
        return Ok(CliModelProvider::Command);
    }
    if let Some(provider) = env_var_non_empty("ESSENCE_MODEL_PROVIDER") {
        return parse_model_provider(&provider);
    }
    if let Some(provider) = agent_provider {
        return parse_model_provider(provider);
    }
    if let Some(provider) = stored_provider {
        return parse_model_provider(provider);
    }
    if model_command.is_some_and(|command| !command.trim().is_empty()) {
        return Ok(CliModelProvider::Command);
    }
    Ok(CliModelProvider::Local)
}

fn parse_model_provider(raw: &str) -> Result<CliModelProvider, String> {
    let normalized = raw.trim().to_ascii_lowercase().replace('_', "-");
    match normalized.as_str() {
        "local" => Ok(CliModelProvider::Local),
        "command" => Ok(CliModelProvider::Command),
        "openai" | "openai-compatible" => Ok(CliModelProvider::OpenaiCompatible),
        _ => Err(format!(
            "unsupported ESSENCE_MODEL_PROVIDER `{raw}`; expected local, command, or openai-compatible"
        )),
    }
}

fn resolve_model_api_key(model_api_key_env: Option<String>) -> Result<Option<String>, String> {
    if let Some(env_name) = non_empty(model_api_key_env) {
        return std::env::var(&env_name)
            .ok()
            .and_then(|value| non_empty(Some(value)))
            .map(Some)
            .ok_or_else(|| format!("model api key env var `{env_name}` is not set"));
    }

    for env_name in ["ESSENCE_MODEL_API_KEY", "OPENAI_API_KEY"] {
        if let Some(value) = env_var_non_empty(env_name) {
            return Ok(Some(value));
        }
    }
    Ok(None)
}

fn env_var_non_empty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .and_then(|value| non_empty(Some(value)))
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

#[derive(Debug, Clone)]
struct ChatModel {
    backend: ChatModelBackend,
    system_prompt: Option<String>,
}

#[derive(Debug, Clone)]
enum ChatModelBackend {
    Local(LocalChatModel),
    Command(CommandChatModel),
    OpenAiCompatible(OpenAiCompatibleChatModel),
}

impl ChatModel {
    fn new(
        provider: CliModelProvider,
        model_command: Option<String>,
        openai_config: OpenAiCompatibleConfig,
        limits: ModelAdapterLimits,
        system_prompt: Option<String>,
    ) -> Result<Self, String> {
        let backend = match provider {
            CliModelProvider::Local => ChatModelBackend::Local(LocalChatModel),
            CliModelProvider::Command => {
                let command = model_command.ok_or_else(|| {
                    "command model provider requires --model-command or ESSENCE_CHAT_MODEL_CMD"
                        .to_string()
                })?;
                ChatModelBackend::Command(CommandChatModel { command, limits })
            }
            CliModelProvider::OpenaiCompatible => {
                let model = openai_config.model.ok_or_else(|| {
                    "openai-compatible model provider requires --model or ESSENCE_MODEL".to_string()
                })?;
                ChatModelBackend::OpenAiCompatible(OpenAiCompatibleChatModel {
                    model,
                    base_url: openai_config.base_url,
                    api_key: openai_config.api_key,
                    limits,
                })
            }
        };
        Ok(Self {
            backend,
            system_prompt,
        })
    }
}

impl ModelClient for ChatModel {
    fn complete(&self, request: ModelRequest) -> Result<ModelResponse, String> {
        let request = match &self.system_prompt {
            Some(prompt) => request_with_system_prompt(request, prompt),
            None => request,
        };
        match &self.backend {
            ChatModelBackend::Local(model) => model.complete(request),
            ChatModelBackend::Command(model) => model.complete(request),
            ChatModelBackend::OpenAiCompatible(model) => model.complete(request),
        }
    }
}

fn request_with_system_prompt(mut request: ModelRequest, prompt: &str) -> ModelRequest {
    if prompt.trim().is_empty() {
        return request;
    }
    request.messages.insert(
        0,
        MessagePayload {
            role: MessageRole::System,
            content: vec![ContentBlock::Text {
                text: prompt.trim().to_string(),
            }],
            usage: None,
            origin: Some("agent_profile".to_string()),
        },
    );
    request
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
    limits: ModelAdapterLimits,
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
struct ModelAdapterLimits {
    timeout: Duration,
    max_response_bytes: usize,
    max_stdout_bytes: usize,
    max_stderr_bytes: usize,
}

#[derive(Debug, Clone)]
struct OpenAiCompatibleConfig {
    model: Option<String>,
    base_url: String,
    api_key: Option<String>,
}

#[derive(Debug, Clone)]
struct OpenAiCompatibleChatModel {
    model: String,
    base_url: String,
    api_key: Option<String>,
    limits: ModelAdapterLimits,
}

impl ModelClient for OpenAiCompatibleChatModel {
    fn complete(&self, request: ModelRequest) -> Result<ModelResponse, String> {
        let body = json!({
            "model": &self.model,
            "messages": render_openai_messages(&request.messages),
            "stream": false,
        });
        let raw = post_openai_chat_completion(
            &self.base_url,
            self.api_key.as_deref(),
            body,
            self.limits,
        )?;
        parse_openai_chat_completion_response(&raw)
    }
}

fn render_openai_messages(messages: &[MessagePayload]) -> Vec<Value> {
    messages
        .iter()
        .filter_map(|message| {
            let content = render_openai_message_content(message);
            if content.trim().is_empty() {
                None
            } else {
                Some(json!({
                    "role": openai_message_role(&message.role),
                    "content": content,
                }))
            }
        })
        .collect()
}

fn openai_message_role(role: &MessageRole) -> &'static str {
    match role {
        MessageRole::System => "system",
        MessageRole::User => "user",
        MessageRole::Assistant => "assistant",
        MessageRole::Tool => "user",
    }
}

fn render_openai_message_content(message: &MessagePayload) -> String {
    let mut parts = Vec::new();
    for content in &message.content {
        match content {
            ContentBlock::Text { text } if !text.trim().is_empty() => parts.push(text.clone()),
            ContentBlock::ToolUse { name, input, .. } => {
                parts.push(format!("tool use `{name}`: {input}"));
            }
            ContentBlock::ToolResult {
                result, is_error, ..
            } => {
                let label = if *is_error {
                    "tool result error"
                } else {
                    "tool result"
                };
                parts.push(format!("{label}: {result}"));
            }
            ContentBlock::File { uri, .. } => parts.push(format!("file: {uri}")),
            ContentBlock::Image { uri, .. } => parts.push(format!("image: {uri}")),
            _ => {}
        }
    }
    parts.join("\n")
}

fn post_openai_chat_completion(
    base_url: &str,
    api_key: Option<&str>,
    body: Value,
    limits: ModelAdapterLimits,
) -> Result<String, String> {
    let url = format!("{}/chat/completions", base_url.trim_end_matches('/'));
    let agent = ureq::AgentBuilder::new().timeout(limits.timeout).build();
    let mut request = agent
        .post(&url)
        .set("Accept", "application/json")
        .set("Content-Type", "application/json");
    if let Some(api_key) = api_key.filter(|value| !value.trim().is_empty()) {
        request = request.set("Authorization", &format!("Bearer {api_key}"));
    }

    let body = serde_json::to_string(&body)
        .map_err(|error| format!("could not encode request: {error}"))?;
    match request.send_string(&body) {
        Ok(response) => {
            let (body, truncated) =
                read_http_response_limited(response, limits.max_response_bytes)?;
            if truncated {
                return Err(format!(
                    "model HTTP response exceeded {} bytes",
                    limits.max_response_bytes
                ));
            }
            Ok(body)
        }
        Err(ureq::Error::Status(status, response)) => {
            let (body, truncated) =
                read_http_response_limited(response, limits.max_response_bytes)?;
            let detail = if body.trim().is_empty() {
                "empty response body".to_string()
            } else {
                truncate(body.trim(), 512)
            };
            let suffix = if truncated { " [truncated]" } else { "" };
            Err(format!(
                "model HTTP request failed with status {status}: {detail}{suffix}"
            ))
        }
        Err(ureq::Error::Transport(error)) => Err(format!("model HTTP request failed: {error}")),
    }
}

fn read_http_response_limited(
    response: ureq::Response,
    limit: usize,
) -> Result<(String, bool), String> {
    let mut reader = response.into_reader();
    let mut bytes = Vec::new();
    let take = limit.saturating_add(1) as u64;
    Read::by_ref(&mut reader)
        .take(take)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("could not read model HTTP response: {error}"))?;
    let truncated = bytes.len() > limit;
    if truncated {
        bytes.truncate(limit);
    }
    Ok((String::from_utf8_lossy(&bytes).to_string(), truncated))
}

fn parse_openai_chat_completion_response(raw: &str) -> Result<ModelResponse, String> {
    let value = serde_json::from_str::<Value>(raw)
        .map_err(|error| format!("could not decode model response: {error}"))?;
    let choice = value
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .ok_or_else(|| "model response did not include choices[0]".to_string())?;
    let text = choice
        .get("message")
        .and_then(|message| message.get("content"))
        .and_then(openai_content_to_text)
        .or_else(|| {
            choice
                .get("text")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .ok_or_else(|| "model response did not include choices[0].message.content".to_string())?;
    if text.trim().is_empty() {
        return Err("model response returned empty assistant content".to_string());
    }

    let mut response = ModelResponse::text(text);
    if let Some(usage) = value.get("usage").cloned() {
        response = response.with_usage(usage);
    }
    if let Some(stop_reason) = choice.get("finish_reason").and_then(Value::as_str) {
        response = response.with_stop_reason(stop_reason);
    }
    Ok(response)
}

fn openai_content_to_text(content: &Value) -> Option<String> {
    match content {
        Value::String(text) => Some(text.clone()),
        Value::Array(items) => {
            let parts = items
                .iter()
                .filter_map(|item| {
                    item.as_str()
                        .map(str::to_string)
                        .or_else(|| item.get("text").and_then(Value::as_str).map(str::to_string))
                })
                .collect::<Vec<_>>();
            if parts.is_empty() {
                None
            } else {
                Some(parts.join("\n"))
            }
        }
        Value::Object(object) => object
            .get("text")
            .and_then(Value::as_str)
            .map(str::to_string),
        Value::Null | Value::Bool(_) | Value::Number(_) => None,
    }
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
    limits: ModelAdapterLimits,
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
    if width == 0 {
        return String::new();
    }
    let mut chars = value.chars();
    let mut output = chars.by_ref().take(width).collect::<String>();
    if chars.next().is_some() && width > 1 {
        output.pop();
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
