use crossterm::{
    event::{self, Event, KeyCode, KeyEvent},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use moxi_contracts::{RiskLevel, ShellAdapterManifest, ShellSurface};
use moxi_core::{file_read_capability, Kernel};
use moxi_runtime::{
    read_only_intent, PlannerStep, ResumeBlocker, RuntimeEventFeedSnapshot, RuntimePolicyProfile,
    RuntimeQuerySnapshot, RuntimeSession,
};
use moxi_shells::{adapter_manifest, ShellController, ShellRequestDraft};
use ratatui::{
    backend::{CrosstermBackend, TestBackend},
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Paragraph, Wrap},
    Terminal,
};
use std::{
    env, fs,
    io::{BufRead, Stdout, Write},
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::Duration,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CliError {
    #[error("unknown command: {0}")]
    UnknownCommand(String),
    #[error("missing value for {0}")]
    MissingValue(&'static str),
    #[error("missing required option: {0}")]
    MissingRequired(&'static str),
    #[error("unknown flag: {0}")]
    UnknownFlag(String),
    #[error("invalid risk level: {0}")]
    InvalidRisk(String),
    #[error("invalid shell surface: {0}")]
    InvalidSurface(String),
    #[error("invalid status render limit: {0}")]
    InvalidLimit(String),
    #[error("invalid watch tick count: {0}")]
    InvalidWatchTicks(String),
    #[error("invalid watch interval milliseconds: {0}")]
    InvalidWatchInterval(String),
    #[error("invalid model provider: {0}")]
    InvalidModelProvider(String),
    #[error("model config already exists: {0}; pass --force to overwrite")]
    ModelConfigExists(String),
    #[error("invalid tui dimension for {flag}: {value}")]
    InvalidTuiDimension { flag: &'static str, value: String },
    #[error("invalid tui key token: {0}")]
    InvalidTuiKey(String),
    #[error("invalid tui poll milliseconds: {0}")]
    InvalidTuiPoll(String),
    #[error("runtime projection graph mismatch: expected {expected}, got {actual}")]
    GraphMismatch { expected: String, actual: String },
    #[error("status input mode conflict; choose only one of --feed or --query")]
    StatusInputConflict,
    #[error("unterminated quoted string in REPL input")]
    UnterminatedQuote,
    #[error("shell error: {0}")]
    Shell(#[from] moxi_shells::ShellError),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type CliResult<T> = Result<T, CliError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Json,
    PrettyJson,
    Text,
    Panel,
}

impl OutputFormat {
    fn is_pretty(self) -> bool {
        matches!(self, Self::PrettyJson)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AdmitOptions {
    tenant_id: String,
    user_id: String,
    workspace_root: String,
    goal: String,
    requested_capabilities: Vec<String>,
    risk_level: RiskLevel,
    session_id: Option<String>,
    request_id: Option<String>,
    source_ref: Option<String>,
    format: OutputFormat,
}

impl AdmitOptions {
    fn into_draft(self) -> ShellRequestDraft {
        let mut draft = ShellRequestDraft::cli_readonly(
            self.tenant_id,
            self.user_id,
            self.workspace_root,
            self.goal,
        );
        if !self.requested_capabilities.is_empty() {
            draft.requested_capabilities = self.requested_capabilities;
        }
        draft.risk_level = self.risk_level;
        draft.session_id = self.session_id;
        draft.request_id = self.request_id;
        draft.source_ref = self.source_ref;
        draft
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManifestOptions {
    surface: ShellSurface,
    format: OutputFormat,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BoundaryOptions {
    surface: ShellSurface,
    format: OutputFormat,
}

#[derive(Debug, serde::Serialize)]
struct BoundaryReport {
    surface: ShellSurface,
    adapter_manifest: ShellAdapterManifest,
    supported_commands: Vec<&'static str>,
    forbidden_commands: Vec<&'static str>,
    trust_boundaries: Vec<&'static str>,
    cannot_execute_directly: bool,
    cannot_authorize: bool,
    cannot_issue_tickets: bool,
    cannot_verify: bool,
    cannot_commit_ledger: bool,
    note: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StatusOptions {
    surface: ShellSurface,
    profile_id: String,
    graph_id: Option<String>,
    input_path: Option<String>,
    allow_demo_input: bool,
    input_mode: StatusInputMode,
    format: OutputFormat,
    render_limit: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WatchOptions {
    status: StatusOptions,
    ticks: usize,
    interval: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InitOptions {
    provider: TuiModelProvider,
    endpoint: String,
    model: String,
    api_key_env: String,
    write: bool,
    force: bool,
    config_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ModelConfigCommandOptions {
    config_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TuiOptions {
    status: StatusOptions,
    width: u16,
    height: u16,
    keys: Vec<TuiKey>,
    interactive: bool,
    poll_interval: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TuiState {
    screen: TuiScreen,
    active_pane: TuiPane,
    session: TuiAgentSession,
    filter: Option<String>,
    command_input: String,
    command_status: String,
    pending_risk: Option<TuiRiskPrompt>,
    conversation_scroll: usize,
    follow_latest_message: bool,
    selected_task_index: usize,
    follow_active_step: bool,
    show_command_palette: bool,
    command_palette_index: usize,
    setup_notice: Option<String>,
    refresh_count: usize,
    should_quit: bool,
}

impl Default for TuiState {
    fn default() -> Self {
        Self {
            screen: TuiScreen::Workspace,
            active_pane: TuiPane::Overview,
            session: TuiAgentSession::default(),
            filter: None,
            command_input: String::new(),
            command_status: "ready: ? shortcuts · / command menu".into(),
            pending_risk: None,
            conversation_scroll: 0,
            follow_latest_message: true,
            selected_task_index: 0,
            follow_active_step: true,
            show_command_palette: false,
            command_palette_index: 0,
            setup_notice: None,
            refresh_count: 0,
            should_quit: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct TuiAgentSession {
    id: String,
    mode: TuiSessionMode,
    workspace: WorkspaceFacts,
    trust: TuiTrustState,
    agents: Vec<TuiAgentProfile>,
    model_config: TuiModelConfig,
    skills: Vec<String>,
    tools: Vec<String>,
    messages: Vec<TuiMessage>,
    steps: Vec<TuiStep>,
    active_step_index: usize,
    loading_tick: usize,
    #[serde(skip)]
    pending_reply: Option<TuiPendingReply>,
    turn_count: usize,
}

impl Default for TuiAgentSession {
    fn default() -> Self {
        let workspace = WorkspaceFacts::detect();
        let agents = TuiAgentProfile::load_for_workspace(&workspace);
        let model_config = TuiModelConfig::load_for_workspace(&workspace);
        let model_config_state = model_config.config_state.clone();
        Self {
            id: "local-r10-demo-session".to_owned(),
            mode: TuiSessionMode::ReadOnly,
            workspace: workspace.clone(),
            trust: TuiTrustState::from_workspace(&workspace),
            agents,
            model_config,
            skills: vec![
                "tui.design".to_owned(),
                "risk.review".to_owned(),
                "docs.prepare".to_owned(),
                "github.prepare".to_owned(),
            ],
            tools: vec![
                "file.read".to_owned(),
                "repo.inspect".to_owned(),
                "git.status".to_owned(),
                "context.trace".to_owned(),
            ],
            messages: vec![
                TuiMessage {
                    agent: "moxi-agent".to_owned(),
                    role: "orchestrator".to_owned(),
                    body: format!(
                        "I opened a guarded read-only session for {}.",
                        workspace.summary()
                    ),
                    task: None,
                    metadata: TuiMessageMeta::new(
                        "session-local",
                        "medium",
                        ["workspace.probe"],
                        "boundary: read-only display",
                    ),
                    state: TuiMessageState::Complete,
                },
                TuiMessage {
                    agent: "guard-agent".to_owned(),
                    role: "risk".to_owned(),
                    body: format!(
                        "Startup is waiting for owner-controlled handoff before workbench use. Model/API config is {}.",
                        model_config_state
                    ),
                    task: None,
                    metadata: TuiMessageMeta::new(
                        "guard",
                        "medium",
                        ["trust.boundary"],
                        "boundary: P2 display-only",
                    ),
                    state: TuiMessageState::Waiting,
                },
            ],
            steps: vec![
                TuiStep::done(1, "Create session shell", "TUI state is resident"),
                TuiStep::active(
                    1,
                    "Collect workspace facts",
                    "cwd/config/mode are available to the workbench",
                ),
                TuiStep::pending(
                    1,
                    "Wait for task input",
                    "next turn will bind input to session",
                ),
            ],
            active_step_index: 1,
            loading_tick: 0,
            pending_reply: None,
            turn_count: 1,
        }
    }
}

impl TuiAgentSession {
    const PERSISTENCE_SCHEMA_VERSION: u8 = 1;

    fn push_system_message(&mut self, topic: &str, body: String) {
        let meta = self.agent_meta(
            "moxi-agent",
            ["session.state"],
            "boundary: read-only display",
        );
        self.messages.push(TuiMessage {
            agent: "moxi-agent".to_owned(),
            role: topic.to_owned(),
            body,
            task: None,
            metadata: meta,
            state: TuiMessageState::Complete,
        });
    }

    fn push_status_message(&mut self) {
        self.push_system_message(
            "status",
            format!(
                "Session {} is {} in {}. git={}, cargo={}, config={}, docs={}, steps={}.",
                self.id,
                self.mode.label(),
                self.workspace.short_path,
                self.workspace.git_state,
                self.workspace.cargo_state,
                self.workspace.config_state,
                self.workspace.docs_state,
                self.steps.len()
            ),
        );
    }

    fn push_tasks_message(&mut self) {
        let active = self
            .steps
            .get(self.active_step_index)
            .map(|step| format!("Turn {} / {}", step.turn, step.label))
            .unwrap_or_else(|| "<none>".to_owned());
        self.push_system_message(
            "tasks",
            format!(
                "Task Tracking has {} session steps; active step is {}.",
                self.steps.len(),
                active
            ),
        );
    }

    fn push_agents_message(&mut self) {
        let agents = self
            .agents
            .iter()
            .map(TuiAgentProfile::summary)
            .collect::<Vec<_>>()
            .join("; ");
        self.push_system_message("agents", format!("Active agents: {agents}."));
    }

    fn push_skills_message(&mut self) {
        self.push_system_message(
            "skills",
            format!(
                "Loaded skills: {}. Available tools: {}.",
                self.skills.join(", "),
                self.tools.join(", ")
            ),
        );
    }

    fn push_context_message(&mut self) {
        let snapshot = self.context_snapshot();
        let sources = snapshot
            .sources
            .iter()
            .map(|source| format!("{}={} ({})", source.label, source.state, source.detail))
            .collect::<Vec<_>>()
            .join("; ");
        self.push_system_message(
            "context",
            format!(
                "Context meter is {}%. Sources: {sources}.",
                snapshot.percent
            ),
        );
    }

    fn push_config_message(&mut self) {
        self.model_config = TuiModelConfig::load_for_workspace(&self.workspace);
        self.push_system_message(
            "config",
            format!(
                "Model/API config: provider={}, endpoint={}, model={}, config={} ({}) key={}. Configured sessions use the read-only OpenAI-compatible chat adapter; failures fall back to local analysis without secrets.",
                self.model_config.provider.label(),
                self.model_config.endpoint,
                self.model_config.model,
                self.model_config.config_path,
                self.model_config.config_state,
                self.model_config.api_key_source.summary()
            ),
        );
    }

    fn setup_config_notice(&mut self) -> String {
        self.model_config = TuiModelConfig::load_for_workspace(&self.workspace);
        format!(
            "config: provider={} endpoint={} model={} config={} ({}) key={}",
            self.model_config.provider.label(),
            self.model_config.endpoint,
            self.model_config.model,
            self.model_config.config_path,
            self.model_config.config_state,
            self.model_config.api_key_source.summary()
        )
    }

    fn push_doctor_message(&mut self) -> TuiDoctorStatus {
        self.model_config = TuiModelConfig::load_for_workspace(&self.workspace);
        let report = TuiModelDoctor::check(&self.model_config);
        self.push_system_message("doctor", report.message());
        report.status
    }

    fn setup_doctor_notice(&mut self) -> String {
        self.model_config = TuiModelConfig::load_for_workspace(&self.workspace);
        let report = TuiModelDoctor::check(&self.model_config);
        format!(
            "doctor: status={} detail={} action={}",
            report.status.label(),
            report.detail,
            report.action
        )
    }

    fn push_models_message(&mut self) -> TuiModelCatalogStatus {
        self.model_config = TuiModelConfig::load_for_workspace(&self.workspace);
        let report = TuiModelCatalog::list(&self.model_config);
        self.push_system_message("models", report.message());
        report.status
    }

    fn setup_models_notice(&mut self) -> String {
        self.model_config = TuiModelConfig::load_for_workspace(&self.workspace);
        let report = TuiModelCatalog::list(&self.model_config);
        let models = if report.models.is_empty() {
            "<none>".to_owned()
        } else {
            report.models.join(", ")
        };
        format!(
            "models: status={} available={} detail={} action={}",
            report.status.label(),
            models,
            report.detail,
            report.action
        )
    }

    fn write_setup_model_config(&mut self) -> Result<String, String> {
        self.model_config = TuiModelConfig::load_for_workspace(&self.workspace);
        let path = PathBuf::from(&self.model_config.config_path);
        if path.exists() {
            return Err(format!(
                "init: config already exists at {}; use top-level moxi init --force outside the TUI if you really want to replace it",
                path.display()
            ));
        }
        let model = if self.model_config.model == "not-configured" {
            default_init_model(self.model_config.provider)
        } else {
            &self.model_config.model
        };
        let template = render_model_config_template(
            self.model_config.provider,
            &self.model_config.endpoint,
            model,
            self.model_config.provider.default_key_env(),
        );
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "init: failed to create config directory {}: {error}",
                    parent.display()
                )
            })?;
        }
        fs::write(&path, template.as_bytes())
            .map_err(|error| format!("init: failed to write {}: {error}", path.display()))?;
        self.model_config = TuiModelConfig::load_for_workspace(&self.workspace);
        Ok(format!(
            "init: wrote env-only config to {}; provider={} endpoint={} model={} api_key_env={}; set the environment variable, then run /doctor",
            path.display(),
            self.model_config.provider.label(),
            self.model_config.endpoint,
            self.model_config.model,
            self.model_config.provider.default_key_env()
        ))
    }

    fn push_resume_message(&mut self, snapshot: &TuiSessionSnapshot) {
        self.push_system_message(
            "resume",
            format!(
                "Found persisted TUI snapshot schema={} session={} turn={} messages={} steps={} context={}%. It was read as local state only; current session was not overwritten.",
                snapshot.schema_version,
                snapshot.session_id,
                snapshot.turn_count,
                snapshot.messages.len(),
                snapshot.steps.len(),
                snapshot.context_percent
            ),
        );
    }

    fn push_trust_message(&mut self) {
        let reasons = self.trust.reasons.join("; ");
        self.push_system_message(
            "trust",
            format!(
                "Workspace trust is {}. Decision: {}. Reasons: {}.",
                self.trust.status.label(),
                self.trust.decision_label(),
                reasons
            ),
        );
    }

    fn approve_read_only_trust(&mut self) {
        self.trust.status = TuiTrustStatus::TrustedReadOnly;
        self.trust.reasons = vec![
            "owner accepted this workspace for read-only TUI inspection".to_owned(),
            "writes, shell commands, Git/GitHub, tickets, proofs, and ledger commits remain P0-gated"
                .to_owned(),
        ];
    }

    fn deny_trust(&mut self) {
        self.trust.status = TuiTrustStatus::Denied;
        self.trust.reasons = vec![
            "owner denied workspace trust intent for this local TUI session".to_owned(),
            "P2 shell will keep risky actions blocked".to_owned(),
        ];
    }

    fn context_snapshot(&self) -> TuiContextSnapshot {
        let sources = vec![
            TuiContextSource::available("cwd", "present", &self.workspace.cwd, 10),
            TuiContextSource::new(
                "git",
                &self.workspace.git_state,
                "branch and dirty-state summary",
                !self.workspace.git_state.contains("not a git repo")
                    && !self.workspace.git_state.contains("unavailable")
                    && !self.workspace.git_state.contains("failed"),
                12,
            ),
            TuiContextSource::new(
                "cargo",
                &self.workspace.cargo_state,
                "workspace/package summary",
                !self.workspace.cargo_state.contains("missing"),
                14,
            ),
            TuiContextSource::new(
                "docs/status.md",
                &self.workspace.docs_state,
                "project status document",
                self.workspace.docs_state == "present",
                14,
            ),
            TuiContextSource::new(
                ".moxi/agents.toml",
                &self.workspace.config_state,
                "agent configuration source",
                self.workspace.config_state == "present",
                12,
            ),
            TuiContextSource::new(
                ".moxi/config.toml",
                &self.model_config.config_state,
                "model/API configuration source",
                self.model_config.is_configured(),
                8,
            ),
            TuiContextSource::available(
                "active agents",
                &format!("{} profiles", self.agents.len()),
                "runtime or fallback agent roster",
                10,
            ),
            TuiContextSource::available(
                "messages",
                &format!("{} messages", self.messages.len()),
                "current conversation window",
                14,
            ),
            TuiContextSource::available(
                "steps",
                &format!("{} steps", self.steps.len()),
                "task tracking state",
                14,
            ),
        ];
        TuiContextSnapshot::from_sources(sources)
    }

    fn submit_user_task(&mut self, task: &str) {
        let task = task.trim();
        if task.is_empty() {
            return;
        }

        self.turn_count += 1;
        let turn = self.turn_count;
        self.messages.push(TuiMessage {
            agent: "owner".to_owned(),
            role: "user".to_owned(),
            body: task.to_owned(),
            task: None,
            metadata: TuiMessageMeta::new(
                "owner-input",
                "none",
                ["local.tui"],
                "source: input task",
            ),
            state: TuiMessageState::Complete,
        });
        self.messages.push(TuiMessage {
            agent: "moxi-agent".to_owned(),
            role: "orchestrator".to_owned(),
            body: format!(
                "Turn {turn} is streaming: reading workspace facts and preparing a read-only model response..."
            ),
            task: Some(task.to_owned()),
            metadata: self.agent_meta("moxi-agent", ["task.plan"], "state: streaming"),
            state: TuiMessageState::Streaming,
        });

        self.steps.push(TuiStep::done(
            turn,
            "Capture user task",
            "input was appended to the session message stream",
        ));
        self.steps.push(TuiStep::active(
            turn,
            "Gather read-only context",
            "workspace facts and conversation metadata are packaged for the adapter",
        ));
        self.steps.push(TuiStep::pending(
            turn,
            "Request model response",
            "configured OpenAI-compatible chat adapter is preferred; local fallback remains read-only",
        ));
        self.active_step_index = self.steps.len().saturating_sub(2);
        self.loading_tick = 0;
        self.pending_reply = None;
    }

    fn advance_loading(&mut self) {
        let Some(message_index) = self
            .messages
            .iter()
            .rposition(|message| message.state == TuiMessageState::Streaming)
        else {
            return;
        };
        self.loading_tick = self.loading_tick.saturating_add(1);
        let turn = self.turn_count;
        if self.loading_tick < 3 {
            let frame = loading_frame(self.loading_tick);
            let message = &mut self.messages[message_index];
            message.body = format!(
                "{frame} Turn {turn} streaming: reading workspace facts, checking risk, and preparing model context..."
            );
            message.metadata.status = format!("stream tick {}", self.loading_tick);
            return;
        }

        if self.pending_reply.is_none() {
            let workspace = self.workspace.clone();
            let trust = self.trust.status;
            let agents = self.agents.clone();
            let skills = self.skills.clone();
            let tools = self.tools.clone();
            let context_percent = self.context_snapshot().percent;
            let task = self.messages[message_index]
                .task
                .as_deref()
                .unwrap_or("<unknown task>");
            let request = TuiBackendRequest {
                turn,
                task,
                workspace: &workspace,
                trust,
                agents: &agents,
                skills: &skills,
                tools: &tools,
                context_percent,
            };
            let response = ModelBackedReadOnlyBackend::new(&self.model_config)
                .respond(request)
                .unwrap_or_else(|error| ReadOnlyWorkspaceBackend.respond_with_note(request, error));
            if let Some(step) = self.steps.get_mut(self.active_step_index) {
                step.state = TuiStepState::Done;
                step.detail = response.completed_step_detail.clone();
            }
            if let Some(step) = self.steps.get_mut(self.active_step_index.saturating_add(1)) {
                step.state = TuiStepState::Active;
                step.label = "Receive model response".to_owned();
                step.detail =
                    "adapter response is ready; staged rendering is appending chunks".to_owned();
            }
            self.pending_reply = Some(TuiPendingReply::from_response(turn, response));
        }

        let done = {
            let pending = self
                .pending_reply
                .as_mut()
                .expect("pending reply is initialized above");
            let message = &mut self.messages[message_index];
            message.agent = pending.response.agent.clone();
            message.role = pending.response.role.clone();
            message.metadata = pending.response.metadata.clone();
            message.body = pending.render_next_chunk(loading_frame(self.loading_tick));
            message.metadata.status = format!(
                "stream chunk {}/{} | backend: {}",
                pending.cursor,
                pending.chunks.len(),
                pending.response.plan.source
            );
            pending.is_done()
        };

        if done {
            let Some(pending) = self.pending_reply.take() else {
                return;
            };
            let message = &mut self.messages[message_index];
            message.body = pending.response.body.clone();
            message.metadata = pending.response.metadata.clone();
            message.state = TuiMessageState::Complete;
            let plan = pending.response.plan;
            self.append_backend_plan_steps(turn, plan, pending.response.next_step_detail);
        }
    }

    fn append_backend_plan_steps(
        &mut self,
        turn: usize,
        plan: TuiBackendPlan,
        next_step_detail: String,
    ) {
        if let Some(existing) = self.steps.get_mut(self.active_step_index.saturating_add(1)) {
            existing.state = TuiStepState::Done;
            existing.label = format!("Backend plan {}", plan.plan_id);
            existing.detail = format!(
                "{} produced {} local steps; blocked authority: {}",
                plan.source,
                plan.steps.len(),
                plan.blocked_authority.join(",")
            );
        }
        for plan_step in plan.steps {
            self.steps.push(TuiStep::done(
                turn,
                &format!("Plan: {}", plan_step.label),
                &plan_step.detail,
            ));
        }
        self.steps.push(TuiStep::active(
            turn,
            "Await P1/P0 adapter",
            &next_step_detail,
        ));
        self.active_step_index = self.steps.len().saturating_sub(1);
    }

    fn is_streaming(&self) -> bool {
        self.messages
            .iter()
            .any(|message| message.state == TuiMessageState::Streaming)
    }

    fn agent_meta<const N: usize>(
        &self,
        agent_name: &str,
        tools: [&str; N],
        status: &str,
    ) -> TuiMessageMeta {
        if let Some(agent) = self.agents.iter().find(|agent| agent.name == agent_name) {
            TuiMessageMeta::new(&agent.model, &agent.reasoning, tools, status)
        } else {
            TuiMessageMeta::new("session-local", "medium", tools, status)
        }
    }

    fn persistence_snapshot(&self) -> TuiSessionSnapshot {
        let context = self.context_snapshot();
        TuiSessionSnapshot {
            schema_version: Self::PERSISTENCE_SCHEMA_VERSION,
            session_id: self.id.clone(),
            mode: self.mode,
            workspace: self.workspace.clone(),
            trust: self.trust.clone(),
            context_percent: context.percent,
            context_sources: context.sources,
            messages: self.messages.clone(),
            steps: self.steps.clone(),
            active_step_index: self.active_step_index,
            turn_count: self.turn_count,
        }
    }

    fn persistence_path(&self) -> PathBuf {
        Path::new(&self.workspace.cwd)
            .join(".moxi")
            .join("session")
            .join("tui-session.json")
    }

    fn save_persistence_snapshot(&self) -> CliResult<PathBuf> {
        let path = self.persistence_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&self.persistence_snapshot())?;
        fs::write(&path, json)?;
        Ok(path)
    }

    fn load_persistence_snapshot(path: &Path) -> CliResult<TuiSessionSnapshot> {
        let text = fs::read_to_string(path)?;
        Ok(serde_json::from_str(&text)?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct TuiSessionSnapshot {
    schema_version: u8,
    session_id: String,
    mode: TuiSessionMode,
    workspace: WorkspaceFacts,
    trust: TuiTrustState,
    context_percent: u8,
    context_sources: Vec<TuiContextSource>,
    messages: Vec<TuiMessage>,
    steps: Vec<TuiStep>,
    active_step_index: usize,
    turn_count: usize,
}

struct TuiBackendRequest<'a> {
    turn: usize,
    task: &'a str,
    workspace: &'a WorkspaceFacts,
    trust: TuiTrustStatus,
    agents: &'a [TuiAgentProfile],
    skills: &'a [String],
    tools: &'a [String],
    context_percent: u8,
}

impl<'a> Copy for TuiBackendRequest<'a> {}

impl<'a> Clone for TuiBackendRequest<'a> {
    fn clone(&self) -> Self {
        *self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TuiBackendResponse {
    agent: String,
    role: String,
    body: String,
    metadata: TuiMessageMeta,
    plan: TuiBackendPlan,
    completed_step_detail: String,
    next_step_detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TuiPendingReply {
    response: TuiBackendResponse,
    chunks: Vec<String>,
    cursor: usize,
}

impl TuiPendingReply {
    fn from_response(turn: usize, response: TuiBackendResponse) -> Self {
        let chunks = staged_reply_chunks(&response.body);
        let chunks = if chunks.is_empty() {
            vec![format!("Turn {turn} received an empty model reply.")]
        } else {
            chunks
        };
        Self {
            response,
            chunks,
            cursor: 0,
        }
    }

    fn render_next_chunk(&mut self, frame: &str) -> String {
        if self.cursor < self.chunks.len() {
            self.cursor += 1;
        }
        let visible = self.chunks[..self.cursor].join("");
        if self.is_done() {
            visible
        } else {
            format!(
                "{}{} {}",
                visible,
                if visible.ends_with('\n') { "" } else { "\n" },
                frame
            )
        }
    }

    fn is_done(&self) -> bool {
        self.cursor >= self.chunks.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TuiBackendPlan {
    plan_id: String,
    source: String,
    steps: Vec<TuiBackendPlanStep>,
    blocked_authority: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TuiBackendPlanStep {
    label: String,
    detail: String,
}

trait TuiAgentBackend {
    fn respond(&self, request: TuiBackendRequest<'_>) -> TuiBackendResponse;
}

struct ReadOnlyWorkspaceBackend;

impl ReadOnlyWorkspaceBackend {
    fn respond_with_note(
        &self,
        request: TuiBackendRequest<'_>,
        adapter_note: String,
    ) -> TuiBackendResponse {
        let mut response = self.respond(request);
        response.body = format!(
            "{} Model adapter fallback: {}",
            response.body,
            redacted_preview(&adapter_note, 180)
        );
        let status = response.metadata.status.clone();
        response.metadata.status = format!("{status} | model fallback");
        response.plan.steps.insert(
            2,
            TuiBackendPlanStep {
                label: "Model adapter fallback".to_owned(),
                detail: redacted_preview(&adapter_note, 180),
            },
        );
        response
    }
}

impl TuiAgentBackend for ReadOnlyWorkspaceBackend {
    fn respond(&self, request: TuiBackendRequest<'_>) -> TuiBackendResponse {
        let agent = request
            .agents
            .iter()
            .find(|agent| agent.name == "moxi-agent")
            .or_else(|| request.agents.first());
        let agent_name = agent
            .map(|agent| agent.name.clone())
            .unwrap_or_else(|| "moxi-agent".to_owned());
        let role = agent
            .map(|agent| agent.role.clone())
            .unwrap_or_else(|| "orchestrator".to_owned());
        let model = agent
            .map(|agent| agent.model.as_str())
            .unwrap_or("session-local");
        let reasoning = agent
            .map(|agent| agent.reasoning.as_str())
            .unwrap_or("medium");
        let mut response_tools = vec![
            "workspace.probe".to_owned(),
            "context.trace".to_owned(),
            "risk.boundary".to_owned(),
        ];
        if request.tools.iter().any(|tool| tool == "git.status") {
            response_tools.push("git.status".to_owned());
        }
        let plan = RuntimePlanningAdapter
            .plan(&request)
            .unwrap_or_else(|| read_only_backend_plan(&request));
        let body = read_only_project_analysis(&request, &plan);

        TuiBackendResponse {
            agent: agent_name,
            role,
            body,
            metadata: TuiMessageMeta::from_tools(
                model,
                reasoning,
                response_tools,
                "state: complete | backend: read-only workspace",
            ),
            plan,
            completed_step_detail:
                "read-only backend response prepared; no execution authority was used".to_owned(),
            next_step_detail: "waiting for a real P1/P0 backend adapter or owner command"
                .to_owned(),
        }
    }
}

struct ModelBackedReadOnlyBackend<'a> {
    config: &'a TuiModelConfig,
}

impl<'a> ModelBackedReadOnlyBackend<'a> {
    fn new(config: &'a TuiModelConfig) -> Self {
        Self { config }
    }

    fn respond(&self, request: TuiBackendRequest<'_>) -> Result<TuiBackendResponse, String> {
        if self.config.needs_setup() {
            return Err(format!(
                "model/API config is {}; run /config or /doctor before API-backed chat",
                self.config.config_state
            ));
        }
        if self.config.endpoint == "not-configured" || !self.config.endpoint.starts_with("http") {
            return Err(
                "model endpoint must be an http:// or https:// OpenAI-compatible /v1 base URL"
                    .to_owned(),
            );
        }
        let Some(secret) = self.config.secret() else {
            return Err(format!(
                "{} is redacted but not available to this process",
                self.config.api_key_source.summary()
            ));
        };

        let prompt = build_read_only_chat_prompt(request);
        let reply = post_openai_chat_completion(
            &self.config.endpoint,
            &self.config.model,
            &secret,
            &prompt,
        )?;
        let agent = request
            .agents
            .iter()
            .find(|agent| agent.name == "moxi-agent")
            .or_else(|| request.agents.first());
        let agent_name = agent
            .map(|agent| agent.name.clone())
            .unwrap_or_else(|| "moxi-agent".to_owned());
        let role = agent
            .map(|agent| agent.role.clone())
            .unwrap_or_else(|| "orchestrator".to_owned());
        let reasoning = agent
            .map(|agent| agent.reasoning.as_str())
            .unwrap_or("medium");
        let plan = read_only_model_plan(request, self.config.provider.label());

        Ok(TuiBackendResponse {
            agent: agent_name,
            role,
            body: reply,
            metadata: TuiMessageMeta::new(
                &self.config.model,
                reasoning,
                ["model.chat", "context.pack", "risk.boundary"],
                "state: complete | backend: read-only model",
            ),
            plan,
            completed_step_detail:
                "read-only context packaged; no file write, shell, Git/GitHub, ticket, proof, or ledger authority was used"
                    .to_owned(),
            next_step_detail:
                "model replied in read-only mode; wait for owner intent or trusted P0 adapter"
                    .to_owned(),
        })
    }
}

#[derive(Default)]
struct RuntimePlanningAdapter;

impl RuntimePlanningAdapter {
    fn plan(&self, request: &TuiBackendRequest<'_>) -> Option<TuiBackendPlan> {
        let mut kernel = Kernel::new_in_memory(&request.workspace.cwd).ok()?;
        kernel.register_capability(file_read_capability()).ok()?;
        let runtime = RuntimeSession::new(kernel)
            .with_policy_profile(RuntimePolicyProfile::shell_ide_readonly());
        let intent = read_only_intent(request.task, &request.workspace.cwd, "file.read");
        let planner = runtime.planner_plan(&intent).ok()?;
        let steps = runtime_planner_steps_to_tui(request, &planner.steps);
        Some(TuiBackendPlan {
            plan_id: format!("runtime-{}", planner.plan_id),
            source: format!("runtime-planner:{:?}", planner.source),
            steps,
            blocked_authority: blocked_p2_authority(),
        })
    }
}

fn runtime_planner_steps_to_tui(
    request: &TuiBackendRequest<'_>,
    runtime_steps: &[PlannerStep],
) -> Vec<TuiBackendPlanStep> {
    let focus = read_only_task_focus(request.task);
    let runtime_evidence = runtime_steps
        .iter()
        .map(runtime_planner_step_evidence)
        .collect::<Vec<_>>()
        .join(" | ");
    let runtime_evidence = if runtime_evidence.is_empty() {
        "runtime planner returned no concrete local step".to_owned()
    } else {
        runtime_evidence
    };

    vec![
        TuiBackendPlanStep {
            label: format!("Understand {focus}"),
            detail: format!(
                "Classify owner request as {focus}; trust={}; context={}%; P2 shell grants no authority",
                request.trust.label(),
                request.context_percent
            ),
        },
        TuiBackendPlanStep {
            label: runtime_context_step_label(focus).to_owned(),
            detail: format!(
                "Use cwd={}, git={}, cargo={}, docs={}, config={}. runtime evidence: {}",
                request.workspace.short_path,
                request.workspace.git_state,
                request.workspace.cargo_state,
                request.workspace.docs_state,
                request.workspace.config_state,
                runtime_evidence
            ),
        },
        TuiBackendPlanStep {
            label: "Draft read-only response".to_owned(),
            detail:
                "Answer in the conversation and keep writes, shell, Git/GitHub, tickets, proofs, and ledger blocked"
                    .to_owned(),
        },
    ]
}

fn runtime_context_step_label(focus: &str) -> &'static str {
    match focus {
        "project status" => "Read project status facts",
        "agent configuration" => "Read agent and skill context",
        "verification readiness" => "Prepare safe verification outline",
        "trust and risk" => "Review trust and risk signals",
        _ => "Read workspace context",
    }
}

fn runtime_planner_step_evidence(step: &PlannerStep) -> String {
    format!(
        "{} via {}; target={:?}:{}; risk={:?}; {}",
        step.capability_id,
        step.step_id,
        step.target.resource_type,
        step.target.resource_ref,
        step.risk_level,
        step.rationale
    )
}

fn read_only_backend_plan(request: &TuiBackendRequest<'_>) -> TuiBackendPlan {
    let focus = read_only_task_focus(request.task);
    let first = match focus {
        "project status" => TuiBackendPlanStep {
            label: "Summarize project state".to_owned(),
            detail: format!(
                "Use cwd, git={}, cargo={}, docs={} as read-only facts",
                request.workspace.git_state, request.workspace.cargo_state, request.workspace.docs_state
            ),
        },
        "agent configuration" => TuiBackendPlanStep {
            label: "Summarize active agents".to_owned(),
            detail: format!(
                "Use {} configured/fallback agents and {} skills without loading external authority",
                request.agents.len(),
                request.skills.len()
            ),
        },
        "verification readiness" => TuiBackendPlanStep {
            label: "Prepare verification plan".to_owned(),
            detail: "List safe checks first; build/test execution still needs owner intent and P0 path"
                .to_owned(),
        },
        "trust and risk" => TuiBackendPlanStep {
            label: "Review trust boundary".to_owned(),
            detail: format!(
                "Current trust is {}; approvals remain local intent only",
                request.trust.label()
            ),
        },
        _ => TuiBackendPlanStep {
            label: "Inspect workspace context".to_owned(),
            detail: format!(
                "Use context meter {}% and local workspace facts before proposing work",
                request.context_percent
            ),
        },
    };
    TuiBackendPlan {
        plan_id: format!("tui-readonly-turn-{}", request.turn),
        source: "read-only-workspace-backend".to_owned(),
        steps: vec![
            first,
            TuiBackendPlanStep {
                label: "Produce owner-facing answer".to_owned(),
                detail: "Explain findings in chat without executing tools or mutating files".to_owned(),
            },
            TuiBackendPlanStep {
                label: "Wait for P0-capable adapter".to_owned(),
                detail: "Any write, shell, Git/GitHub, ticket, proof, or ledger action remains blocked here"
                    .to_owned(),
            },
        ],
        blocked_authority: blocked_p2_authority(),
    }
}

fn read_only_model_plan(request: TuiBackendRequest<'_>, provider: &str) -> TuiBackendPlan {
    TuiBackendPlan {
        plan_id: format!("model-chat-turn-{}", request.turn),
        source: format!("openai-compatible-chat:{provider}"),
        steps: vec![
            TuiBackendPlanStep {
                label: "Package read-only context".to_owned(),
                detail: format!(
                    "Use cwd={}, git={}, cargo={}, docs={}, trust={}, context={}%",
                    request.workspace.short_path,
                    request.workspace.git_state,
                    request.workspace.cargo_state,
                    request.workspace.docs_state,
                    request.trust.label(),
                    request.context_percent
                ),
            },
            TuiBackendPlanStep {
                label: "Request model response".to_owned(),
                detail:
                    "POST /chat/completions with owner task and safe workspace facts; no tools are exposed"
                        .to_owned(),
            },
            TuiBackendPlanStep {
                label: "Render model reply".to_owned(),
                detail:
                    "Append the provider response to the conversation with model/reasoning metadata"
                        .to_owned(),
            },
        ],
        blocked_authority: blocked_p2_authority(),
    }
}

fn blocked_p2_authority() -> Vec<String> {
    vec![
        "write".to_owned(),
        "shell.execute".to_owned(),
        "git.github".to_owned(),
        "ticket.issue".to_owned(),
        "proof.verify".to_owned(),
        "ledger.commit".to_owned(),
    ]
}

fn build_read_only_chat_prompt(request: TuiBackendRequest<'_>) -> String {
    format!(
        "You are moxi-agent, a guarded read-only CLI assistant.\n\
         Answer the owner in Chinese unless they clearly request another language.\n\
         You may use only the facts below. Do not claim you wrote files, executed shell commands, committed Git/GitHub changes, issued tickets, verified proofs, or wrote ledger events.\n\
         If the task needs those effects, say they require the trusted P0 path.\n\n\
         Owner task:\n{}\n\n\
         Workspace facts:\n- cwd: {}\n- git: {}\n- cargo: {}\n- docs/status.md: {}\n- agent config: {}\n- trust: {}\n- context meter: {}%\n- active agents: {}\n- loaded skills: {}\n- available read-only tools: {}",
        request.task,
        request.workspace.cwd,
        request.workspace.git_state,
        request.workspace.cargo_state,
        request.workspace.docs_state,
        request.workspace.config_state,
        request.trust.label(),
        request.context_percent,
        request
            .agents
            .iter()
            .map(TuiAgentProfile::summary)
            .collect::<Vec<_>>()
            .join("; "),
        request.skills.join(", "),
        request.tools.join(", ")
    )
}

fn staged_reply_chunks(body: &str) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut current = String::new();
    for segment in body.split_inclusive(['。', '.', '!', '?', '\n']) {
        current.push_str(segment);
        if current.chars().count() >= 48 || segment.ends_with('\n') {
            chunks.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    if chunks.len() <= 1 && body.chars().count() > 72 {
        chunks = body
            .chars()
            .collect::<Vec<_>>()
            .chunks(56)
            .map(|chunk| chunk.iter().collect::<String>())
            .collect();
    }
    chunks
}

fn read_only_project_analysis(request: &TuiBackendRequest<'_>, plan: &TuiBackendPlan) -> String {
    let focus = read_only_task_focus(request.task);
    let agent_count = request.agents.len();
    let skill_count = request.skills.len();
    let first_step = plan
        .steps
        .first()
        .map(|step| step.label.as_str())
        .unwrap_or("Inspect workspace context");
    format!(
        "Turn {} read-only backend analysis for \"{}\": focus={focus}; backend={} ; plan={} ; first_step=\"{}\" ; blocked={}. workspace={} ; git={} ; cargo={} ; docs={} ; config={} ; trust={} ; context={}%; agents={} ; skills={}. Next safe step: inspect context or ask for a concrete plan. P0 remains required for writes, shell execution, Git/GitHub, tickets, proofs, or ledger commits.",
        request.turn,
        request.task,
        plan.source,
        plan.plan_id,
        first_step,
        plan.blocked_authority.join(","),
        request.workspace.short_path,
        request.workspace.git_state,
        request.workspace.cargo_state,
        request.workspace.docs_state,
        request.workspace.config_state,
        request.trust.label(),
        request.context_percent,
        agent_count,
        skill_count,
    )
}

fn read_only_task_focus(task: &str) -> &'static str {
    let normalized = normalize_token(task);
    let words = normalized
        .split('_')
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>();
    if words
        .iter()
        .any(|word| matches!(*word, "status" | "state" | "progress"))
    {
        "project status"
    } else if words
        .iter()
        .any(|word| matches!(*word, "agent" | "agents" | "skill" | "skills"))
    {
        "agent configuration"
    } else if words
        .iter()
        .any(|word| matches!(*word, "test" | "tests" | "build" | "cargo"))
    {
        "verification readiness"
    } else if words
        .iter()
        .any(|word| matches!(*word, "risk" | "trust" | "approve" | "approval"))
    {
        "trust and risk"
    } else {
        "workspace inspection"
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct TuiTrustState {
    status: TuiTrustStatus,
    reasons: Vec<String>,
}

impl TuiTrustState {
    fn from_workspace(workspace: &WorkspaceFacts) -> Self {
        let mut reasons = Vec::new();
        if workspace.trust_state == "present" {
            reasons.push(".moxi/trust.toml is present".to_owned());
        } else {
            reasons.push(".moxi/trust.toml is missing; workspace trust is unknown".to_owned());
        }
        if workspace.config_state == "present" {
            reasons.push(".moxi/agents.toml is present and may affect active agents".to_owned());
        } else {
            reasons.push(".moxi/agents.toml is missing; using fallback agents".to_owned());
        }
        if workspace.git_state.contains("dirty") {
            reasons.push(format!(
                "Git workspace has pending changes: {}",
                workspace.git_state
            ));
        }
        let status = if workspace.trust_state == "present" {
            TuiTrustStatus::KnownReadOnly
        } else {
            TuiTrustStatus::NeedsReview
        };
        Self { status, reasons }
    }

    fn should_show_gate(&self) -> bool {
        matches!(
            self.status,
            TuiTrustStatus::NeedsReview | TuiTrustStatus::Denied
        )
    }

    fn decision_label(&self) -> &'static str {
        match self.status {
            TuiTrustStatus::KnownReadOnly => "trust file present; read-only entry can continue",
            TuiTrustStatus::NeedsReview => "owner review recommended before entering workspace",
            TuiTrustStatus::TrustedReadOnly => "owner accepted read-only local session intent",
            TuiTrustStatus::Denied => "owner denied workspace trust intent",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum TuiTrustStatus {
    KnownReadOnly,
    NeedsReview,
    TrustedReadOnly,
    Denied,
}

impl TuiTrustStatus {
    fn label(self) -> &'static str {
        match self {
            Self::KnownReadOnly => "known-read-only",
            Self::NeedsReview => "needs-review",
            Self::TrustedReadOnly => "trusted-read-only",
            Self::Denied => "denied",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct TuiContextSnapshot {
    percent: u8,
    sources: Vec<TuiContextSource>,
}

impl TuiContextSnapshot {
    fn from_sources(sources: Vec<TuiContextSource>) -> Self {
        let total = sources
            .iter()
            .map(|source| source.weight)
            .sum::<u16>()
            .max(1);
        let used = sources
            .iter()
            .filter(|source| source.available)
            .map(|source| source.weight)
            .sum::<u16>();
        let percent = ((used * 100) / total).min(100) as u8;
        Self { percent, sources }
    }

    fn ratio(&self) -> f32 {
        self.percent as f32 / 100.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct TuiContextSource {
    label: String,
    state: String,
    detail: String,
    available: bool,
    weight: u16,
}

impl TuiContextSource {
    fn available(label: &str, state: &str, detail: &str, weight: u16) -> Self {
        Self::new(label, state, detail, true, weight)
    }

    fn new(label: &str, state: &str, detail: &str, available: bool, weight: u16) -> Self {
        Self {
            label: label.to_owned(),
            state: state.to_owned(),
            detail: detail.to_owned(),
            available,
            weight,
        }
    }
}

fn loading_frame(tick: usize) -> &'static str {
    match tick % 4 {
        0 => "[|]",
        1 => "[/]",
        2 => "[-]",
        _ => "[\\]",
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct TuiAgentProfile {
    name: String,
    role: String,
    model: String,
    reasoning: String,
}

impl TuiAgentProfile {
    fn load_for_workspace(workspace: &WorkspaceFacts) -> Vec<Self> {
        let path = Path::new(&workspace.cwd).join(".moxi").join("agents.toml");
        let Ok(text) = fs::read_to_string(path) else {
            return Self::fallback_profiles();
        };
        let agents = Self::parse_agents_toml(&text);
        if agents.is_empty() {
            Self::fallback_profiles()
        } else {
            agents
        }
    }

    fn fallback_profiles() -> Vec<Self> {
        vec![
            Self::new("moxi-agent", "orchestrator", "session-local", "medium"),
            Self::new("ui-agent", "rich-cli", "session-local", "medium"),
            Self::new("guard-agent", "risk", "session-local", "medium"),
        ]
    }

    fn parse_agents_toml(text: &str) -> Vec<Self> {
        let mut agents = Vec::new();
        let mut current = ParsedAgentProfile::default();
        let mut in_agent = false;

        for raw_line in text.lines() {
            let line = raw_line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if line == "[[agents]]" {
                if in_agent {
                    if let Some(agent) = current.finish() {
                        agents.push(agent);
                    }
                    current = ParsedAgentProfile::default();
                }
                in_agent = true;
                continue;
            }
            if !in_agent {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let Some(value) = parse_toml_string(value.trim()) else {
                continue;
            };
            match key.trim() {
                "name" => current.name = Some(value),
                "role" => current.role = Some(value),
                "model" => current.model = Some(value),
                "reasoning" => current.reasoning = Some(value),
                _ => {}
            }
        }

        if in_agent {
            if let Some(agent) = current.finish() {
                agents.push(agent);
            }
        }
        agents
    }

    fn new(name: &str, role: &str, model: &str, reasoning: &str) -> Self {
        Self {
            name: name.to_owned(),
            role: role.to_owned(),
            model: model.to_owned(),
            reasoning: reasoning.to_owned(),
        }
    }

    fn summary(&self) -> String {
        format!(
            "{} [{}] model={} reasoning={}",
            self.name, self.role, self.model, self.reasoning
        )
    }
}

#[derive(Default)]
struct ParsedAgentProfile {
    name: Option<String>,
    role: Option<String>,
    model: Option<String>,
    reasoning: Option<String>,
}

impl ParsedAgentProfile {
    fn finish(self) -> Option<TuiAgentProfile> {
        let name = self.name?;
        Some(TuiAgentProfile {
            role: self.role.unwrap_or_else(|| "agent".to_owned()),
            model: self.model.unwrap_or_else(|| "session-local".to_owned()),
            reasoning: self.reasoning.unwrap_or_else(|| "medium".to_owned()),
            name,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct TuiModelConfig {
    provider: TuiModelProvider,
    endpoint: String,
    model: String,
    api_key_source: TuiApiKeySource,
    config_path: String,
    config_state: String,
}

impl TuiModelConfig {
    fn load_for_workspace(workspace: &WorkspaceFacts) -> Self {
        let path = Path::new(&workspace.cwd).join(".moxi").join("config.toml");
        Self::load_at(&path)
    }

    fn load_at(path: &Path) -> Self {
        Self::load_at_with_env(path, |name| env::var(name).ok())
    }

    fn load_at_with_env(path: &Path, get_env: impl Fn(&str) -> Option<String>) -> Self {
        let config_path = path.display().to_string();
        let parsed = fs::read_to_string(path)
            .ok()
            .map(|text| ParsedModelConfig::from_toml(&text))
            .unwrap_or_default();
        let env_provider = get_env("MOXI_PROVIDER");
        let env_endpoint = get_env("MOXI_ENDPOINT");
        let env_model = get_env("MOXI_MODEL");

        let provider = parsed
            .provider
            .as_deref()
            .or(env_provider.as_deref())
            .map(TuiModelProvider::parse)
            .unwrap_or(TuiModelProvider::OpenAi);
        let endpoint = parsed
            .endpoint
            .or(env_endpoint)
            .unwrap_or_else(|| provider.default_endpoint().to_owned());
        let model = parsed
            .model
            .or(env_model)
            .unwrap_or_else(|| "not-configured".to_owned());
        let api_key_source = TuiApiKeySource::resolve(
            parsed.api_key_env.as_deref(),
            parsed.api_key.as_deref(),
            provider.default_key_env(),
            &get_env,
        );
        let config_state = if path.is_file() {
            if model == "not-configured" || matches!(api_key_source, TuiApiKeySource::Missing) {
                "present-incomplete"
            } else {
                "present"
            }
        } else if get_env("MOXI_API_KEY").is_some()
            || get_env("OPENAI_API_KEY").is_some()
            || get_env("OPENROUTER_API_KEY").is_some()
            || get_env("MOXI_MODEL").is_some()
            || get_env("MOXI_ENDPOINT").is_some()
        {
            "env-only"
        } else {
            "missing"
        }
        .to_owned();

        Self {
            provider,
            endpoint,
            model,
            api_key_source,
            config_path,
            config_state,
        }
    }

    fn is_configured(&self) -> bool {
        self.model != "not-configured"
            && !matches!(self.api_key_source, TuiApiKeySource::Missing)
            && self.config_state != "missing"
    }

    fn needs_setup(&self) -> bool {
        !self.is_configured()
    }

    fn secret(&self) -> Option<String> {
        match &self.api_key_source {
            TuiApiKeySource::Missing => None,
            TuiApiKeySource::Env { name, .. } => env::var(name).ok(),
            TuiApiKeySource::Config { .. } => fs::read_to_string(&self.config_path)
                .ok()
                .and_then(|text| ParsedModelConfig::from_toml(&text).api_key)
                .filter(|secret| !secret.trim().is_empty()),
        }
    }

    fn setup_sample(&self) -> String {
        let model = if self.model == "not-configured" {
            "gpt-4o-mini"
        } else {
            &self.model
        };
        render_model_config_template(
            self.provider,
            &self.endpoint,
            model,
            self.provider.default_key_env(),
        )
    }

    fn redacted_summary(&self) -> String {
        format!(
            "provider={} endpoint={} model={} config={} ({}) key={}",
            self.provider.label(),
            self.endpoint,
            self.model,
            self.config_path,
            self.config_state,
            self.api_key_source.summary()
        )
    }
}

fn render_model_config_template(
    provider: TuiModelProvider,
    endpoint: &str,
    model: &str,
    api_key_env: &str,
) -> String {
    format!(
        "provider = \"{}\"\nendpoint = \"{}\"\nmodel = \"{}\"\napi_key_env = \"{}\"\n",
        provider.label(),
        escape_toml_string(endpoint),
        escape_toml_string(model),
        escape_toml_string(api_key_env)
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum TuiModelProvider {
    OpenAi,
    OpenRouter,
    Custom,
    Local,
}

impl TuiModelProvider {
    fn parse(value: &str) -> Self {
        match normalize_token(value).as_str() {
            "openrouter" => Self::OpenRouter,
            "custom" => Self::Custom,
            "local" | "ollama" | "lmstudio" => Self::Local,
            _ => Self::OpenAi,
        }
    }

    fn try_parse(value: &str) -> CliResult<Self> {
        match normalize_token(value).as_str() {
            "openai" => Ok(Self::OpenAi),
            "openrouter" => Ok(Self::OpenRouter),
            "custom" => Ok(Self::Custom),
            "local" | "ollama" | "lmstudio" => Ok(Self::Local),
            _ => Err(CliError::InvalidModelProvider(value.to_owned())),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::OpenAi => "openai",
            Self::OpenRouter => "openrouter",
            Self::Custom => "custom",
            Self::Local => "local",
        }
    }

    fn default_endpoint(self) -> &'static str {
        match self {
            Self::OpenAi => "https://api.openai.com/v1",
            Self::OpenRouter => "https://openrouter.ai/api/v1",
            Self::Custom => "not-configured",
            Self::Local => "http://localhost:11434/v1",
        }
    }

    fn default_key_env(self) -> &'static str {
        match self {
            Self::OpenAi => "OPENAI_API_KEY",
            Self::OpenRouter => "OPENROUTER_API_KEY",
            Self::Custom | Self::Local => "MOXI_API_KEY",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum TuiApiKeySource {
    Missing,
    Env { name: String, redacted: String },
    Config { redacted: String },
}

impl TuiApiKeySource {
    fn resolve(
        config_env: Option<&str>,
        config_key: Option<&str>,
        default_env: &str,
        get_env: &impl Fn(&str) -> Option<String>,
    ) -> Self {
        if let Some(secret) = config_key.filter(|value| !value.trim().is_empty()) {
            return Self::Config {
                redacted: redact_secret(secret),
            };
        }

        for name in [config_env, Some("MOXI_API_KEY"), Some(default_env)]
            .into_iter()
            .flatten()
        {
            if let Some(secret) = get_env(name) {
                if !secret.trim().is_empty() {
                    return Self::Env {
                        name: name.to_owned(),
                        redacted: redact_secret(&secret),
                    };
                }
            }
        }

        Self::Missing
    }

    fn summary(&self) -> String {
        match self {
            Self::Missing => "missing".to_owned(),
            Self::Env { name, redacted } => format!("env:{name}={redacted}"),
            Self::Config { redacted } => format!("config:{redacted}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TuiDoctorStatus {
    Ready,
    NeedsSetup,
    InvalidKey,
    ModelNotFound,
    BadEndpoint,
    Quota,
    Network,
    Timeout,
    UnsupportedResponse,
}

impl TuiDoctorStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::NeedsSetup => "needs-setup",
            Self::InvalidKey => "invalid-key",
            Self::ModelNotFound => "model-not-found",
            Self::BadEndpoint => "bad-endpoint",
            Self::Quota => "quota",
            Self::Network => "network",
            Self::Timeout => "timeout",
            Self::UnsupportedResponse => "unsupported-response",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TuiModelCatalogStatus {
    Ready,
    NeedsSetup,
    InvalidKey,
    BadEndpoint,
    Quota,
    Network,
    Timeout,
    UnsupportedResponse,
}

impl TuiModelCatalogStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::NeedsSetup => "needs-setup",
            Self::InvalidKey => "invalid-key",
            Self::BadEndpoint => "bad-endpoint",
            Self::Quota => "quota",
            Self::Network => "network",
            Self::Timeout => "timeout",
            Self::UnsupportedResponse => "unsupported-response",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TuiModelCatalogReport {
    status: TuiModelCatalogStatus,
    provider: TuiModelProvider,
    endpoint: String,
    configured_model: String,
    models: Vec<String>,
    detail: String,
    action: String,
}

impl TuiModelCatalogReport {
    fn message(&self) -> String {
        let models = if self.models.is_empty() {
            "<none>".to_owned()
        } else {
            self.models.join(", ")
        };
        format!(
            "Models: status={} provider={} endpoint={} configured_model={}. Available: {}. Detail: {} Action: {}",
            self.status.label(),
            self.provider.label(),
            self.endpoint,
            self.configured_model,
            models,
            self.detail,
            self.action
        )
    }

    fn cli_text(&self) -> String {
        let models = if self.models.is_empty() {
            "<none>".to_owned()
        } else {
            self.models.join("\n- ")
        };
        format!(
            "MOXI models\nstatus: {}\nprovider: {}\nendpoint: {}\nconfigured_model: {}\nmodels:\n- {}\ndetail: {}\naction: {}",
            self.status.label(),
            self.provider.label(),
            self.endpoint,
            self.configured_model,
            models,
            self.detail,
            self.action
        )
    }
}

struct TuiModelCatalog;

impl TuiModelCatalog {
    fn list(config: &TuiModelConfig) -> TuiModelCatalogReport {
        if config.needs_setup() {
            return TuiModelCatalogReport {
                status: TuiModelCatalogStatus::NeedsSetup,
                provider: config.provider,
                endpoint: config.endpoint.clone(),
                configured_model: config.model.clone(),
                models: Vec::new(),
                detail: format!(
                    "configuration is {}; key source is {}",
                    config.config_state,
                    config.api_key_source.summary()
                ),
                action: "open First-run Setup or create .moxi/config.toml before listing models"
                    .to_owned(),
            };
        }
        if config.endpoint == "not-configured" || !config.endpoint.starts_with("http") {
            return TuiModelCatalogReport {
                status: TuiModelCatalogStatus::BadEndpoint,
                provider: config.provider,
                endpoint: config.endpoint.clone(),
                configured_model: config.model.clone(),
                models: Vec::new(),
                detail: "endpoint must be an http:// or https:// OpenAI-compatible base URL"
                    .to_owned(),
                action: "set endpoint to an OpenAI-compatible /v1 endpoint".to_owned(),
            };
        }
        let Some(secret) = config.secret() else {
            return TuiModelCatalogReport {
                status: TuiModelCatalogStatus::NeedsSetup,
                provider: config.provider,
                endpoint: config.endpoint.clone(),
                configured_model: config.model.clone(),
                models: Vec::new(),
                detail: format!(
                    "{} is redacted but not available to this process",
                    config.api_key_source.summary()
                ),
                action: "export the configured api_key_env before launching moxi".to_owned(),
            };
        };

        match http_list_openai_models(&config.endpoint, &secret) {
            Ok(response) => classify_model_catalog_response(config, response),
            Err(error) => TuiModelCatalogReport {
                status: if error.contains("timed out") {
                    TuiModelCatalogStatus::Timeout
                } else {
                    TuiModelCatalogStatus::Network
                },
                provider: config.provider,
                endpoint: config.endpoint.clone(),
                configured_model: config.model.clone(),
                models: Vec::new(),
                detail: error,
                action:
                    "check network access, endpoint URL, local server state, proxy, or firewall"
                        .to_owned(),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TuiDoctorReport {
    status: TuiDoctorStatus,
    provider: TuiModelProvider,
    endpoint: String,
    model: String,
    detail: String,
    action: String,
}

impl TuiDoctorReport {
    fn message(&self) -> String {
        format!(
            "Doctor: status={} provider={} endpoint={} model={}. Detail: {} Action: {}",
            self.status.label(),
            self.provider.label(),
            self.endpoint,
            self.model,
            self.detail,
            self.action
        )
    }

    fn cli_text(&self) -> String {
        format!(
            "MOXI doctor\nstatus: {}\nprovider: {}\nendpoint: {}\nmodel: {}\ndetail: {}\naction: {}",
            self.status.label(),
            self.provider.label(),
            self.endpoint,
            self.model,
            self.detail,
            self.action
        )
    }
}

struct TuiModelDoctor;

impl TuiModelDoctor {
    fn check(config: &TuiModelConfig) -> TuiDoctorReport {
        if config.needs_setup() {
            return TuiDoctorReport {
                status: TuiDoctorStatus::NeedsSetup,
                provider: config.provider,
                endpoint: config.endpoint.clone(),
                model: config.model.clone(),
                detail: format!(
                    "configuration is {}; key source is {}",
                    config.config_state,
                    config.api_key_source.summary()
                ),
                action: "open First-run Setup or create .moxi/config.toml with provider, endpoint, model, and api_key_env".to_owned(),
            };
        }

        if config.endpoint == "not-configured" || !config.endpoint.starts_with("http") {
            return TuiDoctorReport {
                status: TuiDoctorStatus::BadEndpoint,
                provider: config.provider,
                endpoint: config.endpoint.clone(),
                model: config.model.clone(),
                detail: "endpoint must be an http:// or https:// OpenAI-compatible base URL"
                    .to_owned(),
                action: "set endpoint to https://api.openai.com/v1, https://openrouter.ai/api/v1, or a local-compatible /v1 endpoint".to_owned(),
            };
        }

        let Some(secret) = config.secret() else {
            return TuiDoctorReport {
                status: TuiDoctorStatus::NeedsSetup,
                provider: config.provider,
                endpoint: config.endpoint.clone(),
                model: config.model.clone(),
                detail: format!("{} is redacted but not available to this process", config.api_key_source.summary()),
                action: "export the configured api_key_env before launching moxi, or use a local provider that accepts your key policy".to_owned(),
            };
        };

        match http_get_openai_model(&config.endpoint, &config.model, &secret) {
            Ok(response) => classify_doctor_response(config, response),
            Err(error) => TuiDoctorReport {
                status: if error.contains("timed out") {
                    TuiDoctorStatus::Timeout
                } else {
                    TuiDoctorStatus::Network
                },
                provider: config.provider,
                endpoint: config.endpoint.clone(),
                model: config.model.clone(),
                detail: error,
                action:
                    "check network access, endpoint URL, local server state, proxy, or firewall"
                        .to_owned(),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HttpProbeResponse {
    status: u16,
    body: String,
}

fn classify_doctor_response(
    config: &TuiModelConfig,
    response: HttpProbeResponse,
) -> TuiDoctorReport {
    let normalized_body = normalize_token(&response.body);
    let status = match response.status {
        200 => {
            if normalized_body.contains("id") || normalized_body.contains("object") {
                TuiDoctorStatus::Ready
            } else {
                TuiDoctorStatus::UnsupportedResponse
            }
        }
        401 | 403 => TuiDoctorStatus::InvalidKey,
        404 => TuiDoctorStatus::ModelNotFound,
        402 | 429 => TuiDoctorStatus::Quota,
        400 => {
            if normalized_body.contains("model") || normalized_body.contains("not_found") {
                TuiDoctorStatus::ModelNotFound
            } else {
                TuiDoctorStatus::BadEndpoint
            }
        }
        500..=599 => TuiDoctorStatus::BadEndpoint,
        _ => TuiDoctorStatus::UnsupportedResponse,
    };
    let action = match status {
        TuiDoctorStatus::Ready => "configuration is ready for read-only model chat",
        TuiDoctorStatus::InvalidKey => {
            "check the api_key_env value; the key is not printed by MOXI"
        }
        TuiDoctorStatus::ModelNotFound => "check the model name or provider catalog",
        TuiDoctorStatus::Quota => "check quota, billing, or rate limits for the provider",
        TuiDoctorStatus::BadEndpoint => "check endpoint base URL and OpenAI-compatible /v1 routing",
        TuiDoctorStatus::UnsupportedResponse => {
            "provider responded, but response shape is not recognized as OpenAI-compatible"
        }
        TuiDoctorStatus::NeedsSetup | TuiDoctorStatus::Network | TuiDoctorStatus::Timeout => {
            "review setup and retry /doctor"
        }
    };
    TuiDoctorReport {
        status,
        provider: config.provider,
        endpoint: config.endpoint.clone(),
        model: config.model.clone(),
        detail: format!(
            "HTTP {} from provider; body preview: {}",
            response.status,
            redacted_preview(&response.body, 120)
        ),
        action: action.to_owned(),
    }
}

fn classify_model_catalog_response(
    config: &TuiModelConfig,
    response: HttpProbeResponse,
) -> TuiModelCatalogReport {
    let status = match response.status {
        200 => TuiModelCatalogStatus::Ready,
        401 | 403 => TuiModelCatalogStatus::InvalidKey,
        402 | 429 => TuiModelCatalogStatus::Quota,
        400 | 404 | 500..=599 => TuiModelCatalogStatus::BadEndpoint,
        _ => TuiModelCatalogStatus::UnsupportedResponse,
    };
    let (status, models, detail) = if status == TuiModelCatalogStatus::Ready {
        match parse_openai_model_ids(&response.body) {
            Ok(models) if !models.is_empty() => {
                let shown = models.into_iter().take(20).collect::<Vec<_>>();
                let detail = format!(
                    "HTTP {} from provider; showing up to 20 model ids",
                    response.status
                );
                (TuiModelCatalogStatus::Ready, shown, detail)
            }
            Ok(_) => (
                TuiModelCatalogStatus::UnsupportedResponse,
                Vec::new(),
                format!(
                    "HTTP {} from provider; no model ids found in body preview: {}",
                    response.status,
                    redacted_preview(&response.body, 120)
                ),
            ),
            Err(error) => (
                TuiModelCatalogStatus::UnsupportedResponse,
                Vec::new(),
                format!(
                    "HTTP {} from provider; {error}; body preview: {}",
                    response.status,
                    redacted_preview(&response.body, 120)
                ),
            ),
        }
    } else {
        (
            status,
            Vec::new(),
            format!(
                "HTTP {} from provider; body preview: {}",
                response.status,
                redacted_preview(&response.body, 120)
            ),
        )
    };
    let action = match status {
        TuiModelCatalogStatus::Ready => {
            "choose one model id and set it as model in .moxi/config.toml"
        }
        TuiModelCatalogStatus::InvalidKey => {
            "check the api_key_env value; the key is not printed by MOXI"
        }
        TuiModelCatalogStatus::Quota => "check quota, billing, or rate limits for the provider",
        TuiModelCatalogStatus::BadEndpoint => {
            "check endpoint base URL and OpenAI-compatible /v1 routing"
        }
        TuiModelCatalogStatus::UnsupportedResponse => {
            "provider responded, but /models did not match the OpenAI-compatible catalog shape"
        }
        TuiModelCatalogStatus::NeedsSetup
        | TuiModelCatalogStatus::Network
        | TuiModelCatalogStatus::Timeout => "review setup and retry /models",
    };
    TuiModelCatalogReport {
        status,
        provider: config.provider,
        endpoint: config.endpoint.clone(),
        configured_model: config.model.clone(),
        models,
        detail,
        action: action.to_owned(),
    }
}

fn http_get_openai_model(
    endpoint: &str,
    model: &str,
    secret: &str,
) -> Result<HttpProbeResponse, String> {
    let url = format!("{}/models/{}", endpoint.trim_end_matches('/'), model);
    let response = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|error| format!("doctor client setup failed: {error}"))?
        .get(url)
        .bearer_auth(secret)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .map_err(|error| {
            if error.is_timeout() {
                format!("network request timed out: {error}")
            } else {
                format!("network request failed: {error}")
            }
        })?;
    let status = response.status().as_u16();
    let body = response
        .text()
        .map_err(|error| format!("network response read failed: {error}"))?;
    Ok(HttpProbeResponse { status, body })
}

fn http_list_openai_models(endpoint: &str, secret: &str) -> Result<HttpProbeResponse, String> {
    let url = format!("{}/models", endpoint.trim_end_matches('/'));
    let response = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|error| format!("models client setup failed: {error}"))?
        .get(url)
        .bearer_auth(secret)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .map_err(|error| {
            if error.is_timeout() {
                format!("model catalog request timed out: {error}")
            } else {
                format!("model catalog request failed: {error}")
            }
        })?;
    let status = response.status().as_u16();
    let body = response
        .text()
        .map_err(|error| format!("model catalog response read failed: {error}"))?;
    Ok(HttpProbeResponse { status, body })
}

fn post_openai_chat_completion(
    endpoint: &str,
    model: &str,
    secret: &str,
    prompt: &str,
) -> Result<String, String> {
    let url = format!("{}/chat/completions", endpoint.trim_end_matches('/'));
    let body = serde_json::json!({
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "You are moxi-agent inside a guarded read-only CLI shell. Never claim to write files, run shell commands, mutate Git/GitHub, issue tickets, verify proofs, or commit ledger events."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0.2,
        "stream": false
    });
    let response = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|error| format!("chat client setup failed: {error}"))?
        .post(url)
        .bearer_auth(secret)
        .header(reqwest::header::ACCEPT, "application/json")
        .json(&body)
        .send()
        .map_err(|error| {
            if error.is_timeout() {
                format!("model chat request timed out: {error}")
            } else {
                format!("model chat request failed: {error}")
            }
        })?;
    let status = response.status().as_u16();
    let body = response
        .text()
        .map_err(|error| format!("model chat response read failed: {error}"))?;
    if !(200..300).contains(&status) {
        return Err(classify_chat_error(status, &body));
    }
    parse_openai_chat_content(&body)
}

fn classify_chat_error(status: u16, body: &str) -> String {
    let normalized_body = normalize_token(body);
    let category = match status {
        401 | 403 => "invalid key",
        404 => "model or endpoint not found",
        402 | 429 => "quota or rate limit",
        400 => {
            if normalized_body.contains("model") || normalized_body.contains("not_found") {
                "model not found"
            } else {
                "bad request"
            }
        }
        500..=599 => "provider/server error",
        _ => "unsupported provider response",
    };
    format!(
        "model chat failed: {category}; HTTP {status}; body preview: {}",
        redacted_preview(body, 160)
    )
}

fn parse_openai_chat_content(body: &str) -> Result<String, String> {
    let json: serde_json::Value = serde_json::from_str(body)
        .map_err(|error| format!("model chat response was not JSON: {error}"))?;
    let content = json
        .get("choices")
        .and_then(|choices| choices.as_array())
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("message"))
        .and_then(|message| message.get("content"))
        .and_then(|content| content.as_str())
        .map(str::trim)
        .filter(|content| !content.is_empty())
        .ok_or_else(|| {
            format!(
                "unsupported chat response shape; body preview: {}",
                redacted_preview(body, 160)
            )
        })?;
    Ok(content.to_owned())
}

fn parse_openai_model_ids(body: &str) -> Result<Vec<String>, String> {
    let json: serde_json::Value = serde_json::from_str(body)
        .map_err(|error| format!("model catalog response was not JSON: {error}"))?;
    let data = json
        .get("data")
        .and_then(|data| data.as_array())
        .ok_or_else(|| "unsupported model catalog shape: missing data array".to_owned())?;
    let mut ids = data
        .iter()
        .filter_map(|item| item.get("id").and_then(|id| id.as_str()))
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    Ok(ids)
}

fn redacted_preview(value: &str, max_chars: usize) -> String {
    let compact = redact_inline_secrets(value)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace("Bearer ", "Bearer <redacted> ");
    compact.chars().take(max_chars).collect()
}

fn redact_inline_secrets(value: &str) -> String {
    value
        .split_inclusive(|ch: char| {
            ch.is_whitespace() || matches!(ch, '"' | '\'' | ',' | ':' | '}')
        })
        .map(|token| {
            let secret_chars = token
                .chars()
                .filter(|ch| ch.is_ascii_alphanumeric() || matches!(*ch, '-' | '_' | '.'))
                .collect::<String>();
            if looks_like_secret(&secret_chars) {
                token.replace(&secret_chars, &redact_secret(&secret_chars))
            } else {
                token.to_owned()
            }
        })
        .collect()
}

fn looks_like_secret(value: &str) -> bool {
    let value = value.trim();
    value.len() >= 16
        && (value.starts_with("sk-")
            || value.starts_with("sk_")
            || value.starts_with("pk-")
            || value.starts_with("key-")
            || value.contains("secret")
            || value.contains("token"))
}

#[derive(Default)]
struct ParsedModelConfig {
    provider: Option<String>,
    endpoint: Option<String>,
    model: Option<String>,
    api_key_env: Option<String>,
    api_key: Option<String>,
}

impl ParsedModelConfig {
    fn from_toml(text: &str) -> Self {
        let mut parsed = Self::default();
        for raw_line in text.lines() {
            let line = raw_line.split('#').next().unwrap_or("").trim();
            if line.is_empty() || line.starts_with('[') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let Some(value) = parse_toml_string(value.trim()) else {
                continue;
            };
            match key.trim() {
                "provider" => parsed.provider = Some(value),
                "endpoint" => parsed.endpoint = Some(value),
                "model" => parsed.model = Some(value),
                "api_key_env" => parsed.api_key_env = Some(value),
                "api_key" => parsed.api_key = Some(value),
                _ => {}
            }
        }
        parsed
    }
}

fn redact_secret(value: &str) -> String {
    let value = value.trim();
    if value.len() <= 8 {
        "****".to_owned()
    } else {
        format!("{}...{}", &value[..4], &value[value.len() - 4..])
    }
}

fn escape_toml_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn parse_toml_string(value: &str) -> Option<String> {
    let value = value.trim();
    if value.len() < 2 || !value.starts_with('"') || !value.ends_with('"') {
        return None;
    }
    Some(value[1..value.len() - 1].replace("\\\"", "\""))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum TuiSessionMode {
    ReadOnly,
}

impl TuiSessionMode {
    fn label(self) -> &'static str {
        match self {
            Self::ReadOnly => "read-only",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct WorkspaceFacts {
    cwd: String,
    short_path: String,
    config_path: String,
    config_state: String,
    trust_path: String,
    trust_state: String,
    git_state: String,
    cargo_state: String,
    docs_state: String,
    trust: String,
}

impl WorkspaceFacts {
    fn detect() -> Self {
        let cwd_path = env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("C:\\MOXI-Essence-agent\\MOXI-Essence-agent"));
        Self::detect_at(&cwd_path)
    }

    fn detect_at(cwd_path: &Path) -> Self {
        let cwd = cwd_path.display().to_string();
        let short_path = cwd_path
            .file_name()
            .and_then(|value| value.to_str())
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .or_else(|| {
                cwd.rsplit(['\\', '/'])
                    .next()
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| cwd.clone());
        let config_path = ".moxi\\agents.toml".to_owned();
        let trust_path = ".moxi\\trust.toml".to_owned();
        let config_state = presence_state(&cwd_path.join(".moxi").join("agents.toml"));
        let trust_state = presence_state(&cwd_path.join(".moxi").join("trust.toml"));
        let docs_state = presence_state(&cwd_path.join("docs").join("status.md"));
        let cargo_state = cargo_workspace_state(&cwd_path.join("Cargo.toml"));
        let git_state = git_workspace_state(cwd_path);
        Self {
            config_path,
            config_state,
            trust_path,
            trust_state,
            git_state,
            cargo_state,
            docs_state,
            trust: "pending".to_owned(),
            cwd,
            short_path,
        }
    }

    fn summary(&self) -> String {
        format!(
            "{} | git: {} | cargo: {}",
            self.short_path, self.git_state, self.cargo_state
        )
    }
}

fn presence_state(path: &Path) -> String {
    if path.is_file() {
        "present".to_owned()
    } else {
        "missing".to_owned()
    }
}

fn cargo_workspace_state(path: &Path) -> String {
    let Ok(text) = fs::read_to_string(path) else {
        return "Cargo.toml missing".to_owned();
    };
    let member_count = text.matches("\"crates/").count();
    if text.contains("[workspace]") {
        format!("workspace {member_count} crates")
    } else {
        "package".to_owned()
    }
}

fn git_workspace_state(cwd: &Path) -> String {
    if !cwd.join(".git").exists() {
        return "not a git repo".to_owned();
    }
    let Ok(output) = Command::new("git")
        .args(["status", "--short", "--branch"])
        .current_dir(cwd)
        .output()
    else {
        return "git unavailable".to_owned();
    };
    if !output.status.success() {
        return "git status failed".to_owned();
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut lines = text.lines();
    let branch = lines
        .next()
        .unwrap_or("## <unknown>")
        .trim_start_matches("## ")
        .trim()
        .to_owned();
    let dirty_count = lines.filter(|line| !line.trim().is_empty()).count();
    if dirty_count == 0 {
        format!("{branch} clean")
    } else {
        format!("{branch} dirty {dirty_count}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct TuiMessage {
    agent: String,
    role: String,
    body: String,
    task: Option<String>,
    metadata: TuiMessageMeta,
    state: TuiMessageState,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct TuiMessageMeta {
    model: String,
    reasoning: String,
    tools: Vec<String>,
    status: String,
}

impl TuiMessageMeta {
    fn new<const N: usize>(model: &str, reasoning: &str, tools: [&str; N], status: &str) -> Self {
        Self {
            model: model.to_owned(),
            reasoning: reasoning.to_owned(),
            tools: tools.iter().map(|tool| (*tool).to_owned()).collect(),
            status: status.to_owned(),
        }
    }

    fn from_tools(model: &str, reasoning: &str, tools: Vec<String>, status: &str) -> Self {
        Self {
            model: model.to_owned(),
            reasoning: reasoning.to_owned(),
            tools,
            status: status.to_owned(),
        }
    }

    fn render(&self) -> String {
        format!(
            "model: {} | reasoning: {} | tools: {} | {}",
            self.model,
            self.reasoning,
            self.tools.join(","),
            self.status
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum TuiMessageState {
    Complete,
    Streaming,
    Waiting,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TuiRiskPrompt {
    task: String,
    level: TuiRiskLevel,
    reason: String,
}

impl TuiRiskPrompt {
    fn detect(task: &str) -> Option<Self> {
        let normalized = normalize_token(task);
        let words = normalized
            .split('_')
            .filter(|word| !word.is_empty())
            .collect::<Vec<_>>();
        let high_tokens = [
            "delete",
            "remove",
            "rm",
            "write",
            "edit",
            "modify",
            "commit",
            "push",
            "github",
            "shell",
            "execute",
            "powershell",
            "cargo_run",
        ];
        let medium_tokens = ["install", "network", "download", "test", "tests", "build"];
        if high_tokens.iter().any(|token| {
            words.contains(token)
                || (token.contains('_') && normalized.contains(token))
                || (*token == "rm" && normalized == "rm")
        }) {
            Some(Self {
                task: task.to_owned(),
                level: TuiRiskLevel::High,
                reason: "task appears to request write, shell, Git/GitHub, or execution authority"
                    .to_owned(),
            })
        } else if medium_tokens.iter().any(|token| words.contains(token)) {
            Some(Self {
                task: task.to_owned(),
                level: TuiRiskLevel::Medium,
                reason: "task may require build, test, install, network, or expanded context"
                    .to_owned(),
            })
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TuiRiskLevel {
    Medium,
    High,
}

impl TuiRiskLevel {
    fn label(self) -> &'static str {
        match self {
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    fn color(self) -> Color {
        match self {
            Self::Medium => Color::Yellow,
            Self::High => Color::Red,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct TuiStep {
    turn: usize,
    label: String,
    detail: String,
    state: TuiStepState,
}

impl TuiStep {
    fn done(turn: usize, label: &str, detail: &str) -> Self {
        Self::new(turn, label, detail, TuiStepState::Done)
    }

    fn active(turn: usize, label: &str, detail: &str) -> Self {
        Self::new(turn, label, detail, TuiStepState::Active)
    }

    fn pending(turn: usize, label: &str, detail: &str) -> Self {
        Self::new(turn, label, detail, TuiStepState::Pending)
    }

    fn new(turn: usize, label: &str, detail: &str, state: TuiStepState) -> Self {
        Self {
            turn,
            label: label.to_owned(),
            detail: detail.to_owned(),
            state,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum TuiStepState {
    Done,
    Active,
    Pending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TuiScreen {
    Boot,
    Trust,
    Setup,
    Core,
    Workspace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TuiPane {
    Overview,
    Graph,
    Tasks,
    Approvals,
    Boundary,
    Keys,
}

impl TuiPane {
    fn next(self) -> Self {
        match self {
            Self::Overview => Self::Graph,
            Self::Graph => Self::Tasks,
            Self::Tasks => Self::Approvals,
            Self::Approvals => Self::Boundary,
            Self::Boundary => Self::Keys,
            Self::Keys => Self::Overview,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Graph => "Graph",
            Self::Tasks => "Tasks",
            Self::Approvals => "Approvals",
            Self::Boundary => "Boundary",
            Self::Keys => "Keys",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TuiKey {
    Tab,
    Focus(TuiPane),
    Screen(TuiScreen),
    MoveConversationDown,
    MoveConversationUp,
    MoveTaskDown,
    MoveTaskUp,
    Refresh,
    Quit,
    Filter(String),
    ToggleCommandPalette,
    InputChar(char),
    Backspace,
    SubmitCommand,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StatusInputMode {
    EventFeed,
    QuerySnapshot,
}

pub fn run<I, S, W>(args: I, mut writer: W) -> CliResult<i32>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
    W: Write,
{
    let args = normalize_args(args);
    run_command_with_default_interactive(&args, None::<&[u8]>, &mut writer, false)
}

pub fn run_with_io<I, S, R, W>(args: I, reader: R, mut writer: W) -> CliResult<i32>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
    R: BufRead,
    W: Write,
{
    let args = normalize_args(args);
    if args.first().is_some_and(|command| command == "repl") {
        run_repl(reader, writer)
    } else {
        run_command_with_default_interactive(&args, Some(reader), &mut writer, true)
    }
}

fn run_command(args: &[String], writer: &mut impl Write) -> CliResult<i32> {
    run_command_with_default_interactive(args, None::<&[u8]>, writer, false)
}

fn run_command_with_default_interactive<R>(
    args: &[String],
    reader: Option<R>,
    writer: &mut impl Write,
    default_interactive: bool,
) -> CliResult<i32>
where
    R: BufRead,
{
    let Some((command, rest)) = args.split_first() else {
        let mut options = parse_tui(&[])?;
        options.interactive = default_interactive;
        return run_tui(options, writer).map(|()| 0);
    };

    if command.starts_with('-') && !matches!(command.as_str(), "-h" | "--help") {
        let mut options = parse_tui(args)?;
        if default_interactive && options.keys.is_empty() {
            options.interactive = true;
        }
        return run_tui(options, writer).map(|()| 0);
    }

    match command.as_str() {
        "admit" => {
            let options = parse_admit(rest)?;
            let format = options.format;
            let admission = ShellController::default().admit_shell_request(options.into_draft())?;
            write_json(writer, &admission, format)?;
        }
        "manifest" => {
            let options = parse_manifest(rest)?;
            let manifest = adapter_manifest(options.surface);
            write_json(writer, &manifest, options.format)?;
        }
        "boundary" => {
            let options = parse_boundary(rest)?;
            let format = options.format;
            let report = boundary_report(options.surface);
            if matches!(format, OutputFormat::Text) {
                write_boundary_text(writer, &report)?;
            } else {
                write_json(writer, &report, format)?;
            }
        }
        "status" => {
            let options = parse_status(rest)?;
            let format = options.format;
            let render_limit = options.render_limit;
            let projection = project_status(options, reader)?;
            render_status_projection(writer, &projection, format, render_limit)?;
        }
        "watch" => {
            let options = parse_watch(rest)?;
            run_watch(options, writer)?;
        }
        "init" => {
            let options = parse_init(rest)?;
            run_init(options, writer)?;
        }
        "config" => {
            let options = parse_model_config_command(rest)?;
            run_config(options, writer)?;
        }
        "doctor" => {
            let options = parse_model_config_command(rest)?;
            run_doctor(options, writer)?;
        }
        "models" => {
            let options = parse_model_config_command(rest)?;
            run_models(options, writer)?;
        }
        "tui" => {
            let options = parse_tui(rest)?;
            run_tui(options, writer)?;
        }
        "help" | "--help" | "-h" => {
            writeln!(writer, "{}", help_text())?;
        }
        unknown => return Err(CliError::UnknownCommand(unknown.to_owned())),
    }

    Ok(0)
}

fn project_status<R>(
    options: StatusOptions,
    reader: Option<R>,
) -> CliResult<moxi_shells::ShellProjection>
where
    R: BufRead,
{
    let surface = options.surface;
    let profile_id = options.profile_id.clone();
    let graph_id = options.graph_id.clone();
    let input_mode = options.input_mode;
    let text = read_status_input(options, reader)?;
    match input_mode {
        StatusInputMode::EventFeed => {
            let snapshot: RuntimeEventFeedSnapshot = serde_json::from_str(&text)?;
            ensure_graph_matches(graph_id, snapshot.graph_id.as_deref())?;
            Ok(ShellController::default().project_event_feed(surface, profile_id, snapshot)?)
        }
        StatusInputMode::QuerySnapshot => {
            let snapshot: RuntimeQuerySnapshot = serde_json::from_str(&text)?;
            ensure_graph_matches(graph_id, Some(&snapshot.graph.graph_id))?;
            Ok(ShellController::default().project_query_snapshot(surface, snapshot)?)
        }
    }
}

fn render_status_projection(
    writer: &mut impl Write,
    projection: &moxi_shells::ShellProjection,
    format: OutputFormat,
    render_limit: Option<usize>,
) -> CliResult<()> {
    match format {
        OutputFormat::Text => write_status_text(writer, projection, render_limit)?,
        OutputFormat::Panel => write_status_panel(writer, projection, render_limit)?,
        OutputFormat::Json | OutputFormat::PrettyJson => write_json(writer, projection, format)?,
    }
    Ok(())
}

fn run_watch(options: WatchOptions, writer: &mut impl Write) -> CliResult<()> {
    for tick in 0..options.ticks {
        let projection = project_status(options.status.clone(), None::<&[u8]>)?;
        writeln!(writer, "watch tick {}/{}", tick + 1, options.ticks)?;
        render_status_projection(
            writer,
            &projection,
            options.status.format,
            options.status.render_limit,
        )?;
        if tick + 1 < options.ticks {
            thread::sleep(options.interval);
        }
    }
    Ok(())
}

fn run_init(options: InitOptions, writer: &mut impl Write) -> CliResult<()> {
    let template = render_model_config_template(
        options.provider,
        &options.endpoint,
        &options.model,
        &options.api_key_env,
    );
    if options.write {
        if options.config_path.exists() && !options.force {
            return Err(CliError::ModelConfigExists(
                options.config_path.display().to_string(),
            ));
        }
        if let Some(parent) = options.config_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&options.config_path, template.as_bytes())?;
        writeln!(writer, "MOXI model config written")?;
        writeln!(writer, "path: {}", options.config_path.display())?;
        writeln!(writer, "provider: {}", options.provider.label())?;
        writeln!(writer, "endpoint: {}", options.endpoint)?;
        writeln!(writer, "model: {}", options.model)?;
        writeln!(writer, "api_key_env: {}", options.api_key_env)?;
        writeln!(
            writer,
            "next: set ${} in your shell, then run moxi and use /doctor",
            options.api_key_env
        )?;
    } else {
        writeln!(writer, "MOXI model config preview")?;
        writeln!(writer, "path: {}", options.config_path.display())?;
        writeln!(writer, "mode: dry-run; pass --write to create the file")?;
        writeln!(
            writer,
            "secret rule: this template stores only api_key_env, never a raw API key"
        )?;
        writeln!(writer)?;
        write!(writer, "{template}")?;
        writeln!(writer)?;
        writeln!(
            writer,
            "next: set ${} in your shell, then run moxi init --write",
            options.api_key_env
        )?;
    }
    Ok(())
}

fn run_config(options: ModelConfigCommandOptions, writer: &mut impl Write) -> CliResult<()> {
    let config = TuiModelConfig::load_at(&options.config_path);
    writeln!(writer, "MOXI model config")?;
    writeln!(writer, "{}", config.redacted_summary())?;
    writeln!(
        writer,
        "boundary: read-only config inspection; secrets are redacted"
    )?;
    Ok(())
}

fn run_doctor(options: ModelConfigCommandOptions, writer: &mut impl Write) -> CliResult<()> {
    let config = TuiModelConfig::load_at(&options.config_path);
    let report = TuiModelDoctor::check(&config);
    writeln!(writer, "{}", report.cli_text())?;
    writeln!(
        writer,
        "boundary: read-only connectivity probe; no execution or mutation authority"
    )?;
    Ok(())
}

fn run_models(options: ModelConfigCommandOptions, writer: &mut impl Write) -> CliResult<()> {
    let config = TuiModelConfig::load_at(&options.config_path);
    let report = TuiModelCatalog::list(&config);
    writeln!(writer, "{}", report.cli_text())?;
    writeln!(
        writer,
        "boundary: read-only model catalog probe; no execution or mutation authority"
    )?;
    Ok(())
}

fn run_tui(options: TuiOptions, writer: &mut impl Write) -> CliResult<()> {
    let mut state = TuiState::default();
    let mut projection = project_status(options.status.clone(), None::<&[u8]>)?;
    if options.interactive {
        state.screen = TuiScreen::Boot;
        state.command_status = "startup: Enter continues · q exits".into();
        return run_tui_interactive(options, projection, state);
    }
    for key in &options.keys {
        apply_tui_key(&mut state, key);
        if matches!(key, TuiKey::Refresh) {
            projection = project_status(options.status.clone(), None::<&[u8]>)?;
        }
        if state.should_quit {
            break;
        }
    }
    write_tui_snapshot(writer, &projection, &state, options.width, options.height)
}

fn run_tui_interactive(
    options: TuiOptions,
    mut projection: moxi_shells::ShellProjection,
    mut state: TuiState,
) -> CliResult<()> {
    let mut stdout = std::io::stdout();
    enable_raw_mode()?;
    if let Err(error) = execute!(stdout, EnterAlternateScreen) {
        let _ = disable_raw_mode();
        return Err(error.into());
    }

    let result = run_tui_interactive_inner(&options, &mut stdout, &mut projection, &mut state);

    let raw_mode_result = disable_raw_mode();
    let alternate_screen_result = execute!(stdout, LeaveAlternateScreen);

    result?;
    raw_mode_result?;
    alternate_screen_result?;
    Ok(())
}

fn run_tui_interactive_inner(
    options: &TuiOptions,
    stdout: &mut Stdout,
    projection: &mut moxi_shells::ShellProjection,
    state: &mut TuiState,
) -> CliResult<()> {
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    loop {
        terminal.draw(|frame| {
            let area = frame.area();
            render_tui_snapshot(frame, area, projection, state);
        })?;
        if state.should_quit {
            break;
        }
        if event::poll(options.poll_interval)? {
            if let Event::Key(event) = event::read()? {
                if let Some(key) = tui_key_from_event(event) {
                    apply_tui_key(state, &key);
                    if matches!(key, TuiKey::Refresh) {
                        *projection = project_status(options.status.clone(), None::<&[u8]>)?;
                    }
                }
            }
        }
    }
    Ok(())
}

fn tui_key_from_event(event: KeyEvent) -> Option<TuiKey> {
    match event.code {
        KeyCode::Tab => Some(TuiKey::Tab),
        KeyCode::Enter => Some(TuiKey::SubmitCommand),
        KeyCode::Backspace => Some(TuiKey::Backspace),
        KeyCode::PageDown => Some(TuiKey::MoveConversationDown),
        KeyCode::PageUp => Some(TuiKey::MoveConversationUp),
        KeyCode::Down => Some(TuiKey::MoveTaskDown),
        KeyCode::Up => Some(TuiKey::MoveTaskUp),
        KeyCode::Char('?') => Some(TuiKey::Focus(TuiPane::Keys)),
        KeyCode::Char('o') | KeyCode::Char('O') => Some(TuiKey::Focus(TuiPane::Overview)),
        KeyCode::Char('g') | KeyCode::Char('G') => Some(TuiKey::Focus(TuiPane::Graph)),
        KeyCode::Char('t') | KeyCode::Char('T') => Some(TuiKey::Focus(TuiPane::Tasks)),
        KeyCode::Char('a') | KeyCode::Char('A') => Some(TuiKey::Focus(TuiPane::Approvals)),
        KeyCode::Char('b') | KeyCode::Char('B') => Some(TuiKey::Focus(TuiPane::Boundary)),
        KeyCode::Char('1') => Some(TuiKey::Screen(TuiScreen::Boot)),
        KeyCode::Char('2') => Some(TuiKey::Screen(TuiScreen::Trust)),
        KeyCode::Char('3') => Some(TuiKey::Screen(TuiScreen::Setup)),
        KeyCode::Char('4') => Some(TuiKey::Screen(TuiScreen::Core)),
        KeyCode::Char('5') => Some(TuiKey::Screen(TuiScreen::Workspace)),
        KeyCode::Char('f') | KeyCode::Char('F') => Some(TuiKey::Focus(TuiPane::Tasks)),
        KeyCode::Char('j') | KeyCode::Char('J') => Some(TuiKey::MoveTaskDown),
        KeyCode::Char('k') | KeyCode::Char('K') => Some(TuiKey::MoveTaskUp),
        KeyCode::Char('r') | KeyCode::Char('R') => Some(TuiKey::Refresh),
        KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => Some(TuiKey::Quit),
        KeyCode::Char(value) => Some(TuiKey::InputChar(value)),
        _ => None,
    }
}

fn apply_tui_key(state: &mut TuiState, key: &TuiKey) {
    match key {
        TuiKey::Tab => state.active_pane = state.active_pane.next(),
        TuiKey::Focus(pane) => state.active_pane = *pane,
        TuiKey::Screen(screen) => {
            state.screen = *screen;
            if state.screen != TuiScreen::Setup {
                state.setup_notice = None;
            }
        }
        TuiKey::MoveConversationDown => {
            if state.show_command_palette {
                move_command_palette_selection(state, 5);
            } else {
                state.active_pane = TuiPane::Overview;
                state.follow_latest_message = false;
                state.conversation_scroll = state.conversation_scroll.saturating_add(1);
            }
        }
        TuiKey::MoveConversationUp => {
            if state.show_command_palette {
                move_command_palette_selection(state, -5);
            } else {
                state.active_pane = TuiPane::Overview;
                state.follow_latest_message = false;
                state.conversation_scroll = state.conversation_scroll.saturating_sub(1);
            }
        }
        TuiKey::MoveTaskDown => {
            if state.show_command_palette {
                move_command_palette_selection(state, 1);
            } else {
                state.active_pane = TuiPane::Tasks;
                state.follow_active_step = false;
                let max_index = state.session.steps.len().saturating_sub(1);
                state.selected_task_index =
                    state.selected_task_index.saturating_add(1).min(max_index);
            }
        }
        TuiKey::MoveTaskUp => {
            if state.show_command_palette {
                move_command_palette_selection(state, -1);
            } else {
                state.active_pane = TuiPane::Tasks;
                state.follow_active_step = false;
                state.selected_task_index = state.selected_task_index.saturating_sub(1);
            }
        }
        TuiKey::Refresh => {
            state.refresh_count += 1;
            state.session.advance_loading();
            state.follow_latest_message = true;
            state.conversation_scroll = 0;
            state.selected_task_index = state.session.active_step_index;
            state.command_status = if state.session.is_streaming() {
                "streaming agent response; refresh advances local demo frame".into()
            } else {
                "latest agent response is complete; shell remains read-only".into()
            };
        }
        TuiKey::Quit => state.should_quit = true,
        TuiKey::Filter(value) => {
            state.filter = if value.is_empty() {
                None
            } else {
                Some(value.to_owned())
            };
            state.selected_task_index = 0;
        }
        TuiKey::ToggleCommandPalette => {
            state.show_command_palette = !state.show_command_palette;
            if state.show_command_palette {
                state.active_pane = TuiPane::Keys;
                state.command_palette_index = 0;
                state.command_status =
                    "command palette open: Up/Down select, PgUp/PgDn scroll, Enter run".into();
            } else {
                state.command_status = "ready: ? shortcuts · / command menu".into();
            }
        }
        TuiKey::InputChar(value) => {
            state.command_input.push(*value);
            state.active_pane = TuiPane::Keys;
            if state.screen == TuiScreen::Setup {
                state.setup_notice = Some("setup command input active".to_owned());
            }
            if state.command_input.starts_with('/') {
                state.show_command_palette = true;
                state.command_palette_index = 0;
                state.command_status =
                    "command palette filtering; Enter runs selected command".into();
            }
        }
        TuiKey::Backspace => {
            state.command_input.pop();
            state.active_pane = TuiPane::Keys;
            if state.screen == TuiScreen::Setup && state.command_input.is_empty() {
                state.setup_notice = None;
            }
            if state.command_input.starts_with('/') {
                state.show_command_palette = true;
                state.command_palette_index = 0;
            } else if state.command_input.is_empty() {
                state.show_command_palette = false;
            }
        }
        TuiKey::SubmitCommand => {
            if state.screen != TuiScreen::Workspace && state.command_input.trim().is_empty() {
                advance_tui_startup_screen(state);
            } else if state.show_command_palette {
                submit_selected_palette_command(state);
            } else {
                submit_tui_command(state);
            }
        }
    }
}

fn move_command_palette_selection(state: &mut TuiState, delta: isize) {
    let commands = filtered_command_palette_entries(state.command_input.trim());
    if commands.is_empty() {
        state.command_palette_index = 0;
        return;
    }
    let max_index = commands.len() - 1;
    let step = delta.unsigned_abs();
    if delta.is_negative() {
        state.command_palette_index = state.command_palette_index.saturating_sub(step);
    } else {
        state.command_palette_index = state
            .command_palette_index
            .saturating_add(step)
            .min(max_index);
    }
    state.command_status = format!(
        "command palette selected {}",
        commands[state.command_palette_index].command
    );
}

fn submit_selected_palette_command(state: &mut TuiState) {
    let commands = filtered_command_palette_entries(state.command_input.trim());
    if let Some(entry) = commands.get(
        state
            .command_palette_index
            .min(commands.len().saturating_sub(1)),
    ) {
        state.command_input = entry.command.to_owned();
        submit_tui_command(state);
    } else {
        state.command_input.clear();
        state.show_command_palette = false;
        state.command_status = "no matching command".into();
    }
}

fn advance_tui_startup_screen(state: &mut TuiState) {
    match state.screen {
        TuiScreen::Boot => {
            if state.session.trust.should_show_gate() {
                state.screen = TuiScreen::Trust;
                state.command_status =
                    "trust gate: Enter read-only · /approve accept · /deny block".into();
            } else if state.session.model_config.needs_setup() {
                state.screen = TuiScreen::Setup;
                state.command_status = "first-run setup: model/API config is missing".into();
            } else {
                state.screen = TuiScreen::Core;
                state.command_status = "trusted read-only workspace; Agent Core ready".into();
            }
        }
        TuiScreen::Trust => {
            if state.session.model_config.needs_setup() {
                state.screen = TuiScreen::Setup;
                state.command_status = "first-run setup: model/API config is missing".into();
            } else {
                state.screen = TuiScreen::Core;
                state.command_status = "Agent Core ready: Enter opens workspace".into();
            }
        }
        TuiScreen::Setup => {
            state.screen = TuiScreen::Core;
            state.setup_notice = None;
            state.command_status = "setup guide acknowledged; Agent Core ready".into();
        }
        TuiScreen::Core => {
            state.screen = TuiScreen::Workspace;
            state.active_pane = TuiPane::Keys;
            state.command_status = "ready: type a task or open / command menu".into();
        }
        TuiScreen::Workspace => {}
    }
}

fn submit_tui_command(state: &mut TuiState) {
    let command = state.command_input.trim().to_owned();
    state.command_input.clear();
    state.show_command_palette = false;
    let from_setup = state.screen == TuiScreen::Setup;
    if !command.starts_with('/') && !command.is_empty() {
        if let Some(prompt) = TuiRiskPrompt::detect(&command) {
            state.pending_risk = Some(prompt);
            state.active_pane = TuiPane::Approvals;
            state.command_status = "risk prompt pending near input; use /approve or /deny".into();
            return;
        }
        state.session.submit_user_task(&command);
        state.screen = TuiScreen::Workspace;
        state.active_pane = TuiPane::Keys;
        state.follow_active_step = true;
        state.follow_latest_message = true;
        state.conversation_scroll = 0;
        state.selected_task_index = state.session.active_step_index;
        state.command_status = format!(
            "submitted Turn {} to session {}; streaming local agent response",
            state.session.turn_count, state.session.id
        );
        return;
    }
    match normalize_token(command.trim_start_matches('/')).as_str() {
        "" => {
            state.command_status = "ready: ? shortcuts · / command menu".into();
        }
        "init" | "setup" => {
            if from_setup {
                match state.session.write_setup_model_config() {
                    Ok(notice) => {
                        state.setup_notice = Some(notice);
                        state.command_status =
                            "setup init wrote env-only config; set API key env then run /doctor"
                                .into();
                    }
                    Err(notice) => {
                        state.setup_notice = Some(notice);
                        state.command_status =
                            "setup init blocked; existing config was not overwritten".into();
                    }
                }
            } else {
                state.command_status =
                    "open First-run Setup before using /init; top-level moxi init is also available"
                        .into();
            }
        }
        "help" | "keys" => {
            state.active_pane = TuiPane::Keys;
            state.show_command_palette = true;
            state.command_status = "command menu open".into();
        }
        "status" => {
            state.active_pane = TuiPane::Overview;
            state.session.push_status_message();
            state.follow_latest_message = true;
            state.conversation_scroll = 0;
            state.command_status = format!(
                "showing session {} status ({})",
                state.session.id,
                state.session.mode.label()
            );
        }
        "tasks" => {
            state.active_pane = TuiPane::Tasks;
            state.screen = TuiScreen::Workspace;
            state.session.push_tasks_message();
            state.follow_latest_message = true;
            state.conversation_scroll = 0;
            state.command_status = format!("showing {} session steps", state.session.steps.len());
        }
        "agents" | "core" => {
            state.session.push_agents_message();
            state.follow_latest_message = true;
            state.conversation_scroll = 0;
            state.screen = TuiScreen::Core;
            state.command_status = "showing Agent Core information".into();
        }
        "skills" => {
            state.session.push_skills_message();
            state.follow_latest_message = true;
            state.conversation_scroll = 0;
            state.screen = TuiScreen::Core;
            state.command_status = "showing loaded tools and skills".into();
        }
        "context" => {
            state.active_pane = TuiPane::Overview;
            state.screen = TuiScreen::Workspace;
            state.session.push_context_message();
            state.follow_latest_message = true;
            state.conversation_scroll = 0;
            let snapshot = state.session.context_snapshot();
            state.command_status = format!(
                "showing {} context sources ({}%)",
                snapshot.sources.len(),
                snapshot.percent
            );
        }
        "config" => {
            state.active_pane = TuiPane::Overview;
            if from_setup {
                let notice = state.session.setup_config_notice();
                state.setup_notice = Some(notice);
            } else {
                state.screen = TuiScreen::Workspace;
                state.session.push_config_message();
            }
            state.follow_latest_message = true;
            state.conversation_scroll = 0;
            state.command_status = if from_setup {
                "setup config check complete; secrets are redacted".into()
            } else {
                "showing model/API configuration; secrets are redacted".into()
            };
        }
        "doctor" => {
            state.active_pane = TuiPane::Overview;
            let status = if from_setup {
                let notice = state.session.setup_doctor_notice();
                let label = notice
                    .split_whitespace()
                    .find_map(|part| part.strip_prefix("status="))
                    .unwrap_or("unknown")
                    .to_owned();
                state.setup_notice = Some(notice);
                label
            } else {
                state.screen = TuiScreen::Workspace;
                state.session.push_doctor_message().label().to_owned()
            };
            state.follow_latest_message = true;
            state.conversation_scroll = 0;
            state.command_status = format!("doctor completed: {status}");
        }
        "models" => {
            state.active_pane = TuiPane::Overview;
            let status = if from_setup {
                let notice = state.session.setup_models_notice();
                let label = notice
                    .split_whitespace()
                    .find_map(|part| part.strip_prefix("status="))
                    .unwrap_or("unknown")
                    .to_owned();
                state.setup_notice = Some(notice);
                label
            } else {
                state.screen = TuiScreen::Workspace;
                state.session.push_models_message().label().to_owned()
            };
            state.follow_latest_message = true;
            state.conversation_scroll = 0;
            state.command_status = format!("models completed: {status}");
        }
        "save" | "persist" => match state.session.save_persistence_snapshot() {
            Ok(path) => {
                state.active_pane = TuiPane::Overview;
                state.command_status =
                    format!("saved local TUI session snapshot to {}", path.display());
            }
            Err(error) => {
                state.active_pane = TuiPane::Boundary;
                state.command_status = format!("session snapshot save failed: {error}");
            }
        },
        "resume" | "load" => {
            let path = state.session.persistence_path();
            match TuiAgentSession::load_persistence_snapshot(&path) {
                Ok(snapshot) => {
                    state.active_pane = TuiPane::Overview;
                    state.screen = TuiScreen::Workspace;
                    state.session.push_resume_message(&snapshot);
                    state.follow_latest_message = true;
                    state.conversation_scroll = 0;
                    state.command_status =
                        format!("loaded local TUI snapshot summary from {}", path.display());
                }
                Err(error) => {
                    state.active_pane = TuiPane::Boundary;
                    state.command_status = format!("no readable TUI snapshot: {error}");
                }
            }
        }
        "trust" => {
            state.screen = TuiScreen::Trust;
            state.session.push_trust_message();
            state.follow_latest_message = true;
            state.conversation_scroll = 0;
            state.command_status = "workspace trust review opened".into();
        }
        "approve" | "y" => {
            state.active_pane = TuiPane::Approvals;
            if let Some(prompt) = state.pending_risk.take() {
                let task = prompt.task;
                state.session.submit_user_task(&task);
                state.screen = TuiScreen::Workspace;
                state.follow_active_step = true;
                state.follow_latest_message = true;
                state.conversation_scroll = 0;
                state.selected_task_index = state.session.active_step_index;
                state.command_status =
                    "risk intent accepted for local planning only; P0 still authorizes effects"
                        .into();
            } else {
                state.session.approve_read_only_trust();
                state.screen = TuiScreen::Core;
                state.command_status =
                    "read-only trust intent captured; P0 still authorizes effects".into();
            }
        }
        "deny" | "n" => {
            state.active_pane = TuiPane::Approvals;
            if state.pending_risk.take().is_some() {
                state.screen = TuiScreen::Workspace;
                state.command_status = "risk prompt denied; task was not submitted".into();
            } else {
                state.session.deny_trust();
                state.screen = TuiScreen::Trust;
                state.command_status =
                    "workspace trust denied; risky action remains blocked".into();
            }
        }
        "details" => {
            state.active_pane = TuiPane::Tasks;
            state.selected_task_index = selected_session_step_index(state);
            state.follow_active_step = false;
            state.command_status = "selected step detail is visible in task tracking".into();
        }
        "follow" => {
            state.active_pane = TuiPane::Tasks;
            state.follow_active_step = true;
            state.selected_task_index = state.session.active_step_index;
            state.command_status = "task tracking follows active step".into();
        }
        "boundary" => {
            state.active_pane = TuiPane::Boundary;
            state.command_status = "showing shell authority boundary".into();
        }
        "demo" => {
            state.active_pane = TuiPane::Graph;
            state.filter = None;
            state.selected_task_index = 0;
            state.command_status = "demo projection restored".into();
        }
        "clear" => {
            state.filter = None;
            state.command_status = "filter cleared".into();
        }
        "quit" | "exit" => state.should_quit = true,
        value if value.starts_with("filter_") => {
            let filter = value.trim_start_matches("filter_").replace('_', " ");
            state.filter = if filter.is_empty() {
                None
            } else {
                Some(filter)
            };
            state.selected_task_index = 0;
            state.active_pane = TuiPane::Tasks;
            state.command_status = "filter applied; projection remains read-only".into();
        }
        _ => {
            if from_setup {
                state.setup_notice = Some(
                    "setup: supported actions are /init, /config, /doctor, and /models".to_owned(),
                );
            }
            state.command_status =
                "blocked: safe shell only; open / command menu for supported actions".into();
        }
    }
}

fn read_status_input<R>(options: StatusOptions, reader: Option<R>) -> CliResult<String>
where
    R: BufRead,
{
    let text = if let Some(path) = options.input_path {
        fs::read_to_string(path)?
    } else if options.allow_demo_input {
        demo_query_snapshot_json()
    } else {
        let mut reader = reader.ok_or(CliError::MissingRequired("--input or stdin"))?;
        let mut text = String::new();
        reader.read_to_string(&mut text)?;
        text
    };
    Ok(text.trim_start_matches('\u{feff}').to_owned())
}

fn ensure_graph_matches(expected: Option<String>, actual: Option<&str>) -> CliResult<()> {
    if let Some(expected) = expected {
        let actual = actual.unwrap_or("<none>");
        if actual != expected {
            return Err(CliError::GraphMismatch {
                expected,
                actual: actual.to_owned(),
            });
        }
    }
    Ok(())
}

fn demo_query_snapshot_json() -> String {
    serde_json::json!({
        "graph": {
            "graph_id": "demo_graph",
            "goal": "preview MOXI shell experience",
            "path": "task_path",
            "task_count": 4,
            "completed_count": 1,
            "running_count": 1,
            "blocked_count": 2,
            "awaiting_approval_count": 1,
            "failed_count": 0,
            "is_complete": false
        },
        "planner": null,
        "tasks": [
            {
                "task_id": "demo_intake",
                "skill_id": null,
                "capability_id": "shell.admit",
                "target": {
                    "resource_type": "file",
                    "resource_ref": "workspace://current"
                },
                "state": "completed",
                "last_stage": "completed",
                "progress": 1.0,
                "message": "request normalized into a read-only shell projection",
                "idempotency_key": null,
                "retry_safe": true,
                "blocker": null,
                "updated_at": "2026-05-28T01:30:00Z"
            },
            {
                "task_id": "demo_plan",
                "skill_id": "skill.runtime.plan",
                "capability_id": "runtime.plan",
                "target": {
                    "resource_type": "file",
                    "resource_ref": "docs/status.md"
                },
                "state": "running",
                "last_stage": "executing",
                "progress": 0.62,
                "message": "rendering current graph, tasks, blockers, and boundary",
                "idempotency_key": "demo.plan.readonly",
                "retry_safe": true,
                "blocker": null,
                "updated_at": "2026-05-28T01:30:03Z"
            },
            {
                "task_id": "demo_approval",
                "skill_id": "skill.p0.review",
                "capability_id": "github.write",
                "target": {
                    "resource_type": "network",
                    "resource_ref": "github://origin/v0.2.0"
                },
                "state": "awaiting_approval",
                "last_stage": "awaiting_approval",
                "progress": 0.2,
                "message": "approval is display-only here; P0 owns the real decision",
                "idempotency_key": null,
                "retry_safe": null,
                "blocker": "awaiting_approval",
                "updated_at": "2026-05-28T01:30:05Z"
            },
            {
                "task_id": "demo_boundary",
                "skill_id": "skill.boundary.check",
                "capability_id": "ledger.commit",
                "target": {
                    "resource_type": "workflow",
                    "resource_ref": "p0://ledger"
                },
                "state": "planned",
                "last_stage": "planned",
                "progress": 0.0,
                "message": "blocked in shell: no ticket, execute, verify, or ledger authority",
                "idempotency_key": null,
                "retry_safe": null,
                "blocker": "dependency_incomplete",
                "updated_at": "2026-05-28T01:30:07Z"
            }
        ],
        "attempts": [],
        "adoption_probes": [],
        "events": [{
            "event_id": "demo_event_1",
            "graph_id": "demo_graph",
            "run_id": "demo_run",
            "task_id": "demo_plan",
            "stage": "executing",
            "message": "preview dashboard is using built-in demo data",
            "progress": 0.62,
            "timestamp": "2026-05-28T01:30:03Z"
        }],
        "resume_plan": {
            "graph_id": "demo_graph",
            "completed_task_ids": ["demo_intake"],
            "ready_task_ids": [],
            "blocked_task_ids": ["demo_boundary"],
            "running_task_ids": ["demo_plan"],
            "awaiting_approval_task_ids": ["demo_approval"],
            "failed_task_ids": [],
            "blockers": {
                "demo_approval": "awaiting_approval",
                "demo_boundary": "dependency_incomplete"
            },
            "adoption_recommendations": {},
            "running_task_policy": "require_inspection",
            "is_complete": false
        },
        "event_cursor": 1,
        "policy_profile": {
            "profile_id": "shell.cli.fast",
            "allowed_capabilities": ["file.read"],
            "allow_fast_path": true,
            "allow_task_path": false,
            "allow_trusted_execution_path": false,
            "allow_skills": false,
            "allow_running_task_retry": false,
            "max_tasks_per_graph": 4
        }
    })
    .to_string()
}

fn run_repl<R, W>(mut reader: R, mut writer: W) -> CliResult<i32>
where
    R: BufRead,
    W: Write,
{
    writeln!(
        writer,
        "moxi-cli repl: submit/guarded rich-cli only. Type help or exit."
    )?;

    let mut line = String::new();
    loop {
        write!(writer, "moxi> ")?;
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            writeln!(writer)?;
            break;
        }

        let trimmed = line.trim().trim_start_matches('\u{feff}').trim();
        if trimmed.is_empty() {
            continue;
        }
        if matches!(trimmed, "exit" | "quit") {
            writeln!(writer, "bye")?;
            break;
        }

        match tokenize_repl_line(trimmed).and_then(|args| run_command(&args, &mut writer)) {
            Ok(_) => {}
            Err(error) => writeln!(writer, "error: {error}")?,
        }
    }

    Ok(0)
}

fn normalize_args<I, S>(args: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut args = args.into_iter().map(Into::into).collect::<Vec<_>>();
    if args.first().is_some_and(|arg| looks_like_program_name(arg)) {
        args.remove(0);
    }
    args
}

fn looks_like_program_name(value: &str) -> bool {
    let normalized = value.replace('\\', "/");
    let name = normalized.rsplit('/').next().unwrap_or(value);
    matches!(name, "moxi-cli" | "moxi-cli.exe" | "moxi" | "moxi.exe")
}

fn tokenize_repl_line(line: &str) -> CliResult<Vec<String>> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut token_started = false;
    let mut chars = line.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '\\' if quote.is_some() => {
                if matches!(chars.peek(), Some('"') | Some('\'') | Some('\\')) {
                    current.push(chars.next().unwrap());
                } else {
                    current.push(ch);
                }
                token_started = true;
            }
            '"' | '\'' => {
                if quote == Some(ch) {
                    quote = None;
                } else if quote.is_none() {
                    quote = Some(ch);
                    token_started = true;
                } else {
                    current.push(ch);
                    token_started = true;
                }
            }
            ch if ch.is_whitespace() && quote.is_none() => {
                if token_started {
                    tokens.push(std::mem::take(&mut current));
                    token_started = false;
                }
            }
            ch => {
                current.push(ch);
                token_started = true;
            }
        }
    }

    if quote.is_some() {
        return Err(CliError::UnterminatedQuote);
    }
    if token_started {
        tokens.push(current);
    }

    Ok(tokens)
}

fn parse_admit(args: &[String]) -> CliResult<AdmitOptions> {
    let mut tenant_id = "local".to_owned();
    let mut user_id = "local".to_owned();
    let mut workspace_root = env::current_dir()?.to_string_lossy().into_owned();
    let mut goal = None;
    let mut requested_capabilities = Vec::new();
    let mut risk_level = RiskLevel::Low;
    let mut session_id = None;
    let mut request_id = None;
    let mut source_ref = None;
    let mut format = OutputFormat::Json;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--tenant" | "-t" => {
                tenant_id = value_after(args, &mut index, "--tenant")?;
            }
            "--user" | "-u" => {
                user_id = value_after(args, &mut index, "--user")?;
            }
            "--workspace" | "-w" => {
                workspace_root = value_after(args, &mut index, "--workspace")?;
            }
            "--goal" | "-g" => {
                goal = Some(value_after(args, &mut index, "--goal")?);
            }
            "--capability" | "-c" => {
                requested_capabilities.push(value_after(args, &mut index, "--capability")?);
            }
            "--risk" => {
                risk_level = parse_risk(&value_after(args, &mut index, "--risk")?)?;
            }
            "--session" => {
                session_id = Some(value_after(args, &mut index, "--session")?);
            }
            "--request-id" => {
                request_id = Some(value_after(args, &mut index, "--request-id")?);
            }
            "--source" => {
                source_ref = Some(value_after(args, &mut index, "--source")?);
            }
            "--pretty" => {
                format = OutputFormat::PrettyJson;
            }
            "--json" => {
                format = OutputFormat::Json;
            }
            flag if flag.starts_with('-') => return Err(CliError::UnknownFlag(flag.to_owned())),
            value => {
                if goal.is_none() {
                    goal = Some(value.to_owned());
                } else {
                    return Err(CliError::UnknownFlag(value.to_owned()));
                }
            }
        }
        index += 1;
    }

    Ok(AdmitOptions {
        tenant_id,
        user_id,
        workspace_root,
        goal: goal.ok_or(CliError::MissingRequired("--goal"))?,
        requested_capabilities,
        risk_level,
        session_id,
        request_id,
        source_ref,
        format,
    })
}

fn parse_manifest(args: &[String]) -> CliResult<ManifestOptions> {
    let mut surface = ShellSurface::Cli;
    let mut format = OutputFormat::Json;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--surface" | "-s" => {
                surface = parse_surface(&value_after(args, &mut index, "--surface")?)?;
            }
            "--pretty" => {
                format = OutputFormat::PrettyJson;
            }
            "--json" => {
                format = OutputFormat::Json;
            }
            flag if flag.starts_with('-') => return Err(CliError::UnknownFlag(flag.to_owned())),
            value => return Err(CliError::UnknownFlag(value.to_owned())),
        }
        index += 1;
    }

    Ok(ManifestOptions { surface, format })
}

fn parse_boundary(args: &[String]) -> CliResult<BoundaryOptions> {
    let mut surface = ShellSurface::Cli;
    let mut format = OutputFormat::Json;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--surface" | "-s" => {
                surface = parse_surface(&value_after(args, &mut index, "--surface")?)?;
            }
            "--pretty" => {
                format = OutputFormat::PrettyJson;
            }
            "--json" => {
                format = OutputFormat::Json;
            }
            "--text" => {
                format = OutputFormat::Text;
            }
            flag if flag.starts_with('-') => return Err(CliError::UnknownFlag(flag.to_owned())),
            value => return Err(CliError::UnknownFlag(value.to_owned())),
        }
        index += 1;
    }

    Ok(BoundaryOptions { surface, format })
}

fn parse_status(args: &[String]) -> CliResult<StatusOptions> {
    parse_status_with_defaults(args, OutputFormat::Json)
}

fn parse_status_with_defaults(
    args: &[String],
    default_format: OutputFormat,
) -> CliResult<StatusOptions> {
    let mut surface = ShellSurface::Cli;
    let mut profile_id = None;
    let mut graph_id = None;
    let mut input_path = None;
    let mut input_mode = None;
    let mut format = default_format;
    let mut render_limit = None;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--surface" | "-s" => {
                surface = parse_surface(&value_after(args, &mut index, "--surface")?)?;
            }
            "--profile" | "--profile-id" => {
                profile_id = Some(value_after(args, &mut index, "--profile")?);
            }
            "--graph" | "--graph-id" => {
                graph_id = Some(value_after(args, &mut index, "--graph")?);
            }
            "--input" | "-i" => {
                input_path = Some(value_after(args, &mut index, "--input")?);
            }
            "--feed" | "--event-feed" => {
                if input_mode.replace(StatusInputMode::EventFeed).is_some() {
                    return Err(CliError::StatusInputConflict);
                }
            }
            "--query" | "--query-snapshot" => {
                if input_mode.replace(StatusInputMode::QuerySnapshot).is_some() {
                    return Err(CliError::StatusInputConflict);
                }
            }
            "--pretty" => {
                format = OutputFormat::PrettyJson;
            }
            "--json" => {
                format = OutputFormat::Json;
            }
            "--text" => {
                format = OutputFormat::Text;
            }
            "--panel" => {
                format = OutputFormat::Panel;
            }
            "--limit" => {
                let value = value_after(args, &mut index, "--limit")?;
                render_limit = Some(parse_limit(&value)?);
            }
            flag if flag.starts_with('-') => return Err(CliError::UnknownFlag(flag.to_owned())),
            value => return Err(CliError::UnknownFlag(value.to_owned())),
        }
        index += 1;
    }

    Ok(StatusOptions {
        surface,
        profile_id: profile_id.unwrap_or_else(|| default_status_profile(surface).to_owned()),
        graph_id,
        input_path,
        allow_demo_input: false,
        input_mode: input_mode.unwrap_or(StatusInputMode::EventFeed),
        format,
        render_limit,
    })
}

fn parse_watch(args: &[String]) -> CliResult<WatchOptions> {
    let mut status_args = Vec::new();
    let mut ticks = 1;
    let mut interval = Duration::from_millis(1000);
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--ticks" => {
                let value = value_after(args, &mut index, "--ticks")?;
                ticks = parse_watch_ticks(&value)?;
            }
            "--interval-ms" => {
                let value = value_after(args, &mut index, "--interval-ms")?;
                interval = Duration::from_millis(parse_watch_interval_ms(&value)?);
            }
            value => status_args.push(value.to_owned()),
        }
        index += 1;
    }

    let status = parse_status_with_defaults(&status_args, OutputFormat::Panel)?;
    if status.input_path.is_none() {
        return Err(CliError::MissingRequired("--input"));
    }

    Ok(WatchOptions {
        status,
        ticks,
        interval,
    })
}

fn parse_init(args: &[String]) -> CliResult<InitOptions> {
    let mut provider = TuiModelProvider::OpenAi;
    let mut endpoint: Option<String> = None;
    let mut model: Option<String> = None;
    let mut api_key_env: Option<String> = None;
    let mut write = false;
    let mut force = false;
    let mut config_path: Option<PathBuf> = None;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--provider" | "-p" => {
                provider =
                    TuiModelProvider::try_parse(&value_after(args, &mut index, "--provider")?)?;
            }
            "--endpoint" | "-e" => {
                endpoint = Some(value_after(args, &mut index, "--endpoint")?);
            }
            "--model" | "-m" => {
                model = Some(value_after(args, &mut index, "--model")?);
            }
            "--api-key-env" => {
                api_key_env = Some(value_after(args, &mut index, "--api-key-env")?);
            }
            "--config" => {
                config_path = Some(PathBuf::from(value_after(args, &mut index, "--config")?));
            }
            "--write" => {
                write = true;
            }
            "--force" => {
                force = true;
            }
            flag if flag.starts_with('-') => return Err(CliError::UnknownFlag(flag.to_owned())),
            value => return Err(CliError::UnknownFlag(value.to_owned())),
        }
        index += 1;
    }

    Ok(InitOptions {
        provider,
        endpoint: endpoint.unwrap_or_else(|| provider.default_endpoint().to_owned()),
        model: model.unwrap_or_else(|| default_init_model(provider).to_owned()),
        api_key_env: api_key_env.unwrap_or_else(|| provider.default_key_env().to_owned()),
        write,
        force,
        config_path: config_path.unwrap_or_else(default_model_config_path),
    })
}

fn parse_model_config_command(args: &[String]) -> CliResult<ModelConfigCommandOptions> {
    let mut config_path: Option<PathBuf> = None;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--config" => {
                config_path = Some(PathBuf::from(value_after(args, &mut index, "--config")?));
            }
            flag if flag.starts_with('-') => return Err(CliError::UnknownFlag(flag.to_owned())),
            value => return Err(CliError::UnknownFlag(value.to_owned())),
        }
        index += 1;
    }

    Ok(ModelConfigCommandOptions {
        config_path: config_path.unwrap_or_else(default_model_config_path),
    })
}

fn parse_tui(args: &[String]) -> CliResult<TuiOptions> {
    let mut status_args = Vec::new();
    let mut width = 100;
    let mut height = 30;
    let mut keys = Vec::new();
    let mut interactive = false;
    let mut poll_interval = Duration::from_millis(250);
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--width" => {
                let value = value_after(args, &mut index, "--width")?;
                width = parse_tui_dimension("--width", &value)?;
            }
            "--height" => {
                let value = value_after(args, &mut index, "--height")?;
                height = parse_tui_dimension("--height", &value)?;
            }
            "--keys" => {
                let value = value_after(args, &mut index, "--keys")?;
                keys = parse_tui_keys(&value)?;
            }
            "--interactive" => {
                interactive = true;
            }
            "--poll-ms" => {
                let value = value_after(args, &mut index, "--poll-ms")?;
                poll_interval = Duration::from_millis(parse_tui_poll_ms(&value)?);
            }
            value => status_args.push(value.to_owned()),
        }
        index += 1;
    }

    let mut status = parse_status_with_defaults(&status_args, OutputFormat::Panel)?;
    if status.input_path.is_none() {
        status.allow_demo_input = true;
        status.input_mode = StatusInputMode::QuerySnapshot;
        if status.graph_id.is_none() {
            status.graph_id = Some("demo_graph".into());
        }
    }
    status.format = OutputFormat::Panel;

    Ok(TuiOptions {
        status,
        width,
        height,
        keys,
        interactive,
        poll_interval,
    })
}

fn default_status_profile(surface: ShellSurface) -> &'static str {
    match surface {
        ShellSurface::Cli => "shell.cli.fast",
        ShellSurface::DigitalHuman => "shell.digital_human.readonly",
        ShellSurface::Ide
        | ShellSurface::Desktop
        | ShellSurface::Web
        | ShellSurface::Mobile
        | ShellSurface::Api
        | ShellSurface::Mcp => "shell.ide.readonly",
    }
}

fn default_init_model(provider: TuiModelProvider) -> &'static str {
    match provider {
        TuiModelProvider::OpenAi => "gpt-4o-mini",
        TuiModelProvider::OpenRouter => "openai/gpt-4o-mini",
        TuiModelProvider::Custom => "gpt-demo",
        TuiModelProvider::Local => "llama3.1",
    }
}

fn default_model_config_path() -> PathBuf {
    PathBuf::from(".moxi").join("config.toml")
}

fn value_after(args: &[String], index: &mut usize, flag: &'static str) -> CliResult<String> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or(CliError::MissingValue(flag))
}

fn parse_risk(value: &str) -> CliResult<RiskLevel> {
    match normalize_token(value).as_str() {
        "low" => Ok(RiskLevel::Low),
        "medium" => Ok(RiskLevel::Medium),
        "high" => Ok(RiskLevel::High),
        "critical" => Ok(RiskLevel::Critical),
        _ => Err(CliError::InvalidRisk(value.to_owned())),
    }
}

fn parse_surface(value: &str) -> CliResult<ShellSurface> {
    match normalize_token(value).as_str() {
        "cli" => Ok(ShellSurface::Cli),
        "ide" => Ok(ShellSurface::Ide),
        "desktop" => Ok(ShellSurface::Desktop),
        "web" => Ok(ShellSurface::Web),
        "mobile" => Ok(ShellSurface::Mobile),
        "api" => Ok(ShellSurface::Api),
        "mcp" | "mcpserver" | "mcp_server" => Ok(ShellSurface::Mcp),
        "digitalhuman" | "digital_human" => Ok(ShellSurface::DigitalHuman),
        _ => Err(CliError::InvalidSurface(value.to_owned())),
    }
}

fn parse_limit(value: &str) -> CliResult<usize> {
    value
        .parse::<usize>()
        .map_err(|_| CliError::InvalidLimit(value.to_owned()))
}

fn parse_watch_ticks(value: &str) -> CliResult<usize> {
    let ticks = value
        .parse::<usize>()
        .map_err(|_| CliError::InvalidWatchTicks(value.to_owned()))?;
    if ticks == 0 {
        return Err(CliError::InvalidWatchTicks(value.to_owned()));
    }
    Ok(ticks)
}

fn parse_watch_interval_ms(value: &str) -> CliResult<u64> {
    value
        .parse::<u64>()
        .map_err(|_| CliError::InvalidWatchInterval(value.to_owned()))
}

fn parse_tui_dimension(flag: &'static str, value: &str) -> CliResult<u16> {
    let dimension = value
        .parse::<u16>()
        .map_err(|_| CliError::InvalidTuiDimension {
            flag,
            value: value.to_owned(),
        })?;
    if dimension < 20 {
        return Err(CliError::InvalidTuiDimension {
            flag,
            value: value.to_owned(),
        });
    }
    Ok(dimension)
}

fn parse_tui_keys(value: &str) -> CliResult<Vec<TuiKey>> {
    value
        .split(',')
        .filter(|token| !token.trim().is_empty())
        .map(parse_tui_key)
        .collect()
}

fn parse_tui_key(value: &str) -> CliResult<TuiKey> {
    let trimmed = value.trim();
    match normalize_token(trimmed).as_str() {
        "tab" => Ok(TuiKey::Tab),
        "o" | "overview" => Ok(TuiKey::Focus(TuiPane::Overview)),
        "g" | "graph" | "graphs" | "graph-summary" => Ok(TuiKey::Focus(TuiPane::Graph)),
        "t" | "tasks" => Ok(TuiKey::Focus(TuiPane::Tasks)),
        "a" | "approvals" | "blockers" => Ok(TuiKey::Focus(TuiPane::Approvals)),
        "b" | "boundary" => Ok(TuiKey::Focus(TuiPane::Boundary)),
        "?" | "help" | "keys" | "menu" => Ok(TuiKey::ToggleCommandPalette),
        "boot" | "logo" | "1" => Ok(TuiKey::Screen(TuiScreen::Boot)),
        "trust" | "risk" | "2" => Ok(TuiKey::Screen(TuiScreen::Trust)),
        "setup" | "config" | "3" => Ok(TuiKey::Screen(TuiScreen::Setup)),
        "core" | "agents" | "4" => Ok(TuiKey::Screen(TuiScreen::Core)),
        "workspace" | "chat" | "5" => Ok(TuiKey::Screen(TuiScreen::Workspace)),
        "chat_down" | "pagedown" | "page_down" => Ok(TuiKey::MoveConversationDown),
        "chat_up" | "pageup" | "page_up" => Ok(TuiKey::MoveConversationUp),
        "j" | "down" => Ok(TuiKey::MoveTaskDown),
        "k" | "up" => Ok(TuiKey::MoveTaskUp),
        "r" | "refresh" => Ok(TuiKey::Refresh),
        "enter" | "submit" => Ok(TuiKey::SubmitCommand),
        "backspace" | "bs" => Ok(TuiKey::Backspace),
        "q" | "quit" => Ok(TuiKey::Quit),
        _ if trimmed.starts_with('/') => Ok(TuiKey::Filter(trimmed[1..].to_owned())),
        _ if trimmed.starts_with("type:") => {
            let value = trimmed.trim_start_matches("type:");
            Ok(TuiKey::InputChar(value.chars().next().unwrap_or(' ')))
        }
        _ => Err(CliError::InvalidTuiKey(trimmed.to_owned())),
    }
}

fn parse_tui_poll_ms(value: &str) -> CliResult<u64> {
    let millis = value
        .parse::<u64>()
        .map_err(|_| CliError::InvalidTuiPoll(value.to_owned()))?;
    if millis == 0 {
        return Err(CliError::InvalidTuiPoll(value.to_owned()));
    }
    Ok(millis)
}

fn normalize_token(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace(['-', ' '], "_")
}

fn boundary_report(surface: ShellSurface) -> BoundaryReport {
    BoundaryReport {
        surface,
        adapter_manifest: adapter_manifest(surface),
        supported_commands: vec![
            "admit", "manifest", "status", "watch", "tui", "init", "config", "doctor", "models",
            "boundary", "help", "repl",
        ],
        forbidden_commands: vec![
            "execute",
            "approve",
            "issue-ticket",
            "ticket",
            "verify",
            "commit",
            "ledger",
        ],
        trust_boundaries: vec![
            "submit_only",
            "projection_only",
            "approval_display_only",
        ],
        cannot_execute_directly: true,
        cannot_authorize: true,
        cannot_issue_tickets: true,
        cannot_verify: true,
        cannot_commit_ledger: true,
        note: "shell commands submit requests and render projections only; trusted P0 owns authorization, tickets, execution, verification, and ledger commits",
    }
}

fn write_json<T: serde::Serialize>(
    writer: &mut impl Write,
    value: &T,
    format: OutputFormat,
) -> CliResult<()> {
    if format.is_pretty() {
        writeln!(writer, "{}", serde_json::to_string_pretty(value)?)?;
    } else {
        writeln!(writer, "{}", serde_json::to_string(value)?)?;
    }
    Ok(())
}

fn write_boundary_text(writer: &mut impl Write, report: &BoundaryReport) -> CliResult<()> {
    writeln!(writer, "MOXI shell boundary")?;
    writeln!(writer, "surface: {:?}", report.surface)?;
    writeln!(writer, "shell: {}", report.adapter_manifest.shell_id)?;
    writeln!(
        writer,
        "permission_modes: {}",
        report
            .adapter_manifest
            .supported_permission_modes
            .iter()
            .map(|mode| format!("{mode:?}"))
            .collect::<Vec<_>>()
            .join(", ")
    )?;
    writeln!(
        writer,
        "trust_boundaries: {}",
        report.trust_boundaries.join(", ")
    )?;
    writeln!(
        writer,
        "supported_commands: {}",
        report.supported_commands.join(", ")
    )?;
    writeln!(
        writer,
        "forbidden_commands: {}",
        report.forbidden_commands.join(", ")
    )?;
    writeln!(writer, "cannot_execute_directly: true")?;
    writeln!(writer, "cannot_authorize: true")?;
    writeln!(writer, "cannot_issue_tickets: true")?;
    writeln!(writer, "cannot_verify: true")?;
    writeln!(writer, "cannot_commit_ledger: true")?;
    writeln!(writer, "note: {}", report.note)?;
    Ok(())
}

fn write_status_text(
    writer: &mut impl Write,
    projection: &moxi_shells::ShellProjection,
    render_limit: Option<usize>,
) -> CliResult<()> {
    writeln!(writer, "MOXI status")?;
    writeln!(writer, "surface: {:?}", projection.surface)?;
    writeln!(writer, "profile: {}", projection.profile_id)?;
    writeln!(
        writer,
        "graph: {}",
        projection.graph_id.as_deref().unwrap_or("<none>")
    )?;
    if let Some(goal) = &projection.graph_goal {
        writeln!(writer, "goal: {goal}")?;
    }
    if let Some(path) = projection.runtime_path {
        writeln!(writer, "path: {path:?}")?;
    }
    writeln!(
        writer,
        "stage: {}",
        projection
            .latest_stage
            .map(|stage| format!("{stage:?}"))
            .unwrap_or_else(|| "<none>".to_owned())
    )?;
    writeln!(writer, "progress: {}", percent(projection.latest_progress))?;
    writeln!(
        writer,
        "task: {}",
        projection.current_task_id.as_deref().unwrap_or("<none>")
    )?;
    writeln!(
        writer,
        "message: {}",
        projection.latest_message.as_deref().unwrap_or("<none>")
    )?;
    writeln!(writer, "cursor: {}", projection.event_cursor)?;
    writeln!(writer, "complete: {}", projection.is_complete)?;

    if projection.blockers.is_empty() {
        writeln!(writer, "blockers: none")?;
    } else {
        writeln!(writer, "blockers:")?;
        let shown = shown_count(render_limit, projection.blockers.len());
        for blocker in projection.blockers.iter().take(shown) {
            writeln!(writer, "- {}: {:?}", blocker.task_ref, blocker.blocker)?;
        }
        write_hidden_text(writer, "blockers", projection.blockers.len(), shown)?;
    }

    if !projection.graphs.is_empty() {
        writeln!(writer, "graphs:")?;
        let shown = shown_count(render_limit, projection.graphs.len());
        for graph in projection.graphs.iter().take(shown) {
            writeln!(
                writer,
                "- {} path={:?} tasks={} completed={} running={} awaiting={} blocked={} failed={} complete={}",
                graph.graph_id,
                graph.path,
                graph.task_count,
                graph.completed_count,
                graph.running_count,
                graph.awaiting_approval_count,
                graph.blocked_count,
                graph.failed_count,
                graph.is_complete
            )?;
        }
        write_hidden_text(writer, "graphs", projection.graphs.len(), shown)?;
    }

    if !projection.tasks.is_empty() {
        writeln!(writer, "tasks:")?;
        let shown = shown_count(render_limit, projection.tasks.len());
        for task in projection.tasks.iter().take(shown) {
            writeln!(
                writer,
                "- {} state={} capability={} progress={} blocker={} message={}",
                task.task_id,
                task.state,
                task.capability_id,
                percent(task.progress),
                task.blocker
                    .as_ref()
                    .map(|blocker| format!("{blocker:?}"))
                    .unwrap_or_else(|| "none".to_owned()),
                task.message.as_deref().unwrap_or("<none>")
            )?;
        }
        write_hidden_text(writer, "tasks", projection.tasks.len(), shown)?;
    }

    Ok(())
}

fn write_status_panel(
    writer: &mut impl Write,
    projection: &moxi_shells::ShellProjection,
    render_limit: Option<usize>,
) -> CliResult<()> {
    let width = 72;
    write_panel_rule(writer, width)?;
    write_panel_row(writer, width, "MOXI CLI STATUS")?;
    write_panel_rule(writer, width)?;
    write_panel_row(
        writer,
        width,
        &format!(
            "surface={:?} profile={}",
            projection.surface, projection.profile_id
        ),
    )?;
    write_panel_row(
        writer,
        width,
        &format!(
            "graph={} cursor={} complete={}",
            projection.graph_id.as_deref().unwrap_or("<none>"),
            projection.event_cursor,
            projection.is_complete
        ),
    )?;
    if let Some(goal) = &projection.graph_goal {
        write_panel_row(writer, width, &format!("goal={goal}"))?;
    }
    if let Some(path) = projection.runtime_path {
        write_panel_row(writer, width, &format!("path={path:?}"))?;
    }
    write_panel_rule(writer, width)?;
    write_panel_row(
        writer,
        width,
        &format!(
            "stage={} progress={} task={}",
            projection
                .latest_stage
                .map(|stage| format!("{stage:?}"))
                .unwrap_or_else(|| "<none>".to_owned()),
            percent(projection.latest_progress),
            projection.current_task_id.as_deref().unwrap_or("<none>")
        ),
    )?;
    write_panel_row(
        writer,
        width,
        &format!(
            "message={}",
            projection.latest_message.as_deref().unwrap_or("<none>")
        ),
    )?;
    write_panel_rule(writer, width)?;

    if projection.blockers.is_empty() {
        write_panel_row(writer, width, "blockers: none")?;
    } else {
        write_panel_row(writer, width, "blockers:")?;
        let shown = shown_count(render_limit, projection.blockers.len());
        for blocker in projection.blockers.iter().take(shown) {
            write_panel_row(
                writer,
                width,
                &format!("  {} -> {:?}", blocker.task_ref, blocker.blocker),
            )?;
        }
        write_hidden_panel_row(writer, width, "blockers", projection.blockers.len(), shown)?;
    }

    if !projection.graphs.is_empty() {
        write_panel_rule(writer, width)?;
        write_panel_row(writer, width, "graphs:")?;
        let shown = shown_count(render_limit, projection.graphs.len());
        for graph in projection.graphs.iter().take(shown) {
            write_panel_row(
                writer,
                width,
                &format!(
                    "  {} tasks={} done={} run={} wait={} block={} fail={}",
                    graph.graph_id,
                    graph.task_count,
                    graph.completed_count,
                    graph.running_count,
                    graph.awaiting_approval_count,
                    graph.blocked_count,
                    graph.failed_count
                ),
            )?;
        }
        write_hidden_panel_row(writer, width, "graphs", projection.graphs.len(), shown)?;
    }

    if !projection.tasks.is_empty() {
        write_panel_rule(writer, width)?;
        write_panel_row(writer, width, "tasks:")?;
        let shown = shown_count(render_limit, projection.tasks.len());
        for task in projection.tasks.iter().take(shown) {
            write_panel_row(
                writer,
                width,
                &format!(
                    "  {} [{}] {} {}",
                    task.task_id,
                    task.state,
                    task.capability_id,
                    percent(task.progress)
                ),
            )?;
            if let Some(blocker) = &task.blocker {
                write_panel_row(writer, width, &format!("    blocker={blocker:?}"))?;
            }
            if let Some(message) = &task.message {
                write_panel_row(writer, width, &format!("    message={message}"))?;
            }
        }
        write_hidden_panel_row(writer, width, "tasks", projection.tasks.len(), shown)?;
    }

    write_panel_rule(writer, width)?;
    write_panel_row(
        writer,
        width,
        "boundary: projection only; no execute/approve/ticket/verify/ledger",
    )?;
    write_panel_rule(writer, width)?;
    Ok(())
}

fn write_tui_snapshot(
    writer: &mut impl Write,
    projection: &moxi_shells::ShellProjection,
    state: &TuiState,
    width: u16,
    height: u16,
) -> CliResult<()> {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test backend terminal creation cannot fail");
    terminal
        .draw(|frame| {
            let area = frame.area();
            render_tui_snapshot(frame, area, projection, state);
        })
        .expect("test backend draw cannot fail");
    let buffer = terminal.backend().buffer();
    for y in 0..buffer.area.height {
        let mut line = String::new();
        for x in 0..buffer.area.width {
            line.push_str(buffer.cell((x, y)).map(|cell| cell.symbol()).unwrap_or(" "));
        }
        writeln!(writer, "{}", line.trim_end())?;
    }
    Ok(())
}

fn render_tui_snapshot(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    projection: &moxi_shells::ShellProjection,
    state: &TuiState,
) {
    match state.screen {
        TuiScreen::Boot => render_tui_boot(frame, area, projection),
        TuiScreen::Trust => render_tui_trust(frame, area, projection, state),
        TuiScreen::Setup => render_tui_setup(frame, area, state),
        TuiScreen::Core => render_tui_core(frame, area, projection, state),
        TuiScreen::Workspace => render_tui_workspace(frame, area, projection, state),
    }
}

fn render_tui_workspace(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    projection: &moxi_shells::ShellProjection,
    state: &TuiState,
) {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(12),
            Constraint::Length(4),
            Constraint::Length(1),
        ])
        .split(area);

    frame.render_widget(tui_header(projection, state), vertical[0]);
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Min(64),
            Constraint::Length(1),
            Constraint::Length(42),
        ])
        .split(vertical[1]);
    frame.render_widget(tui_chat_stream(projection, state), body[0]);
    frame.render_widget(tui_task_tracker(projection, state), body[2]);
    frame.render_widget(tui_input_box(state), vertical[2]);
    frame.render_widget(tui_status_bar(projection, state), vertical[3]);
    if state.show_command_palette {
        render_command_palette(frame, area, state);
    }
}

fn render_tui_boot(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    projection: &moxi_shells::ShellProjection,
) {
    let lines = vec![
        Line::from(vec![
            Span::styled("      MOXI", style_gradient_1()),
            Span::styled(" // ", style_dim()),
            Span::styled("AGENT", style_gradient_3()),
            Span::styled("      guarded terminal intelligence", style_dim()),
        ]),
        Line::from(vec![Span::styled(
            "  ███╗   ███╗ ██████╗ ██╗  ██╗██╗       █████╗  ██████╗ ███████╗███╗   ██╗████████╗",
            style_gradient_1(),
        )]),
        Line::from(vec![Span::styled(
            "  ████╗ ████║██╔═══██╗╚██╗██╔╝██║      ██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝",
            style_gradient_2(),
        )]),
        Line::from(vec![Span::styled(
            "  ██╔████╔██║██║   ██║ ╚███╔╝ ██║█████╗███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║",
            style_gradient_3(),
        )]),
        Line::from(vec![Span::styled(
            "  ██║╚██╔╝██║██║   ██║ ██╔██╗ ██║╚════╝██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║",
            style_gradient_2(),
        )]),
        Line::from(vec![Span::styled(
            "  ██║ ╚═╝ ██║╚██████╔╝██╔╝ ██╗██║      ██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║",
            style_gradient_1(),
        )]),
        Line::from(vec![Span::styled(
            "  ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝      ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝",
            style_dim(),
        )]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "        SILVER CORE ONLINE  |  P0 GUARDED  |  P2 RICH CLI",
            style_focus(),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  moxi-agent", style_brand()),
            Span::styled("  guarded agent operating system", style_dim()),
            Span::styled("    session ", style_label()),
            Span::styled("local-r10-demo-session", style_value()),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  CORE ", style_label()),
            badge("Silver Core", Color::Yellow),
            Span::raw(" "),
            Span::styled("SHELL ", style_label()),
            badge("P2 rich-cli", Color::Cyan),
            Span::raw(" "),
            Span::styled("MODE ", style_label()),
            badge("guarded read-only", Color::Green),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "  Initialization waterfall",
            style_warning(),
        )]),
        Line::from(vec![
            Span::styled("  > ", style_focus()),
            Span::styled("Initializing Silver Core", style_value()),
            Span::raw("       "),
            progress_bar(0.78, 24),
        ]),
        Line::from(vec![Span::styled(
            "  + Loading Agent Core profiles",
            style_success(),
        )]),
        Line::from(vec![Span::styled(
            "  + Reading configured skills and tools",
            style_success(),
        )]),
        Line::from(vec![Span::styled(
            format!(
                "  > Reading workspace context: {}",
                workspace_display_path()
            ),
            style_value(),
        )]),
        Line::from(vec![Span::styled(
            "  - Checking trust boundary",
            style_dim(),
        )]),
        Line::from(vec![Span::styled(
            "  - Waiting for owner handoff",
            style_dim(),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Enter", style_focus()),
            Span::styled(" continue startup flow", style_value()),
            Span::styled("    4", style_focus()),
            Span::styled(" workspace", style_value()),
            Span::styled("    q", style_danger()),
            Span::styled(" quit", style_value()),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  graph ", style_label()),
            Span::styled(
                projection
                    .graph_id
                    .as_deref()
                    .unwrap_or("demo_graph")
                    .to_owned(),
                style_value(),
            ),
            Span::styled("    context ", style_label()),
            Span::styled("workspace facts ready", style_success()),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(tui_panel_block(
                "moxi-agent // startup",
                Color::Yellow,
                BorderType::Double,
            ))
            .wrap(Wrap { trim: true }),
        centered_rect(area, 100, 28),
    );
}

fn render_tui_trust(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    projection: &moxi_shells::ShellProjection,
    state: &TuiState,
) {
    let mut lines = vec![
        Line::from(vec![Span::styled(
            "moxi-agent will enter this workspace:",
            style_label(),
        )]),
        Line::from(vec![Span::styled(
            state.session.workspace.cwd.clone(),
            style_value(),
        )]),
        Line::from(vec![
            Span::styled("trust state: ", style_label()),
            Span::styled(
                state.session.trust.status.label(),
                match state.session.trust.status {
                    TuiTrustStatus::KnownReadOnly | TuiTrustStatus::TrustedReadOnly => {
                        style_success()
                    }
                    TuiTrustStatus::NeedsReview => style_warning(),
                    TuiTrustStatus::Denied => style_danger(),
                },
            ),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled("Current safety mode", style_warning())]),
        Line::from(vec![Span::styled(
            "* Read-only inspection: allowed",
            style_success(),
        )]),
        Line::from(vec![Span::styled(
            "o File writes: require owner confirmation",
            style_dim(),
        )]),
        Line::from(vec![Span::styled(
            "o Shell commands: require owner confirmation",
            style_dim(),
        )]),
        Line::from(vec![Span::styled(
            "o Git commit / GitHub push: require owner confirmation",
            style_dim(),
        )]),
        Line::from(""),
        Line::from(vec![Span::styled("Trust reasons", style_warning())]),
    ];
    lines.extend(
        state
            .session
            .trust
            .reasons
            .iter()
            .take(4)
            .map(|reason| Line::from(vec![Span::styled(format!("* {reason}"), style_value())])),
    );
    lines.extend([
        Line::from(""),
        Line::from(vec![Span::styled("Risk note", style_warning())]),
        Line::from(vec![Span::styled(
            "The rich CLI shell cannot authorize or execute by itself.",
            style_value(),
        )]),
        Line::from(vec![Span::styled(
            "High-risk actions must go through the P0 guarded path.",
            style_value(),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Enter", style_focus()),
            Span::raw(" read-only     "),
            Span::styled("/trust", style_focus()),
            Span::raw(" trust workspace     "),
            Span::styled("/deny", style_danger()),
            Span::raw(" exit"),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("profile ", style_label()),
            Span::styled(projection.profile_id.clone(), style_value()),
        ]),
    ]);
    frame.render_widget(
        Paragraph::new(lines)
            .block(tui_panel_block(
                "Workspace Trust",
                Color::Yellow,
                BorderType::Rounded,
            ))
            .wrap(Wrap { trim: true }),
        centered_rect(area, 84, 21),
    );
}

fn render_tui_setup(frame: &mut ratatui::Frame<'_>, area: Rect, state: &TuiState) {
    let config = &state.session.model_config;
    let key_style = if matches!(config.api_key_source, TuiApiKeySource::Missing) {
        style_warning()
    } else {
        style_success()
    };
    let sample = config.setup_sample();
    let sample_lines = sample
        .lines()
        .map(|line| Line::from(vec![Span::styled(format!("  {line}"), style_value())]));
    let mut lines = vec![
        Line::from(vec![
            Span::styled("MOXI CLI Alpha setup", style_brand()),
            Span::styled("  read-only model chat preparation", style_dim()),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Model/API configuration is required before real chat is connected.",
            style_warning(),
        )]),
        Line::from(vec![Span::styled(
            "This page is a guide only: it does not write files, print full keys, or call the network.",
            style_value(),
        )]),
        Line::from(""),
        Line::from(vec![Span::styled("Detected configuration", style_warning())]),
        Line::from(vec![
            Span::styled("provider: ", style_label()),
            Span::styled(config.provider.label(), style_value()),
            Span::styled("    model: ", style_label()),
            Span::styled(config.model.clone(), style_value()),
        ]),
        Line::from(vec![
            Span::styled("endpoint: ", style_label()),
            Span::styled(config.endpoint.clone(), style_value()),
        ]),
        Line::from(vec![
            Span::styled("config: ", style_label()),
            Span::styled(config.config_path.clone(), style_value()),
            Span::styled(" (", style_dim()),
            Span::styled(config.config_state.clone(), style_dim()),
            Span::styled(")", style_dim()),
        ]),
        Line::from(vec![
            Span::styled("api key: ", style_label()),
            Span::styled(config.api_key_source.summary(), key_style),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled("Create .moxi/config.toml", style_warning())]),
        Line::from(vec![Span::styled("[model]", style_dim())]),
    ];
    lines.extend(sample_lines);
    lines.extend([
        Line::from(""),
        Line::from(vec![Span::styled("Supported providers", style_warning())]),
        Line::from("openai | openrouter | custom | local"),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Environment alternative",
            style_warning(),
        )]),
        Line::from("MOXI_PROVIDER / MOXI_ENDPOINT / MOXI_MODEL"),
        Line::from("MOXI_API_KEY / OPENAI_API_KEY / OPENROUTER_API_KEY"),
        Line::from(""),
        Line::from(vec![Span::styled("Setup checks", style_warning())]),
        Line::from(vec![
            Span::styled("/init", style_focus()),
            Span::raw(" write env-only .moxi/config.toml"),
        ]),
        Line::from(vec![
            Span::styled("/config", style_focus()),
            Span::raw(" redacted state  "),
            Span::styled("/doctor", style_focus()),
            Span::raw(" readiness  "),
            Span::styled("/models", style_focus()),
            Span::raw(" provider catalog"),
        ]),
        Line::from(vec![Span::styled(
            state
                .setup_notice
                .clone()
                .unwrap_or_else(|| "No setup check has run on this page yet.".to_owned()),
            style_value(),
        )]),
        Line::from(""),
        Line::from(vec![Span::styled("Next Alpha steps", style_warning())]),
        Line::from("* Run /init, /config, /doctor, or /models here without leaving setup"),
        Line::from("o /doctor tests endpoint, key, model, quota, and response shape"),
        Line::from("o /models lists provider model ids when the endpoint supports it"),
        Line::from("o configured sessions use read-only model chat after setup"),
        Line::from(""),
        Line::from(vec![
            Span::styled("Enter", style_focus()),
            Span::raw(" continue to Agent Core    "),
            Span::styled("/config", style_focus()),
            Span::raw(" show redacted state    "),
            Span::styled("5", style_focus()),
            Span::raw(" workspace"),
        ]),
    ]);
    frame.render_widget(
        Paragraph::new(lines)
            .block(tui_panel_block(
                "First-run Setup",
                Color::Cyan,
                BorderType::Rounded,
            ))
            .wrap(Wrap { trim: true }),
        centered_rect(area, 100, 31),
    );
}

fn render_tui_core(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    projection: &moxi_shells::ShellProjection,
    state: &TuiState,
) {
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(34), Constraint::Percentage(66)])
        .split(centered_rect(area, 108, 29));
    let logo = vec![
        Line::from(vec![Span::styled("   M O X I", style_gradient_1())]),
        Line::from(vec![Span::styled("   AGENT CORE", style_gradient_3())]),
        Line::from(vec![Span::styled("   ===========", style_gradient_2())]),
        Line::from(""),
        Line::from(vec![Span::styled("  [MOXI]", style_gradient_1())]),
        Line::from(vec![Span::styled("  [CORE]", style_gradient_2())]),
        Line::from(vec![Span::styled("  [ P0 ] protected", style_success())]),
        Line::from(vec![Span::styled("  [ P2 ] rich-cli", style_focus())]),
        Line::from(""),
        Line::from(vec![Span::styled("moxi-agent", style_brand())]),
        Line::from(vec![Span::styled("Silver Core online", style_success())]),
        Line::from(vec![Span::styled(
            format!("Session: {}", state.session.id),
            style_dim(),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::styled("trust ", style_label()),
            badge(state.session.trust.status.label(), Color::Yellow),
        ]),
        Line::from(vec![
            Span::styled("mode  ", style_label()),
            badge(state.session.mode.label(), Color::Green),
        ]),
        Line::from(vec![
            Span::styled("ctx   ", style_label()),
            progress_bar(state.session.context_snapshot().ratio(), 12),
            Span::styled(
                format!("{}%", state.session.context_snapshot().percent),
                style_focus(),
            ),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(logo)
            .block(tui_panel_block(
                "Identity",
                Color::Magenta,
                BorderType::Rounded,
            ))
            .wrap(Wrap { trim: true }),
        body[0],
    );

    let snapshot_path = state.session.persistence_path();
    let snapshot_dir = snapshot_path
        .parent()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "<none>".to_owned());
    let snapshot_file = snapshot_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("tui-session.json")
        .to_owned();
    let lines = vec![
        Line::from(vec![
            Span::styled("moxi-agent v0.1.0", style_brand()),
            Span::styled(" | Silver Core | guarded rich-cli", style_dim()),
        ]),
        Line::from(vec![
            Span::styled("cwd: ", style_label()),
            Span::styled(state.session.workspace.cwd.clone(), style_value()),
        ]),
        Line::from(vec![
            Span::styled("config: ", style_label()),
            Span::styled(state.session.workspace.config_path.clone(), style_value()),
            Span::styled(" (", style_dim()),
            Span::styled(state.session.workspace.config_state.clone(), style_dim()),
            Span::styled(")", style_dim()),
            Span::styled(" | graph=", style_label()),
            Span::styled(
                projection
                    .graph_id
                    .as_deref()
                    .unwrap_or("demo_graph")
                    .to_owned(),
                style_value(),
            ),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled("Agent Runtime", style_warning())]),
        Line::from(vec![
            Span::styled("orchestrator ", style_label()),
            badge("adaptive", Color::Magenta),
            Span::raw(" "),
            Span::styled("mode ", style_label()),
            badge(state.session.mode.label(), Color::Green),
            Span::raw(" "),
            Span::styled("trust ", style_label()),
            badge(state.session.trust.status.label(), Color::Yellow),
        ]),
        Line::from("approval: required for write / shell / git / github"),
        Line::from(vec![
            Span::styled("session dir: ", style_label()),
            Span::styled(snapshot_dir, style_dim()),
        ]),
        Line::from(vec![
            Span::styled("session file: ", style_label()),
            Span::styled(snapshot_file, style_dim()),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled("Loaded Agents", style_warning())]),
    ];
    let mut lines = lines;
    lines.extend(
        state
            .session
            .agents
            .iter()
            .map(|agent| Line::from(agent.summary())),
    );
    lines.extend([
        Line::from(""),
        Line::from(vec![Span::styled("Available Tools", style_warning())]),
        Line::from(state.session.tools.join(" | ")),
        Line::from(""),
        Line::from(vec![Span::styled("Available Skills", style_warning())]),
        Line::from(state.session.skills.join(" | ")),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Press Enter to open workspace, or 4 to jump there directly",
            style_focus(),
        )]),
    ]);
    frame.render_widget(
        Paragraph::new(lines)
            .block(tui_panel_block(
                "moxi-agent core",
                Color::Yellow,
                BorderType::Rounded,
            ))
            .wrap(Wrap { trim: true }),
        body[1],
    );
}

fn render_command_palette(frame: &mut ratatui::Frame<'_>, area: Rect, state: &TuiState) {
    let area = centered_rect(area, 58, 13);
    let entries = filtered_command_palette_entries(state.command_input.trim());
    let entry_window =
        command_palette_visible_window(entries.len(), state.command_palette_index, 5);
    let mut lines = vec![
        Line::from(vec![
            Span::styled("filter ", style_label()),
            Span::styled(
                if state.command_input.trim().is_empty() {
                    "/"
                } else {
                    state.command_input.trim()
                },
                style_value(),
            ),
            Span::styled(
                "  Up/Down select · PgUp/PgDn scroll · Enter run · Esc quit",
                style_dim(),
            ),
        ]),
        Line::from(""),
    ];
    if entries.is_empty() {
        lines.push(Line::from(vec![Span::styled(
            "No safe command matches this filter",
            style_warning(),
        )]));
    } else {
        let selected = state.command_palette_index.min(entries.len() - 1);
        if entry_window.start > 0 {
            lines.push(Line::from(vec![Span::styled(
                format!("... {} earlier commands", entry_window.start),
                style_dim(),
            )]));
        }
        for (index, entry) in entries
            .iter()
            .enumerate()
            .skip(entry_window.start)
            .take(entry_window.end.saturating_sub(entry_window.start))
        {
            let is_selected = index == selected;
            lines.push(Line::from(vec![
                Span::styled(
                    if is_selected { "> " } else { "  " },
                    if is_selected {
                        style_focus()
                    } else {
                        style_dim()
                    },
                ),
                Span::styled(
                    entry.command,
                    if is_selected {
                        style_focus()
                    } else {
                        style_value()
                    },
                ),
                Span::styled("  ", style_dim()),
                Span::styled(entry.description, style_dim()),
            ]));
        }
        if entry_window.end < entries.len() {
            lines.push(Line::from(vec![Span::styled(
                format!("... {} more commands", entries.len() - entry_window.end),
                style_dim(),
            )]));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(vec![Span::styled(
        "P2 shell: commands render local state only; effects remain P0-gated",
        style_warning(),
    )]));
    frame.render_widget(
        Paragraph::new(lines)
            .block(tui_panel_block(
                "Command Palette",
                Color::Yellow,
                BorderType::Rounded,
            ))
            .wrap(Wrap { trim: true }),
        area,
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CommandPaletteWindow {
    start: usize,
    end: usize,
}

fn command_palette_visible_window(
    total_entries: usize,
    selected_index: usize,
    visible_entries: usize,
) -> CommandPaletteWindow {
    if total_entries == 0 || visible_entries == 0 {
        return CommandPaletteWindow { start: 0, end: 0 };
    }
    let selected_index = selected_index.min(total_entries - 1);
    let half_window = visible_entries / 2;
    let mut start = selected_index.saturating_sub(half_window);
    let max_start = total_entries.saturating_sub(visible_entries);
    start = start.min(max_start);
    let end = start.saturating_add(visible_entries).min(total_entries);
    CommandPaletteWindow { start, end }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CommandPaletteEntry {
    command: &'static str,
    description: &'static str,
}

const COMMAND_PALETTE_ENTRIES: &[CommandPaletteEntry] = &[
    CommandPaletteEntry {
        command: "/status",
        description: "current session and workspace facts",
    },
    CommandPaletteEntry {
        command: "/tasks",
        description: "open task tracking and selected step",
    },
    CommandPaletteEntry {
        command: "/agents",
        description: "inspect active Agent Core profiles",
    },
    CommandPaletteEntry {
        command: "/skills",
        description: "inspect loaded skills and shell tools",
    },
    CommandPaletteEntry {
        command: "/context",
        description: "show context meter sources",
    },
    CommandPaletteEntry {
        command: "/init",
        description: "setup only: create env-only model file",
    },
    CommandPaletteEntry {
        command: "/config",
        description: "inspect redacted model/API config",
    },
    CommandPaletteEntry {
        command: "/doctor",
        description: "test model/API endpoint readiness",
    },
    CommandPaletteEntry {
        command: "/models",
        description: "list provider model ids",
    },
    CommandPaletteEntry {
        command: "/save",
        description: "write local TUI session snapshot",
    },
    CommandPaletteEntry {
        command: "/resume",
        description: "read local snapshot summary",
    },
    CommandPaletteEntry {
        command: "/trust",
        description: "open workspace trust review",
    },
    CommandPaletteEntry {
        command: "/approve",
        description: "accept current local risk/trust intent",
    },
    CommandPaletteEntry {
        command: "/deny",
        description: "deny current local risk/trust intent",
    },
    CommandPaletteEntry {
        command: "/details",
        description: "show selected task-step details",
    },
    CommandPaletteEntry {
        command: "/follow",
        description: "resume active-step following",
    },
    CommandPaletteEntry {
        command: "/boundary",
        description: "show shell authority boundary",
    },
    CommandPaletteEntry {
        command: "/help",
        description: "keep this palette open",
    },
    CommandPaletteEntry {
        command: "/quit",
        description: "exit the TUI",
    },
];

fn filtered_command_palette_entries(filter: &str) -> Vec<CommandPaletteEntry> {
    let filter = filter.trim().trim_start_matches('/');
    if filter.is_empty() {
        return COMMAND_PALETTE_ENTRIES.to_vec();
    }
    let filter = normalize_token(filter);
    COMMAND_PALETTE_ENTRIES
        .iter()
        .copied()
        .filter(|entry| {
            normalize_token(entry.command.trim_start_matches('/')).contains(&filter)
                || normalize_token(entry.description).contains(&filter)
        })
        .collect()
}

fn centered_rect(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;
    Rect {
        x,
        y,
        width,
        height,
    }
}

fn workspace_display_path() -> String {
    env::current_dir()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| "C:\\MOXI-Essence-agent\\MOXI-Essence-agent".to_owned())
}

fn tui_header(projection: &moxi_shells::ShellProjection, state: &TuiState) -> Paragraph<'static> {
    Paragraph::new(vec![
        Line::from(vec![
            Span::styled("moxi-agent", style_brand()),
            Span::styled(" // Silver Core", style_gradient_2()),
            Span::raw("    "),
            badge("P0 guarded", Color::Yellow),
            Span::raw(" "),
            badge("P2 rich-cli", Color::Cyan),
            Span::raw(" "),
            badge(state.session.mode.label(), Color::Green),
        ]),
        Line::from(vec![
            Span::styled("cwd: ", style_label()),
            Span::styled(state.session.workspace.cwd.clone(), style_value()),
        ]),
        Line::from(vec![
            Span::styled("config: ", style_label()),
            Span::styled(state.session.workspace.config_path.clone(), style_value()),
            Span::styled(" (", style_dim()),
            Span::styled(state.session.workspace.config_state.clone(), style_dim()),
            Span::styled(")", style_dim()),
            Span::styled(" | core: ", style_label()),
            Span::styled("Silver Core", style_success()),
            Span::styled(" | trust: ", style_label()),
            Span::styled(state.session.trust.status.label(), style_focus()),
            Span::styled(" | graph: ", style_label()),
            Span::styled(
                projection
                    .graph_id
                    .as_deref()
                    .unwrap_or("<none>")
                    .to_owned(),
                style_value(),
            ),
        ]),
    ])
    .style(style_value())
}

fn tui_chat_stream(
    projection: &moxi_shells::ShellProjection,
    state: &TuiState,
) -> Paragraph<'static> {
    let selected = selected_task(projection, state);
    let awaiting_approval = projection
        .blockers
        .iter()
        .filter(|blocker| blocker.blocker == ResumeBlocker::AwaitingApproval)
        .count();
    let mut lines = vec![Line::from(vec![
        Span::styled("Conversation", style_label()),
        Span::styled(
            format!(" 路 {} messages  ", state.session.messages.len()),
            style_dim(),
        ),
        Span::styled("Session ", style_label()),
        Span::styled(state.session.id.clone(), style_value()),
        Span::raw(" "),
        badge(state.session.mode.label(), Color::Green),
        Span::raw(" "),
        badge(format!("turn {}", state.session.turn_count), Color::Blue),
        Span::raw(" "),
        badge(
            if state.session.is_streaming() {
                "streaming"
            } else {
                "idle"
            },
            if state.session.is_streaming() {
                Color::Yellow
            } else {
                Color::DarkGray
            },
        ),
        Span::raw(" "),
        badge(
            if state.follow_latest_message {
                "chat follow"
            } else {
                "chat manual"
            },
            if state.follow_latest_message {
                Color::Green
            } else {
                Color::Yellow
            },
        ),
        Span::styled(
            format!(" scroll={}", state.conversation_scroll),
            style_dim(),
        ),
    ])];

    for message in &state.session.messages {
        lines.extend([
            Line::from(""),
            Line::from(vec![
                Span::styled(
                    message_state_marker(message.state),
                    message_state_style(message.state),
                ),
                Span::raw(" "),
                Span::styled(message.agent.clone(), style_brand()),
                Span::raw(" "),
                Span::styled(format!("[{}]", message.role), style_dim()),
            ]),
            Line::from(vec![Span::styled(message.body.clone(), style_value())]),
            Line::from(vec![Span::styled(message.metadata.render(), style_dim())]),
        ]);
    }

    lines.extend([
        Line::from(""),
        Line::from(vec![
            Span::styled("Workspace ", style_label()),
            Span::styled(state.session.workspace.short_path.clone(), style_value()),
            Span::styled(" | git ", style_label()),
            Span::styled(state.session.workspace.git_state.clone(), style_value()),
            Span::styled(" | cargo ", style_label()),
            Span::styled(state.session.workspace.cargo_state.clone(), style_value()),
        ]),
        Line::from(vec![
            Span::styled("Sources ", style_label()),
            Span::styled(
                format!(
                    "config={} docs={}",
                    state.session.workspace.config_state, state.session.workspace.docs_state
                ),
                style_dim(),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Status ", style_label()),
            badge(
                format!("{} session steps", state.session.steps.len()),
                Color::Blue,
            ),
            Span::raw(" "),
            badge(
                format!("{} projection tasks", projection.tasks.len()),
                Color::Cyan,
            ),
            Span::raw(" "),
            badge(format!("{} approvals", awaiting_approval), Color::Yellow),
            Span::raw(" "),
            Span::styled(
                format!("progress {}", percent(projection.latest_progress)),
                progress_style(projection.latest_progress),
            ),
            Span::raw(" "),
            progress_bar(projection.latest_progress, 16),
        ]),
        Line::from(vec![
            Span::styled("Goal ", style_label()),
            Span::styled(
                projection
                    .graph_goal
                    .as_deref()
                    .unwrap_or("preview MOXI shell experience")
                    .to_owned(),
                style_value(),
            ),
        ]),
    ]);

    if let Some(task) = selected {
        lines.extend([
            Line::from(vec![
                Span::styled("Selected ", style_label()),
                Span::styled(task.task_id.clone(), style_value()),
                Span::raw(" "),
                status_badge(&task.state),
                Span::raw(" "),
                Span::styled(task.capability_id.clone(), style_accent()),
                Span::raw(" "),
                Span::styled(percent(task.progress), progress_style(task.progress)),
            ]),
            Line::from(vec![
                Span::styled("Message ", style_label()),
                Span::styled(
                    task.message.as_deref().unwrap_or("<none>").to_owned(),
                    style_value(),
                ),
            ]),
        ]);
        if let Some(blocker) = &task.blocker {
            lines.push(Line::from(vec![
                Span::styled("Blocker ", style_label()),
                Span::styled(format!("{blocker:?}"), blocker_style(blocker)),
            ]));
        }
    }

    let title = format!("Conversation · {} messages", state.session.messages.len());
    let visible_lines = visible_conversation_lines(lines, state);
    let _title = title;
    Paragraph::new(visible_lines).wrap(Wrap { trim: true })
}

fn visible_conversation_lines(lines: Vec<Line<'static>>, state: &TuiState) -> Vec<Line<'static>> {
    let limit = 18usize;
    if lines.len() <= limit {
        return lines;
    }
    let mut visible = vec![lines[0].clone()];
    let body = &lines[1..];
    let content_limit = limit.saturating_sub(1);
    let max_start = body.len().saturating_sub(content_limit);
    let start = if state.follow_latest_message {
        max_start
    } else {
        state.conversation_scroll.min(max_start)
    };
    let has_earlier = start > 0;
    let mut visible_content_limit = content_limit.saturating_sub(usize::from(has_earlier));
    let has_newer = start.saturating_add(visible_content_limit) < body.len();
    visible_content_limit = visible_content_limit.saturating_sub(usize::from(has_newer));
    let end = start.saturating_add(visible_content_limit).min(body.len());
    if start > 0 {
        visible.push(Line::from(vec![Span::styled(
            format!("... {} earlier lines hidden (PageUp/PageDown)", start),
            style_dim(),
        )]));
    }
    visible.extend(body[start..end].iter().cloned());
    if end < body.len() {
        visible.push(Line::from(vec![Span::styled(
            format!("... {} newer lines hidden (PageDown)", body.len() - end),
            style_dim(),
        )]));
    }
    visible
}

fn tui_input_box(state: &TuiState) -> Paragraph<'static> {
    let mut lines = Vec::new();
    if let Some(prompt) = &state.pending_risk {
        lines.push(Line::from(vec![
            Span::styled("risk ", style_label()),
            badge(prompt.level.label(), prompt.level.color()),
            Span::raw(" "),
            Span::styled(prompt.reason.clone(), style_warning()),
        ]));
        lines.push(Line::from(vec![
            Span::styled("/approve", style_focus()),
            Span::raw(" continue as local planning intent  "),
            Span::styled("/deny", style_danger()),
            Span::raw(" cancel"),
        ]));
    } else {
        lines.push(Line::from(""));
    }
    lines.push(Line::from(vec![
        Span::styled("> ", style_focus()),
        Span::styled(
            if state.command_input.is_empty() {
                "Ask moxi-agent to inspect the current project".to_owned()
            } else {
                state.command_input.clone()
            },
            if state.command_input.is_empty() {
                style_dim()
            } else {
                style_value()
            },
        ),
    ]));
    Paragraph::new(lines)
        .block(tui_panel_block(
            "Input Task",
            Color::Yellow,
            BorderType::Plain,
        ))
        .wrap(Wrap { trim: true })
}

fn tui_status_bar(
    projection: &moxi_shells::ShellProjection,
    state: &TuiState,
) -> Paragraph<'static> {
    let context = state.session.context_snapshot();
    Paragraph::new(Line::from(vec![
        Span::styled(
            format!(
                "graph={} pane={} active={} selected_task={} filter={} refresh={} quit={} | ",
                projection.graph_id.as_deref().unwrap_or("<none>"),
                state.active_pane.label(),
                state.active_pane.label(),
                state.selected_task_index,
                state.filter.as_deref().unwrap_or("<none>"),
                state.refresh_count,
                state.should_quit
            ),
            style_dim(),
        ),
        Span::styled("/context | ? command menu | ", style_dim()),
        Span::styled("mode ", style_label()),
        Span::styled(state.session.mode.label(), style_dim()),
        Span::styled(" | model session-local | reasoning medium | ", style_dim()),
        Span::styled("context ", style_label()),
        progress_bar(context.ratio(), 10),
        Span::styled(format!("{}%", context.percent), style_focus()),
        Span::styled(state.command_status.clone(), style_value()),
    ]))
}

fn tui_task_tracker(
    projection: &moxi_shells::ShellProjection,
    state: &TuiState,
) -> Paragraph<'static> {
    let tasks = filtered_tasks(projection, state);
    let selected_step_index = selected_session_step_index(state);
    let selected_step = state.session.steps.get(selected_step_index);
    let mut lines = Vec::new();
    lines.push(Line::from(vec![
        Span::styled("follow: ", style_label()),
        Span::styled(
            if state.follow_active_step {
                "active"
            } else {
                "manual"
            },
            if state.follow_active_step {
                style_success()
            } else {
                style_warning()
            },
        ),
        Span::styled(" | selected: ", style_label()),
        Span::styled(
            selected_step
                .map(|step| step.label.clone())
                .unwrap_or_else(|| "<none>".to_owned()),
            style_value(),
        ),
    ]));
    if let Some(step) = selected_step {
        lines.push(Line::from(vec![
            Span::styled("detail: ", style_label()),
            Span::styled(step.detail.clone(), style_value()),
        ]));
    }
    lines.push(Line::from(""));

    for (turn_index, turn) in visible_task_tracking_turns(state).iter().enumerate() {
        if turn_index > 0 {
            lines.push(Line::from(""));
        }
        lines.push(Line::from(vec![Span::styled(
            format!("Turn {turn}"),
            style_warning(),
        )]));
        for (index, step) in state
            .session
            .steps
            .iter()
            .enumerate()
            .filter(|(_, step)| step.turn == *turn)
        {
            let is_active = index == state.session.active_step_index;
            let is_selected = index == selected_step_index;
            lines.push(Line::from(vec![
                Span::styled(
                    tui_step_marker(step.state, is_active, is_selected),
                    tui_step_style(step.state, is_active, is_selected),
                ),
                Span::raw(" "),
                Span::styled(
                    step.label.clone(),
                    tui_step_style(step.state, is_active, is_selected),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(step.detail.clone(), style_dim()),
            ]));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![Span::styled(
        "Runtime projection",
        style_warning(),
    )]));

    if tasks.is_empty() {
        lines.push(Line::from(vec![Span::styled(
            "o No runtime tasks in projection",
            style_dim(),
        )]));
    } else {
        for task in tasks.iter() {
            let marker = if task.progress >= 1.0 { "* " } else { "o " };
            let style = if task.progress >= 1.0 {
                style_success()
            } else {
                style_dim()
            };
            lines.push(Line::from(vec![
                Span::styled(marker, style),
                Span::styled(task.task_id.clone(), style_value()),
            ]));
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(task.state.clone(), style_dim()),
                Span::raw(" | "),
                Span::styled(percent(task.progress), progress_style(task.progress)),
            ]));
        }
    }

    Paragraph::new(lines)
        .block(tui_panel_block(
            "Task Tracking",
            Color::Magenta,
            BorderType::Rounded,
        ))
        .wrap(Wrap { trim: true })
}

fn visible_task_tracking_turns(state: &TuiState) -> Vec<usize> {
    let mut turns = Vec::new();
    if let Some(active_turn) = state
        .session
        .steps
        .get(state.session.active_step_index)
        .map(|step| step.turn)
    {
        turns.push(active_turn);
    }
    for step in &state.session.steps {
        if !turns.contains(&step.turn) {
            turns.push(step.turn);
        }
    }
    turns
}

fn message_state_marker(state: TuiMessageState) -> &'static str {
    match state {
        TuiMessageState::Complete => "*",
        TuiMessageState::Streaming => "~",
        TuiMessageState::Waiting => ">",
    }
}

fn message_state_style(state: TuiMessageState) -> Style {
    match state {
        TuiMessageState::Complete => style_success(),
        TuiMessageState::Streaming => style_warning(),
        TuiMessageState::Waiting => style_focus(),
    }
}

fn tui_step_marker(state: TuiStepState, is_active: bool, is_selected: bool) -> &'static str {
    if is_selected {
        ">"
    } else if is_active {
        "@"
    } else {
        match state {
            TuiStepState::Done => "*",
            TuiStepState::Active => "@",
            TuiStepState::Pending => "o",
        }
    }
}

fn tui_step_style(state: TuiStepState, is_active: bool, is_selected: bool) -> Style {
    if is_selected {
        style_focus()
    } else if is_active {
        style_warning()
    } else {
        match state {
            TuiStepState::Done => style_success(),
            TuiStepState::Active => style_warning(),
            TuiStepState::Pending => style_dim(),
        }
    }
}

fn tui_panel_block<T>(title: T, border_color: Color, border_type: BorderType) -> Block<'static>
where
    T: Into<String>,
{
    Block::default()
        .borders(Borders::ALL)
        .border_type(border_type)
        .border_style(Style::default().fg(border_color))
        .title(Span::styled(
            title.into(),
            Style::default()
                .fg(border_color)
                .add_modifier(Modifier::BOLD),
        ))
}

fn style_brand() -> Style {
    Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD)
}

fn style_gradient_1() -> Style {
    Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD)
}

fn style_gradient_2() -> Style {
    Style::default()
        .fg(Color::LightYellow)
        .add_modifier(Modifier::BOLD)
}

fn style_gradient_3() -> Style {
    Style::default()
        .fg(Color::LightMagenta)
        .add_modifier(Modifier::BOLD)
}

fn style_label() -> Style {
    Style::default().fg(Color::Gray)
}

fn style_dim() -> Style {
    Style::default().fg(Color::DarkGray)
}

fn style_value() -> Style {
    Style::default().fg(Color::White)
}

fn style_accent() -> Style {
    Style::default()
        .fg(Color::Magenta)
        .add_modifier(Modifier::BOLD)
}

fn style_focus() -> Style {
    Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::BOLD)
}

fn style_success() -> Style {
    Style::default()
        .fg(Color::Green)
        .add_modifier(Modifier::BOLD)
}

fn style_warning() -> Style {
    Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD)
}

fn style_danger() -> Style {
    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
}

fn progress_style(progress: f32) -> Style {
    if progress >= 1.0 {
        style_success()
    } else if progress > 0.0 {
        style_focus()
    } else {
        style_warning()
    }
}

fn blocker_style(blocker: &ResumeBlocker) -> Style {
    match blocker {
        ResumeBlocker::AwaitingApproval => style_warning(),
        ResumeBlocker::DependencyIncomplete => style_danger(),
        ResumeBlocker::RunningCheckpoint => style_accent(),
        ResumeBlocker::NonIdempotentRunningCheckpoint => style_accent(),
        ResumeBlocker::Failed => style_danger(),
        ResumeBlocker::AlreadyFinished => style_success(),
    }
}

fn status_badge(status: &str) -> Span<'static> {
    let color = match status {
        "Completed" => Color::Green,
        "Running" => Color::Cyan,
        "AwaitingApproval" => Color::Yellow,
        "Failed" => Color::Red,
        "Planned" => Color::Magenta,
        _ => Color::Blue,
    };
    badge(status.to_owned(), color)
}

fn badge<T>(text: T, color: Color) -> Span<'static>
where
    T: Into<String>,
{
    Span::styled(
        format!(" {} ", text.into()),
        Style::default()
            .fg(Color::Black)
            .bg(color)
            .add_modifier(Modifier::BOLD),
    )
}

fn progress_bar(progress: f32, width: usize) -> Span<'static> {
    let clamped = progress.clamp(0.0, 1.0);
    let filled = (clamped * width as f32).round() as usize;
    let mut bar = String::from("[");
    bar.push_str(&"#".repeat(filled));
    bar.push_str(&"-".repeat(width.saturating_sub(filled)));
    bar.push(']');
    Span::styled(bar, progress_style(clamped))
}

fn selected_index(index: usize, len: usize) -> Option<usize> {
    if len == 0 {
        None
    } else {
        Some(index.min(len - 1))
    }
}

fn selected_session_step_index(state: &TuiState) -> usize {
    if state.session.steps.is_empty() {
        0
    } else if state.follow_active_step {
        state
            .session
            .active_step_index
            .min(state.session.steps.len() - 1)
    } else {
        state.selected_task_index.min(state.session.steps.len() - 1)
    }
}

fn selected_task<'a>(
    projection: &'a moxi_shells::ShellProjection,
    state: &TuiState,
) -> Option<&'a moxi_shells::ShellTaskView> {
    let tasks = filtered_tasks(projection, state);
    selected_index(state.selected_task_index, tasks.len())
        .and_then(|index| tasks.get(index).copied())
}

fn filtered_tasks<'a>(
    projection: &'a moxi_shells::ShellProjection,
    state: &TuiState,
) -> Vec<&'a moxi_shells::ShellTaskView> {
    projection
        .tasks
        .iter()
        .filter(|task| {
            matches_filter(
                state.filter.as_deref(),
                &[
                    &task.task_id,
                    &task.state,
                    &task.capability_id,
                    task.message.as_deref().unwrap_or(""),
                ],
            )
        })
        .collect()
}

fn matches_filter(filter: Option<&str>, fields: &[&str]) -> bool {
    let Some(filter) = filter else {
        return true;
    };
    let filter = normalize_token(filter);
    fields
        .iter()
        .any(|field| normalize_token(field).contains(&filter))
}

fn shown_count(render_limit: Option<usize>, total: usize) -> usize {
    render_limit.unwrap_or(total).min(total)
}

fn write_hidden_text(
    writer: &mut impl Write,
    label: &str,
    total: usize,
    shown: usize,
) -> CliResult<()> {
    if total > shown {
        writeln!(
            writer,
            "- {} more {} hidden by --limit",
            total - shown,
            label
        )?;
    }
    Ok(())
}

fn write_hidden_panel_row(
    writer: &mut impl Write,
    width: usize,
    label: &str,
    total: usize,
    shown: usize,
) -> CliResult<()> {
    if total > shown {
        write_panel_row(
            writer,
            width,
            &format!("  ... {} more {} hidden by --limit", total - shown, label),
        )?;
    }
    Ok(())
}

fn write_panel_rule(writer: &mut impl Write, width: usize) -> CliResult<()> {
    writeln!(writer, "+{}+", "-".repeat(width.saturating_sub(2)))?;
    Ok(())
}

fn write_panel_row(writer: &mut impl Write, width: usize, text: &str) -> CliResult<()> {
    let inner_width = width.saturating_sub(4);
    let mut remaining = text;
    if remaining.is_empty() {
        writeln!(writer, "| {:inner_width$} |", "")?;
        return Ok(());
    }
    while !remaining.is_empty() {
        let split = split_at_char_boundary(remaining, inner_width);
        let (line, rest) = remaining.split_at(split);
        writeln!(writer, "| {:inner_width$} |", line)?;
        remaining = rest.trim_start();
    }
    Ok(())
}

fn split_at_char_boundary(text: &str, max_bytes: usize) -> usize {
    if text.len() <= max_bytes {
        return text.len();
    }
    let mut split = 0;
    for (index, _) in text.char_indices() {
        if index > max_bytes {
            break;
        }
        split = index;
    }
    split.max(1)
}

fn percent(value: f32) -> String {
    let value = if value.is_finite() { value } else { 0.0 };
    format!("{:.0}%", value.clamp(0.0, 1.0) * 100.0)
}

fn help_text() -> &'static str {
    "moxi\n\nDefault:\n  moxi\n    Opens the resident branded read-only TUI workbench. Startup pages wait for owner input instead of flashing through onboarding.\n\nCommands:\n  init [--provider openai|openrouter|custom|local] [--endpoint <url>] [--model <id>] [--api-key-env <name>] [--write] [--force] [--config <path>]\n  config [--config <path>]\n  doctor [--config <path>]\n  models [--config <path>]\n  admit --goal <text> [--tenant <id>] [--user <id>] [--workspace <path>] [--capability <id>] [--risk low|medium|high|critical]\n  manifest [--surface cli|mcp|api|ide|desktop|web|mobile|digital-human]\n  boundary [--surface cli|mcp|api|ide|desktop|web|mobile|digital-human] [--text]\n  status [--feed|--query] [--input <snapshot.json>] [--surface cli|mcp|api|ide|desktop|web|mobile|digital-human] [--profile <id>] [--text|--panel] [--limit <n>]\n  watch [--feed|--query] --input <snapshot.json> [--surface cli|mcp|api|ide|desktop|web|mobile|digital-human] [--profile <id>] [--text|--panel] [--limit <n>] [--ticks <n>] [--interval-ms <n>]\n  tui [--feed|--query] [--input <snapshot.json>] [--surface cli|mcp|api|ide|desktop|web|mobile|digital-human] [--profile <id>] [--width <n>] [--height <n>] [--keys tab,o,g,t,a,b,?,j,k,/filter,r,q] [--interactive] [--poll-ms <n>]\n  repl\n\nTUI startup: Enter advances Boot -> Trust -> First-run Setup when model/API config is missing -> Agent Core -> Workspace; 5 jumps to the workbench.\nTUI commands: /help, /status, /tasks, /agents, /skills, /context, /config, /doctor, /models, /boundary, /trust, /approve, /deny, /details, /save, /resume, /clear, /quit.\n\nModel/API config: init previews or writes .moxi/config.toml with provider, endpoint, model, and api_key_env only; it never writes raw API keys. config reads .moxi/config.toml or MOXI_/OPENAI_/OPENROUTER_ environment variables and always redacts API keys. doctor tests OpenAI-compatible endpoint readiness and reports invalid key, model not found, quota/rate limit, timeout, network, bad endpoint, and unsupported response categories. models lists OpenAI-compatible provider model ids when available. Configured TUI tasks use read-only OpenAI-compatible /chat/completions; failures fall back to local analysis.\n\nBoundary: this CLI submits requests and renders shell contracts only; it can watch snapshot files and render a read-only TUI preview, but it cannot execute, authorize, issue tickets, verify, or commit ledger events."
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn event_feed_json() -> String {
        serde_json::json!({
            "schema_version": 1,
            "graph_id": "graph_1",
            "from_cursor": 0,
            "next_cursor": 2,
            "event_count": 1,
            "events": [],
            "latest_stage": "planned",
            "latest_message": "planning graph",
            "latest_progress": 0.25,
            "current_task_id": "task_1",
            "blockers": {},
            "is_complete": false,
            "generated_at": "2026-05-26T05:30:00Z"
        })
        .to_string()
    }

    fn query_snapshot_json() -> String {
        serde_json::json!({
            "graph": {
                "graph_id": "graph_detail",
                "goal": "read project",
                "path": "task_path",
                "task_count": 1,
                "completed_count": 0,
                "running_count": 0,
                "blocked_count": 1,
                "awaiting_approval_count": 1,
                "failed_count": 0,
                "is_complete": false
            },
            "planner": null,
            "tasks": [{
                "task_id": "task_1",
                "skill_id": "skill.file.read",
                "capability_id": "file.read",
                "target": {
                    "resource_type": "file",
                    "resource_ref": "README.md"
                },
                "state": "awaiting_approval",
                "last_stage": "awaiting_approval",
                "progress": 0.5,
                "message": "waiting for approval",
                "idempotency_key": null,
                "retry_safe": null,
                "blocker": "awaiting_approval",
                "updated_at": "2026-05-26T05:30:00Z"
            }],
            "attempts": [],
            "adoption_probes": [],
            "events": [{
                "event_id": "event_1",
                "graph_id": "graph_detail",
                "run_id": "run_1",
                "task_id": "task_1",
                "stage": "awaiting_approval",
                "message": "waiting for approval",
                "progress": 0.5,
                "timestamp": "2026-05-26T05:30:00Z"
            }],
            "resume_plan": {
                "graph_id": "graph_detail",
                "completed_task_ids": [],
                "ready_task_ids": [],
                "blocked_task_ids": ["task_1"],
                "running_task_ids": [],
                "awaiting_approval_task_ids": ["task_1"],
                "failed_task_ids": [],
                "blockers": {
                    "task_1": "awaiting_approval"
                },
                "adoption_recommendations": {},
                "running_task_policy": "require_inspection",
                "is_complete": false
            },
            "event_cursor": 3,
            "policy_profile": {
                "profile_id": "shell.ide.readonly",
                "allowed_capabilities": ["file.read"],
                "allow_fast_path": false,
                "allow_task_path": true,
                "allow_trusted_execution_path": false,
                "allow_skills": true,
                "allow_running_task_retry": false,
                "max_tasks_per_graph": 8
            }
        })
        .to_string()
    }

    fn mock_http_once(status: u16, body: &'static str) -> String {
        mock_http_once_with_path(status, body, None)
    }

    fn mock_http_once_with_path(
        status: u16,
        body: &'static str,
        expected_path: Option<&'static str>,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 2048];
            let read = stream.read(&mut request).unwrap_or(0);
            let request_text = String::from_utf8_lossy(&request[..read]);
            if let Some(path) = expected_path {
                assert!(
                    request_text.starts_with(&format!("POST {path} "))
                        || request_text.starts_with(&format!("GET {path} ")),
                    "unexpected request path: {request_text}"
                );
            }
            let response = format!(
                "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).unwrap();
        });
        format!("http://{addr}/v1")
    }

    fn multi_task_query_snapshot_json() -> String {
        let task = |id: &str, state: &str, stage: &str, blocker: Option<&str>, progress: f32| {
            serde_json::json!({
                "task_id": id,
                "skill_id": "skill.file.read",
                "capability_id": "file.read",
                "target": {
                    "resource_type": "file",
                    "resource_ref": format!("{id}.md")
                },
                "state": state,
                "last_stage": stage,
                "progress": progress,
                "message": format!("{id} message"),
                "idempotency_key": null,
                "retry_safe": null,
                "blocker": blocker,
                "updated_at": "2026-05-26T05:30:00Z"
            })
        };
        serde_json::json!({
            "graph": {
                "graph_id": "graph_many",
                "goal": "read many files",
                "path": "task_path",
                "task_count": 3,
                "completed_count": 0,
                "running_count": 1,
                "blocked_count": 2,
                "awaiting_approval_count": 1,
                "failed_count": 0,
                "is_complete": false
            },
            "planner": null,
            "tasks": [
                task("task_1", "awaiting_approval", "awaiting_approval", Some("awaiting_approval"), 0.1),
                task("task_2", "planned", "planned", Some("dependency_incomplete"), 0.2),
                task("task_3", "running", "executing", None, 0.3)
            ],
            "attempts": [],
            "adoption_probes": [],
            "events": [{
                "event_id": "event_1",
                "graph_id": "graph_many",
                "run_id": "run_1",
                "task_id": "task_1",
                "stage": "awaiting_approval",
                "message": "waiting",
                "progress": 0.1,
                "timestamp": "2026-05-26T05:30:00Z"
            }],
            "resume_plan": {
                "graph_id": "graph_many",
                "completed_task_ids": [],
                "ready_task_ids": [],
                "blocked_task_ids": ["task_2"],
                "running_task_ids": ["task_3"],
                "awaiting_approval_task_ids": ["task_1"],
                "failed_task_ids": [],
                "blockers": {
                    "task_1": "awaiting_approval",
                    "task_2": "dependency_incomplete"
                },
                "adoption_recommendations": {},
                "running_task_policy": "require_inspection",
                "is_complete": false
            },
            "event_cursor": 7,
            "policy_profile": {
                "profile_id": "shell.ide.readonly",
                "allowed_capabilities": ["file.read"],
                "allow_fast_path": false,
                "allow_task_path": true,
                "allow_trusted_execution_path": false,
                "allow_skills": true,
                "allow_running_task_retry": false,
                "max_tasks_per_graph": 8
            }
        })
        .to_string()
    }

    #[test]
    fn admit_outputs_submit_only_shell_admission_json() {
        let mut output = Vec::new();

        let code = run(
            [
                "moxi-cli",
                "admit",
                "--tenant",
                "tenant_a",
                "--user",
                "user_a",
                "--workspace",
                "/workspace",
                "--goal",
                "read status",
                "--capability",
                "file.read",
            ],
            &mut output,
        )
        .unwrap();
        let json: Value = serde_json::from_slice(&output).unwrap();

        assert_eq!(code, 0);
        assert_eq!(json["surface"], "cli");
        assert_eq!(json["policy_profile"]["profile_id"], "shell.cli.fast");
        assert_eq!(json["normalized_entry"]["candidate"]["goal"], "read status");
        assert_eq!(
            json["normalized_entry"]["candidate"]["requested_capabilities"],
            serde_json::json!(["file.read"])
        );
        assert_eq!(json["cannot_execute_directly"], true);
        assert_eq!(json["cannot_authorize"], true);
    }

    #[test]
    fn high_risk_admit_marks_trusted_execution_path() {
        let mut output = Vec::new();

        run(
            [
                "moxi-cli",
                "admit",
                "--workspace",
                "/workspace",
                "--goal",
                "inspect risky change",
                "--risk",
                "high",
            ],
            &mut output,
        )
        .unwrap();
        let json: Value = serde_json::from_slice(&output).unwrap();

        assert_eq!(json["requires_trusted_execution_path"], true);
        assert_eq!(json["approval_hint"]["status"], "awaiting_approval");
    }

    #[test]
    fn manifest_outputs_read_only_cli_surface() {
        let mut output = Vec::new();

        run(["moxi-cli", "manifest", "--surface", "cli"], &mut output).unwrap();
        let json: Value = serde_json::from_slice(&output).unwrap();

        assert_eq!(json["shell_id"], "shell.cli");
        assert_eq!(json["surface"], "cli");
        assert_eq!(
            json["supported_permission_modes"],
            serde_json::json!(["read_only"])
        );
    }

    #[test]
    fn boundary_outputs_non_authorizing_shell_contract() {
        let mut output = Vec::new();

        run(["moxi-cli", "boundary", "--surface", "cli"], &mut output).unwrap();
        let json: Value = serde_json::from_slice(&output).unwrap();

        assert_eq!(json["surface"], "cli");
        assert_eq!(json["adapter_manifest"]["shell_id"], "shell.cli");
        assert_eq!(json["cannot_execute_directly"], true);
        assert_eq!(json["cannot_authorize"], true);
        assert_eq!(json["cannot_issue_tickets"], true);
        assert_eq!(json["cannot_verify"], true);
        assert_eq!(json["cannot_commit_ledger"], true);
        assert_eq!(
            json["forbidden_commands"],
            serde_json::json!([
                "execute",
                "approve",
                "issue-ticket",
                "ticket",
                "verify",
                "commit",
                "ledger"
            ])
        );
    }

    #[test]
    fn boundary_can_render_readable_text() {
        let mut output = Vec::new();

        run(["moxi-cli", "boundary", "--text"], &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();

        assert!(text.contains("MOXI shell boundary"));
        assert!(text.contains("surface: Cli"));
        assert!(text.contains("permission_modes: ReadOnly"));
        assert!(
            text.contains("trust_boundaries: submit_only, projection_only, approval_display_only")
        );
        assert!(text.contains("forbidden_commands: execute, approve"));
        assert!(text.contains("cannot_commit_ledger: true"));
    }

    #[test]
    fn rejects_missing_goal() {
        let mut output = Vec::new();

        let error = run(
            ["moxi-cli", "admit", "--workspace", "/workspace"],
            &mut output,
        )
        .unwrap_err();

        assert!(matches!(error, CliError::MissingRequired("--goal")));
        assert!(output.is_empty());
    }

    #[test]
    fn rejects_execute_as_unknown_command() {
        let mut output = Vec::new();

        let error = run(["moxi-cli", "execute"], &mut output).unwrap_err();

        assert!(matches!(error, CliError::UnknownCommand(command) if command == "execute"));
        assert!(output.is_empty());
    }

    #[test]
    fn status_projects_runtime_event_feed_from_stdin() {
        let input = event_feed_json();
        let mut output = Vec::new();

        let code = run_with_io(
            ["moxi-cli", "status", "--graph", "graph_1"],
            input.as_bytes(),
            &mut output,
        )
        .unwrap();
        let json: Value = serde_json::from_slice(&output).unwrap();

        assert_eq!(code, 0);
        assert_eq!(json["surface"], "cli");
        assert_eq!(json["profile_id"], "shell.cli.fast");
        assert_eq!(json["graph_id"], "graph_1");
        assert_eq!(json["latest_stage"], "planned");
        assert_eq!(json["latest_message"], "planning graph");
        assert_eq!(json["current_task_id"], "task_1");
        assert_eq!(json["event_cursor"], 2);
    }

    #[test]
    fn status_tolerates_utf8_bom_from_piped_stdin() {
        let input = format!("\u{feff}{}", event_feed_json());
        let mut output = Vec::new();

        let code = run_with_io(
            ["moxi-cli", "status", "--graph", "graph_1"],
            input.as_bytes(),
            &mut output,
        )
        .unwrap();
        let json: Value = serde_json::from_slice(&output).unwrap();

        assert_eq!(code, 0);
        assert_eq!(json["graph_id"], "graph_1");
        assert_eq!(json["latest_message"], "planning graph");
    }

    #[test]
    fn status_rejects_mismatched_graph_id() {
        let input = event_feed_json();
        let mut output = Vec::new();

        let error = run_with_io(
            ["moxi-cli", "status", "--graph", "graph_other"],
            input.as_bytes(),
            &mut output,
        )
        .unwrap_err();

        assert!(
            matches!(error, CliError::GraphMismatch { expected, actual } if expected == "graph_other" && actual == "graph_1")
        );
        assert!(output.is_empty());
    }

    #[test]
    fn status_projects_runtime_query_snapshot_from_stdin() {
        let input = query_snapshot_json();
        let mut output = Vec::new();

        let code = run_with_io(
            [
                "moxi-cli",
                "status",
                "--query",
                "--surface",
                "ide",
                "--graph",
                "graph_detail",
            ],
            input.as_bytes(),
            &mut output,
        )
        .unwrap();
        let json: Value = serde_json::from_slice(&output).unwrap();

        assert_eq!(code, 0);
        assert_eq!(json["surface"], "ide");
        assert_eq!(json["profile_id"], "shell.ide.readonly");
        assert_eq!(json["graph_id"], "graph_detail");
        assert_eq!(json["graph_goal"], "read project");
        assert_eq!(json["graphs"][0]["awaiting_approval_count"], 1);
        assert_eq!(json["tasks"][0]["task_id"], "task_1");
        assert_eq!(json["tasks"][0]["blocker"], "awaiting_approval");
        assert_eq!(json["event_cursor"], 3);
    }

    #[test]
    fn status_can_render_event_feed_as_readable_text() {
        let input = event_feed_json();
        let mut output = Vec::new();

        let code = run_with_io(
            ["moxi-cli", "status", "--graph", "graph_1", "--text"],
            input.as_bytes(),
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("MOXI status"));
        assert!(text.contains("surface: Cli"));
        assert!(text.contains("graph: graph_1"));
        assert!(text.contains("stage: Planned"));
        assert!(text.contains("progress: 25%"));
        assert!(text.contains("task: task_1"));
        assert!(text.contains("message: planning graph"));
        assert!(text.contains("blockers: none"));
    }

    #[test]
    fn status_can_render_query_snapshot_as_readable_text() {
        let input = query_snapshot_json();
        let mut output = Vec::new();

        let code = run_with_io(
            [
                "moxi-cli",
                "status",
                "--query",
                "--surface",
                "ide",
                "--graph",
                "graph_detail",
                "--text",
            ],
            input.as_bytes(),
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("goal: read project"));
        assert!(text.contains("path: TaskPath"));
        assert!(text.contains("graphs:"));
        assert!(text.contains("awaiting=1"));
        assert!(text.contains("tasks:"));
        assert!(text.contains("state=AwaitingApproval"));
        assert!(text.contains("blocker=AwaitingApproval"));
    }

    #[test]
    fn status_can_render_event_feed_as_static_panel() {
        let input = event_feed_json();
        let mut output = Vec::new();

        let code = run_with_io(
            ["moxi-cli", "status", "--graph", "graph_1", "--panel"],
            input.as_bytes(),
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text
            .contains("+----------------------------------------------------------------------+"));
        assert!(text.contains("MOXI CLI STATUS"));
        assert!(text.contains("surface=Cli profile=shell.cli.fast"));
        assert!(text.contains("graph=graph_1 cursor=2 complete=false"));
        assert!(text.contains("stage=Planned progress=25% task=task_1"));
        assert!(text.contains("blockers: none"));
        assert!(text.contains("boundary: projection only; no execute/approve/ticket/verify/ledger"));
    }

    #[test]
    fn status_can_render_query_snapshot_as_static_panel() {
        let input = query_snapshot_json();
        let mut output = Vec::new();

        let code = run_with_io(
            [
                "moxi-cli",
                "status",
                "--query",
                "--surface",
                "ide",
                "--graph",
                "graph_detail",
                "--panel",
            ],
            input.as_bytes(),
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("surface=Ide profile=shell.ide.readonly"));
        assert!(text.contains("goal=read project"));
        assert!(text.contains("path=TaskPath"));
        assert!(text.contains("graphs:"));
        assert!(text.contains("graph_detail tasks=1 done=0 run=0 wait=1 block=1 fail=0"));
        assert!(text.contains("tasks:"));
        assert!(text.contains("task_1 [AwaitingApproval] file.read 50%"));
        assert!(text.contains("blocker=AwaitingApproval"));
    }

    #[test]
    fn status_text_limit_hides_extra_rendered_rows_only() {
        let input = multi_task_query_snapshot_json();
        let mut output = Vec::new();

        let code = run_with_io(
            [
                "moxi-cli",
                "status",
                "--query",
                "--surface",
                "ide",
                "--graph",
                "graph_many",
                "--text",
                "--limit",
                "1",
            ],
            input.as_bytes(),
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("- task_1: AwaitingApproval"));
        assert!(text.contains("- 1 more blockers hidden by --limit"));
        assert!(text.contains("- task_1 state=AwaitingApproval"));
        assert!(text.contains("- 2 more tasks hidden by --limit"));
        assert!(!text.contains("task_3 state=Running"));
    }

    #[test]
    fn status_panel_limit_hides_extra_rendered_rows_only() {
        let input = multi_task_query_snapshot_json();
        let mut output = Vec::new();

        let code = run_with_io(
            [
                "moxi-cli",
                "status",
                "--query",
                "--surface",
                "ide",
                "--graph",
                "graph_many",
                "--panel",
                "--limit",
                "1",
            ],
            input.as_bytes(),
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("task_1 -> AwaitingApproval"));
        assert!(text.contains("... 1 more blockers hidden by --limit"));
        assert!(text.contains("task_1 [AwaitingApproval] file.read 10%"));
        assert!(text.contains("... 2 more tasks hidden by --limit"));
        assert!(!text.contains("task_3 [Running]"));
    }

    #[test]
    fn status_limit_does_not_truncate_json_projection() {
        let input = multi_task_query_snapshot_json();
        let mut output = Vec::new();

        let code = run_with_io(
            [
                "moxi-cli",
                "status",
                "--query",
                "--surface",
                "ide",
                "--graph",
                "graph_many",
                "--limit",
                "1",
            ],
            input.as_bytes(),
            &mut output,
        )
        .unwrap();
        let json: Value = serde_json::from_slice(&output).unwrap();

        assert_eq!(code, 0);
        assert_eq!(json["tasks"].as_array().unwrap().len(), 3);
        assert_eq!(json["blockers"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn status_rejects_invalid_limit() {
        let mut output = Vec::new();

        let error = run_with_io(
            ["moxi-cli", "status", "--limit", "many"],
            event_feed_json().as_bytes(),
            &mut output,
        )
        .unwrap_err();

        assert!(matches!(error, CliError::InvalidLimit(value) if value == "many"));
        assert!(output.is_empty());
    }

    #[test]
    fn status_rejects_conflicting_input_modes() {
        let mut output = Vec::new();

        let error = run_with_io(
            ["moxi-cli", "status", "--feed", "--query"],
            event_feed_json().as_bytes(),
            &mut output,
        )
        .unwrap_err();

        assert!(matches!(error, CliError::StatusInputConflict));
        assert!(output.is_empty());
    }

    #[test]
    fn watch_renders_snapshot_file_as_panel_by_default() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("query-snapshot.json");
        std::fs::write(&path, query_snapshot_json()).unwrap();
        let mut output = Vec::new();

        let code = run(
            [
                "moxi-cli",
                "watch",
                "--query",
                "--surface",
                "ide",
                "--graph",
                "graph_detail",
                "--input",
                path.to_str().unwrap(),
                "--ticks",
                "1",
            ],
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("watch tick 1/1"));
        assert!(text.contains("MOXI CLI STATUS"));
        assert!(text.contains("surface=Ide profile=shell.ide.readonly"));
        assert!(text.contains("boundary: projection only; no execute/approve/ticket/verify/ledger"));
    }

    #[test]
    fn watch_can_render_multiple_text_ticks_without_runtime_execution() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("event-feed.json");
        std::fs::write(&path, event_feed_json()).unwrap();
        let mut output = Vec::new();

        let code = run(
            [
                "moxi-cli",
                "watch",
                "--graph",
                "graph_1",
                "--input",
                path.to_str().unwrap(),
                "--text",
                "--ticks",
                "2",
                "--interval-ms",
                "0",
            ],
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("watch tick 1/2"));
        assert!(text.contains("watch tick 2/2"));
        assert_eq!(text.matches("MOXI status").count(), 2);
        assert!(text.contains("stage: Planned"));
    }

    #[test]
    fn watch_requires_snapshot_input_path() {
        let mut output = Vec::new();

        let error = run(["moxi-cli", "watch", "--graph", "graph_1"], &mut output).unwrap_err();

        assert!(matches!(error, CliError::MissingRequired("--input")));
        assert!(output.is_empty());
    }

    #[test]
    fn watch_rejects_zero_ticks() {
        let mut output = Vec::new();

        let error = run(
            [
                "moxi-cli",
                "watch",
                "--input",
                "snapshot.json",
                "--ticks",
                "0",
            ],
            &mut output,
        )
        .unwrap_err();

        assert!(matches!(error, CliError::InvalidWatchTicks(value) if value == "0"));
        assert!(output.is_empty());
    }

    #[test]
    fn tui_renders_read_only_snapshot_dashboard() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("query-snapshot.json");
        std::fs::write(&path, query_snapshot_json()).unwrap();
        let mut output = Vec::new();

        let code = run(
            [
                "moxi-cli",
                "tui",
                "--query",
                "--surface",
                "ide",
                "--graph",
                "graph_detail",
                "--input",
                path.to_str().unwrap(),
                "--width",
                "120",
                "--height",
                "36",
            ],
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("moxi-agent"));
        assert!(text.contains("local-r10-demo-session"));
        assert!(text.contains("guarded read-only session"));
        assert!(text.contains("Create session shell"));
        assert!(text.contains("Input Task"));
        assert!(text.contains("graph=graph_detail"));
        assert!(text.contains("1 projection tasks"));
        assert!(text.contains("1 approvals"));
        assert!(text.contains("task_1"));
        assert!(text.contains("Task Tracking"));
    }

    #[test]
    fn tui_without_input_renders_builtin_demo_dashboard() {
        let mut output = Vec::new();

        let code = run(
            [
                "moxi-cli", "tui", "--width", "112", "--height", "30", "--keys", "g,q",
            ],
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("moxi-agent"));
        assert!(text.contains("graph=demo_graph"));
        assert!(text.contains("local-r10-demo-session"));
        assert!(text.contains("guarded read-only session"));
        assert!(text.contains("model: session-local"));
        assert!(text.contains("tools: workspace.probe"));
        assert!(text.contains("Collect workspace facts"));
        assert!(text.contains("Input Task"));
        assert!(text.contains("active=Graph selected_task=0 filter=<none>"));
        assert!(text.contains("quit=true"));
    }

    #[test]
    fn tui_command_bar_accepts_safe_builtin_commands_only() {
        let mut output = Vec::new();

        let code = run(
            [
                "moxi-cli",
                "tui",
                "--width",
                "120",
                "--height",
                "30",
                "--keys",
                "type:/,type:b,type:o,type:u,type:n,type:d,type:a,type:r,type:y,enter,q",
            ],
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("pane=Boundary"));
        assert!(text.contains("> Ask moxi-agent"));
        assert!(text.contains("Task Tracking"));
    }

    #[test]
    fn tui_state_starts_with_agent_session_scaffold() {
        let state = TuiState::default();

        assert_eq!(state.session.id, "local-r10-demo-session");
        assert_eq!(state.session.mode, TuiSessionMode::ReadOnly);
        assert_eq!(state.session.turn_count, 1);
        assert_eq!(state.session.agents.len(), 3);
        assert!(state
            .session
            .skills
            .iter()
            .any(|skill| skill == "tui.design"));
        assert!(state.session.tools.iter().any(|tool| tool == "git.status"));
        assert_eq!(state.session.messages.len(), 2);
        assert_eq!(state.session.steps.len(), 3);
        assert_eq!(
            state.session.steps[state.session.active_step_index].label,
            "Collect workspace facts"
        );
        assert!(state.session.workspace.cwd.contains("MOXI-Essence-agent"));
        assert_eq!(state.session.workspace.config_path, ".moxi\\agents.toml");
        assert_eq!(state.session.workspace.trust, "pending");
        assert_eq!(state.session.workspace.trust_path, ".moxi\\trust.toml");
        assert_eq!(state.session.trust.status, TuiTrustStatus::NeedsReview);
        assert!(!state.session.workspace.cargo_state.is_empty());
        assert!(!state.session.workspace.docs_state.is_empty());
    }

    #[test]
    fn workspace_probe_reports_missing_files_without_failing() {
        let temp = tempfile::tempdir().unwrap();

        let facts = WorkspaceFacts::detect_at(temp.path());

        assert_eq!(
            facts.short_path,
            temp.path().file_name().unwrap().to_string_lossy()
        );
        assert_eq!(facts.config_state, "missing");
        assert_eq!(facts.trust_state, "missing");
        assert_eq!(facts.docs_state, "missing");
        assert_eq!(facts.cargo_state, "Cargo.toml missing");
        assert_eq!(facts.git_state, "not a git repo");
    }

    #[test]
    fn trust_state_detects_known_read_only_workspace_marker() {
        let temp = tempfile::tempdir().unwrap();
        let moxi_dir = temp.path().join(".moxi");
        std::fs::create_dir(&moxi_dir).unwrap();
        std::fs::write(moxi_dir.join("trust.toml"), "mode = \"read-only\"\n").unwrap();
        let workspace = WorkspaceFacts::detect_at(temp.path());

        let trust = TuiTrustState::from_workspace(&workspace);

        assert_eq!(workspace.trust_state, "present");
        assert_eq!(trust.status, TuiTrustStatus::KnownReadOnly);
        assert!(!trust.should_show_gate());
    }

    #[test]
    fn startup_flow_conditionally_skips_trust_when_marker_exists() {
        let mut state = TuiState {
            screen: TuiScreen::Boot,
            ..TuiState::default()
        };
        apply_tui_key(&mut state, &TuiKey::SubmitCommand);
        assert_eq!(state.screen, TuiScreen::Trust);

        state.screen = TuiScreen::Boot;
        state.session.trust.status = TuiTrustStatus::KnownReadOnly;
        state.session.model_config = TuiModelConfig {
            provider: TuiModelProvider::OpenAi,
            endpoint: "https://api.openai.com/v1".to_owned(),
            model: "gpt-demo".to_owned(),
            api_key_source: TuiApiKeySource::Env {
                name: "OPENAI_API_KEY".to_owned(),
                redacted: "sk-d...demo".to_owned(),
            },
            config_path: ".moxi\\config.toml".to_owned(),
            config_state: "present".to_owned(),
        };
        apply_tui_key(&mut state, &TuiKey::SubmitCommand);
        assert_eq!(state.screen, TuiScreen::Core);
    }

    #[test]
    fn trust_commands_capture_local_intent_without_authority() {
        let mut state = TuiState {
            command_input: "/approve".to_owned(),
            ..TuiState::default()
        };

        submit_tui_command(&mut state);

        assert_eq!(state.session.trust.status, TuiTrustStatus::TrustedReadOnly);
        assert_eq!(state.screen, TuiScreen::Core);
        assert!(state.command_status.contains("P0 still authorizes"));

        state.command_input = "/deny".to_owned();
        submit_tui_command(&mut state);

        assert_eq!(state.session.trust.status, TuiTrustStatus::Denied);
        assert_eq!(state.screen, TuiScreen::Trust);
        assert!(state.command_status.contains("blocked"));
    }

    #[test]
    fn workspace_probe_reads_repo_cargo_and_docs_facts() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("moxi-cli crate should live under crates/moxi-cli");

        let facts = WorkspaceFacts::detect_at(root);

        assert!(facts.cargo_state.contains("workspace"));
        assert_eq!(facts.docs_state, "present");
    }

    #[test]
    fn tui_context_snapshot_scores_available_sources() {
        let session = TuiAgentSession::default();

        let snapshot = session.context_snapshot();

        assert_eq!(snapshot.sources.len(), 9);
        assert!(snapshot.percent > 50);
        assert!(snapshot
            .sources
            .iter()
            .any(|source| source.label == "messages" && source.available));
        assert!(snapshot
            .sources
            .iter()
            .any(|source| source.label == "steps" && source.available));
    }

    #[test]
    fn model_config_reports_missing_local_config() {
        let temp = tempfile::tempdir().unwrap();
        let config = TuiModelConfig::load_at_with_env(
            &temp.path().join(".moxi").join("config.toml"),
            |_| None,
        );

        assert_eq!(config.provider, TuiModelProvider::OpenAi);
        assert_eq!(config.endpoint, "https://api.openai.com/v1");
        assert_eq!(config.model, "not-configured");
        assert_eq!(config.config_state, "missing");
        assert_eq!(config.api_key_source, TuiApiKeySource::Missing);
        assert!(!config.is_configured());
        assert!(config.needs_setup());
        assert!(config.setup_sample().contains("api_key_env"));
    }

    #[test]
    fn model_config_loads_config_toml_with_redacted_key() {
        let temp = tempfile::tempdir().unwrap();
        let moxi_dir = temp.path().join(".moxi");
        fs::create_dir_all(&moxi_dir).unwrap();
        let path = moxi_dir.join("config.toml");
        let raw_secret = "sk-test-secret-123456";
        fs::write(
            &path,
            format!(
                "[model]\nprovider = \"openrouter\"\nendpoint = \"https://openrouter.ai/api/v1\"\nmodel = \"openai/gpt-4o-mini\"\napi_key = \"{raw_secret}\"\n"
            ),
        )
        .unwrap();

        let config = TuiModelConfig::load_at(&path);

        assert_eq!(config.provider, TuiModelProvider::OpenRouter);
        assert_eq!(config.endpoint, "https://openrouter.ai/api/v1");
        assert_eq!(config.model, "openai/gpt-4o-mini");
        assert_eq!(config.config_state, "present");
        assert_eq!(
            config.api_key_source,
            TuiApiKeySource::Config {
                redacted: "sk-t...3456".to_owned()
            }
        );
        assert!(!config.api_key_source.summary().contains(raw_secret));
        assert!(config.is_configured());
    }

    #[test]
    fn model_config_uses_env_key_without_printing_secret() {
        let temp = tempfile::tempdir().unwrap();
        let moxi_dir = temp.path().join(".moxi");
        fs::create_dir_all(&moxi_dir).unwrap();
        let path = moxi_dir.join("config.toml");
        let env_name = "MOXI_TEST_API_KEY_FOR_CONFIG";
        let raw_secret = "env-secret-abcdef";
        fs::write(
            &path,
            format!(
                "provider = \"custom\"\nendpoint = \"https://models.example.test/v1\"\nmodel = \"demo-model\"\napi_key_env = \"{env_name}\"\n"
            ),
        )
        .unwrap();
        let config = TuiModelConfig::load_at_with_env(&path, |name| {
            (name == env_name).then(|| raw_secret.to_owned())
        });
        assert_eq!(config.provider, TuiModelProvider::Custom);
        assert_eq!(
            config.api_key_source,
            TuiApiKeySource::Env {
                name: env_name.to_owned(),
                redacted: "env-...cdef".to_owned()
            }
        );
        assert!(!config.api_key_source.summary().contains(raw_secret));
    }

    #[test]
    fn doctor_reports_setup_gap_without_network() {
        let config = TuiModelConfig {
            provider: TuiModelProvider::OpenAi,
            endpoint: "https://api.openai.com/v1".to_owned(),
            model: "not-configured".to_owned(),
            api_key_source: TuiApiKeySource::Missing,
            config_path: ".moxi\\config.toml".to_owned(),
            config_state: "missing".to_owned(),
        };

        let report = TuiModelDoctor::check(&config);

        assert_eq!(report.status, TuiDoctorStatus::NeedsSetup);
        assert!(report.message().contains("needs-setup"));
        assert!(report.message().contains(".moxi/config.toml"));
    }

    #[test]
    fn doctor_classifies_openai_compatible_statuses() {
        let ready = classify_doctor_response(
            &test_doctor_config("http://127.0.0.1:1/v1"),
            HttpProbeResponse {
                status: 200,
                body: r#"{"id":"gpt-demo","object":"model"}"#.to_owned(),
            },
        );
        assert_eq!(ready.status, TuiDoctorStatus::Ready);

        let invalid = classify_doctor_response(
            &test_doctor_config("http://127.0.0.1:1/v1"),
            HttpProbeResponse {
                status: 401,
                body: r#"{"error":{"message":"invalid api key"}}"#.to_owned(),
            },
        );
        assert_eq!(invalid.status, TuiDoctorStatus::InvalidKey);

        let missing_model = classify_doctor_response(
            &test_doctor_config("http://127.0.0.1:1/v1"),
            HttpProbeResponse {
                status: 404,
                body: r#"{"error":{"message":"model not found"}}"#.to_owned(),
            },
        );
        assert_eq!(missing_model.status, TuiDoctorStatus::ModelNotFound);

        let quota = classify_doctor_response(
            &test_doctor_config("http://127.0.0.1:1/v1"),
            HttpProbeResponse {
                status: 429,
                body: r#"{"error":{"message":"rate limit"}}"#.to_owned(),
            },
        );
        assert_eq!(quota.status, TuiDoctorStatus::Quota);
    }

    #[test]
    fn doctor_probe_reaches_local_openai_compatible_endpoint() {
        let endpoint = mock_http_once(200, r#"{"id":"gpt-demo","object":"model"}"#);
        let response = http_get_openai_model(&endpoint, "gpt-demo", "secret").unwrap();

        assert_eq!(response.status, 200);
        assert!(response.body.contains("gpt-demo"));
    }

    #[test]
    fn model_catalog_parses_openai_model_ids() {
        let models = parse_openai_model_ids(
            r#"{"object":"list","data":[{"id":"gpt-b"},{"id":"gpt-a"},{"id":"gpt-a"}]}"#,
        )
        .unwrap();

        assert_eq!(models, vec!["gpt-a".to_owned(), "gpt-b".to_owned()]);
    }

    #[test]
    fn model_catalog_lists_local_openai_compatible_endpoint() {
        let endpoint = mock_http_once_with_path(
            200,
            r#"{"object":"list","data":[{"id":"gpt-demo"},{"id":"gpt-mini"}]}"#,
            Some("/v1/models"),
        );
        let response = http_list_openai_models(&endpoint, "secret").unwrap();
        let report = classify_model_catalog_response(&test_doctor_config(&endpoint), response);

        assert_eq!(report.status, TuiModelCatalogStatus::Ready);
        assert_eq!(
            report.models,
            vec!["gpt-demo".to_owned(), "gpt-mini".to_owned()]
        );
        assert!(report.message().contains("gpt-demo"));
    }

    #[test]
    fn init_previews_model_config_without_writing_file() {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join(".moxi").join("config.toml");
        let mut output = Vec::new();

        let code = run(
            [
                "moxi-cli",
                "init",
                "--provider",
                "openrouter",
                "--model",
                "anthropic/claude-sonnet-4",
                "--config",
                config_path.to_str().unwrap(),
            ],
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(!config_path.exists());
        assert!(text.contains("MOXI model config preview"));
        assert!(text.contains("mode: dry-run"));
        assert!(text.contains("provider = \"openrouter\""));
        assert!(text.contains("endpoint = \"https://openrouter.ai/api/v1\""));
        assert!(text.contains("model = \"anthropic/claude-sonnet-4\""));
        assert!(text.contains("api_key_env = \"OPENROUTER_API_KEY\""));
        assert!(text.contains("never a raw API key"));
    }

    #[test]
    fn init_writes_env_only_model_config_and_refuses_overwrite() {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join(".moxi").join("config.toml");
        let raw_secret = "sk-visible-never-0000";
        let mut output = Vec::new();

        let code = run(
            [
                "moxi-cli",
                "init",
                "--provider",
                "custom",
                "--endpoint",
                "https://models.example.test/v1",
                "--model",
                "gpt-demo",
                "--api-key-env",
                "MOXI_EXAMPLE_KEY",
                "--config",
                config_path.to_str().unwrap(),
                "--write",
            ],
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();
        let written = fs::read_to_string(&config_path).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("MOXI model config written"));
        assert!(text.contains("api_key_env: MOXI_EXAMPLE_KEY"));
        assert!(!text.contains(raw_secret));
        assert!(written.contains("provider = \"custom\""));
        assert!(written.contains("endpoint = \"https://models.example.test/v1\""));
        assert!(written.contains("model = \"gpt-demo\""));
        assert!(written.contains("api_key_env = \"MOXI_EXAMPLE_KEY\""));
        assert!(!written.contains("api_key ="));
        assert!(!written.contains(raw_secret));

        let error = run(
            [
                "moxi-cli",
                "init",
                "--config",
                config_path.to_str().unwrap(),
                "--write",
            ],
            &mut Vec::new(),
        )
        .unwrap_err();

        assert!(matches!(error, CliError::ModelConfigExists(path) if path.contains("config.toml")));
    }

    #[test]
    fn top_level_config_prints_redacted_model_state() {
        let temp = tempfile::tempdir().unwrap();
        let moxi_dir = temp.path().join(".moxi");
        fs::create_dir_all(&moxi_dir).unwrap();
        let config_path = moxi_dir.join("config.toml");
        let raw_secret = "sk-visible-never-1111";
        fs::write(
            &config_path,
            format!("provider = \"openai\"\nmodel = \"gpt-demo\"\napi_key = \"{raw_secret}\"\n"),
        )
        .unwrap();
        let mut output = Vec::new();

        let code = run(
            [
                "moxi-cli",
                "config",
                "--config",
                config_path.to_str().unwrap(),
            ],
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("MOXI model config"));
        assert!(text.contains("provider=openai"));
        assert!(text.contains("model=gpt-demo"));
        assert!(text.contains("key=config:sk-v...1111"));
        assert!(text.contains("secrets are redacted"));
        assert!(!text.contains(raw_secret));
    }

    #[test]
    fn top_level_doctor_reports_actionable_status_without_secret() {
        let temp = tempfile::tempdir().unwrap();
        let moxi_dir = temp.path().join(".moxi");
        fs::create_dir_all(&moxi_dir).unwrap();
        let endpoint = mock_http_once(401, r#"{"error":{"message":"invalid api key"}}"#);
        let env_name = "MOXI_TEST_TOP_LEVEL_DOCTOR_KEY";
        let raw_secret = "doctor-secret-top-level-123456";
        let config_path = moxi_dir.join("config.toml");
        fs::write(
            &config_path,
            format!(
                "provider = \"custom\"\nendpoint = \"{endpoint}\"\nmodel = \"gpt-demo\"\napi_key_env = \"{env_name}\"\n"
            ),
        )
        .unwrap();
        env::set_var(env_name, raw_secret);
        let mut output = Vec::new();

        let code = run(
            [
                "moxi-cli",
                "doctor",
                "--config",
                config_path.to_str().unwrap(),
            ],
            &mut output,
        )
        .unwrap();
        env::remove_var(env_name);
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("MOXI doctor"));
        assert!(text.contains("status: invalid-key"));
        assert!(text.contains("check the api_key_env value"));
        assert!(text.contains("read-only connectivity probe"));
        assert!(!text.contains(raw_secret));
    }

    #[test]
    fn top_level_models_lists_catalog_without_secret() {
        let temp = tempfile::tempdir().unwrap();
        let moxi_dir = temp.path().join(".moxi");
        fs::create_dir_all(&moxi_dir).unwrap();
        let endpoint = mock_http_once_with_path(
            200,
            r#"{"object":"list","data":[{"id":"gpt-demo"},{"id":"gpt-mini"}]}"#,
            Some("/v1/models"),
        );
        let env_name = "MOXI_TEST_TOP_LEVEL_MODELS_KEY";
        let raw_secret = "models-secret-top-level-123456";
        let config_path = moxi_dir.join("config.toml");
        fs::write(
            &config_path,
            format!(
                "provider = \"custom\"\nendpoint = \"{endpoint}\"\nmodel = \"gpt-demo\"\napi_key_env = \"{env_name}\"\n"
            ),
        )
        .unwrap();
        env::set_var(env_name, raw_secret);
        let mut output = Vec::new();

        let code = run(
            [
                "moxi-cli",
                "models",
                "--config",
                config_path.to_str().unwrap(),
            ],
            &mut output,
        )
        .unwrap();
        env::remove_var(env_name);
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("MOXI models"));
        assert!(text.contains("status: ready"));
        assert!(text.contains("- gpt-demo"));
        assert!(text.contains("- gpt-mini"));
        assert!(text.contains("read-only model catalog probe"));
        assert!(!text.contains(raw_secret));
    }

    #[test]
    fn model_chat_adapter_posts_read_only_prompt() {
        let endpoint = mock_http_once_with_path(
            200,
            r#"{"choices":[{"message":{"role":"assistant","content":"主人，MOXI 已进入只读模型聊天。"}}]}"#,
            Some("/v1/chat/completions"),
        );
        let reply =
            post_openai_chat_completion(&endpoint, "gpt-demo", "secret", "检查当前项目状态")
                .unwrap();

        assert_eq!(reply, "主人，MOXI 已进入只读模型聊天。");
    }

    #[test]
    fn model_chat_adapter_redacts_error_preview() {
        let endpoint = mock_http_once_with_path(
            401,
            r#"{"error":{"message":"invalid key sk-visible-never-0000"}}"#,
            Some("/v1/chat/completions"),
        );
        let error =
            post_openai_chat_completion(&endpoint, "gpt-demo", "secret", "检查当前项目状态")
                .unwrap_err();

        assert!(error.contains("invalid key"));
        assert!(!error.contains("sk-visible-never-0000"));
        assert!(error.contains("sk-v...0000"));
    }

    #[test]
    fn staged_reply_chunks_progress_before_completion() {
        let body = "第一段说明 MOXI 正在读取上下文，并且会把当前工作区状态压缩为只读事实。第二段说明模型回复会分块显示，让主人看到回答正在逐步出现。第三段提醒 P0 仍然负责写入和执行，TUI 只负责展示和收集主人意图。";
        let response = TuiBackendResponse {
            agent: "moxi-agent".to_owned(),
            role: "orchestrator".to_owned(),
            body: body.to_owned(),
            metadata: TuiMessageMeta::new(
                "gpt-demo",
                "medium",
                ["model.chat"],
                "state: complete | backend: read-only model",
            ),
            plan: read_only_backend_plan(&sample_backend_request("检查状态")),
            completed_step_detail: "complete".to_owned(),
            next_step_detail: "next".to_owned(),
        };
        let mut pending = TuiPendingReply::from_response(2, response);

        let first = pending.render_next_chunk("[/]");
        assert!(!pending.is_done());
        assert!(first.contains("第一段"));
        assert!(first.contains("[/]"));

        while !pending.is_done() {
            pending.render_next_chunk("[-]");
        }
        assert!(pending.is_done());
    }

    fn test_doctor_config(endpoint: &str) -> TuiModelConfig {
        TuiModelConfig {
            provider: TuiModelProvider::Custom,
            endpoint: endpoint.to_owned(),
            model: "gpt-demo".to_owned(),
            api_key_source: TuiApiKeySource::Config {
                redacted: "sk-t...test".to_owned(),
            },
            config_path: ".moxi\\config.toml".to_owned(),
            config_state: "present".to_owned(),
        }
    }

    fn advance_session_until_complete(session: &mut TuiAgentSession) {
        for _ in 0..32 {
            if !session.is_streaming() {
                return;
            }
            session.advance_loading();
        }
        panic!("session did not finish staged reply");
    }

    fn advance_state_until_complete(state: &mut TuiState) {
        for _ in 0..32 {
            if !state.session.is_streaming() {
                return;
            }
            apply_tui_key(state, &TuiKey::Refresh);
        }
        panic!("state did not finish staged reply");
    }

    fn sample_backend_request(task: &str) -> TuiBackendRequest<'_> {
        let workspace = Box::leak(Box::new(WorkspaceFacts {
            cwd: "C:\\demo".to_owned(),
            short_path: "demo".to_owned(),
            config_path: ".moxi\\agents.toml".to_owned(),
            config_state: "present".to_owned(),
            trust_path: ".moxi\\trust.toml".to_owned(),
            trust_state: "present".to_owned(),
            git_state: "main clean".to_owned(),
            cargo_state: "workspace 2 crates".to_owned(),
            docs_state: "present".to_owned(),
            trust: "pending".to_owned(),
        }));
        let agents = Box::leak(Box::new(vec![TuiAgentProfile {
            name: "moxi-agent".to_owned(),
            role: "orchestrator".to_owned(),
            model: "backend-local".to_owned(),
            reasoning: "high".to_owned(),
        }]));
        let skills = Box::leak(Box::new(vec![
            "tui.design".to_owned(),
            "risk.review".to_owned(),
        ]));
        let tools = Box::leak(Box::new(vec![
            "repo.inspect".to_owned(),
            "git.status".to_owned(),
        ]));
        TuiBackendRequest {
            turn: 2,
            task,
            workspace,
            trust: TuiTrustStatus::KnownReadOnly,
            agents,
            skills,
            tools,
            context_percent: 88,
        }
    }

    #[test]
    fn tui_config_command_pushes_redacted_message() {
        let temp = tempfile::tempdir().unwrap();
        let moxi_dir = temp.path().join(".moxi");
        fs::create_dir_all(&moxi_dir).unwrap();
        let raw_secret = "sk-visible-never-9999";
        fs::write(
            moxi_dir.join("config.toml"),
            format!("provider = \"openai\"\nmodel = \"gpt-demo\"\napi_key = \"{raw_secret}\"\n"),
        )
        .unwrap();
        let workspace = WorkspaceFacts::detect_at(temp.path());
        let mut state = TuiState {
            session: TuiAgentSession {
                model_config: TuiModelConfig::load_for_workspace(&workspace),
                workspace,
                ..TuiAgentSession::default()
            },
            command_input: "/config".to_owned(),
            ..TuiState::default()
        };

        submit_tui_command(&mut state);

        let message = state
            .session
            .messages
            .iter()
            .rev()
            .find(|message| message.role == "config")
            .unwrap();
        assert!(message.body.contains("provider=openai"));
        assert!(message.body.contains("key=config:sk-v...9999"));
        assert!(!message.body.contains(raw_secret));
        assert!(state.command_status.contains("secrets are redacted"));
    }

    #[test]
    fn tui_doctor_command_pushes_actionable_message_without_secret() {
        let temp = tempfile::tempdir().unwrap();
        let moxi_dir = temp.path().join(".moxi");
        fs::create_dir_all(&moxi_dir).unwrap();
        let endpoint = mock_http_once(401, r#"{"error":{"message":"invalid api key"}}"#);
        let env_name = "MOXI_TEST_DOCTOR_KEY";
        let raw_secret = "doctor-secret-123456";
        fs::write(
            moxi_dir.join("config.toml"),
            format!(
                "provider = \"custom\"\nendpoint = \"{endpoint}\"\nmodel = \"gpt-demo\"\napi_key_env = \"{env_name}\"\n"
            ),
        )
        .unwrap();
        env::set_var(env_name, raw_secret);
        let workspace = WorkspaceFacts::detect_at(temp.path());
        let mut state = TuiState {
            session: TuiAgentSession {
                model_config: TuiModelConfig::load_for_workspace(&workspace),
                workspace,
                ..TuiAgentSession::default()
            },
            command_input: "/doctor".to_owned(),
            ..TuiState::default()
        };

        submit_tui_command(&mut state);

        env::remove_var(env_name);
        let message = state
            .session
            .messages
            .iter()
            .rev()
            .find(|message| message.role == "doctor")
            .unwrap();
        assert!(message.body.contains("status=invalid-key"));
        assert!(message.body.contains("check the api_key_env value"));
        assert!(!message.body.contains(raw_secret));
        assert!(state.command_status.contains("invalid-key"));
    }

    #[test]
    fn tui_models_command_lists_provider_models_without_secret() {
        let temp = tempfile::tempdir().unwrap();
        let moxi_dir = temp.path().join(".moxi");
        fs::create_dir_all(&moxi_dir).unwrap();
        let endpoint = mock_http_once_with_path(
            200,
            r#"{"object":"list","data":[{"id":"gpt-demo"},{"id":"gpt-mini"}]}"#,
            Some("/v1/models"),
        );
        let env_name = "MOXI_TEST_MODELS_KEY";
        let raw_secret = "models-secret-123456";
        fs::write(
            moxi_dir.join("config.toml"),
            format!(
                "provider = \"custom\"\nendpoint = \"{endpoint}\"\nmodel = \"gpt-demo\"\napi_key_env = \"{env_name}\"\n"
            ),
        )
        .unwrap();
        env::set_var(env_name, raw_secret);
        let workspace = WorkspaceFacts::detect_at(temp.path());
        let mut state = TuiState {
            session: TuiAgentSession {
                model_config: TuiModelConfig::load_for_workspace(&workspace),
                workspace,
                ..TuiAgentSession::default()
            },
            command_input: "/models".to_owned(),
            ..TuiState::default()
        };

        submit_tui_command(&mut state);

        env::remove_var(env_name);
        let message = state
            .session
            .messages
            .iter()
            .rev()
            .find(|message| message.role == "models")
            .unwrap();
        assert!(message.body.contains("status=ready"));
        assert!(message.body.contains("gpt-demo"));
        assert!(message.body.contains("gpt-mini"));
        assert!(!message.body.contains(raw_secret));
        assert!(state.command_status.contains("ready"));
    }

    #[test]
    fn tui_configured_task_uses_model_chat_adapter() {
        let temp = tempfile::tempdir().unwrap();
        let moxi_dir = temp.path().join(".moxi");
        fs::create_dir_all(&moxi_dir).unwrap();
        let endpoint = mock_http_once_with_path(
            200,
            r#"{"choices":[{"message":{"role":"assistant","content":"主人，模型已读取只读上下文并回复。"}}]}"#,
            Some("/v1/chat/completions"),
        );
        let env_name = "MOXI_TEST_CHAT_KEY";
        let raw_secret = "chat-secret-123456";
        fs::write(
            moxi_dir.join("config.toml"),
            format!(
                "provider = \"custom\"\nendpoint = \"{endpoint}\"\nmodel = \"gpt-demo\"\napi_key_env = \"{env_name}\"\n"
            ),
        )
        .unwrap();
        env::set_var(env_name, raw_secret);
        let workspace = WorkspaceFacts::detect_at(temp.path());
        let mut session = TuiAgentSession {
            model_config: TuiModelConfig::load_for_workspace(&workspace),
            workspace,
            ..TuiAgentSession::default()
        };

        session.submit_user_task("检查当前项目状态");
        advance_session_until_complete(&mut session);
        env::remove_var(env_name);

        let message = session.messages.last().unwrap();
        assert_eq!(message.state, TuiMessageState::Complete);
        assert_eq!(message.body, "主人，模型已读取只读上下文并回复。");
        assert_eq!(message.metadata.model, "gpt-demo");
        assert!(message.metadata.status.contains("read-only model"));
        assert!(session
            .steps
            .iter()
            .any(|step| step.label == "Plan: Request model response"));
        assert!(!message.body.contains(raw_secret));
    }

    #[test]
    fn tui_session_persistence_snapshot_roundtrips_as_local_json() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceFacts::detect_at(temp.path());
        let mut session = TuiAgentSession {
            model_config: TuiModelConfig::load_for_workspace(&workspace),
            workspace,
            ..TuiAgentSession::default()
        };
        session.submit_user_task("inspect project status");
        advance_session_until_complete(&mut session);

        let path = session.save_persistence_snapshot().unwrap();
        assert_eq!(
            path,
            temp.path()
                .join(".moxi")
                .join("session")
                .join("tui-session.json")
        );

        let snapshot = TuiAgentSession::load_persistence_snapshot(&path).unwrap();

        assert_eq!(snapshot.schema_version, 1);
        assert_eq!(snapshot.session_id, "local-r10-demo-session");
        assert_eq!(snapshot.workspace.cwd, temp.path().display().to_string());
        assert_eq!(snapshot.turn_count, 2);
        assert!(snapshot.context_percent > 0);
        assert!(snapshot
            .messages
            .iter()
            .any(|message| message.body.contains("read-only backend analysis")));
        assert!(snapshot
            .steps
            .iter()
            .any(|step| step.label == "Plan: Understand project status"));
        assert!(snapshot
            .steps
            .iter()
            .any(|step| step.label == "Await P1/P0 adapter"));
    }

    #[test]
    fn agent_profiles_load_from_agents_toml() {
        let text = r#"
[[agents]]
name = "moxi-agent"
role = "orchestrator"
model = "gpt-5.5"
reasoning = "high"

[[agents]]
name = "ui-agent"
role = "rich-cli"
"#;

        let agents = TuiAgentProfile::parse_agents_toml(text);

        assert_eq!(agents.len(), 2);
        assert_eq!(agents[0].name, "moxi-agent");
        assert_eq!(agents[0].model, "gpt-5.5");
        assert_eq!(agents[0].reasoning, "high");
        assert_eq!(agents[1].name, "ui-agent");
        assert_eq!(agents[1].role, "rich-cli");
        assert_eq!(agents[1].model, "session-local");
        assert_eq!(agents[1].reasoning, "medium");
    }

    #[test]
    fn agent_profiles_fallback_when_config_is_missing() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceFacts::detect_at(temp.path());

        let agents = TuiAgentProfile::load_for_workspace(&workspace);

        assert_eq!(agents.len(), 3);
        assert!(agents.iter().any(|agent| agent.name == "moxi-agent"));
    }

    #[test]
    fn agent_profiles_load_for_workspace_config_file() {
        let temp = tempfile::tempdir().unwrap();
        let config_dir = temp.path().join(".moxi");
        std::fs::create_dir(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("agents.toml"),
            r#"
[[agents]]
name = "research-agent"
role = "workspace-research"
model = "local-probe"
reasoning = "low"
"#,
        )
        .unwrap();
        let workspace = WorkspaceFacts::detect_at(temp.path());

        let agents = TuiAgentProfile::load_for_workspace(&workspace);

        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].name, "research-agent");
        assert_eq!(agents[0].role, "workspace-research");
    }

    #[test]
    fn tui_messages_carry_structured_model_reasoning_and_tools() {
        let mut state = TuiState {
            command_input: "inspect project status".to_owned(),
            ..TuiState::default()
        };

        submit_tui_command(&mut state);

        let agent_message = state
            .session
            .messages
            .iter()
            .rev()
            .find(|message| message.agent == "moxi-agent")
            .unwrap();
        assert_eq!(agent_message.metadata.model, "session-local");
        assert_eq!(agent_message.metadata.reasoning, "medium");
        assert_eq!(agent_message.metadata.tools, vec!["task.plan"]);
        assert_eq!(agent_message.metadata.status, "state: streaming");

        apply_tui_key(&mut state, &TuiKey::Refresh);
        let agent_message = state
            .session
            .messages
            .iter()
            .rev()
            .find(|message| message.agent == "moxi-agent")
            .unwrap();
        assert_eq!(agent_message.metadata.status, "stream tick 1");
        assert!(agent_message
            .metadata
            .render()
            .contains("model: session-local"));
        assert!(agent_message.metadata.render().contains("tools: task.plan"));
    }

    #[test]
    fn tui_session_converts_user_task_into_messages_and_steps() {
        let mut state = TuiState {
            command_input: "inspect project status".to_owned(),
            ..TuiState::default()
        };

        submit_tui_command(&mut state);

        assert_eq!(state.session.turn_count, 2);
        assert_eq!(state.session.messages.len(), 4);
        assert!(state
            .session
            .messages
            .iter()
            .any(|message| message.agent == "owner" && message.body == "inspect project status"));
        assert!(state
            .session
            .messages
            .iter()
            .any(|message| message.agent == "moxi-agent"
                && message.body.contains("Turn 2")
                && message.state == TuiMessageState::Streaming));
        assert_eq!(state.session.steps.len(), 6);
        assert_eq!(
            state.session.steps[state.session.active_step_index].label,
            "Gather read-only context"
        );
        assert_eq!(state.selected_task_index, state.session.active_step_index);
        assert!(state.follow_active_step);
        assert!(state.command_status.contains("submitted Turn 2"));
    }

    #[test]
    fn tui_detects_risky_input_before_submission() {
        let high = TuiRiskPrompt::detect("commit and push these changes to github").unwrap();
        assert_eq!(high.level, TuiRiskLevel::High);
        assert!(high.reason.contains("write"));

        let medium = TuiRiskPrompt::detect("run tests for the workspace").unwrap();
        assert_eq!(medium.level, TuiRiskLevel::Medium);

        assert!(TuiRiskPrompt::detect("inspect project status").is_none());
    }

    #[test]
    fn tui_risky_task_waits_for_local_approval_intent() {
        let mut state = TuiState {
            command_input: "commit and push current branch".to_owned(),
            ..TuiState::default()
        };

        submit_tui_command(&mut state);

        assert!(state.pending_risk.is_some());
        assert_eq!(state.active_pane, TuiPane::Approvals);
        assert_eq!(state.session.turn_count, 1);
        assert!(state.command_status.contains("risk prompt pending"));

        state.command_input = "/approve".to_owned();
        submit_tui_command(&mut state);

        assert!(state.pending_risk.is_none());
        assert_eq!(state.session.turn_count, 2);
        assert!(state.session.is_streaming());
        assert!(state.command_status.contains("local planning only"));
    }

    #[test]
    fn tui_risky_task_can_be_denied_without_submission() {
        let mut state = TuiState {
            command_input: "delete generated files".to_owned(),
            ..TuiState::default()
        };

        submit_tui_command(&mut state);
        assert!(state.pending_risk.is_some());

        state.command_input = "/deny".to_owned();
        submit_tui_command(&mut state);

        assert!(state.pending_risk.is_none());
        assert_eq!(state.session.turn_count, 1);
        assert!(state.command_status.contains("not submitted"));
    }

    #[test]
    fn tui_refresh_advances_streaming_agent_reply() {
        let mut state = TuiState {
            command_input: "inspect project status".to_owned(),
            ..TuiState::default()
        };

        submit_tui_command(&mut state);
        assert!(state.session.is_streaming());

        apply_tui_key(&mut state, &TuiKey::Refresh);
        assert!(state.session.is_streaming());
        assert_eq!(state.session.loading_tick, 1);
        assert!(state.command_status.contains("streaming agent response"));

        apply_tui_key(&mut state, &TuiKey::Refresh);
        apply_tui_key(&mut state, &TuiKey::Refresh);
        assert!(state.session.is_streaming());
        let staged_reply = state
            .session
            .messages
            .iter()
            .rev()
            .find(|message| message.agent == "moxi-agent")
            .unwrap();
        assert!(staged_reply.metadata.status.contains("stream chunk 1/"));

        advance_state_until_complete(&mut state);

        assert!(!state.session.is_streaming());
        assert!(state.command_status.contains("complete"));
        assert_eq!(
            state.session.steps[state.session.active_step_index].label,
            "Await P1/P0 adapter"
        );
        assert_eq!(
            state.session.steps[state.session.active_step_index].state,
            TuiStepState::Active
        );
        let completed_reply = state
            .session
            .messages
            .iter()
            .rev()
            .find(|message| message.agent == "moxi-agent")
            .unwrap();
        assert!(completed_reply
            .body
            .contains("read-only backend analysis for \"inspect project status\""));
        assert!(completed_reply.body.contains("focus=project status"));
        assert!(completed_reply
            .body
            .contains("backend=runtime-planner:Deterministic"));
        assert!(completed_reply.body.contains("plan=runtime-plan_"));
        assert!(completed_reply
            .body
            .contains("first_step=\"Understand project status\""));
        assert!(completed_reply.body.contains("blocked=write"));
        assert!(completed_reply.body.contains("context="));
        assert!(completed_reply.body.contains("agents="));
        assert!(completed_reply.body.contains("workspace="));
        assert!(completed_reply.body.contains("git="));
        assert!(completed_reply.body.contains("cargo="));
        assert!(completed_reply.body.contains("P0 remains required"));
        assert!(completed_reply
            .metadata
            .status
            .contains("backend: read-only workspace"));
        assert!(completed_reply.metadata.status.contains("model fallback"));
        assert!(completed_reply
            .metadata
            .tools
            .iter()
            .any(|tool| tool == "workspace.probe"));
        assert!(state
            .session
            .steps
            .iter()
            .any(|step| step.label.starts_with("Backend plan runtime-plan_")));
        assert!(state
            .session
            .steps
            .iter()
            .any(|step| step.label == "Plan: Understand project status"));
        assert!(state
            .session
            .steps
            .iter()
            .any(|step| step.detail.contains("runtime evidence: file.read via")));
        assert!(state
            .session
            .steps
            .iter()
            .any(|step| step.detail.contains("blocked authority")));
    }

    #[test]
    fn tui_read_only_backend_tracks_focus_and_metadata() {
        let workspace = WorkspaceFacts {
            cwd: "C:\\demo".to_owned(),
            short_path: "demo".to_owned(),
            config_path: ".moxi\\agents.toml".to_owned(),
            config_state: "present".to_owned(),
            trust_path: ".moxi\\trust.toml".to_owned(),
            trust_state: "present".to_owned(),
            git_state: "main clean".to_owned(),
            cargo_state: "workspace 2 crates".to_owned(),
            docs_state: "present".to_owned(),
            trust: "pending".to_owned(),
        };
        let agents = vec![TuiAgentProfile {
            name: "moxi-agent".to_owned(),
            role: "orchestrator".to_owned(),
            model: "backend-local".to_owned(),
            reasoning: "high".to_owned(),
        }];
        let skills = vec!["tui.design".to_owned(), "risk.review".to_owned()];
        let tools = vec!["repo.inspect".to_owned(), "git.status".to_owned()];

        let agents_response = ReadOnlyWorkspaceBackend.respond(TuiBackendRequest {
            turn: 2,
            task: "summarize active agents and skills",
            workspace: &workspace,
            trust: TuiTrustStatus::KnownReadOnly,
            agents: &agents,
            skills: &skills,
            tools: &tools,
            context_percent: 88,
        });
        assert_eq!(agents_response.agent, "moxi-agent");
        assert_eq!(agents_response.role, "orchestrator");
        assert_eq!(agents_response.metadata.model, "backend-local");
        assert_eq!(agents_response.metadata.reasoning, "high");
        assert!(agents_response
            .metadata
            .tools
            .iter()
            .any(|tool| tool == "git.status"));
        assert!(agents_response.body.contains("focus=agent configuration"));
        assert!(agents_response.body.contains("config=present"));
        assert!(agents_response.body.contains("trust=known-read-only"));
        assert!(agents_response.body.contains("context=88%"));
        assert!(agents_response.body.contains("agents=1"));
        assert!(agents_response.body.contains("skills=2"));
        assert!(agents_response.plan.plan_id.starts_with("runtime-plan_"));
        assert_eq!(agents_response.plan.source, "runtime-planner:Deterministic");
        assert_eq!(
            agents_response.plan.steps[0].label,
            "Understand agent configuration"
        );
        assert!(agents_response.plan.steps[1]
            .detail
            .contains("runtime evidence: file.read via"));
        assert!(agents_response
            .plan
            .blocked_authority
            .iter()
            .any(|authority| authority == "ledger.commit"));

        let verification = ReadOnlyWorkspaceBackend.respond(TuiBackendRequest {
            turn: 3,
            task: "check cargo tests",
            workspace: &workspace,
            trust: TuiTrustStatus::KnownReadOnly,
            agents: &agents,
            skills: &skills,
            tools: &tools,
            context_percent: 88,
        });
        assert!(verification.body.contains("focus=verification readiness"));
        assert_eq!(
            verification.plan.steps[0].label,
            "Understand verification readiness"
        );
        assert!(verification.body.contains("P0 remains required"));
    }

    #[test]
    fn tui_slash_commands_append_state_backed_messages() {
        let mut state = TuiState {
            command_input: "/status".to_owned(),
            ..TuiState::default()
        };
        submit_tui_command(&mut state);
        assert!(state
            .session
            .messages
            .iter()
            .any(|message| message.role == "status" && message.body.contains("git=")));

        state.command_input = "/tasks".to_owned();
        submit_tui_command(&mut state);
        assert!(state
            .session
            .messages
            .iter()
            .any(|message| message.role == "tasks" && message.body.contains("active step")));

        state.command_input = "/agents".to_owned();
        submit_tui_command(&mut state);
        assert!(state
            .session
            .messages
            .iter()
            .any(|message| message.role == "agents" && message.body.contains("ui-agent")));

        state.command_input = "/skills".to_owned();
        submit_tui_command(&mut state);
        assert!(state
            .session
            .messages
            .iter()
            .any(|message| message.role == "skills" && message.body.contains("tui.design")));

        state.command_input = "/context".to_owned();
        submit_tui_command(&mut state);
        assert!(state
            .session
            .messages
            .iter()
            .any(|message| message.role == "context"
                && message.body.contains("Context meter")
                && message.body.contains("messages=")));
        assert!(state.command_status.contains("context sources"));
    }

    #[test]
    fn tui_save_and_resume_commands_use_local_snapshot_summary() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceFacts::detect_at(temp.path());
        let mut state = TuiState {
            session: TuiAgentSession {
                model_config: TuiModelConfig::load_for_workspace(&workspace),
                workspace,
                ..TuiAgentSession::default()
            },
            command_input: "inspect project status".to_owned(),
            ..TuiState::default()
        };
        submit_tui_command(&mut state);
        apply_tui_key(&mut state, &TuiKey::Refresh);
        apply_tui_key(&mut state, &TuiKey::Refresh);
        apply_tui_key(&mut state, &TuiKey::Refresh);

        state.command_input = "/save".to_owned();
        submit_tui_command(&mut state);

        let path = temp
            .path()
            .join(".moxi")
            .join("session")
            .join("tui-session.json");
        assert!(path.is_file());
        assert!(state
            .command_status
            .contains("saved local TUI session snapshot"));

        let messages_before_resume = state.session.messages.len();
        state.command_input = "/resume".to_owned();
        submit_tui_command(&mut state);

        assert_eq!(state.active_pane, TuiPane::Overview);
        assert!(state
            .command_status
            .contains("loaded local TUI snapshot summary"));
        assert_eq!(state.session.messages.len(), messages_before_resume + 1);
        assert!(state
            .session
            .messages
            .iter()
            .any(|message| message.role == "resume"
                && message.body.contains("current session was not overwritten")));
    }

    #[test]
    fn tui_demo_flow_onboards_completes_task_saves_and_resumes() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceFacts::detect_at(temp.path());
        let mut state = TuiState {
            screen: TuiScreen::Boot,
            session: TuiAgentSession {
                model_config: TuiModelConfig::load_for_workspace(&workspace),
                workspace,
                ..TuiAgentSession::default()
            },
            ..TuiState::default()
        };

        for key in [
            TuiKey::SubmitCommand,
            TuiKey::SubmitCommand,
            TuiKey::SubmitCommand,
            TuiKey::SubmitCommand,
        ] {
            apply_tui_key(&mut state, &key);
        }
        assert_eq!(state.screen, TuiScreen::Workspace);
        assert_eq!(state.active_pane, TuiPane::Keys);

        state.command_input = "inspect project status".to_owned();
        submit_tui_command(&mut state);
        assert_eq!(state.session.turn_count, 2);
        assert!(state.session.is_streaming());

        advance_state_until_complete(&mut state);
        assert!(!state.session.is_streaming());
        assert!(state
            .session
            .messages
            .iter()
            .any(|message| message.body.contains("read-only backend analysis")));
        assert_eq!(
            state.session.steps[state.session.active_step_index].label,
            "Await P1/P0 adapter"
        );

        state.command_input = "/save".to_owned();
        submit_tui_command(&mut state);
        assert!(state.session.persistence_path().is_file());

        let messages_after_save = state.session.messages.len();
        state.command_input = "/resume".to_owned();
        submit_tui_command(&mut state);
        assert_eq!(state.session.messages.len(), messages_after_save + 1);
        assert!(state
            .command_status
            .contains("loaded local TUI snapshot summary"));

        apply_tui_key(&mut state, &TuiKey::Quit);
        assert!(state.should_quit);
    }

    #[test]
    fn tui_high_risk_approval_creates_local_plan_without_trusting_workspace() {
        let mut state = TuiState {
            command_input: "commit and push current branch".to_owned(),
            ..TuiState::default()
        };

        submit_tui_command(&mut state);
        assert!(state.pending_risk.is_some());
        assert_eq!(state.session.trust.status, TuiTrustStatus::NeedsReview);

        state.command_input = "/approve".to_owned();
        submit_tui_command(&mut state);

        assert!(state.pending_risk.is_none());
        assert_eq!(state.session.trust.status, TuiTrustStatus::NeedsReview);
        assert_eq!(state.screen, TuiScreen::Workspace);
        assert!(state.session.is_streaming());
        assert_eq!(state.session.turn_count, 2);
        assert!(state.command_status.contains("local planning only"));
        assert!(state
            .session
            .messages
            .iter()
            .any(|message| message.agent == "owner"
                && message.body == "commit and push current branch"));
    }

    #[test]
    fn tui_status_command_renders_session_state_message() {
        let mut output = Vec::new();

        let code = run(
            [
                "moxi-cli",
                "tui",
                "--width",
                "132",
                "--height",
                "38",
                "--keys",
                "type:/,type:s,type:t,type:a,type:t,type:u,type:s,enter,q",
            ],
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("[status]"));
        assert!(text.contains("git="));
        assert!(text.contains("cargo="));
    }

    #[test]
    fn tui_context_command_renders_context_meter_and_sources() {
        let mut output = Vec::new();

        let code = run(
            [
                "moxi-cli",
                "tui",
                "--width",
                "132",
                "--height",
                "38",
                "--keys",
                "type:/,type:c,type:o,type:n,type:t,type:e,type:x,type:t,enter,q",
            ],
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("[context]"));
        assert!(text.contains("Context meter"));
        assert!(text.contains("docs/status.md"));
        assert!(text.contains("/context"));
    }

    #[test]
    fn tui_task_tracking_can_pause_and_resume_active_step_follow() {
        let mut state = TuiState {
            command_input: "inspect project status".to_owned(),
            ..TuiState::default()
        };
        submit_tui_command(&mut state);
        assert_eq!(
            selected_session_step_index(&state),
            state.session.active_step_index
        );

        apply_tui_key(&mut state, &TuiKey::MoveTaskUp);
        assert!(!state.follow_active_step);
        assert_eq!(state.active_pane, TuiPane::Tasks);
        assert_eq!(
            selected_session_step_index(&state),
            state.session.active_step_index - 1
        );

        state.command_input = "/follow".to_owned();
        submit_tui_command(&mut state);
        assert!(state.follow_active_step);
        assert_eq!(
            selected_session_step_index(&state),
            state.session.active_step_index
        );
        assert_eq!(state.selected_task_index, state.session.active_step_index);
    }

    #[test]
    fn tui_input_task_renders_generated_conversation_turn() {
        let mut output = Vec::new();

        let code = run(
            [
                "moxi-cli",
                "tui",
                "--width",
                "132",
                "--height",
                "34",
                "--keys",
                "type:i,type:n,type:s,type:p,type:e,type:c,type:t,enter,q",
            ],
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("owner"));
        assert!(text.contains("inspect"));
        assert!(text.contains("Turn 2"));
        assert!(text.contains("streaming"));
        assert!(text.contains("follow:"));
        assert!(text.contains("selected:"));
        assert!(text.contains("detail:"));
        assert!(text.contains("Capture user task"));
        assert!(text.contains("Gather read-only context"));
    }

    #[test]
    fn tui_completed_backend_plan_renders_in_task_tracking() {
        let mut output = Vec::new();

        let code = run(
            [
                "moxi-cli",
                "tui",
                "--width",
                "132",
                "--height",
                "38",
                "--keys",
                "type:i,type:n,type:s,type:p,type:e,type:c,type:t,enter,r,r,r,r,r,r,r,r,r,q",
            ],
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("runtime-planner:Deterministic"));
        assert!(text.contains("Plan: Understand workspace"));
        assert!(text.contains("inspection"));
        assert!(text.contains("Plan: Read workspace context"));
        assert!(text.contains("selected: Await P1/P0"));
        assert!(text.contains("read-only backend response prepared"));
    }

    #[test]
    fn tui_streaming_reply_renders_loading_frame() {
        let mut output = Vec::new();

        let code = run(
            [
                "moxi-cli",
                "tui",
                "--width",
                "132",
                "--height",
                "34",
                "--keys",
                "type:i,type:n,type:s,type:p,type:e,type:c,type:t,enter,r,q",
            ],
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("streaming"));
        assert!(text.contains("stream tick 1"));
        assert!(text.contains("preparing model"));
        assert!(text.contains("context..."));
    }

    #[test]
    fn tui_risk_prompt_renders_near_input_box() {
        let mut output = Vec::new();

        let code = run(
            [
                "moxi-cli",
                "tui",
                "--width",
                "132",
                "--height",
                "34",
                "--keys",
                "type:c,type:o,type:m,type:m,type:i,type:t,enter,q",
            ],
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("risk"));
        assert!(text.contains("high"));
        assert!(text.contains("/approve"));
        assert!(text.contains("/deny"));
        assert!(text.contains("local planning intent"));
    }

    #[test]
    fn tui_conversation_scroll_tracks_multi_turn_messages() {
        let mut state = TuiState::default();

        for task in [
            "inspect project status",
            "summarize active agents",
            "prepare next safe plan",
        ] {
            state.command_input = task.to_owned();
            submit_tui_command(&mut state);
        }

        assert_eq!(state.session.turn_count, 4);
        assert_eq!(state.session.messages.len(), 8);
        assert!(state.follow_latest_message);
        assert_eq!(state.conversation_scroll, 0);

        apply_tui_key(&mut state, &TuiKey::MoveConversationDown);
        assert_eq!(state.active_pane, TuiPane::Overview);
        assert!(!state.follow_latest_message);
        assert_eq!(state.conversation_scroll, 1);

        state.command_input = "resume latest turn".to_owned();
        submit_tui_command(&mut state);

        assert_eq!(state.session.turn_count, 5);
        assert!(state.follow_latest_message);
        assert_eq!(state.conversation_scroll, 0);
    }

    #[test]
    fn tui_conversation_scroll_renders_hidden_line_markers() {
        let mut output = Vec::new();

        let code = run(
            [
                "moxi-cli",
                "tui",
                "--width",
                "132",
                "--height",
                "36",
                "--keys",
                "type:a,enter,type:b,enter,type:c,enter,type:d,enter,chat_up,q",
            ],
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("Conversation"));
        assert!(text.contains("chat manual"));
        assert!(text.contains("newer lines hidden"));
    }

    #[test]
    fn tui_enter_advances_startup_flow_before_submitting_workspace_input() {
        let mut state = TuiState {
            screen: TuiScreen::Boot,
            command_status: "startup: Enter continues · q exits".into(),
            ..TuiState::default()
        };

        apply_tui_key(&mut state, &TuiKey::SubmitCommand);
        assert_eq!(state.screen, TuiScreen::Trust);
        assert_eq!(
            state.command_status,
            "trust gate: Enter read-only · /approve accept · /deny block"
        );

        apply_tui_key(&mut state, &TuiKey::SubmitCommand);
        assert_eq!(state.screen, TuiScreen::Setup);
        assert_eq!(
            state.command_status,
            "first-run setup: model/API config is missing"
        );

        apply_tui_key(&mut state, &TuiKey::SubmitCommand);
        assert_eq!(state.screen, TuiScreen::Core);
        assert_eq!(
            state.command_status,
            "setup guide acknowledged; Agent Core ready"
        );

        apply_tui_key(&mut state, &TuiKey::SubmitCommand);
        assert_eq!(state.screen, TuiScreen::Workspace);
        assert_eq!(state.active_pane, TuiPane::Keys);
        assert_eq!(
            state.command_status,
            "ready: type a task or open / command menu"
        );

        let mut output = Vec::new();

        let code = run(
            [
                "moxi-cli",
                "tui",
                "--width",
                "120",
                "--height",
                "30",
                "--keys",
                "boot,enter,enter,enter,enter,q",
            ],
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("moxi-agent"));
        assert!(text.contains("Conversation"));
        assert!(text.contains("Task Tracking"));
        assert!(text.contains("Input Task"));
        assert!(text.contains("quit=true"));
    }

    #[test]
    fn tui_configured_startup_skips_first_run_setup() {
        let mut state = TuiState {
            screen: TuiScreen::Boot,
            ..TuiState::default()
        };
        state.session.trust.status = TuiTrustStatus::KnownReadOnly;
        state.session.model_config = TuiModelConfig {
            provider: TuiModelProvider::OpenAi,
            endpoint: "https://api.openai.com/v1".to_owned(),
            model: "gpt-demo".to_owned(),
            api_key_source: TuiApiKeySource::Env {
                name: "OPENAI_API_KEY".to_owned(),
                redacted: "sk-d...demo".to_owned(),
            },
            config_path: ".moxi\\config.toml".to_owned(),
            config_state: "present".to_owned(),
        };

        apply_tui_key(&mut state, &TuiKey::SubmitCommand);

        assert_eq!(state.screen, TuiScreen::Core);
        assert_eq!(
            state.command_status,
            "trusted read-only workspace; Agent Core ready"
        );
    }

    #[test]
    fn tui_startup_pages_are_addressable_without_auto_flash() {
        let mut output = Vec::new();

        let code = run(
            [
                "moxi-cli", "tui", "--width", "112", "--height", "30", "--keys", "boot,q",
            ],
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("MOXI // AGENT"));
        assert!(text.contains("SILVER CORE ONLINE"));
        assert!(text.contains("Initialization waterfall"));
        assert!(text.contains("Waiting for owner handoff"));
        assert!(text.contains("continue startup flow"));
    }

    #[test]
    fn tui_setup_page_guides_model_api_configuration() {
        let mut output = Vec::new();

        let code = run(
            [
                "moxi-cli", "tui", "--width", "120", "--height", "32", "--keys", "setup,q",
            ],
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("First-run Setup"));
        assert!(text.contains("MOXI CLI Alpha setup"));
        assert!(text.contains(".moxi/config.toml"));
        assert!(text.contains("api_key_env"));
        assert!(text.contains("OPENAI_API_KEY"));
        assert!(text.contains("Environment alternative"));
        assert!(text.contains("Setup checks"));
        assert!(text.contains("/init"));
        assert!(text.contains("/doctor"));
        assert!(text.contains("/models"));
        assert!(text.contains("No setup check has run"));
        assert!(!text.contains("sk-visible-never"));
    }

    #[test]
    fn tui_setup_init_writes_env_only_config_without_secret() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceFacts::detect_at(temp.path());
        let config_path = temp.path().join(".moxi").join("config.toml");
        let mut state = TuiState {
            screen: TuiScreen::Setup,
            session: TuiAgentSession {
                model_config: TuiModelConfig::load_for_workspace(&workspace),
                workspace,
                ..TuiAgentSession::default()
            },
            command_input: "/init".to_owned(),
            ..TuiState::default()
        };

        submit_tui_command(&mut state);

        assert_eq!(state.screen, TuiScreen::Setup);
        assert!(state.command_status.contains("wrote env-only config"));
        assert!(config_path.is_file());
        let written = fs::read_to_string(&config_path).unwrap();
        assert!(written.contains("provider = \"openai\""));
        assert!(written.contains("model = \"gpt-4o-mini\""));
        assert!(written.contains("api_key_env = \"OPENAI_API_KEY\""));
        assert!(!written.contains("api_key ="));
        assert!(state
            .setup_notice
            .as_deref()
            .unwrap()
            .contains("set the environment variable"));
        assert_eq!(
            state.session.model_config.config_state,
            "present-incomplete"
        );
    }

    #[test]
    fn tui_setup_init_refuses_to_overwrite_existing_config() {
        let temp = tempfile::tempdir().unwrap();
        let moxi_dir = temp.path().join(".moxi");
        fs::create_dir_all(&moxi_dir).unwrap();
        let config_path = moxi_dir.join("config.toml");
        fs::write(
            &config_path,
            "provider = \"openai\"\nmodel = \"already-set\"\napi_key_env = \"EXISTING_KEY\"\n",
        )
        .unwrap();
        let workspace = WorkspaceFacts::detect_at(temp.path());
        let mut state = TuiState {
            screen: TuiScreen::Setup,
            session: TuiAgentSession {
                model_config: TuiModelConfig::load_for_workspace(&workspace),
                workspace,
                ..TuiAgentSession::default()
            },
            command_input: "/init".to_owned(),
            ..TuiState::default()
        };

        submit_tui_command(&mut state);

        assert_eq!(state.screen, TuiScreen::Setup);
        assert!(state.command_status.contains("not overwritten"));
        assert!(state
            .setup_notice
            .as_deref()
            .unwrap()
            .contains("config already exists"));
        let written = fs::read_to_string(&config_path).unwrap();
        assert!(written.contains("already-set"));
        assert!(written.contains("EXISTING_KEY"));
        assert!(!written.contains("gpt-4o-mini"));
    }

    #[test]
    fn tui_setup_page_runs_config_check_without_leaving_setup() {
        let temp = tempfile::tempdir().unwrap();
        let moxi_dir = temp.path().join(".moxi");
        fs::create_dir_all(&moxi_dir).unwrap();
        let raw_secret = "sk-visible-never-setup-2222";
        fs::write(
            moxi_dir.join("config.toml"),
            format!("provider = \"openai\"\nmodel = \"gpt-demo\"\napi_key = \"{raw_secret}\"\n"),
        )
        .unwrap();
        let workspace = WorkspaceFacts::detect_at(temp.path());
        let mut state = TuiState {
            screen: TuiScreen::Setup,
            session: TuiAgentSession {
                model_config: TuiModelConfig::load_for_workspace(&workspace),
                workspace,
                ..TuiAgentSession::default()
            },
            command_input: "/config".to_owned(),
            ..TuiState::default()
        };

        submit_tui_command(&mut state);

        assert_eq!(state.screen, TuiScreen::Setup);
        assert!(state.command_status.contains("setup config check complete"));
        let notice = state.setup_notice.as_deref().unwrap();
        assert!(notice.contains("provider=openai"));
        assert!(notice.contains("key=config:sk-v...2222"));
        assert!(!notice.contains(raw_secret));
        assert!(!state
            .session
            .messages
            .iter()
            .any(|message| message.role == "config"));
    }

    #[test]
    fn tui_setup_page_runs_doctor_and_models_checks_in_place() {
        let mut state = TuiState {
            screen: TuiScreen::Setup,
            command_input: "/doctor".to_owned(),
            ..TuiState::default()
        };

        submit_tui_command(&mut state);

        assert_eq!(state.screen, TuiScreen::Setup);
        assert!(state
            .command_status
            .contains("doctor completed: needs-setup"));
        assert!(state
            .setup_notice
            .as_deref()
            .unwrap()
            .contains("doctor: status=needs-setup"));

        state.command_input = "/models".to_owned();
        submit_tui_command(&mut state);

        assert_eq!(state.screen, TuiScreen::Setup);
        assert!(state
            .command_status
            .contains("models completed: needs-setup"));
        assert!(state
            .setup_notice
            .as_deref()
            .unwrap()
            .contains("models: status=needs-setup"));
    }

    #[test]
    fn tui_core_page_renders_visual_identity_and_runtime_facts() {
        let mut output = Vec::new();

        let code = run(
            [
                "moxi-cli", "tui", "--width", "132", "--height", "34", "--keys", "core,q",
            ],
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("AGENT CORE"));
        assert!(text.contains("[ P0 ] protected"));
        assert!(text.contains("[ P2 ] rich-cli"));
        assert!(text.contains("Agent Runtime"));
        assert!(text.contains("session file:"));
        assert!(text.contains("tui-session.json"));
        assert!(text.contains("Loaded Agents"));
    }

    #[test]
    fn bare_moxi_opens_tui_demo_dashboard() {
        let mut output = Vec::new();

        let code = run(["moxi"], &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("moxi-agent"));
        assert!(text.contains("graph=demo_graph"));
        assert!(text.contains("local-r10-demo-session"));
        assert!(text.contains("guarded read-only session"));
        assert!(text.contains("cargo"));
        assert!(text.contains("workspace"));
        assert!(text.contains("guarded"));
    }

    #[test]
    fn bare_moxi_with_tui_options_opens_tui_demo_dashboard() {
        let mut output = Vec::new();

        let code = run(
            ["moxi", "--width", "112", "--height", "30", "--keys", "q"],
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("moxi-agent"));
        assert!(text.contains("graph=demo_graph"));
        assert!(text.contains("active=Overview selected_task=0 filter=<none>"));
        assert!(text.contains("quit=true"));
    }

    #[test]
    fn bare_args_open_tui_demo_dashboard() {
        let mut output = Vec::new();

        let code = run(std::iter::empty::<&str>(), &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("moxi-agent"));
        assert!(text.contains("graph=demo_graph"));
    }

    #[test]
    fn watch_still_requires_snapshot_input_path() {
        let mut output = Vec::new();

        let error = run(["moxi-cli", "watch", "--query"], &mut output).unwrap_err();

        assert!(matches!(error, CliError::MissingRequired("--input")));
        assert!(output.is_empty());
    }

    #[test]
    fn help_documents_default_tui_entrypoint() {
        let mut output = Vec::new();

        let code = run(["moxi", "help"], &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("Default:"));
        assert!(text.contains("moxi"));
        assert!(text.contains("Opens the resident branded read-only TUI workbench."));
        assert!(text.contains("Startup pages wait for owner input"));
        assert!(text.contains("Enter advances Boot -> Trust -> First-run Setup"));
        assert!(text.contains("tui [--feed|--query] [--input <snapshot.json>]"));
    }

    #[test]
    fn tui_rejects_too_small_dimensions() {
        let mut output = Vec::new();

        let error = run(
            [
                "moxi-cli",
                "tui",
                "--input",
                "snapshot.json",
                "--width",
                "10",
            ],
            &mut output,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            CliError::InvalidTuiDimension {
                flag: "--width",
                value
            } if value == "10"
        ));
        assert!(output.is_empty());
    }

    #[test]
    fn tui_keys_can_switch_panes_filter_refresh_and_quit() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("query-snapshot.json");
        std::fs::write(&path, multi_task_query_snapshot_json()).unwrap();
        let mut output = Vec::new();

        let code = run(
            [
                "moxi-cli",
                "tui",
                "--query",
                "--surface",
                "ide",
                "--graph",
                "graph_many",
                "--input",
                path.to_str().unwrap(),
                "--width",
                "132",
                "--height",
                "38",
                "--keys",
                "tab,tab,/task_2,r,q,tab",
            ],
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("pane=Tasks"));
        assert!(text.contains("refresh=1"));
        assert!(text.contains("filter=task_2"));
        assert!(text.contains("active=Tasks selected_task=1 filter=task_2"));
        assert!(text.contains("quit=true"));
        assert!(text.contains("task_2"));
        assert!(text.contains("file.read"));
        assert!(text.contains("DependencyIncomplete"));
    }

    #[test]
    fn tui_keys_can_focus_read_only_panes() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("query-snapshot.json");
        std::fs::write(&path, query_snapshot_json()).unwrap();
        let mut output = Vec::new();

        let code = run(
            [
                "moxi-cli",
                "tui",
                "--query",
                "--surface",
                "ide",
                "--graph",
                "graph_detail",
                "--input",
                path.to_str().unwrap(),
                "--width",
                "112",
                "--height",
                "30",
                "--keys",
                "graph,tasks,boundary,?,q",
            ],
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("Command Palette"));
        assert!(text.contains("/status"));
        assert!(text.contains("Up/Down select"));
        assert!(text.contains("Ask moxi-agent"));
    }

    #[test]
    fn tui_command_palette_filters_and_runs_selected_command() {
        let mut state = TuiState {
            command_input: "/con".to_owned(),
            show_command_palette: true,
            ..TuiState::default()
        };

        let entries = filtered_command_palette_entries(&state.command_input);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].command, "/context");
        assert_eq!(entries[1].command, "/config");

        apply_tui_key(&mut state, &TuiKey::SubmitCommand);

        assert!(!state.show_command_palette);
        assert_eq!(state.command_input, "");
        assert_eq!(state.active_pane, TuiPane::Overview);
        assert_eq!(state.screen, TuiScreen::Workspace);
        assert!(state.command_status.contains("context sources"));
        assert!(state
            .session
            .messages
            .iter()
            .any(|message| message.role == "context"));
    }

    #[test]
    fn tui_command_palette_selection_moves_without_task_selection() {
        let mut state = TuiState {
            show_command_palette: true,
            ..TuiState::default()
        };
        let selected_task = state.selected_task_index;

        apply_tui_key(&mut state, &TuiKey::MoveTaskDown);
        apply_tui_key(&mut state, &TuiKey::MoveTaskDown);

        assert_eq!(state.selected_task_index, selected_task);
        assert_eq!(state.command_palette_index, 2);
        assert!(state.command_status.contains("/agents"));

        apply_tui_key(&mut state, &TuiKey::SubmitCommand);

        assert_eq!(state.screen, TuiScreen::Core);
        assert!(state
            .session
            .messages
            .iter()
            .any(|message| message.role == "agents"));
    }

    #[test]
    fn tui_command_palette_scrolls_to_selected_entry() {
        let window = command_palette_visible_window(COMMAND_PALETTE_ENTRIES.len(), 10, 5);
        assert!(window.start > 0);
        assert!(window.end < COMMAND_PALETTE_ENTRIES.len());
        assert!((window.start..window.end).contains(&10));

        let mut output = Vec::new();
        let code = run(
            [
                "moxi-cli",
                "tui",
                "--width",
                "132",
                "--height",
                "34",
                "--keys",
                "menu,down,down,down,down,down,down,down,down,down,down",
            ],
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("earlier commands"));
        assert!(text.contains(COMMAND_PALETTE_ENTRIES[10].command));
        assert!(text.contains("more commands"));
        assert!(!text.contains("/status  current session"));
    }

    #[test]
    fn tui_keys_can_focus_graph_summary_without_execution() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("query-snapshot.json");
        std::fs::write(&path, query_snapshot_json()).unwrap();
        let mut output = Vec::new();

        let code = run(
            [
                "moxi-cli",
                "tui",
                "--query",
                "--surface",
                "ide",
                "--graph",
                "graph_detail",
                "--input",
                path.to_str().unwrap(),
                "--width",
                "112",
                "--height",
                "30",
                "--keys",
                "g,q",
            ],
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("pane=Graph"));
        assert!(text.contains("active=Graph selected_task=0 filter=<none>"));
        assert!(text.contains("quit=true"));
        assert!(text.contains("graph=graph_detail"));
        assert!(text.contains("local-r10-demo-session"));
        assert!(text.contains("guarded read-only session"));
    }

    #[test]
    fn tui_keys_can_move_task_selection_without_execution() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("query-snapshot.json");
        std::fs::write(&path, multi_task_query_snapshot_json()).unwrap();
        let mut output = Vec::new();

        let code = run(
            [
                "moxi-cli",
                "tui",
                "--query",
                "--surface",
                "ide",
                "--graph",
                "graph_many",
                "--input",
                path.to_str().unwrap(),
                "--width",
                "120",
                "--height",
                "30",
                "--keys",
                "j,j,k,q",
            ],
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("pane=Tasks"));
        assert!(text.contains("active=Tasks selected_task=1"));
        assert!(text.contains("Collect workspace facts"));
        assert!(text.contains("cwd/config/mode"));
        assert!(text.contains("Task Tracking"));
    }

    #[test]
    fn tui_rejects_invalid_key_tokens() {
        let mut output = Vec::new();

        let error = run(
            [
                "moxi-cli",
                "tui",
                "--input",
                "snapshot.json",
                "--keys",
                "execute",
            ],
            &mut output,
        )
        .unwrap_err();

        assert!(matches!(error, CliError::InvalidTuiKey(value) if value == "execute"));
        assert!(output.is_empty());
    }

    #[test]
    fn tui_accepts_poll_option_in_snapshot_key_replay() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("query-snapshot.json");
        std::fs::write(&path, query_snapshot_json()).unwrap();
        let mut output = Vec::new();

        let code = run(
            [
                "moxi-cli",
                "tui",
                "--query",
                "--surface",
                "ide",
                "--graph",
                "graph_detail",
                "--input",
                path.to_str().unwrap(),
                "--width",
                "100",
                "--height",
                "28",
                "--poll-ms",
                "10",
                "--keys",
                "q",
            ],
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("quit=true"));
        assert!(text.contains("moxi-agent"));
    }

    #[test]
    fn tui_rejects_zero_poll_interval() {
        let mut output = Vec::new();

        let error = run(
            [
                "moxi-cli",
                "tui",
                "--input",
                "snapshot.json",
                "--poll-ms",
                "0",
            ],
            &mut output,
        )
        .unwrap_err();

        assert!(matches!(error, CliError::InvalidTuiPoll(value) if value == "0"));
        assert!(output.is_empty());
    }

    #[test]
    fn tui_key_events_map_only_read_only_actions() {
        assert_eq!(
            tui_key_from_event(KeyEvent::from(KeyCode::Tab)),
            Some(TuiKey::Tab)
        );
        assert_eq!(
            tui_key_from_event(KeyEvent::from(KeyCode::Down)),
            Some(TuiKey::MoveTaskDown)
        );
        assert_eq!(
            tui_key_from_event(KeyEvent::from(KeyCode::Up)),
            Some(TuiKey::MoveTaskUp)
        );
        assert_eq!(
            tui_key_from_event(KeyEvent::from(KeyCode::Char('o'))),
            Some(TuiKey::Focus(TuiPane::Overview))
        );
        assert_eq!(
            tui_key_from_event(KeyEvent::from(KeyCode::Char('G'))),
            Some(TuiKey::Focus(TuiPane::Graph))
        );
        assert_eq!(
            tui_key_from_event(KeyEvent::from(KeyCode::Char('T'))),
            Some(TuiKey::Focus(TuiPane::Tasks))
        );
        assert_eq!(
            tui_key_from_event(KeyEvent::from(KeyCode::Char('a'))),
            Some(TuiKey::Focus(TuiPane::Approvals))
        );
        assert_eq!(
            tui_key_from_event(KeyEvent::from(KeyCode::Char('B'))),
            Some(TuiKey::Focus(TuiPane::Boundary))
        );
        assert_eq!(
            tui_key_from_event(KeyEvent::from(KeyCode::Char('?'))),
            Some(TuiKey::Focus(TuiPane::Keys))
        );
        assert_eq!(
            tui_key_from_event(KeyEvent::from(KeyCode::Char('j'))),
            Some(TuiKey::MoveTaskDown)
        );
        assert_eq!(
            tui_key_from_event(KeyEvent::from(KeyCode::Char('K'))),
            Some(TuiKey::MoveTaskUp)
        );
        assert_eq!(
            tui_key_from_event(KeyEvent::from(KeyCode::Char('r'))),
            Some(TuiKey::Refresh)
        );
        assert_eq!(
            tui_key_from_event(KeyEvent::from(KeyCode::Char('q'))),
            Some(TuiKey::Quit)
        );
        assert_eq!(
            tui_key_from_event(KeyEvent::from(KeyCode::Enter)),
            Some(TuiKey::SubmitCommand)
        );
        assert_eq!(
            tui_key_from_event(KeyEvent::from(KeyCode::Char('x'))),
            Some(TuiKey::InputChar('x'))
        );
    }

    #[test]
    fn repl_admits_quoted_goal_and_exits() {
        let input = b"admit --workspace /workspace --goal \"read status\"\nexit\n";
        let mut output = Vec::new();

        let code = run_with_io(["moxi-cli", "repl"], &input[..], &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("moxi-cli repl"));
        assert!(text.contains("\"goal\":\"read status\""));
        assert!(text.contains("\"cannot_execute_directly\":true"));
        assert!(text.contains("bye"));
    }

    #[test]
    fn repl_tolerates_utf8_bom_on_first_piped_line() {
        let input = b"\xEF\xBB\xBFadmit --workspace /workspace --goal \"read status\"\nexit\n";
        let mut output = Vec::new();

        let code = run_with_io(["moxi-cli", "repl"], &input[..], &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("\"goal\":\"read status\""));
        assert!(!text.contains("unknown command"));
        assert!(text.contains("bye"));
    }

    #[test]
    fn repl_reports_unknown_command_without_stopping() {
        let input = b"execute\nmanifest --surface cli\nboundary --text\nquit\n";
        let mut output = Vec::new();

        let code = run_with_io(["moxi-cli", "repl"], &input[..], &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("error: unknown command: execute"));
        assert!(text.contains("\"shell_id\":\"shell.cli\""));
        assert!(text.contains("MOXI shell boundary"));
        assert!(text.contains("cannot_execute_directly: true"));
        assert!(text.contains("bye"));
    }

    #[test]
    fn repl_rejects_unterminated_quotes() {
        let input = b"admit --goal \"read status\nquit\n";
        let mut output = Vec::new();

        run_with_io(["moxi-cli", "repl"], &input[..], &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();

        assert!(text.contains("error: unterminated quoted string"));
    }

    #[test]
    fn repl_projects_status_without_exiting() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("event-feed.json");
        std::fs::write(&path, event_feed_json()).unwrap();
        let input = format!(
            "status --graph graph_1 --input \"{}\"\nexit\n",
            path.display()
        );
        let mut output = Vec::new();

        let code = run_with_io(["moxi-cli", "repl"], input.as_bytes(), &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("\"graph_id\":\"graph_1\""));
        assert!(text.contains("\"latest_message\":\"planning graph\""));
        assert!(text.contains("bye"));
    }

    #[test]
    fn repl_projects_query_status_without_exiting() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("query-snapshot.json");
        std::fs::write(&path, query_snapshot_json()).unwrap();
        let input = format!(
            "status --query --surface ide --graph graph_detail --input \"{}\"\nexit\n",
            path.display()
        );
        let mut output = Vec::new();

        let code = run_with_io(["moxi-cli", "repl"], input.as_bytes(), &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();

        assert_eq!(code, 0);
        assert!(text.contains("\"graph_id\":\"graph_detail\""));
        assert!(text.contains("\"tasks\":["));
        assert!(text.contains("bye"));
    }
}
