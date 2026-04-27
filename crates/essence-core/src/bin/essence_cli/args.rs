use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use essence_core::{ApprovalDecision, LifecycleStatus, PermissionMode, SessionMode};

#[derive(Debug, Parser)]
#[command(
    name = "essence",
    version,
    about = "Minimal v0 CLI for the Essence Agent control plane."
)]
pub(crate) struct Cli {
    #[arg(long, global = true, default_value = ".essence")]
    pub(crate) root: PathBuf,
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    Setup(SetupArgs),
    Chat(ChatArgs),
    Session(SessionArgs),
    Message(MessageArgs),
    Events(EventsArgs),
    Approval(ApprovalArgs),
    Agent(AgentArgs),
    Task(TaskArgs),
    Workspace(WorkspaceArgs),
}

#[derive(Debug, Args)]
pub(crate) struct SetupArgs {
    #[arg(long, value_enum, default_value_t = CliModelProvider::OpenaiCompatible)]
    pub(crate) model_provider: CliModelProvider,
    #[arg(long)]
    pub(crate) model: Option<String>,
    #[arg(long)]
    pub(crate) model_base_url: Option<String>,
    #[arg(long, default_value = "OPENAI_API_KEY")]
    pub(crate) model_api_key_env: Option<String>,
    #[arg(long)]
    pub(crate) model_command: Option<String>,
    #[arg(long, alias = "agent", value_name = "ID")]
    pub(crate) main_agent: Option<String>,
    #[arg(long)]
    pub(crate) main_agent_lane: Option<String>,
    #[arg(long)]
    pub(crate) main_agent_role: Option<String>,
    #[arg(long)]
    pub(crate) main_agent_prompt: Option<String>,
    #[arg(long)]
    pub(crate) main_agent_prompt_file: Option<PathBuf>,
    #[arg(long)]
    pub(crate) main_agent_template: Option<String>,
    #[arg(long)]
    pub(crate) save: bool,
    #[arg(long)]
    pub(crate) no_color: bool,
}

#[derive(Debug, Args)]
pub(crate) struct ChatArgs {
    #[arg(long = "agent", alias = "agent-profile")]
    pub(crate) agent_profile: Option<String>,
    #[arg(long)]
    pub(crate) system_prompt: Option<String>,
    #[arg(long)]
    pub(crate) system_prompt_file: Option<PathBuf>,
    #[arg(long)]
    pub(crate) session_id: Option<String>,
    #[arg(long)]
    pub(crate) cwd: Option<PathBuf>,
    #[arg(long)]
    pub(crate) title: Option<String>,
    #[arg(long)]
    pub(crate) model: Option<String>,
    #[arg(long, value_enum)]
    pub(crate) model_provider: Option<CliModelProvider>,
    #[arg(long)]
    pub(crate) model_base_url: Option<String>,
    #[arg(long)]
    pub(crate) model_api_key_env: Option<String>,
    #[arg(long)]
    pub(crate) model_command: Option<String>,
    #[arg(long, default_value_t = 30_000)]
    pub(crate) model_timeout_ms: u64,
    #[arg(long, default_value_t = 1_048_576)]
    pub(crate) model_max_response_bytes: usize,
    #[arg(long, default_value_t = 1_048_576)]
    pub(crate) model_max_stdout_bytes: usize,
    #[arg(long, default_value_t = 65_536)]
    pub(crate) model_max_stderr_bytes: usize,
    #[arg(long, default_value = "main")]
    pub(crate) agent_id: String,
    #[arg(long, default_value = "main")]
    pub(crate) lane: String,
    #[arg(long, default_value = "CLI Assistant")]
    pub(crate) role: String,
    #[arg(long)]
    pub(crate) no_agent: bool,
    #[arg(long)]
    pub(crate) no_assistant: bool,
    #[arg(long)]
    pub(crate) no_color: bool,
}

#[derive(Debug, Args)]
pub(crate) struct SessionArgs {
    #[command(subcommand)]
    pub(crate) command: SessionCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum SessionCommand {
    Create(SessionCreateArgs),
}

#[derive(Debug, Args)]
pub(crate) struct SessionCreateArgs {
    #[arg(long)]
    pub(crate) cwd: Option<PathBuf>,
    #[arg(long)]
    pub(crate) title: Option<String>,
    #[arg(long)]
    pub(crate) model: Option<String>,
    #[arg(long, value_enum, default_value_t = CliSessionMode::Interactive)]
    pub(crate) mode: CliSessionMode,
    #[arg(long, value_enum, default_value_t = CliPermissionMode::Default)]
    pub(crate) permission_mode: CliPermissionMode,
}

#[derive(Debug, Args)]
pub(crate) struct MessageArgs {
    #[command(subcommand)]
    pub(crate) command: MessageCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum MessageCommand {
    Send(MessageSendArgs),
}

#[derive(Debug, Args)]
pub(crate) struct MessageSendArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long)]
    pub(crate) text: String,
}

#[derive(Debug, Args)]
pub(crate) struct EventsArgs {
    #[command(subcommand)]
    pub(crate) command: EventsCommand,
}

#[derive(Debug, Args)]
pub(crate) struct ApprovalArgs {
    #[command(subcommand)]
    pub(crate) command: ApprovalCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ApprovalCommand {
    Pending(ApprovalPendingArgs),
    Resolve(ApprovalResolveArgs),
}

#[derive(Debug, Args)]
pub(crate) struct ApprovalPendingArgs {
    #[arg(long)]
    pub(crate) session_id: String,
}

#[derive(Debug, Args)]
pub(crate) struct ApprovalResolveArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long)]
    pub(crate) approval_id: String,
    #[arg(long, value_enum)]
    pub(crate) decision: CliApprovalDecision,
    #[arg(long, default_value = "cli")]
    pub(crate) resolved_by: String,
}

#[derive(Debug, Args)]
pub(crate) struct AgentArgs {
    #[command(subcommand)]
    pub(crate) command: AgentCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum AgentCommand {
    Register(AgentRegisterArgs),
    Heartbeat(AgentHeartbeatArgs),
    Define(AgentDefineArgs),
    Profiles(AgentProfilesArgs),
    Templates(AgentTemplatesArgs),
}

#[derive(Debug, Args)]
pub(crate) struct AgentRegisterArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long)]
    pub(crate) agent_id: String,
    #[arg(long)]
    pub(crate) lane: String,
    #[arg(long)]
    pub(crate) role: String,
    #[arg(long = "toolset")]
    pub(crate) toolsets: Vec<String>,
}

#[derive(Debug, Args)]
pub(crate) struct AgentHeartbeatArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long)]
    pub(crate) agent_id: String,
    #[arg(long, value_enum)]
    pub(crate) status: CliLifecycleStatus,
    #[arg(long)]
    pub(crate) lane: Option<String>,
    #[arg(long)]
    pub(crate) run_id: Option<String>,
    #[arg(long)]
    pub(crate) task_id: Option<String>,
    #[arg(long)]
    pub(crate) note: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct AgentDefineArgs {
    #[arg(long)]
    pub(crate) agent_id: String,
    #[arg(long)]
    pub(crate) template: Option<String>,
    #[arg(long, default_value = "main")]
    pub(crate) lane: String,
    #[arg(long, default_value = "Custom Agent")]
    pub(crate) role: String,
    #[arg(long)]
    pub(crate) system_prompt: Option<String>,
    #[arg(long)]
    pub(crate) system_prompt_file: Option<PathBuf>,
    #[arg(long, value_enum)]
    pub(crate) model_provider: Option<CliModelProvider>,
    #[arg(long)]
    pub(crate) model: Option<String>,
    #[arg(long)]
    pub(crate) model_base_url: Option<String>,
    #[arg(long)]
    pub(crate) model_api_key_env: Option<String>,
    #[arg(long)]
    pub(crate) model_command: Option<String>,
    #[arg(long)]
    pub(crate) save: bool,
    #[arg(long)]
    pub(crate) no_color: bool,
}

#[derive(Debug, Args)]
pub(crate) struct AgentProfilesArgs {
    #[arg(long)]
    pub(crate) no_color: bool,
}

#[derive(Debug, Args)]
pub(crate) struct AgentTemplatesArgs {
    #[arg(long)]
    pub(crate) query: Option<String>,
    #[arg(long)]
    pub(crate) category: Option<String>,
    #[arg(long, default_value_t = 40)]
    pub(crate) limit: usize,
    #[arg(long)]
    pub(crate) no_color: bool,
}

#[derive(Debug, Args)]
pub(crate) struct TaskArgs {
    #[command(subcommand)]
    pub(crate) command: TaskCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum TaskCommand {
    Create(TaskCreateArgs),
}

#[derive(Debug, Args)]
pub(crate) struct TaskCreateArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long)]
    pub(crate) title: String,
    #[arg(long, value_enum, default_value_t = CliLifecycleStatus::Queued)]
    pub(crate) status: CliLifecycleStatus,
    #[arg(long)]
    pub(crate) lane: Option<String>,
    #[arg(long)]
    pub(crate) assignee: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct WorkspaceArgs {
    #[command(subcommand)]
    pub(crate) command: WorkspaceCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum WorkspaceCommand {
    Dashboard(WorkspaceDashboardArgs),
    Watch(WorkspaceWatchArgs),
}

#[derive(Debug, Args)]
pub(crate) struct WorkspaceDashboardArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long)]
    pub(crate) no_color: bool,
}

#[derive(Debug, Args)]
pub(crate) struct WorkspaceWatchArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long)]
    pub(crate) no_color: bool,
    #[arg(long)]
    pub(crate) no_clear: bool,
    #[arg(long, default_value_t = 1000)]
    pub(crate) interval_ms: u64,
    #[arg(long)]
    pub(crate) ticks: Option<u64>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum EventsCommand {
    Tail(EventsTailArgs),
    Verify(EventsVerifyArgs),
    AnchorWrite(EventsAnchorWriteArgs),
    AnchorVerify(EventsAnchorVerifyArgs),
}

#[derive(Debug, Args)]
pub(crate) struct EventsTailArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long, default_value_t = 0)]
    pub(crate) after: u64,
    #[arg(long)]
    pub(crate) user_visible: bool,
    #[arg(long)]
    pub(crate) follow: bool,
    #[arg(long, default_value_t = 500)]
    pub(crate) interval_ms: u64,
}

#[derive(Debug, Args)]
pub(crate) struct EventsVerifyArgs {
    #[arg(long)]
    pub(crate) session_id: String,
}

#[derive(Debug, Args)]
pub(crate) struct EventsAnchorWriteArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long)]
    pub(crate) key_id: String,
    #[arg(long, default_value = "ESSENCE_ANCHOR_KEY")]
    pub(crate) key_env: String,
}

#[derive(Debug, Args)]
pub(crate) struct EventsAnchorVerifyArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long, default_value = "ESSENCE_ANCHOR_KEY")]
    pub(crate) key_env: String,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum CliSessionMode {
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
pub(crate) enum CliPermissionMode {
    Default,
    Plan,
    Auto,
    Bypass,
    Readonly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum CliModelProvider {
    Local,
    Command,
    OpenaiCompatible,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum CliApprovalDecision {
    ApproveOnce,
    ApproveSession,
    ApproveAlways,
    Deny,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum CliLifecycleStatus {
    Queued,
    Active,
    Idle,
    Running,
    WaitingTool,
    WaitingApproval,
    Completed,
    Failed,
    Cancelled,
    TimedOut,
}

impl From<CliLifecycleStatus> for LifecycleStatus {
    fn from(value: CliLifecycleStatus) -> Self {
        match value {
            CliLifecycleStatus::Queued => LifecycleStatus::Queued,
            CliLifecycleStatus::Active => LifecycleStatus::Active,
            CliLifecycleStatus::Idle => LifecycleStatus::Idle,
            CliLifecycleStatus::Running => LifecycleStatus::Running,
            CliLifecycleStatus::WaitingTool => LifecycleStatus::WaitingTool,
            CliLifecycleStatus::WaitingApproval => LifecycleStatus::WaitingApproval,
            CliLifecycleStatus::Completed => LifecycleStatus::Completed,
            CliLifecycleStatus::Failed => LifecycleStatus::Failed,
            CliLifecycleStatus::Cancelled => LifecycleStatus::Cancelled,
            CliLifecycleStatus::TimedOut => LifecycleStatus::TimedOut,
        }
    }
}

impl From<CliApprovalDecision> for ApprovalDecision {
    fn from(value: CliApprovalDecision) -> Self {
        match value {
            CliApprovalDecision::ApproveOnce => ApprovalDecision::ApproveOnce,
            CliApprovalDecision::ApproveSession => ApprovalDecision::ApproveSession,
            CliApprovalDecision::ApproveAlways => ApprovalDecision::ApproveAlways,
            CliApprovalDecision::Deny => ApprovalDecision::Deny,
        }
    }
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
