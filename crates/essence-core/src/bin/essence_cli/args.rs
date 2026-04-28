use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};
use essence_core::{
    ApprovalDecision, IsolationMode, LifecycleStatus, PermissionMode, SessionMode, TriggerKind,
};
use serde::{Deserialize, Serialize};

const CLI_LONG_ABOUT: &str = "\
Essence Agent local control plane.

Examples:
  essence setup --save
  essence chat
  essence session create --cwd . --json
  essence events tail --session-id <session-id> --follow --output jsonl
  essence approval pending --session-id <session-id> --json

Use `essence <command> --help` for command-specific examples and flags.
Docs: https://github.com/essence-agent/essence-agent
Issues: https://github.com/essence-agent/essence-agent/issues";

#[derive(Debug, Parser)]
#[command(
    name = "essence",
    version,
    about = "Essence Agent local control plane.",
    long_about = CLI_LONG_ABOUT,
    arg_required_else_help = true,
    disable_version_flag = true,
    infer_subcommands = true,
    subcommand_required = true
)]
pub(crate) struct Cli {
    #[arg(long, global = true, default_value = ".essence")]
    pub(crate) root: PathBuf,
    #[arg(
        long,
        global = true,
        value_enum,
        default_value_t = CliOutputFormat::Text,
        help = "Select stdout format for data commands"
    )]
    pub(crate) output: CliOutputFormat,
    #[arg(
        long,
        global = true,
        conflicts_with = "output",
        help = "Shortcut for --output json"
    )]
    pub(crate) json: bool,
    #[arg(
        short = 'q',
        long,
        global = true,
        help = "Reduce text output to the primary id, count, or status"
    )]
    pub(crate) quiet: bool,
    #[arg(
        long,
        global = true,
        action = ArgAction::Count,
        help = "Increase diagnostic detail in text output"
    )]
    pub(crate) verbose: u8,
    #[arg(
        long,
        global = true,
        help = "Preview mutating commands without writing state"
    )]
    pub(crate) dry_run: bool,
    #[arg(
        long,
        global = true,
        value_enum,
        default_value_t = CliTheme::Auto,
        help = "Select human text theme"
    )]
    pub(crate) theme: CliTheme,
    #[arg(long, global = true, help = "Disable ANSI color in human text output")]
    pub(crate) no_color: bool,
    #[arg(
        short = 'v',
        long = "version",
        action = ArgAction::SetTrue,
        default_value_t = false,
        help = "Print version"
    )]
    pub(crate) version: bool,
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    Setup(SetupArgs),
    Ask(AskArgs),
    Chat(ChatArgs),
    Session(SessionArgs),
    Message(MessageArgs),
    Run(RunArgs),
    Events(EventsArgs),
    Tool(ToolArgs),
    Approval(ApprovalArgs),
    Agent(AgentArgs),
    Task(TaskArgs),
    Artifact(ArtifactArgs),
    Memory(MemoryArgs),
    Subagent(SubagentArgs),
    Snapshot(SnapshotArgs),
    Workspace(WorkspaceArgs),
    Plugin(PluginArgs),
    Mcp(McpArgs),
    Harness(HarnessArgs),
    Theme(ThemeArgs),
    Config(ConfigArgs),
    Doctor(DoctorArgs),
    Completion(CompletionArgs),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum CliOutputFormat {
    Text,
    Json,
    Jsonl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CliTheme {
    Auto,
    Pixel,
    Plain,
}

#[derive(Debug, Args)]
pub(crate) struct CompletionArgs {
    #[command(subcommand)]
    pub(crate) command: Option<CompletionCommand>,
    #[arg(value_enum, help = "Shell to generate completions for")]
    pub(crate) shell: Option<CliCompletionShell>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum CompletionCommand {
    Generate(CompletionGenerateArgs),
    Install(CompletionInstallArgs),
}

#[derive(Debug, Args)]
pub(crate) struct CompletionGenerateArgs {
    #[arg(value_enum)]
    pub(crate) shell: CliCompletionShell,
}

#[derive(Debug, Args)]
pub(crate) struct CompletionInstallArgs {
    #[arg(value_enum)]
    pub(crate) shell: CliCompletionShell,
    #[arg(long)]
    pub(crate) dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum CliCompletionShell {
    Bash,
    Zsh,
    Fish,
    #[value(name = "powershell", alias = "power-shell")]
    PowerShell,
    Elvish,
}

#[derive(Debug, Args)]
pub(crate) struct ConfigArgs {
    #[command(subcommand)]
    pub(crate) command: ConfigCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ConfigCommand {
    Get(ConfigGetArgs),
    Set(ConfigSetArgs),
}

#[derive(Debug, Args)]
pub(crate) struct ConfigGetArgs {
    #[arg(value_enum)]
    pub(crate) key: Option<CliConfigKey>,
}

#[derive(Debug, Args)]
pub(crate) struct ConfigSetArgs {
    #[arg(value_enum)]
    pub(crate) key: CliConfigKey,
    pub(crate) value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum CliConfigKey {
    Provider,
    Model,
    BaseUrl,
    ApiKeyEnv,
    Command,
}

#[derive(Debug, Args)]
pub(crate) struct DoctorArgs {
    #[arg(long, help = "Exit with an error if any doctor check fails")]
    pub(crate) strict: bool,
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
pub(crate) struct AskArgs {
    #[arg(long)]
    pub(crate) session_id: Option<String>,
    #[arg(long)]
    pub(crate) text: String,
    #[arg(long)]
    pub(crate) cwd: Option<PathBuf>,
    #[arg(long)]
    pub(crate) title: Option<String>,
    #[arg(long)]
    pub(crate) system_prompt: Option<String>,
    #[arg(long)]
    pub(crate) system_prompt_file: Option<PathBuf>,
    #[arg(long)]
    pub(crate) agent: Option<String>,
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
    #[arg(long, value_enum, default_value_t = CliPermissionMode::Default)]
    pub(crate) permission_mode: CliPermissionMode,
    #[arg(long, default_value_t = 30_000)]
    pub(crate) model_timeout_ms: u64,
    #[arg(long, default_value_t = 1_048_576)]
    pub(crate) model_max_response_bytes: usize,
    #[arg(long, default_value_t = 1_048_576)]
    pub(crate) model_max_stdout_bytes: usize,
    #[arg(long, default_value_t = 65_536)]
    pub(crate) model_max_stderr_bytes: usize,
}

#[derive(Debug, Args)]
pub(crate) struct SessionArgs {
    #[command(subcommand)]
    pub(crate) command: SessionCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum SessionCommand {
    Create(SessionCreateArgs),
    List(SessionListArgs),
    Show(SessionShowArgs),
    Update(SessionUpdateArgs),
    Cancel(SessionCancelArgs),
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
pub(crate) struct SessionListArgs {
    #[arg(long, value_enum)]
    pub(crate) status: Option<CliLifecycleStatus>,
}

#[derive(Debug, Args)]
pub(crate) struct SessionShowArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long, help = "Show the full replayed ledger projection")]
    pub(crate) projection: bool,
}

#[derive(Debug, Args)]
pub(crate) struct SessionUpdateArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long, value_enum)]
    pub(crate) status: CliLifecycleStatus,
    #[arg(long)]
    pub(crate) title: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct SessionCancelArgs {
    #[arg(long)]
    pub(crate) session_id: String,
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
pub(crate) struct RunArgs {
    #[command(subcommand)]
    pub(crate) command: RunCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum RunCommand {
    Start(RunStartArgs),
    List(RunListArgs),
    Complete(RunCompleteArgs),
    Fail(RunFailArgs),
    Cancel(RunCancelArgs),
}

#[derive(Debug, Args)]
pub(crate) struct RunStartArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long, value_enum, default_value_t = CliTriggerKind::User)]
    pub(crate) trigger: CliTriggerKind,
    #[arg(long)]
    pub(crate) parent_run_id: Option<String>,
    #[arg(long)]
    pub(crate) lane: Option<String>,
    #[arg(long)]
    pub(crate) agent_id: Option<String>,
    #[arg(long)]
    pub(crate) model: Option<String>,
    #[arg(long = "input-event")]
    pub(crate) input_events: Vec<String>,
}

#[derive(Debug, Args)]
pub(crate) struct RunListArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long, value_enum)]
    pub(crate) status: Option<CliLifecycleStatus>,
}

#[derive(Debug, Args)]
pub(crate) struct RunCompleteArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long)]
    pub(crate) run_id: String,
    #[arg(long)]
    pub(crate) usage_json: Option<String>,
    #[arg(long)]
    pub(crate) stop_reason: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct RunFailArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long)]
    pub(crate) run_id: String,
    #[arg(long)]
    pub(crate) reason: String,
}

#[derive(Debug, Args)]
pub(crate) struct RunCancelArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long)]
    pub(crate) run_id: String,
    #[arg(long)]
    pub(crate) reason: String,
}

#[derive(Debug, Args)]
pub(crate) struct EventsArgs {
    #[command(subcommand)]
    pub(crate) command: EventsCommand,
}

#[derive(Debug, Args)]
pub(crate) struct ToolArgs {
    #[command(subcommand)]
    pub(crate) command: ToolCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ToolCommand {
    Specs(ToolSpecsArgs),
    Start(ToolStartArgs),
    List(ToolListArgs),
    Complete(ToolCompleteArgs),
    Fail(ToolFailArgs),
    Run(ToolRunArgs),
}

#[derive(Debug, Args)]
pub(crate) struct ToolSpecsArgs {
    #[arg(long, help = "Include installed plugin tool specs")]
    pub(crate) plugins: bool,
}

#[derive(Debug, Args)]
pub(crate) struct ToolStartArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long)]
    pub(crate) name: String,
    #[arg(long, default_value = "{}")]
    pub(crate) input_json: String,
    #[arg(long)]
    pub(crate) run_id: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct ToolRunArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long)]
    pub(crate) name: String,
    #[arg(long, default_value = "{}")]
    pub(crate) input_json: String,
    #[arg(long)]
    pub(crate) run_id: Option<String>,
    #[arg(long)]
    pub(crate) cwd: Option<String>,
    #[arg(long, value_enum, default_value_t = CliPermissionMode::Default)]
    pub(crate) permission_mode: CliPermissionMode,
}

#[derive(Debug, Args)]
pub(crate) struct ToolListArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long, value_enum)]
    pub(crate) status: Option<CliLifecycleStatus>,
}

#[derive(Debug, Args)]
pub(crate) struct ToolCompleteArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long)]
    pub(crate) tool_call_id: String,
    #[arg(long, default_value = "{}")]
    pub(crate) output_json: String,
}

#[derive(Debug, Args)]
pub(crate) struct ToolFailArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long)]
    pub(crate) tool_call_id: String,
    #[arg(long)]
    pub(crate) error: String,
}

#[derive(Debug, Args)]
pub(crate) struct ApprovalArgs {
    #[command(subcommand)]
    pub(crate) command: ApprovalCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ApprovalCommand {
    Request(ApprovalRequestArgs),
    Pending(ApprovalPendingArgs),
    Resolve(ApprovalResolveArgs),
}

#[derive(Debug, Args)]
pub(crate) struct ApprovalRequestArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long)]
    pub(crate) subject: String,
    #[arg(long, default_value = "{}")]
    pub(crate) input_json: String,
    #[arg(long)]
    pub(crate) reason: String,
    #[arg(long)]
    pub(crate) run_id: Option<String>,
    #[arg(long)]
    pub(crate) tool_call_id: Option<String>,
    #[arg(long)]
    pub(crate) cwd: Option<String>,
    #[arg(long = "allowed-decision", value_enum)]
    pub(crate) allowed_decisions: Vec<CliApprovalDecision>,
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
    List(TaskListArgs),
    Update(TaskUpdateArgs),
    Complete(TaskCompleteArgs),
    Claim(TaskClaimArgs),
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
pub(crate) struct TaskListArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long, value_enum)]
    pub(crate) status: Option<CliLifecycleStatus>,
    #[arg(long)]
    pub(crate) lane: Option<String>,
    #[arg(long)]
    pub(crate) assignee: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct TaskUpdateArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long)]
    pub(crate) task_id: String,
    #[arg(long)]
    pub(crate) title: Option<String>,
    #[arg(long, value_enum)]
    pub(crate) status: Option<CliLifecycleStatus>,
    #[arg(long)]
    pub(crate) assignee: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct TaskCompleteArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long)]
    pub(crate) task_id: String,
}

#[derive(Debug, Args)]
pub(crate) struct TaskClaimArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long)]
    pub(crate) assignee: String,
}

#[derive(Debug, Args)]
pub(crate) struct ArtifactArgs {
    #[command(subcommand)]
    pub(crate) command: ArtifactCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ArtifactCommand {
    Create(ArtifactCreateArgs),
    List(ArtifactListArgs),
    Show(ArtifactShowArgs),
}

#[derive(Debug, Args)]
pub(crate) struct ArtifactCreateArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long)]
    pub(crate) uri: String,
    #[arg(long)]
    pub(crate) kind: String,
    #[arg(long)]
    pub(crate) task_id: Option<String>,
    #[arg(long)]
    pub(crate) run_id: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct ArtifactListArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long)]
    pub(crate) kind: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct ArtifactShowArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long)]
    pub(crate) artifact_id: String,
}

#[derive(Debug, Args)]
pub(crate) struct MemoryArgs {
    #[command(subcommand)]
    pub(crate) command: MemoryCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum MemoryCommand {
    Propose(MemoryProposeArgs),
    Save(MemorySaveArgs),
    Remember(MemoryRememberArgs),
    List(MemoryListArgs),
    Search(MemorySearchArgs),
}

#[derive(Debug, Args)]
pub(crate) struct MemoryProposeArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long)]
    pub(crate) kind: String,
    #[arg(long)]
    pub(crate) text: String,
    #[arg(long)]
    pub(crate) run_id: Option<String>,
    #[arg(long = "source-event")]
    pub(crate) source_events: Vec<String>,
    #[arg(long)]
    pub(crate) confidence: Option<f32>,
}

#[derive(Debug, Args)]
pub(crate) struct MemorySaveArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long)]
    pub(crate) memory_id: String,
}

#[derive(Debug, Args)]
pub(crate) struct MemoryRememberArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long)]
    pub(crate) kind: String,
    #[arg(long)]
    pub(crate) text: String,
    #[arg(long)]
    pub(crate) run_id: Option<String>,
    #[arg(long = "source-event")]
    pub(crate) source_events: Vec<String>,
    #[arg(long)]
    pub(crate) confidence: Option<f32>,
}

#[derive(Debug, Args)]
pub(crate) struct MemoryListArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long)]
    pub(crate) kind: Option<String>,
    #[arg(long)]
    pub(crate) saved: bool,
}

#[derive(Debug, Args)]
pub(crate) struct MemorySearchArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long)]
    pub(crate) query: String,
    #[arg(long, default_value_t = 10)]
    pub(crate) limit: usize,
}

#[derive(Debug, Args)]
pub(crate) struct SubagentArgs {
    #[command(subcommand)]
    pub(crate) command: SubagentCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum SubagentCommand {
    Spawn(SubagentSpawnArgs),
    List(SubagentListArgs),
    Progress(SubagentProgressArgs),
    Steer(SubagentSteerArgs),
    Complete(SubagentCompleteArgs),
    Fail(SubagentFailArgs),
    Cancel(SubagentCancelArgs),
}

#[derive(Debug, Args)]
pub(crate) struct SubagentSpawnArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long)]
    pub(crate) run_id: String,
    #[arg(long)]
    pub(crate) lane: String,
    #[arg(long)]
    pub(crate) goal: String,
    #[arg(long)]
    pub(crate) subagent_id: Option<String>,
    #[arg(long, value_enum, default_value_t = CliIsolationMode::Worktree)]
    pub(crate) isolation: CliIsolationMode,
    #[arg(long = "context-ref")]
    pub(crate) context_refs: Vec<String>,
    #[arg(long = "toolset")]
    pub(crate) toolsets: Vec<String>,
    #[arg(long)]
    pub(crate) max_turns: Option<u32>,
    #[arg(long)]
    pub(crate) max_tool_calls: Option<u32>,
    #[arg(long)]
    pub(crate) max_tokens: Option<u64>,
}

#[derive(Debug, Args)]
pub(crate) struct SubagentListArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long, value_enum)]
    pub(crate) status: Option<CliLifecycleStatus>,
}

#[derive(Debug, Args)]
pub(crate) struct SubagentProgressArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long)]
    pub(crate) subagent_id: String,
    #[arg(long, value_enum)]
    pub(crate) status: CliLifecycleStatus,
}

#[derive(Debug, Args)]
pub(crate) struct SubagentSteerArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long)]
    pub(crate) subagent_id: String,
    #[arg(long)]
    pub(crate) goal: Option<String>,
    #[arg(long = "context-ref")]
    pub(crate) context_refs: Vec<String>,
    #[arg(long = "toolset")]
    pub(crate) toolsets: Vec<String>,
}

#[derive(Debug, Args)]
pub(crate) struct SubagentCompleteArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long)]
    pub(crate) subagent_id: String,
    #[arg(long)]
    pub(crate) summary: Option<String>,
    #[arg(long = "artifact-ref")]
    pub(crate) artifact_refs: Vec<String>,
    #[arg(long)]
    pub(crate) usage_json: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct SubagentFailArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long)]
    pub(crate) subagent_id: String,
    #[arg(long)]
    pub(crate) error: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct SubagentCancelArgs {
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long)]
    pub(crate) subagent_id: String,
    #[arg(long)]
    pub(crate) reason: String,
}

#[derive(Debug, Args)]
pub(crate) struct SnapshotArgs {
    #[command(subcommand)]
    pub(crate) command: SnapshotCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum SnapshotCommand {
    Write(SnapshotWriteArgs),
    Read(SnapshotReadArgs),
}

#[derive(Debug, Args)]
pub(crate) struct SnapshotWriteArgs {
    #[arg(long)]
    pub(crate) session_id: String,
}

#[derive(Debug, Args)]
pub(crate) struct SnapshotReadArgs {
    #[arg(long)]
    pub(crate) session_id: String,
}

#[derive(Debug, Args)]
pub(crate) struct PluginArgs {
    #[command(subcommand)]
    pub(crate) command: PluginCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum PluginCommand {
    Catalog(PluginCatalogArgs),
    List(PluginListArgs),
    Install(PluginInstallArgs),
    Tools(PluginToolsArgs),
    UiSlots(PluginUiSlotsArgs),
}

#[derive(Debug, Args)]
pub(crate) struct PluginCatalogArgs {
    #[arg(long)]
    pub(crate) capability: Option<String>,
    #[arg(long, value_enum)]
    pub(crate) kind: Option<CliPluginKind>,
}

#[derive(Debug, Args)]
pub(crate) struct PluginListArgs {}

#[derive(Debug, Args)]
pub(crate) struct PluginInstallArgs {
    #[arg(long)]
    pub(crate) id: String,
}

#[derive(Debug, Args)]
pub(crate) struct PluginToolsArgs {}

#[derive(Debug, Args)]
pub(crate) struct PluginUiSlotsArgs {}

#[derive(Debug, Args)]
pub(crate) struct McpArgs {
    #[command(subcommand)]
    pub(crate) command: McpCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum McpCommand {
    Manifest(McpManifestArgs),
}

#[derive(Debug, Args)]
pub(crate) struct McpManifestArgs {}

#[derive(Debug, Args)]
pub(crate) struct HarnessArgs {
    #[command(subcommand)]
    pub(crate) command: HarnessCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum HarnessCommand {
    List(HarnessListArgs),
    Run(HarnessRunArgs),
}

#[derive(Debug, Args)]
pub(crate) struct HarnessListArgs {}

#[derive(Debug, Args)]
pub(crate) struct HarnessRunArgs {
    #[arg(long, default_value = "gitnexus")]
    pub(crate) harness: String,
    #[arg(long)]
    pub(crate) session_id: String,
    #[arg(long)]
    pub(crate) tool: String,
    #[arg(long, default_value = "{}")]
    pub(crate) input_json: String,
    #[arg(long)]
    pub(crate) run_id: Option<String>,
    #[arg(long)]
    pub(crate) cwd: Option<String>,
    #[arg(long, value_enum, default_value_t = CliPermissionMode::Default)]
    pub(crate) permission_mode: CliPermissionMode,
}

#[derive(Debug, Args)]
pub(crate) struct ThemeArgs {
    #[command(subcommand)]
    pub(crate) command: ThemeCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ThemeCommand {
    Get(ThemeGetArgs),
    Set(ThemeSetArgs),
    Preview(ThemePreviewArgs),
}

#[derive(Debug, Args)]
pub(crate) struct ThemeGetArgs {}

#[derive(Debug, Args)]
pub(crate) struct ThemeSetArgs {
    #[arg(value_enum)]
    pub(crate) theme: CliTheme,
}

#[derive(Debug, Args)]
pub(crate) struct ThemePreviewArgs {
    #[arg(value_enum)]
    pub(crate) theme: Option<CliTheme>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum CliTriggerKind {
    User,
    Scheduler,
    Hook,
    Subagent,
    Plugin,
    Api,
}

impl From<CliTriggerKind> for TriggerKind {
    fn from(value: CliTriggerKind) -> Self {
        match value {
            CliTriggerKind::User => TriggerKind::User,
            CliTriggerKind::Scheduler => TriggerKind::Scheduler,
            CliTriggerKind::Hook => TriggerKind::Hook,
            CliTriggerKind::Subagent => TriggerKind::Subagent,
            CliTriggerKind::Plugin => TriggerKind::Plugin,
            CliTriggerKind::Api => TriggerKind::Api,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum CliIsolationMode {
    None,
    Worktree,
    Container,
    Remote,
}

impl From<CliIsolationMode> for IsolationMode {
    fn from(value: CliIsolationMode) -> Self {
        match value {
            CliIsolationMode::None => IsolationMode::None,
            CliIsolationMode::Worktree => IsolationMode::Worktree,
            CliIsolationMode::Container => IsolationMode::Container,
            CliIsolationMode::Remote => IsolationMode::Remote,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum CliPluginKind {
    ToolProvider,
    CliHarness,
    BrowserDaemon,
    ResearchRadar,
    MemoryBackend,
    UiShell,
    RolePack,
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
