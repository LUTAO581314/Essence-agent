use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

pub type JsonObject = serde_json::Map<String, Value>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId(pub Uuid);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RunId(pub Uuid);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TurnId(pub Uuid);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventId(pub Uuid);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ToolCallId(pub Uuid);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApprovalId(pub Uuid);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaskId(pub Uuid);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArtifactId(pub Uuid);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AgentId(pub String);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LaneId(pub String);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionMode {
    Interactive,
    Headless,
    Acp,
    Gateway,
    Scheduled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PermissionMode {
    Default,
    Plan,
    Auto,
    Bypass,
    Readonly,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleStatus {
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TriggerKind {
    User,
    Scheduler,
    Hook,
    Subagent,
    Plugin,
    Api,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventVisibility {
    Internal,
    User,
    Audit,
    MemoryCandidate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    SessionMeta,
    SessionStateChanged,
    RunStarted,
    RunStateChanged,
    Snapshot,
    Compaction,
    MessageUser,
    MessageAssistantDelta,
    MessageAssistantFinal,
    ToolCallStarted,
    ToolCallOutput,
    ToolCallCompleted,
    ToolCallFailed,
    ApprovalRequested,
    ApprovalResolved,
    SubagentSpawned,
    SubagentProgress,
    SubagentCompleted,
    SubagentFailed,
    TaskCreated,
    TaskStateChanged,
    TaskBlocked,
    TaskCompleted,
    ArtifactCreated,
    MemoryCandidate,
    MemorySaved,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventSource {
    User,
    MainAgent,
    Subagent(String),
    Tool(String),
    System,
    Plugin(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MessageRole {
    System,
    User,
    Assistant,
    Tool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ContentBlock {
    Text { text: String },
    ToolUse { tool_call_id: ToolCallId, name: String, input: Value },
    ToolResult { tool_call_id: ToolCallId, result: Value, is_error: bool },
    File { uri: String, mime_type: Option<String> },
    Image { uri: String, mime_type: Option<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MessagePayload {
    pub role: MessageRole,
    pub content: Vec<ContentBlock>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EventEnvelope {
    pub event_id: EventId,
    pub seq: u64,
    pub ts: OffsetDateTime,
    pub schema_version: u32,
    pub session_id: SessionId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<RunId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<TurnId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_event_id: Option<EventId>,
    pub event_type: EventType,
    pub source: EventSource,
    pub visibility: EventVisibility,
    #[serde(default)]
    pub payload: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

impl EventEnvelope {
    pub fn new(
        seq: u64,
        session_id: SessionId,
        event_type: EventType,
        source: EventSource,
        visibility: EventVisibility,
        payload: Value,
    ) -> Self {
        Self {
            event_id: EventId(Uuid::new_v4()),
            seq,
            ts: OffsetDateTime::now_utc(),
            schema_version: 1,
            session_id,
            run_id: None,
            turn_id: None,
            trace_id: None,
            parent_event_id: None,
            event_type,
            source,
            visibility,
            payload,
            idempotency_key: None,
            prev_event_id: None,
            prev_hash: None,
            hash: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionMeta {
    pub session_id: SessionId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_session_id: Option<SessionId>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub cwd: String,
    pub mode: SessionMode,
    pub permission_mode: PermissionMode,
    pub status: LifecycleStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    pub transcript_uri: String,
    #[serde(default)]
    pub metadata: JsonObject,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RunMeta {
    pub run_id: RunId,
    pub turn_id: TurnId,
    pub session_id: SessionId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_run_id: Option<RunId>,
    pub trigger: TriggerKind,
    pub status: LifecycleStatus,
    pub started_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<OffsetDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lane_id: Option<LaneId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<AgentId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default)]
    pub input_message_ids: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SubagentRuntime {
    Native,
    Acp,
    ExternalCli,
    Remote,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IsolationMode {
    None,
    Worktree,
    Container,
    Remote,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SubagentMeta {
    pub subagent_id: AgentId,
    pub session_id: SessionId,
    pub parent_session_id: SessionId,
    pub parent_run_id: RunId,
    pub lane_id: LaneId,
    pub goal: String,
    pub runtime: SubagentRuntime,
    pub isolation: IsolationMode,
    pub spawn_depth: u32,
    pub status: LifecycleStatus,
    #[serde(default)]
    pub context_refs: Vec<String>,
    #[serde(default)]
    pub toolsets: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transcript_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    ApproveOnce,
    ApproveSession,
    ApproveAlways,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApprovalRequest {
    pub approval_id: ApprovalId,
    pub session_id: SessionId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<RunId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<ToolCallId>,
    pub subject: String,
    pub input: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    pub reason: String,
    pub allowed_decisions: Vec<ApprovalDecision>,
    pub status: LifecycleStatus,
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskRecord {
    pub task_id: TaskId,
    pub session_id: SessionId,
    pub title: String,
    pub status: LifecycleStatus,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_task_id: Option<TaskId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lane_id: Option<LaneId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignee: Option<AgentId>,
    #[serde(default)]
    pub metadata: JsonObject,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskPatch {
    pub task_id: TaskId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<LifecycleStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<OffsetDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignee: Option<AgentId>,
    #[serde(default)]
    pub metadata: JsonObject,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArtifactRecord {
    pub artifact_id: ArtifactId,
    pub session_id: SessionId,
    pub uri: String,
    pub kind: String,
    pub created_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<TaskId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<RunId>,
    #[serde(default)]
    pub metadata: JsonObject,
}
