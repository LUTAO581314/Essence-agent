use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::Value;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::projection::{LedgerProjection, ProjectionError};
use crate::protocol::{
    AgentId, ApprovalDecision, ApprovalId, ApprovalRequest, ArtifactId, ArtifactRecord,
    ContentBlock, EventEnvelope, EventSource, EventType, EventVisibility, IsolationMode,
    JsonObject, LaneId, LifecycleStatus, MessagePayload, MessageRole, PermissionMode, RunId,
    RunMeta, SessionId, SessionMeta, SessionMode, SessionStatePatch, SubagentMeta, SubagentRuntime,
    TaskId, TaskPatch, TaskRecord, ToolCallId, ToolCallRecord, TriggerKind, TurnId,
};
use crate::wal::{JsonlWal, WalError};

#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    #[error(transparent)]
    Wal(#[from] WalError),
    #[error(transparent)]
    Projection(#[from] ProjectionError),
    #[error("could not encode event payload: {0}")]
    Payload(#[from] serde_json::Error),
}

pub type ControlResult<T> = Result<T, ControlError>;

#[derive(Debug, Clone)]
pub struct ControlPlane {
    root: PathBuf,
}

impl ControlPlane {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn create_session(&self, request: CreateSessionRequest) -> ControlResult<SessionMeta> {
        let session_id = SessionId(Uuid::new_v4());
        let now = OffsetDateTime::now_utc();
        let transcript_uri = self.transcript_uri(&session_id);
        let session = SessionMeta {
            session_id: session_id.clone(),
            parent_session_id: request.parent_session_id,
            created_at: now,
            updated_at: now,
            cwd: request.cwd,
            mode: request.mode,
            permission_mode: request.permission_mode,
            status: LifecycleStatus::Active,
            title: request.title,
            model: request.model,
            transcript_uri,
            metadata: request.metadata,
        };

        self.append_typed_event(
            &session_id,
            EventType::SessionMeta,
            EventSource::System,
            EventVisibility::Audit,
            &session,
        )?;

        Ok(session)
    }

    pub fn update_session_state(
        &self,
        session_id: &SessionId,
        status: LifecycleStatus,
        title: Option<String>,
    ) -> ControlResult<SessionStatePatch> {
        let patch = SessionStatePatch {
            status,
            updated_at: OffsetDateTime::now_utc(),
            title,
        };

        self.append_typed_event(
            session_id,
            EventType::SessionStateChanged,
            EventSource::System,
            EventVisibility::Audit,
            &patch,
        )?;

        Ok(patch)
    }

    pub fn cancel_session(&self, session_id: &SessionId) -> ControlResult<SessionStatePatch> {
        self.update_session_state(session_id, LifecycleStatus::Cancelled, None)
    }

    pub fn submit_user_message(
        &self,
        session_id: &SessionId,
        text: impl Into<String>,
    ) -> ControlResult<EventEnvelope> {
        let payload = MessagePayload {
            role: MessageRole::User,
            content: vec![ContentBlock::Text { text: text.into() }],
            usage: None,
            origin: None,
        };

        self.append_typed_event(
            session_id,
            EventType::MessageUser,
            EventSource::User,
            EventVisibility::User,
            &payload,
        )
    }

    pub fn append_assistant_message(
        &self,
        session_id: &SessionId,
        run_id: Option<&RunId>,
        turn_id: Option<&TurnId>,
        text: impl Into<String>,
    ) -> ControlResult<EventEnvelope> {
        let payload = MessagePayload {
            role: MessageRole::Assistant,
            content: vec![ContentBlock::Text { text: text.into() }],
            usage: None,
            origin: None,
        };

        self.append_typed_event_with_run(
            session_id,
            RunContext::from_options(run_id, turn_id),
            EventType::MessageAssistantFinal,
            EventSource::MainAgent,
            EventVisibility::User,
            &payload,
        )
    }

    pub fn start_run(&self, request: StartRunRequest) -> ControlResult<RunMeta> {
        let run_id = RunId(Uuid::new_v4());
        let turn_id = TurnId(Uuid::new_v4());
        let now = OffsetDateTime::now_utc();
        let run = RunMeta {
            run_id: run_id.clone(),
            turn_id: turn_id.clone(),
            session_id: request.session_id.clone(),
            parent_run_id: request.parent_run_id,
            trigger: request.trigger,
            status: LifecycleStatus::Running,
            started_at: now,
            ended_at: None,
            lane_id: request.lane_id,
            agent_id: request.agent_id,
            model: request.model,
            input_message_ids: request.input_message_ids,
            usage: None,
            stop_reason: None,
        };

        self.append_typed_event_with_run(
            &request.session_id,
            RunContext::new(&run_id, &turn_id),
            EventType::RunStarted,
            EventSource::MainAgent,
            EventVisibility::Audit,
            &run,
        )?;

        Ok(run)
    }

    pub fn complete_run(&self, run: &RunMeta, usage: Option<Value>) -> ControlResult<RunMeta> {
        self.finish_run(run, LifecycleStatus::Completed, usage, None)
    }

    pub fn fail_run(
        &self,
        run: &RunMeta,
        stop_reason: impl Into<String>,
    ) -> ControlResult<RunMeta> {
        self.finish_run(run, LifecycleStatus::Failed, None, Some(stop_reason.into()))
    }

    pub fn cancel_run(
        &self,
        run: &RunMeta,
        stop_reason: impl Into<String>,
    ) -> ControlResult<RunMeta> {
        self.finish_run(
            run,
            LifecycleStatus::Cancelled,
            None,
            Some(stop_reason.into()),
        )
    }

    pub fn request_approval(
        &self,
        request: RequestApprovalRequest,
    ) -> ControlResult<ApprovalRequest> {
        let approval = ApprovalRequest {
            approval_id: ApprovalId(Uuid::new_v4()),
            session_id: request.session_id.clone(),
            run_id: request.run_id.clone(),
            tool_call_id: request.tool_call_id,
            subject: request.subject,
            input: request.input,
            cwd: request.cwd,
            reason: request.reason,
            allowed_decisions: request.allowed_decisions,
            status: LifecycleStatus::WaitingApproval,
            expires_at: request.expires_at,
            decision: None,
            resolved_at: None,
            resolved_by: None,
        };

        self.append_typed_event_with_run(
            &request.session_id,
            RunContext::from_run_only(request.run_id.as_ref()),
            EventType::ApprovalRequested,
            EventSource::System,
            EventVisibility::Audit,
            &approval,
        )?;

        Ok(approval)
    }

    pub fn resolve_approval(
        &self,
        approval: &ApprovalRequest,
        decision: ApprovalDecision,
        resolved_by: impl Into<String>,
    ) -> ControlResult<ApprovalRequest> {
        let mut resolved = approval.clone();
        resolved.status = match decision {
            ApprovalDecision::Deny => LifecycleStatus::Failed,
            _ => LifecycleStatus::Completed,
        };
        resolved.decision = Some(decision);
        resolved.resolved_at = Some(OffsetDateTime::now_utc());
        resolved.resolved_by = Some(resolved_by.into());

        self.append_typed_event_with_run(
            &resolved.session_id,
            RunContext::from_run_only(resolved.run_id.as_ref()),
            EventType::ApprovalResolved,
            EventSource::User,
            EventVisibility::Audit,
            &resolved,
        )?;

        Ok(resolved)
    }

    pub fn start_tool_call(&self, request: StartToolCallRequest) -> ControlResult<ToolCallRecord> {
        let tool_call = ToolCallRecord {
            tool_call_id: ToolCallId(Uuid::new_v4()),
            session_id: request.session_id.clone(),
            run_id: request.run_id.clone(),
            turn_id: request.turn_id.clone(),
            name: request.name,
            input: request.input,
            status: LifecycleStatus::WaitingTool,
            started_at: OffsetDateTime::now_utc(),
            ended_at: None,
            output: None,
            error: None,
        };

        self.append_typed_event_with_run(
            &request.session_id,
            RunContext::from_options(request.run_id.as_ref(), request.turn_id.as_ref()),
            EventType::ToolCallStarted,
            EventSource::MainAgent,
            EventVisibility::Audit,
            &tool_call,
        )?;

        Ok(tool_call)
    }

    pub fn complete_tool_call(
        &self,
        tool_call: &ToolCallRecord,
        output: Value,
    ) -> ControlResult<ToolCallRecord> {
        self.finish_tool_call(tool_call, LifecycleStatus::Completed, Some(output), None)
    }

    pub fn fail_tool_call(
        &self,
        tool_call: &ToolCallRecord,
        error: impl Into<String>,
    ) -> ControlResult<ToolCallRecord> {
        self.finish_tool_call(tool_call, LifecycleStatus::Failed, None, Some(error.into()))
    }

    pub fn create_task(&self, request: CreateTaskRequest) -> ControlResult<TaskRecord> {
        let now = OffsetDateTime::now_utc();
        let task = TaskRecord {
            task_id: TaskId(Uuid::new_v4()),
            session_id: request.session_id.clone(),
            title: request.title,
            status: request.status,
            created_at: now,
            updated_at: now,
            parent_task_id: request.parent_task_id,
            lane_id: request.lane_id,
            assignee: request.assignee,
            metadata: request.metadata,
        };

        self.append_typed_event(
            &request.session_id,
            EventType::TaskCreated,
            EventSource::System,
            EventVisibility::Audit,
            &task,
        )?;

        Ok(task)
    }

    pub fn update_task(
        &self,
        session_id: &SessionId,
        patch: TaskPatch,
    ) -> ControlResult<TaskPatch> {
        self.append_typed_event(
            session_id,
            EventType::TaskStateChanged,
            EventSource::System,
            EventVisibility::Audit,
            &patch,
        )?;

        Ok(patch)
    }

    pub fn complete_task(&self, task: &TaskRecord) -> ControlResult<TaskPatch> {
        let patch = TaskPatch {
            task_id: task.task_id.clone(),
            title: None,
            status: Some(LifecycleStatus::Completed),
            updated_at: Some(OffsetDateTime::now_utc()),
            assignee: None,
            metadata: Default::default(),
        };

        self.append_typed_event(
            &task.session_id,
            EventType::TaskCompleted,
            EventSource::System,
            EventVisibility::Audit,
            &patch,
        )?;

        Ok(patch)
    }

    pub fn create_artifact(&self, request: CreateArtifactRequest) -> ControlResult<ArtifactRecord> {
        let artifact = ArtifactRecord {
            artifact_id: ArtifactId(Uuid::new_v4()),
            session_id: request.session_id.clone(),
            uri: request.uri,
            kind: request.kind,
            created_at: OffsetDateTime::now_utc(),
            task_id: request.task_id,
            run_id: request.run_id,
            metadata: request.metadata,
        };

        self.append_typed_event(
            &request.session_id,
            EventType::ArtifactCreated,
            EventSource::System,
            EventVisibility::Audit,
            &artifact,
        )?;

        Ok(artifact)
    }

    pub fn spawn_subagent(&self, request: SpawnSubagentRequest) -> ControlResult<SubagentMeta> {
        let subagent = SubagentMeta {
            subagent_id: request.subagent_id,
            session_id: request.session_id.clone(),
            parent_session_id: request.parent_session_id,
            parent_run_id: request.parent_run_id,
            lane_id: request.lane_id,
            goal: request.goal,
            runtime: request.runtime,
            isolation: request.isolation,
            spawn_depth: request.spawn_depth,
            status: LifecycleStatus::Running,
            context_refs: request.context_refs,
            toolsets: request.toolsets,
            transcript_ref: request.transcript_ref,
        };

        self.append_typed_event_with_run(
            &request.session_id,
            RunContext::from_run_only(Some(&subagent.parent_run_id)),
            EventType::SubagentSpawned,
            EventSource::MainAgent,
            EventVisibility::Audit,
            &subagent,
        )?;

        Ok(subagent)
    }

    pub fn update_subagent_progress(
        &self,
        subagent: &SubagentMeta,
        status: LifecycleStatus,
    ) -> ControlResult<SubagentMeta> {
        self.record_subagent(subagent, status, EventType::SubagentProgress)
    }

    pub fn complete_subagent(&self, subagent: &SubagentMeta) -> ControlResult<SubagentMeta> {
        self.record_subagent(
            subagent,
            LifecycleStatus::Completed,
            EventType::SubagentCompleted,
        )
    }

    pub fn fail_subagent(&self, subagent: &SubagentMeta) -> ControlResult<SubagentMeta> {
        self.record_subagent(subagent, LifecycleStatus::Failed, EventType::SubagentFailed)
    }

    pub fn append_event(
        &self,
        session_id: &SessionId,
        event_type: EventType,
        source: EventSource,
        visibility: EventVisibility,
        payload: Value,
    ) -> ControlResult<EventEnvelope> {
        let wal = self.wal(session_id);
        let events = wal.replay()?;
        let seq = events.last().map_or(1, |event| event.seq + 1);
        let event = EventEnvelope::new(
            seq,
            session_id.clone(),
            event_type,
            source,
            visibility,
            payload,
        );
        wal.append(&event)?;
        Ok(event)
    }

    pub fn projection(&self, session_id: &SessionId) -> ControlResult<LedgerProjection> {
        let events = self.wal(session_id).replay()?;
        LedgerProjection::replay(&events).map_err(ControlError::from)
    }

    pub fn events(&self, session_id: &SessionId) -> ControlResult<Vec<EventEnvelope>> {
        self.wal(session_id).replay().map_err(ControlError::from)
    }

    pub fn events_after(
        &self,
        session_id: &SessionId,
        after_seq: u64,
    ) -> ControlResult<Vec<EventEnvelope>> {
        Ok(self
            .events(session_id)?
            .into_iter()
            .filter(|event| event.seq > after_seq)
            .collect())
    }

    pub fn wal_path(&self, session_id: &SessionId) -> PathBuf {
        self.root.join(self.transcript_uri(session_id))
    }

    fn append_typed_event<T: Serialize>(
        &self,
        session_id: &SessionId,
        event_type: EventType,
        source: EventSource,
        visibility: EventVisibility,
        payload: &T,
    ) -> ControlResult<EventEnvelope> {
        self.append_event(
            session_id,
            event_type,
            source,
            visibility,
            serde_json::to_value(payload)?,
        )
    }

    fn append_typed_event_with_run<T: Serialize>(
        &self,
        session_id: &SessionId,
        run_context: RunContext<'_>,
        event_type: EventType,
        source: EventSource,
        visibility: EventVisibility,
        payload: &T,
    ) -> ControlResult<EventEnvelope> {
        let payload = serde_json::to_value(payload)?;
        let wal = self.wal(session_id);
        let events = wal.replay()?;
        let seq = events.last().map_or(1, |event| event.seq + 1);
        let mut event = EventEnvelope::new(
            seq,
            session_id.clone(),
            event_type,
            source,
            visibility,
            payload,
        );
        if let Some((run_id, turn_id)) = run_context.parts() {
            event = event.with_run(run_id.clone(), turn_id.clone());
        }
        wal.append(&event)?;
        Ok(event)
    }

    fn finish_run(
        &self,
        run: &RunMeta,
        status: LifecycleStatus,
        usage: Option<Value>,
        stop_reason: Option<String>,
    ) -> ControlResult<RunMeta> {
        let mut updated = run.clone();
        updated.status = status;
        updated.ended_at = Some(OffsetDateTime::now_utc());
        updated.usage = usage;
        updated.stop_reason = stop_reason;

        self.append_typed_event_with_run(
            &updated.session_id,
            RunContext::new(&updated.run_id, &updated.turn_id),
            EventType::RunStateChanged,
            EventSource::MainAgent,
            EventVisibility::Audit,
            &updated,
        )?;

        Ok(updated)
    }

    fn finish_tool_call(
        &self,
        tool_call: &ToolCallRecord,
        status: LifecycleStatus,
        output: Option<Value>,
        error: Option<String>,
    ) -> ControlResult<ToolCallRecord> {
        let mut updated = tool_call.clone();
        updated.status = status;
        updated.ended_at = Some(OffsetDateTime::now_utc());
        updated.output = output;
        updated.error = error;

        let event_type = match updated.status {
            LifecycleStatus::Completed => EventType::ToolCallCompleted,
            LifecycleStatus::Failed => EventType::ToolCallFailed,
            _ => EventType::ToolCallOutput,
        };

        self.append_typed_event_with_run(
            &updated.session_id,
            RunContext::from_options(updated.run_id.as_ref(), updated.turn_id.as_ref()),
            event_type,
            EventSource::Tool(updated.name.clone()),
            EventVisibility::Audit,
            &updated,
        )?;

        Ok(updated)
    }

    fn record_subagent(
        &self,
        subagent: &SubagentMeta,
        status: LifecycleStatus,
        event_type: EventType,
    ) -> ControlResult<SubagentMeta> {
        let mut updated = subagent.clone();
        updated.status = status;

        self.append_typed_event_with_run(
            &updated.session_id,
            RunContext::from_run_only(Some(&updated.parent_run_id)),
            event_type,
            EventSource::Subagent(updated.subagent_id.0.clone()),
            EventVisibility::Audit,
            &updated,
        )?;

        Ok(updated)
    }

    fn wal(&self, session_id: &SessionId) -> JsonlWal {
        JsonlWal::new(self.wal_path(session_id))
    }

    fn transcript_uri(&self, session_id: &SessionId) -> String {
        format!("sessions/{}.jsonl", session_id.0)
    }
}

#[derive(Debug, Clone, Copy)]
struct RunContext<'a> {
    run_id: Option<&'a RunId>,
    turn_id: Option<&'a TurnId>,
}

impl<'a> RunContext<'a> {
    fn new(run_id: &'a RunId, turn_id: &'a TurnId) -> Self {
        Self {
            run_id: Some(run_id),
            turn_id: Some(turn_id),
        }
    }

    fn from_options(run_id: Option<&'a RunId>, turn_id: Option<&'a TurnId>) -> Self {
        Self { run_id, turn_id }
    }

    fn from_run_only(run_id: Option<&'a RunId>) -> Self {
        Self {
            run_id,
            turn_id: None,
        }
    }

    fn parts(self) -> Option<(&'a RunId, &'a TurnId)> {
        match (self.run_id, self.turn_id) {
            (Some(run_id), Some(turn_id)) => Some((run_id, turn_id)),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CreateSessionRequest {
    pub cwd: String,
    pub mode: SessionMode,
    pub permission_mode: PermissionMode,
    pub title: Option<String>,
    pub model: Option<String>,
    pub parent_session_id: Option<SessionId>,
    pub metadata: serde_json::Map<String, Value>,
}

impl CreateSessionRequest {
    pub fn interactive(cwd: impl Into<String>) -> Self {
        Self {
            cwd: cwd.into(),
            mode: SessionMode::Interactive,
            permission_mode: PermissionMode::Default,
            title: None,
            model: None,
            parent_session_id: None,
            metadata: Default::default(),
        }
    }

    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self
    }
}

#[derive(Debug, Clone)]
pub struct StartRunRequest {
    pub session_id: SessionId,
    pub trigger: TriggerKind,
    pub parent_run_id: Option<RunId>,
    pub lane_id: Option<crate::protocol::LaneId>,
    pub agent_id: Option<crate::protocol::AgentId>,
    pub model: Option<String>,
    pub input_message_ids: Vec<crate::protocol::EventId>,
}

impl StartRunRequest {
    pub fn user(session_id: SessionId) -> Self {
        Self {
            session_id,
            trigger: TriggerKind::User,
            parent_run_id: None,
            lane_id: None,
            agent_id: None,
            model: None,
            input_message_ids: Vec::new(),
        }
    }

    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self
    }
}

#[derive(Debug, Clone)]
pub struct RequestApprovalRequest {
    pub session_id: SessionId,
    pub run_id: Option<RunId>,
    pub tool_call_id: Option<ToolCallId>,
    pub subject: String,
    pub input: Value,
    pub cwd: Option<String>,
    pub reason: String,
    pub allowed_decisions: Vec<ApprovalDecision>,
    pub expires_at: OffsetDateTime,
}

impl RequestApprovalRequest {
    pub fn new(
        session_id: SessionId,
        subject: impl Into<String>,
        input: Value,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            session_id,
            run_id: None,
            tool_call_id: None,
            subject: subject.into(),
            input,
            cwd: None,
            reason: reason.into(),
            allowed_decisions: vec![ApprovalDecision::ApproveOnce, ApprovalDecision::Deny],
            expires_at: OffsetDateTime::now_utc() + Duration::minutes(30),
        }
    }

    pub fn for_run(mut self, run_id: RunId) -> Self {
        self.run_id = Some(run_id);
        self
    }

    pub fn for_tool_call(mut self, tool_call_id: ToolCallId) -> Self {
        self.tool_call_id = Some(tool_call_id);
        self
    }

    pub fn with_cwd(mut self, cwd: impl Into<String>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    pub fn with_allowed_decisions(mut self, decisions: Vec<ApprovalDecision>) -> Self {
        self.allowed_decisions = decisions;
        self
    }
}

#[derive(Debug, Clone)]
pub struct StartToolCallRequest {
    pub session_id: SessionId,
    pub run_id: Option<RunId>,
    pub turn_id: Option<TurnId>,
    pub name: String,
    pub input: Value,
}

impl StartToolCallRequest {
    pub fn new(session_id: SessionId, name: impl Into<String>, input: Value) -> Self {
        Self {
            session_id,
            run_id: None,
            turn_id: None,
            name: name.into(),
            input,
        }
    }

    pub fn for_run(mut self, run: &RunMeta) -> Self {
        self.run_id = Some(run.run_id.clone());
        self.turn_id = Some(run.turn_id.clone());
        self
    }
}

#[derive(Debug, Clone)]
pub struct CreateTaskRequest {
    pub session_id: SessionId,
    pub title: String,
    pub status: LifecycleStatus,
    pub parent_task_id: Option<TaskId>,
    pub lane_id: Option<LaneId>,
    pub assignee: Option<AgentId>,
    pub metadata: JsonObject,
}

impl CreateTaskRequest {
    pub fn new(session_id: SessionId, title: impl Into<String>) -> Self {
        Self {
            session_id,
            title: title.into(),
            status: LifecycleStatus::Queued,
            parent_task_id: None,
            lane_id: None,
            assignee: None,
            metadata: Default::default(),
        }
    }

    pub fn with_status(mut self, status: LifecycleStatus) -> Self {
        self.status = status;
        self
    }

    pub fn with_parent(mut self, parent_task_id: TaskId) -> Self {
        self.parent_task_id = Some(parent_task_id);
        self
    }

    pub fn with_lane(mut self, lane_id: impl Into<String>) -> Self {
        self.lane_id = Some(LaneId(lane_id.into()));
        self
    }

    pub fn with_assignee(mut self, agent_id: impl Into<String>) -> Self {
        self.assignee = Some(AgentId(agent_id.into()));
        self
    }
}

#[derive(Debug, Clone)]
pub struct CreateArtifactRequest {
    pub session_id: SessionId,
    pub uri: String,
    pub kind: String,
    pub task_id: Option<TaskId>,
    pub run_id: Option<RunId>,
    pub metadata: JsonObject,
}

impl CreateArtifactRequest {
    pub fn new(session_id: SessionId, uri: impl Into<String>, kind: impl Into<String>) -> Self {
        Self {
            session_id,
            uri: uri.into(),
            kind: kind.into(),
            task_id: None,
            run_id: None,
            metadata: Default::default(),
        }
    }

    pub fn for_task(mut self, task_id: TaskId) -> Self {
        self.task_id = Some(task_id);
        self
    }

    pub fn for_run(mut self, run_id: RunId) -> Self {
        self.run_id = Some(run_id);
        self
    }
}

#[derive(Debug, Clone)]
pub struct SpawnSubagentRequest {
    pub subagent_id: AgentId,
    pub session_id: SessionId,
    pub parent_session_id: SessionId,
    pub parent_run_id: RunId,
    pub lane_id: LaneId,
    pub goal: String,
    pub runtime: SubagentRuntime,
    pub isolation: IsolationMode,
    pub spawn_depth: u32,
    pub context_refs: Vec<String>,
    pub toolsets: Vec<String>,
    pub transcript_ref: Option<String>,
}

impl SpawnSubagentRequest {
    pub fn native(
        session_id: SessionId,
        parent_run: &RunMeta,
        lane_id: impl Into<String>,
        goal: impl Into<String>,
    ) -> Self {
        let lane_id = LaneId(lane_id.into());
        let subagent_id = AgentId(format!("subagent-{}", Uuid::new_v4()));
        Self {
            subagent_id,
            session_id: session_id.clone(),
            parent_session_id: parent_run.session_id.clone(),
            parent_run_id: parent_run.run_id.clone(),
            transcript_ref: Some(format!(
                "sessions/{}/sidechains/{}.jsonl",
                session_id.0, lane_id.0
            )),
            lane_id,
            goal: goal.into(),
            runtime: SubagentRuntime::Native,
            isolation: IsolationMode::Worktree,
            spawn_depth: 1,
            context_refs: Vec::new(),
            toolsets: Vec::new(),
        }
    }

    pub fn with_subagent_id(mut self, subagent_id: impl Into<String>) -> Self {
        self.subagent_id = AgentId(subagent_id.into());
        self
    }

    pub fn with_isolation(mut self, isolation: IsolationMode) -> Self {
        self.isolation = isolation;
        self
    }

    pub fn with_context_ref(mut self, context_ref: impl Into<String>) -> Self {
        self.context_refs.push(context_ref.into());
        self
    }

    pub fn with_toolset(mut self, toolset: impl Into<String>) -> Self {
        self.toolsets.push(toolset.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use time::OffsetDateTime;
    use uuid::Uuid;

    use crate::control::{
        ControlPlane, CreateArtifactRequest, CreateSessionRequest, CreateTaskRequest,
        RequestApprovalRequest, SpawnSubagentRequest, StartToolCallRequest,
    };
    use crate::protocol::{
        ApprovalDecision, ContentBlock, EventType, IsolationMode, LifecycleStatus, TaskPatch,
    };

    #[test]
    fn creates_session_and_projects_user_messages() {
        let root = std::env::temp_dir().join(format!("essence-control-{}", Uuid::new_v4()));
        let control = ControlPlane::new(&root);

        let session = control
            .create_session(
                CreateSessionRequest::interactive(".")
                    .with_title("Control plane")
                    .with_model("test-model"),
            )
            .unwrap();
        control
            .submit_user_message(&session.session_id, "build the next layer")
            .unwrap();

        let events = control.events(&session.session_id).unwrap();
        let projection = control.projection(&session.session_id).unwrap();

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].seq, 1);
        assert_eq!(events[1].seq, 2);
        assert_eq!(projection.session.unwrap().status, LifecycleStatus::Active);
        assert_eq!(projection.messages.len(), 1);
        assert_eq!(
            projection.messages[0].content[0],
            ContentBlock::Text {
                text: "build the next layer".to_string()
            }
        );
        assert!(control.wal_path(&session.session_id).exists());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn records_run_lifecycle_and_assistant_output() {
        let root = std::env::temp_dir().join(format!("essence-control-{}", Uuid::new_v4()));
        let control = ControlPlane::new(&root);
        let session = control
            .create_session(CreateSessionRequest::interactive("."))
            .unwrap();

        let run = control
            .start_run(crate::control::StartRunRequest::user(
                session.session_id.clone(),
            ))
            .unwrap();
        control
            .append_assistant_message(
                &session.session_id,
                Some(&run.run_id),
                Some(&run.turn_id),
                "finished",
            )
            .unwrap();
        let completed = control.complete_run(&run, None).unwrap();

        let events = control.events(&session.session_id).unwrap();
        let projection = control.projection(&session.session_id).unwrap();

        assert_eq!(events.len(), 4);
        assert_eq!(events[1].event_type, EventType::RunStarted);
        assert_eq!(events[2].run_id, Some(run.run_id.clone()));
        assert_eq!(events[3].event_type, EventType::RunStateChanged);
        assert_eq!(completed.status, LifecycleStatus::Completed);
        assert_eq!(
            projection.runs.get(&run.run_id).unwrap().status,
            LifecycleStatus::Completed
        );
        assert_eq!(projection.messages.len(), 1);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn records_session_cancel_and_event_cursor() {
        let root = std::env::temp_dir().join(format!("essence-control-{}", Uuid::new_v4()));
        let control = ControlPlane::new(&root);
        let session = control
            .create_session(CreateSessionRequest::interactive("."))
            .unwrap();
        control
            .submit_user_message(&session.session_id, "hello")
            .unwrap();
        control.cancel_session(&session.session_id).unwrap();

        let projection = control.projection(&session.session_id).unwrap();
        let events_after_first = control.events_after(&session.session_id, 1).unwrap();

        assert_eq!(
            projection.session.unwrap().status,
            LifecycleStatus::Cancelled
        );
        assert_eq!(events_after_first.len(), 2);
        assert_eq!(events_after_first[0].seq, 2);
        assert_eq!(
            events_after_first[1].event_type,
            EventType::SessionStateChanged
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn records_run_cancellation() {
        let root = std::env::temp_dir().join(format!("essence-control-{}", Uuid::new_v4()));
        let control = ControlPlane::new(&root);
        let session = control
            .create_session(CreateSessionRequest::interactive("."))
            .unwrap();
        let run = control
            .start_run(crate::control::StartRunRequest::user(
                session.session_id.clone(),
            ))
            .unwrap();

        let cancelled = control.cancel_run(&run, "user interrupted").unwrap();
        let projection = control.projection(&session.session_id).unwrap();

        assert_eq!(cancelled.status, LifecycleStatus::Cancelled);
        assert_eq!(cancelled.stop_reason, Some("user interrupted".to_string()));
        assert_eq!(
            projection.runs.get(&run.run_id).unwrap().status,
            LifecycleStatus::Cancelled
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn records_approval_request_and_resolution() {
        let root = std::env::temp_dir().join(format!("essence-control-{}", Uuid::new_v4()));
        let control = ControlPlane::new(&root);
        let session = control
            .create_session(CreateSessionRequest::interactive("."))
            .unwrap();
        let run = control
            .start_run(crate::control::StartRunRequest::user(
                session.session_id.clone(),
            ))
            .unwrap();

        let approval = control
            .request_approval(
                RequestApprovalRequest::new(
                    session.session_id.clone(),
                    "shell command",
                    json!({"command": "cargo test"}),
                    "Running project tests touches the local workspace.",
                )
                .for_run(run.run_id.clone())
                .with_cwd("."),
            )
            .unwrap();
        let resolved = control
            .resolve_approval(&approval, ApprovalDecision::ApproveOnce, "user")
            .unwrap();

        let projection = control.projection(&session.session_id).unwrap();
        let projected = projection.approvals.get(&approval.approval_id).unwrap();

        assert_eq!(resolved.status, LifecycleStatus::Completed);
        assert_eq!(projected.decision, Some(ApprovalDecision::ApproveOnce));
        assert_eq!(projected.status, LifecycleStatus::Completed);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn records_tool_call_lifecycle() {
        let root = std::env::temp_dir().join(format!("essence-control-{}", Uuid::new_v4()));
        let control = ControlPlane::new(&root);
        let session = control
            .create_session(CreateSessionRequest::interactive("."))
            .unwrap();
        let run = control
            .start_run(crate::control::StartRunRequest::user(
                session.session_id.clone(),
            ))
            .unwrap();

        let tool_call = control
            .start_tool_call(
                StartToolCallRequest::new(
                    session.session_id.clone(),
                    "shell",
                    json!({"command": "cargo test"}),
                )
                .for_run(&run),
            )
            .unwrap();
        let completed = control
            .complete_tool_call(&tool_call, json!({"exit_code": 0}))
            .unwrap();

        let projection = control.projection(&session.session_id).unwrap();
        let projected = projection.tool_calls.get(&tool_call.tool_call_id).unwrap();

        assert_eq!(completed.status, LifecycleStatus::Completed);
        assert_eq!(projected.status, LifecycleStatus::Completed);
        assert_eq!(projected.output, Some(json!({"exit_code": 0})));
        assert_eq!(projected.run_id, Some(run.run_id));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn records_tasks_and_artifacts() {
        let root = std::env::temp_dir().join(format!("essence-control-{}", Uuid::new_v4()));
        let control = ControlPlane::new(&root);
        let session = control
            .create_session(CreateSessionRequest::interactive("."))
            .unwrap();
        let run = control
            .start_run(crate::control::StartRunRequest::user(
                session.session_id.clone(),
            ))
            .unwrap();

        let task = control
            .create_task(
                CreateTaskRequest::new(session.session_id.clone(), "Wire task projection")
                    .with_status(LifecycleStatus::Running)
                    .with_lane("main")
                    .with_assignee("essence"),
            )
            .unwrap();
        control
            .update_task(
                &session.session_id,
                TaskPatch {
                    task_id: task.task_id.clone(),
                    title: Some("Wire task and artifact projection".to_string()),
                    status: Some(LifecycleStatus::Running),
                    updated_at: Some(OffsetDateTime::now_utc()),
                    assignee: None,
                    metadata: Default::default(),
                },
            )
            .unwrap();
        control.complete_task(&task).unwrap();
        let artifact = control
            .create_artifact(
                CreateArtifactRequest::new(
                    session.session_id.clone(),
                    "artifact://notes/task.md",
                    "markdown",
                )
                .for_task(task.task_id.clone())
                .for_run(run.run_id.clone()),
            )
            .unwrap();

        let projection = control.projection(&session.session_id).unwrap();
        let projected_task = projection.tasks.get(&task.task_id).unwrap();
        let projected_artifact = projection.artifacts.get(&artifact.artifact_id).unwrap();

        assert_eq!(projected_task.status, LifecycleStatus::Completed);
        assert_eq!(projected_task.title, "Wire task and artifact projection");
        assert_eq!(projected_artifact.task_id, Some(task.task_id));
        assert_eq!(projected_artifact.run_id, Some(run.run_id));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn records_subagent_lifecycle() {
        let root = std::env::temp_dir().join(format!("essence-control-{}", Uuid::new_v4()));
        let control = ControlPlane::new(&root);
        let session = control
            .create_session(CreateSessionRequest::interactive("."))
            .unwrap();
        let run = control
            .start_run(crate::control::StartRunRequest::user(
                session.session_id.clone(),
            ))
            .unwrap();

        let subagent = control
            .spawn_subagent(
                SpawnSubagentRequest::native(
                    session.session_id.clone(),
                    &run,
                    "research",
                    "Collect references",
                )
                .with_subagent_id("researcher-1")
                .with_isolation(IsolationMode::Worktree)
                .with_context_ref("event://1")
                .with_toolset("web"),
            )
            .unwrap();
        let progressed = control
            .update_subagent_progress(&subagent, LifecycleStatus::WaitingTool)
            .unwrap();
        let completed = control.complete_subagent(&progressed).unwrap();

        let projection = control.projection(&session.session_id).unwrap();
        let projected = projection.subagents.get("researcher-1").unwrap();

        assert_eq!(completed.status, LifecycleStatus::Completed);
        assert_eq!(projected.status, LifecycleStatus::Completed);
        assert_eq!(projected.lane_id.0, "research");
        assert_eq!(projected.context_refs, vec!["event://1".to_string()]);
        assert_eq!(projected.toolsets, vec!["web".to_string()]);

        let _ = std::fs::remove_dir_all(root);
    }
}
