use std::collections::BTreeMap;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::protocol::{
    AgentHeartbeat, AgentId, AgentRecord, ApprovalDecision, ApprovalId, ApprovalRequest,
    ArtifactId, ArtifactRecord, EventEnvelope, EventType, LifecycleStatus, MemoryId, MemoryRecord,
    MessagePayload, RunId, RunMeta, SessionMeta, SessionStatePatch, SubagentMeta, TaskId,
    TaskPatch, TaskRecord, ToolCallId, ToolCallRecord,
};

#[derive(Debug, thiserror::Error)]
pub enum ProjectionError {
    #[error("could not decode {event_type:?} payload at seq {seq}: {source}")]
    Payload {
        seq: u64,
        event_type: EventType,
        #[source]
        source: serde_json::Error,
    },
}

pub type ProjectionResult<T> = Result<T, ProjectionError>;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct LedgerProjection {
    pub latest_seq: u64,
    pub session: Option<SessionMeta>,
    pub runs: BTreeMap<RunId, RunMeta>,
    pub agents: BTreeMap<AgentId, AgentRecord>,
    pub agent_heartbeats: BTreeMap<AgentId, AgentHeartbeat>,
    pub subagents: BTreeMap<String, SubagentMeta>,
    pub approvals: BTreeMap<ApprovalId, ApprovalRequest>,
    pub tool_calls: BTreeMap<ToolCallId, ToolCallRecord>,
    pub tasks: BTreeMap<TaskId, TaskRecord>,
    pub artifacts: BTreeMap<ArtifactId, ArtifactRecord>,
    pub memories: BTreeMap<MemoryId, MemoryRecord>,
    pub messages: Vec<MessagePayload>,
}

impl LedgerProjection {
    pub fn replay<'a>(
        events: impl IntoIterator<Item = &'a EventEnvelope>,
    ) -> ProjectionResult<Self> {
        let mut projection = Self::default();
        for event in events {
            projection.apply(event)?;
        }
        Ok(projection)
    }

    pub fn apply(&mut self, event: &EventEnvelope) -> ProjectionResult<()> {
        self.latest_seq = self.latest_seq.max(event.seq);

        match &event.event_type {
            EventType::SessionMeta => {
                let session = decode_payload::<SessionMeta>(event)?;
                self.session = Some(session);
            }
            EventType::SessionStateChanged => {
                let patch = decode_payload::<SessionStatePatch>(event)?;
                if let Some(session) = &mut self.session {
                    session.status = patch.status;
                    session.updated_at = patch.updated_at;
                    if let Some(title) = patch.title {
                        session.title = Some(title);
                    }
                }
            }
            EventType::RunStarted | EventType::RunStateChanged => {
                let run = decode_payload::<RunMeta>(event)?;
                self.runs.insert(run.run_id.clone(), run);
            }
            EventType::AgentRegistered | EventType::AgentStateChanged => {
                let agent = decode_payload::<AgentRecord>(event)?;
                self.agents.insert(agent.agent_id.clone(), agent);
            }
            EventType::AgentHeartbeat => {
                let heartbeat = decode_payload::<AgentHeartbeat>(event)?;
                self.agent_heartbeats
                    .insert(heartbeat.agent_id.clone(), heartbeat);
            }
            EventType::SubagentSpawned
            | EventType::SubagentProgress
            | EventType::SubagentSteered
            | EventType::SubagentCompleted
            | EventType::SubagentFailed
            | EventType::SubagentCancelled => {
                let subagent = decode_payload::<SubagentMeta>(event)?;
                self.subagents
                    .insert(subagent.subagent_id.0.clone(), subagent);
            }
            EventType::ApprovalRequested | EventType::ApprovalResolved => {
                let approval = decode_payload::<ApprovalRequest>(event)?;
                self.approvals
                    .insert(approval.approval_id.clone(), approval);
            }
            EventType::ToolCallStarted
            | EventType::ToolCallOutput
            | EventType::ToolCallCompleted
            | EventType::ToolCallFailed => {
                let tool_call = decode_payload::<ToolCallRecord>(event)?;
                self.tool_calls
                    .insert(tool_call.tool_call_id.clone(), tool_call);
            }
            EventType::TaskCreated => {
                let task = decode_payload::<TaskRecord>(event)?;
                self.tasks.insert(task.task_id.clone(), task);
            }
            EventType::TaskStateChanged | EventType::TaskBlocked | EventType::TaskCompleted => {
                let patch = decode_payload::<TaskPatch>(event)?;
                if let Some(task) = self.tasks.get_mut(&patch.task_id) {
                    if let Some(title) = patch.title {
                        task.title = title;
                    }
                    if let Some(status) = patch.status {
                        task.status = status;
                    } else if matches!(&event.event_type, EventType::TaskBlocked) {
                        task.status = LifecycleStatus::WaitingApproval;
                    } else if matches!(&event.event_type, EventType::TaskCompleted) {
                        task.status = LifecycleStatus::Completed;
                    }
                    if let Some(updated_at) = patch.updated_at {
                        task.updated_at = updated_at;
                    }
                    if let Some(assignee) = patch.assignee {
                        task.assignee = Some(assignee);
                    }
                    task.metadata.extend(patch.metadata);
                }
            }
            EventType::ArtifactCreated => {
                let artifact = decode_payload::<ArtifactRecord>(event)?;
                self.artifacts
                    .insert(artifact.artifact_id.clone(), artifact);
            }
            EventType::MemoryCandidate | EventType::MemorySaved => {
                let memory = decode_payload::<MemoryRecord>(event)?;
                self.memories.insert(memory.memory_id.clone(), memory);
            }
            EventType::MessageUser
            | EventType::MessageAssistantDelta
            | EventType::MessageAssistantFinal => {
                self.messages.push(decode_payload::<MessagePayload>(event)?);
            }
            _ => {}
        }

        Ok(())
    }

    pub fn pending_approvals(&self) -> impl Iterator<Item = &ApprovalRequest> {
        self.approvals
            .values()
            .filter(|approval| approval.status == LifecycleStatus::WaitingApproval)
    }

    pub fn pending_approvals_for_tool_call<'a>(
        &'a self,
        tool_call_id: &'a ToolCallId,
    ) -> impl Iterator<Item = &'a ApprovalRequest> {
        self.pending_approvals()
            .filter(move |approval| approval.tool_call_id.as_ref() == Some(tool_call_id))
    }

    pub fn pending_approvals_for_run<'a>(
        &'a self,
        run_id: &'a RunId,
    ) -> impl Iterator<Item = &'a ApprovalRequest> {
        self.pending_approvals()
            .filter(move |approval| approval.run_id.as_ref() == Some(run_id))
    }

    pub fn approval_grants_for_subject<'a>(
        &'a self,
        subject: &'a str,
    ) -> impl Iterator<Item = &'a ApprovalRequest> {
        self.approvals.values().filter(move |approval| {
            approval.status == LifecycleStatus::Completed
                && approval.subject == subject
                && matches!(
                    approval.decision,
                    Some(ApprovalDecision::ApproveSession | ApprovalDecision::ApproveAlways)
                )
        })
    }

    pub fn has_approval_grant_for_subject(&self, subject: &str) -> bool {
        self.approval_grants_for_subject(subject).next().is_some()
    }

    pub fn approval_always_grants_for_subject<'a>(
        &'a self,
        subject: &'a str,
    ) -> impl Iterator<Item = &'a ApprovalRequest> {
        self.approvals.values().filter(move |approval| {
            approval.status == LifecycleStatus::Completed
                && approval.subject == subject
                && approval.decision == Some(ApprovalDecision::ApproveAlways)
        })
    }

    pub fn has_approval_always_grant_for_subject(&self, subject: &str) -> bool {
        self.approval_always_grants_for_subject(subject)
            .next()
            .is_some()
    }
}

fn decode_payload<T: DeserializeOwned>(event: &EventEnvelope) -> ProjectionResult<T> {
    serde_json::from_value(event.payload.clone()).map_err(|source| ProjectionError::Payload {
        seq: event.seq,
        event_type: event.event_type.clone(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::{json, to_value};
    use time::OffsetDateTime;
    use uuid::Uuid;

    use crate::protocol::{
        ApprovalDecision, ApprovalId, ApprovalRequest, ArtifactId, ArtifactRecord, ContentBlock,
        EventEnvelope, EventSource, EventType, EventVisibility, LifecycleStatus, MemoryId,
        MemoryRecord, MessagePayload, MessageRole, PermissionMode, RunId, RunMeta, SessionId,
        SessionMeta, SessionMode, TaskId, TaskPatch, TaskRecord, ToolCallId, TriggerKind, TurnId,
    };

    use super::LedgerProjection;

    #[test]
    fn replays_core_ledger_views() {
        let now = OffsetDateTime::now_utc();
        let session_id = SessionId(Uuid::new_v4());
        let run_id = RunId(Uuid::new_v4());
        let turn_id = TurnId(Uuid::new_v4());
        let task_id = TaskId(Uuid::new_v4());
        let artifact_id = ArtifactId(Uuid::new_v4());
        let memory_id = MemoryId(Uuid::new_v4());

        let session = SessionMeta {
            session_id: session_id.clone(),
            parent_session_id: None,
            created_at: now,
            updated_at: now,
            cwd: ".".to_string(),
            mode: SessionMode::Interactive,
            permission_mode: PermissionMode::Default,
            status: LifecycleStatus::Active,
            title: Some("Build kernel".to_string()),
            model: Some("gpt".to_string()),
            transcript_uri: "sessions/main.jsonl".to_string(),
            metadata: Default::default(),
        };
        let run = RunMeta {
            run_id: run_id.clone(),
            turn_id,
            session_id: session_id.clone(),
            parent_run_id: None,
            trigger: TriggerKind::User,
            status: LifecycleStatus::Running,
            started_at: now,
            ended_at: None,
            lane_id: None,
            agent_id: None,
            model: Some("gpt".to_string()),
            input_message_ids: Vec::new(),
            usage: None,
            stop_reason: None,
        };
        let task = TaskRecord {
            task_id: task_id.clone(),
            session_id: session_id.clone(),
            title: "Project WAL".to_string(),
            status: LifecycleStatus::Running,
            created_at: now,
            updated_at: now,
            parent_task_id: None,
            lane_id: None,
            assignee: None,
            metadata: Default::default(),
        };
        let artifact = ArtifactRecord {
            artifact_id: artifact_id.clone(),
            session_id: session_id.clone(),
            uri: "artifact://notes.md".to_string(),
            kind: "markdown".to_string(),
            created_at: now,
            task_id: Some(task_id.clone()),
            run_id: Some(run_id),
            metadata: Default::default(),
        };
        let memory = MemoryRecord {
            memory_id: memory_id.clone(),
            session_id: session_id.clone(),
            kind: "decision".to_string(),
            text: "Use JSONL as the source of truth.".to_string(),
            status: LifecycleStatus::Completed,
            created_at: now,
            updated_at: now,
            source_event_ids: Vec::new(),
            run_id: None,
            confidence: Some(0.9),
            metadata: Default::default(),
        };

        let events = vec![
            envelope(
                1,
                session_id.clone(),
                EventType::SessionMeta,
                to_value(session).unwrap(),
            ),
            envelope(
                2,
                session_id.clone(),
                EventType::RunStarted,
                to_value(run).unwrap(),
            ),
            envelope(
                3,
                session_id.clone(),
                EventType::TaskCreated,
                to_value(task).unwrap(),
            ),
            envelope(
                4,
                session_id.clone(),
                EventType::TaskCompleted,
                to_value(TaskPatch {
                    task_id: task_id.clone(),
                    title: None,
                    status: None,
                    updated_at: Some(now),
                    assignee: None,
                    metadata: Default::default(),
                })
                .unwrap(),
            ),
            envelope(
                5,
                session_id.clone(),
                EventType::ArtifactCreated,
                to_value(artifact).unwrap(),
            ),
            envelope(
                6,
                session_id.clone(),
                EventType::MemorySaved,
                to_value(memory).unwrap(),
            ),
            envelope(
                7,
                session_id,
                EventType::MessageAssistantFinal,
                to_value(MessagePayload {
                    role: MessageRole::Assistant,
                    content: vec![ContentBlock::Text {
                        text: "done".to_string(),
                    }],
                    usage: None,
                    origin: None,
                })
                .unwrap(),
            ),
        ];

        let projection = LedgerProjection::replay(&events).unwrap();

        assert_eq!(projection.latest_seq, 7);
        assert_eq!(projection.session.unwrap().status, LifecycleStatus::Active);
        assert_eq!(
            projection.tasks.get(&task_id).unwrap().status,
            LifecycleStatus::Completed
        );
        assert_eq!(
            projection.artifacts.get(&artifact_id).unwrap().kind,
            "markdown"
        );
        assert_eq!(
            projection.memories.get(&memory_id).unwrap().text,
            "Use JSONL as the source of truth."
        );
        assert_eq!(projection.messages.len(), 1);
    }

    #[test]
    fn returns_payload_errors_with_event_context() {
        let session_id = SessionId(Uuid::new_v4());
        let event = envelope(
            7,
            session_id,
            EventType::TaskCreated,
            json!({"title": "missing ids"}),
        );

        let error = LedgerProjection::replay([&event]).unwrap_err();

        assert!(error.to_string().contains("TaskCreated"));
        assert!(error.to_string().contains("seq 7"));
    }

    #[test]
    fn filters_pending_approvals() {
        let session_id = SessionId(Uuid::new_v4());
        let run_id = RunId(Uuid::new_v4());
        let tool_call_id = ToolCallId(Uuid::new_v4());
        let pending = approval(
            session_id.clone(),
            run_id.clone(),
            tool_call_id.clone(),
            LifecycleStatus::WaitingApproval,
        );
        let resolved = approval(
            session_id.clone(),
            run_id.clone(),
            ToolCallId(Uuid::new_v4()),
            LifecycleStatus::Completed,
        );
        let events = vec![
            envelope(
                1,
                session_id.clone(),
                EventType::ApprovalRequested,
                to_value(pending.clone()).unwrap(),
            ),
            envelope(
                2,
                session_id,
                EventType::ApprovalResolved,
                to_value(resolved).unwrap(),
            ),
        ];

        let projection = LedgerProjection::replay(&events).unwrap();
        let pending = projection.pending_approvals().collect::<Vec<_>>();
        let by_tool = projection
            .pending_approvals_for_tool_call(&tool_call_id)
            .collect::<Vec<_>>();
        let by_run = projection
            .pending_approvals_for_run(&run_id)
            .collect::<Vec<_>>();

        assert_eq!(pending.len(), 1);
        assert_eq!(by_tool.len(), 1);
        assert_eq!(by_run.len(), 1);
        assert_eq!(pending[0].approval_id, by_tool[0].approval_id);
    }

    #[test]
    fn filters_session_approval_grants() {
        let session_id = SessionId(Uuid::new_v4());
        let run_id = RunId(Uuid::new_v4());
        let mut grant = approval(
            session_id.clone(),
            run_id.clone(),
            ToolCallId(Uuid::new_v4()),
            LifecycleStatus::Completed,
        );
        grant.subject = "code.list".to_string();
        grant.decision = Some(ApprovalDecision::ApproveSession);
        let mut one_shot = approval(
            session_id.clone(),
            run_id,
            ToolCallId(Uuid::new_v4()),
            LifecycleStatus::Completed,
        );
        one_shot.subject = "code.list".to_string();
        one_shot.decision = Some(ApprovalDecision::ApproveOnce);
        let events = vec![
            envelope(
                1,
                session_id.clone(),
                EventType::ApprovalResolved,
                to_value(grant.clone()).unwrap(),
            ),
            envelope(
                2,
                session_id,
                EventType::ApprovalResolved,
                to_value(one_shot).unwrap(),
            ),
        ];

        let projection = LedgerProjection::replay(&events).unwrap();
        let grants = projection
            .approval_grants_for_subject("code.list")
            .collect::<Vec<_>>();

        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].approval_id, grant.approval_id);
        assert!(projection.has_approval_grant_for_subject("code.list"));
        assert!(!projection.has_approval_grant_for_subject("other.tool"));
    }

    #[test]
    fn filters_approve_always_grants() {
        let session_id = SessionId(Uuid::new_v4());
        let run_id = RunId(Uuid::new_v4());
        let mut always = approval(
            session_id.clone(),
            run_id.clone(),
            ToolCallId(Uuid::new_v4()),
            LifecycleStatus::Completed,
        );
        always.subject = "code.list".to_string();
        always.decision = Some(ApprovalDecision::ApproveAlways);
        let mut session_only = approval(
            session_id.clone(),
            run_id,
            ToolCallId(Uuid::new_v4()),
            LifecycleStatus::Completed,
        );
        session_only.subject = "code.list".to_string();
        session_only.decision = Some(ApprovalDecision::ApproveSession);
        let events = vec![
            envelope(
                1,
                session_id.clone(),
                EventType::ApprovalResolved,
                to_value(always.clone()).unwrap(),
            ),
            envelope(
                2,
                session_id,
                EventType::ApprovalResolved,
                to_value(session_only).unwrap(),
            ),
        ];

        let projection = LedgerProjection::replay(&events).unwrap();
        let grants = projection
            .approval_always_grants_for_subject("code.list")
            .collect::<Vec<_>>();

        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].approval_id, always.approval_id);
        assert!(projection.has_approval_always_grant_for_subject("code.list"));
    }

    fn envelope(
        seq: u64,
        session_id: SessionId,
        event_type: EventType,
        payload: serde_json::Value,
    ) -> EventEnvelope {
        EventEnvelope::new(
            seq,
            session_id,
            event_type,
            EventSource::System,
            EventVisibility::Audit,
            payload,
        )
    }

    fn approval(
        session_id: SessionId,
        run_id: RunId,
        tool_call_id: ToolCallId,
        status: LifecycleStatus,
    ) -> ApprovalRequest {
        ApprovalRequest {
            approval_id: ApprovalId(Uuid::new_v4()),
            session_id,
            run_id: Some(run_id),
            tool_call_id: Some(tool_call_id),
            subject: "code.list".to_string(),
            input: json!({}),
            cwd: None,
            reason: "test".to_string(),
            allowed_decisions: Vec::new(),
            status,
            expires_at: OffsetDateTime::now_utc(),
            decision: None,
            resolved_at: None,
            resolved_by: None,
        }
    }
}
