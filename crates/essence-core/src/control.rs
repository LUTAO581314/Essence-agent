use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::projection::{LedgerProjection, ProjectionError};
use crate::protocol::{
    ContentBlock, EventEnvelope, EventSource, EventType, EventVisibility, LifecycleStatus,
    MessagePayload, MessageRole, PermissionMode, RunId, RunMeta, SessionId, SessionMeta,
    SessionMode, TriggerKind, TurnId,
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

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use crate::control::{ControlPlane, CreateSessionRequest};
    use crate::protocol::{ContentBlock, EventType, LifecycleStatus};

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
}
