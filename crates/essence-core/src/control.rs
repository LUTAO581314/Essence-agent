use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::projection::{LedgerProjection, ProjectionError};
use crate::protocol::{
    ContentBlock, EventEnvelope, EventSource, EventType, EventVisibility, LifecycleStatus,
    MessagePayload, MessageRole, PermissionMode, SessionId, SessionMeta, SessionMode,
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

    fn wal(&self, session_id: &SessionId) -> JsonlWal {
        JsonlWal::new(self.wal_path(session_id))
    }

    fn transcript_uri(&self, session_id: &SessionId) -> String {
        format!("sessions/{}.jsonl", session_id.0)
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

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use crate::control::{ControlPlane, CreateSessionRequest};
    use crate::protocol::{ContentBlock, LifecycleStatus};

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
}
