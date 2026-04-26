use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::Value;

use crate::projection::{LedgerProjection, ProjectionError};
use crate::protocol::{
    ContentBlock, EventEnvelope, EventSource, EventType, EventVisibility, LifecycleStatus,
    MessagePayload, MessageRole, SubagentMeta,
};
use crate::wal::{JsonlWal, WalError};

#[derive(Debug, thiserror::Error)]
pub enum SidechainError {
    #[error(transparent)]
    Wal(#[from] WalError),
    #[error(transparent)]
    Projection(#[from] ProjectionError),
    #[error("subagent {subagent_id} has no transcript reference")]
    MissingTranscriptRef { subagent_id: String },
    #[error("sidechain transcript path must be relative: {0}")]
    AbsoluteTranscriptRef(String),
    #[error("sidechain transcript path cannot contain parent segments: {0}")]
    ParentSegmentTranscriptRef(String),
    #[error("could not encode sidechain event payload: {0}")]
    Payload(#[from] serde_json::Error),
}

pub type SidechainResult<T> = Result<T, SidechainError>;

#[derive(Debug, Clone)]
pub struct SidechainTranscript {
    subagent: SubagentMeta,
    wal: JsonlWal,
}

impl SidechainTranscript {
    pub fn open(root: impl AsRef<Path>, subagent: SubagentMeta) -> SidechainResult<Self> {
        let transcript_ref = subagent.transcript_ref.as_ref().ok_or_else(|| {
            SidechainError::MissingTranscriptRef {
                subagent_id: subagent.subagent_id.0.clone(),
            }
        })?;
        let path = resolve_transcript_ref(root.as_ref(), transcript_ref)?;
        Ok(Self {
            subagent,
            wal: JsonlWal::new(path),
        })
    }

    pub fn subagent(&self) -> &SubagentMeta {
        &self.subagent
    }

    pub fn path(&self) -> &Path {
        self.wal.path()
    }

    pub fn append_assistant_message(
        &self,
        text: impl Into<String>,
    ) -> SidechainResult<EventEnvelope> {
        let payload = MessagePayload {
            role: MessageRole::Assistant,
            content: vec![ContentBlock::Text { text: text.into() }],
            usage: None,
            origin: Some(self.subagent.subagent_id.0.clone()),
        };

        self.append_typed_event(
            EventType::MessageAssistantFinal,
            EventVisibility::User,
            &payload,
        )
    }

    pub fn append_progress(&self, status: LifecycleStatus) -> SidechainResult<EventEnvelope> {
        let mut payload = self.subagent.clone();
        payload.status = status;

        self.append_typed_event(
            EventType::SubagentProgress,
            EventVisibility::Audit,
            &payload,
        )
    }

    pub fn append_event(
        &self,
        event_type: EventType,
        visibility: EventVisibility,
        payload: Value,
    ) -> SidechainResult<EventEnvelope> {
        let events = self.wal.replay()?;
        let seq = events.last().map_or(1, |event| event.seq + 1);
        let event = EventEnvelope::new(
            seq,
            self.subagent.session_id.clone(),
            event_type,
            EventSource::Subagent(self.subagent.subagent_id.0.clone()),
            visibility,
            payload,
        );
        self.wal.append(&event)?;
        Ok(event)
    }

    pub fn events(&self) -> SidechainResult<Vec<EventEnvelope>> {
        self.wal.replay().map_err(SidechainError::from)
    }

    pub fn projection(&self) -> SidechainResult<LedgerProjection> {
        let events = self.events()?;
        LedgerProjection::replay(&events).map_err(SidechainError::from)
    }

    fn append_typed_event<T: Serialize>(
        &self,
        event_type: EventType,
        visibility: EventVisibility,
        payload: &T,
    ) -> SidechainResult<EventEnvelope> {
        self.append_event(event_type, visibility, serde_json::to_value(payload)?)
    }
}

pub fn resolve_transcript_ref(
    root: impl AsRef<Path>,
    transcript_ref: &str,
) -> SidechainResult<PathBuf> {
    let relative = Path::new(transcript_ref);
    if relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                std::path::Component::Prefix(_) | std::path::Component::RootDir
            )
        })
    {
        return Err(SidechainError::AbsoluteTranscriptRef(
            transcript_ref.to_string(),
        ));
    }
    if relative
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(SidechainError::ParentSegmentTranscriptRef(
            transcript_ref.to_string(),
        ));
    }
    Ok(root.as_ref().join(relative))
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use crate::control::{
        ControlPlane, CreateSessionRequest, SpawnSubagentRequest, StartRunRequest,
    };
    use crate::protocol::{EventType, LifecycleStatus};

    use super::resolve_transcript_ref;

    #[test]
    fn records_sidechain_messages_and_progress() {
        let root = std::env::temp_dir().join(format!("essence-sidechain-{}", Uuid::new_v4()));
        let control = ControlPlane::new(&root);
        let session = control
            .create_session(CreateSessionRequest::interactive("."))
            .unwrap();
        let run = control
            .start_run(StartRunRequest::user(session.session_id.clone()))
            .unwrap();
        let subagent = control
            .spawn_subagent(
                SpawnSubagentRequest::native(
                    session.session_id.clone(),
                    &run,
                    "research",
                    "Collect references",
                )
                .with_subagent_id("researcher-1"),
            )
            .unwrap();

        let sidechain = control.sidechain(&subagent).unwrap();
        sidechain
            .append_assistant_message("Found two relevant notes.")
            .unwrap();
        sidechain
            .append_progress(LifecycleStatus::WaitingTool)
            .unwrap();

        let events = sidechain.events().unwrap();
        let projection = sidechain.projection().unwrap();

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].seq, 1);
        assert_eq!(events[0].event_type, EventType::MessageAssistantFinal);
        assert_eq!(events[1].event_type, EventType::SubagentProgress);
        assert_eq!(projection.messages.len(), 1);
        assert_eq!(
            projection.subagents.get("researcher-1").unwrap().status,
            LifecycleStatus::WaitingTool
        );
        assert!(sidechain.path().exists());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn rejects_sidechain_paths_outside_root() {
        assert!(resolve_transcript_ref(".", "../outside.jsonl").is_err());
        assert!(resolve_transcript_ref(".", "/tmp/outside.jsonl").is_err());
    }
}
