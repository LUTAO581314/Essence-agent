use serde::{Deserialize, Serialize};

use crate::control::{ControlPlane, ControlResult, CreateSessionRequest};
use crate::protocol::{ApprovalRequest, EventEnvelope, SessionId, SessionMeta};
use crate::snapshot::ProjectionSnapshot;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApiCreateSessionRequest {
    pub cwd: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

impl ApiCreateSessionRequest {
    pub fn interactive(cwd: impl Into<String>) -> Self {
        Self {
            cwd: cwd.into(),
            title: None,
            model: None,
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

impl From<ApiCreateSessionRequest> for CreateSessionRequest {
    fn from(request: ApiCreateSessionRequest) -> Self {
        let mut create = CreateSessionRequest::interactive(request.cwd);
        if let Some(title) = request.title {
            create = create.with_title(title);
        }
        if let Some(model) = request.model {
            create = create.with_model(model);
        }
        create
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApiSendMessageRequest {
    pub session_id: SessionId,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiEventsAfterRequest {
    pub session_id: SessionId,
    pub after_seq: u64,
}

#[derive(Debug, Clone)]
pub struct ControlApi {
    control: ControlPlane,
}

impl ControlApi {
    pub fn new(control: ControlPlane) -> Self {
        Self { control }
    }

    pub fn control(&self) -> &ControlPlane {
        &self.control
    }

    pub fn create_session(&self, request: ApiCreateSessionRequest) -> ControlResult<SessionMeta> {
        self.control.create_session(request.into())
    }

    pub fn send_message(&self, request: ApiSendMessageRequest) -> ControlResult<EventEnvelope> {
        self.control
            .submit_user_message(&request.session_id, request.text)
    }

    pub fn events_after(
        &self,
        request: ApiEventsAfterRequest,
    ) -> ControlResult<Vec<EventEnvelope>> {
        self.control
            .events_after(&request.session_id, request.after_seq)
    }

    pub fn pending_approvals(&self, session_id: &SessionId) -> ControlResult<Vec<ApprovalRequest>> {
        self.control.pending_approvals(session_id)
    }

    pub fn write_projection_snapshot(
        &self,
        session_id: &SessionId,
    ) -> ControlResult<ProjectionSnapshot> {
        self.control.write_projection_snapshot(session_id)
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use crate::api::{
        ApiCreateSessionRequest, ApiEventsAfterRequest, ApiSendMessageRequest, ControlApi,
    };
    use crate::control::ControlPlane;
    use crate::protocol::EventType;

    #[test]
    fn api_facade_creates_session_and_streams_events() {
        let root = std::env::temp_dir().join(format!("essence-api-{}", Uuid::new_v4()));
        let api = ControlApi::new(ControlPlane::new(&root));
        let session = api
            .create_session(ApiCreateSessionRequest::interactive(".").with_title("API"))
            .unwrap();

        api.send_message(ApiSendMessageRequest {
            session_id: session.session_id.clone(),
            text: "hello api".to_string(),
        })
        .unwrap();
        let events = api
            .events_after(ApiEventsAfterRequest {
                session_id: session.session_id.clone(),
                after_seq: 1,
            })
            .unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, EventType::MessageUser);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn api_facade_writes_projection_snapshots() {
        let root = std::env::temp_dir().join(format!("essence-api-{}", Uuid::new_v4()));
        let api = ControlApi::new(ControlPlane::new(&root));
        let session = api
            .create_session(ApiCreateSessionRequest::interactive("."))
            .unwrap();

        let snapshot = api.write_projection_snapshot(&session.session_id).unwrap();

        assert_eq!(snapshot.latest_seq, 1);
        assert!(api
            .control()
            .snapshot_store()
            .path_for_session(&session.session_id)
            .exists());

        let _ = std::fs::remove_dir_all(root);
    }
}
