use serde::{Deserialize, Serialize};

use crate::control::{ControlPlane, ControlResult, CreateSessionRequest};
#[cfg(feature = "mcp")]
use crate::mcp::McpAdapterManifest;
use crate::memory_index::MemorySearchHit;
#[cfg(feature = "swarm")]
use crate::protocol::{AgentHeartbeat, LifecycleStatus, SubagentBudget};
use crate::protocol::{ApprovalRequest, EventEnvelope, SessionId, SessionMeta};
use crate::snapshot::ProjectionSnapshot;
#[cfg(feature = "swarm")]
use crate::swarm::{SwarmAgentSpec, SwarmRuntime, SwarmTick};

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

#[cfg(feature = "swarm")]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApiRegisterAgentRequest {
    pub session_id: SessionId,
    pub agent_id: String,
    pub lane_id: String,
    pub role: String,
    #[serde(default)]
    pub toolsets: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<SubagentBudget>,
}

#[cfg(feature = "swarm")]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiAgentHeartbeatRequest {
    pub session_id: SessionId,
    pub agent_id: String,
    pub status: LifecycleStatus,
}

#[cfg(feature = "swarm")]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiSwarmTickRequest {
    pub session_id: SessionId,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApiMemorySearchRequest {
    pub session_id: SessionId,
    pub query: String,
    pub limit: usize,
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

    #[cfg(feature = "swarm")]
    pub fn register_agent(
        &self,
        request: ApiRegisterAgentRequest,
    ) -> ControlResult<Option<SwarmAgentSpec>> {
        let mut agent = SwarmAgentSpec::native(request.agent_id, request.lane_id, request.role);
        for toolset in request.toolsets {
            agent = agent.with_toolset(toolset);
        }
        if let Some(budget) = request.budget {
            agent = agent.with_budget(budget);
        }
        SwarmRuntime::new(self.control.clone()).register_agent(&request.session_id, agent)
    }

    #[cfg(feature = "swarm")]
    pub fn agent_heartbeat(
        &self,
        request: ApiAgentHeartbeatRequest,
    ) -> ControlResult<Option<AgentHeartbeat>> {
        SwarmRuntime::new(self.control.clone()).heartbeat(
            &request.session_id,
            &crate::protocol::AgentId(request.agent_id),
            request.status,
        )
    }

    #[cfg(feature = "swarm")]
    pub fn swarm_tick(&self, request: ApiSwarmTickRequest) -> ControlResult<SwarmTick> {
        SwarmRuntime::new(self.control.clone()).tick_session(&request.session_id)
    }

    pub fn memory_search(
        &self,
        request: ApiMemorySearchRequest,
    ) -> ControlResult<Vec<MemorySearchHit>> {
        let store = self.control.memory_store(&request.session_id)?;
        let index = crate::memory_index::MemoryIndex::from_store(&store);
        Ok(index.search(&request.query, request.limit))
    }

    #[cfg(feature = "mcp")]
    pub fn mcp_manifest(&self) -> McpAdapterManifest {
        let tools = [
            crate::registry::ToolSpec::new(
                "essence_events_after",
                "Return ledger events after a sequence cursor.",
                crate::registry::ToolPermission::Allow,
            )
            .with_capability("read_only"),
            crate::registry::ToolSpec::new(
                "essence_swarm_tick",
                "Advance one scheduler tick for a session.",
                crate::registry::ToolPermission::RequireApproval,
            ),
            crate::registry::ToolSpec::new(
                "essence_memory_search",
                "Search saved local memories for a session.",
                crate::registry::ToolPermission::Allow,
            )
            .with_capability("read_only"),
        ];
        McpAdapterManifest::from_tools("essence", tools.iter())
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    #[cfg(all(feature = "mcp", feature = "swarm"))]
    use crate::api::ApiMemorySearchRequest;
    #[cfg(feature = "swarm")]
    use crate::api::{ApiAgentHeartbeatRequest, ApiRegisterAgentRequest, ApiSwarmTickRequest};
    use crate::api::{
        ApiCreateSessionRequest, ApiEventsAfterRequest, ApiSendMessageRequest, ControlApi,
    };
    use crate::control::ControlPlane;
    use crate::protocol::EventType;
    #[cfg(feature = "swarm")]
    use crate::protocol::{LifecycleStatus, SubagentBudget};

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

    #[cfg(all(feature = "mcp", feature = "swarm"))]
    #[test]
    fn api_facade_registers_agents_ticks_and_searches_memory() {
        let root = std::env::temp_dir().join(format!("essence-api-{}", Uuid::new_v4()));
        let api = ControlApi::new(ControlPlane::new(&root));
        let session = api
            .create_session(ApiCreateSessionRequest::interactive("."))
            .unwrap();
        api.register_agent(ApiRegisterAgentRequest {
            session_id: session.session_id.clone(),
            agent_id: "researcher".to_string(),
            lane_id: "research".to_string(),
            role: "Research".to_string(),
            toolsets: vec!["gitnexus".to_string()],
            budget: Some(SubagentBudget {
                max_turns: Some(2),
                max_tool_calls: Some(4),
                max_tokens: None,
            }),
        })
        .unwrap();
        api.agent_heartbeat(ApiAgentHeartbeatRequest {
            session_id: session.session_id.clone(),
            agent_id: "researcher".to_string(),
            status: LifecycleStatus::Idle,
        })
        .unwrap();
        api.control()
            .create_task(crate::control::CreateTaskRequest::new(
                session.session_id.clone(),
                "Research memory index",
            ))
            .unwrap();

        let tick = api
            .swarm_tick(ApiSwarmTickRequest {
                session_id: session.session_id.clone(),
            })
            .unwrap();
        let search = api
            .memory_search(ApiMemorySearchRequest {
                session_id: session.session_id.clone(),
                query: "durable ledger".to_string(),
                limit: 3,
            })
            .unwrap();
        let manifest = api.mcp_manifest();

        assert!(tick.dispatched.len() <= 1);
        assert!(search.is_empty());
        assert_eq!(manifest.server_name, "essence");
        assert!(manifest
            .tools
            .iter()
            .any(|tool| tool.name == "essence_swarm_tick"));

        let _ = std::fs::remove_dir_all(root);
    }
}
