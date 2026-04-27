use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::plugin::{PluginKind, PluginManifest, PluginSource};
use crate::projection::LedgerProjection;
use crate::protocol::{AgentHeartbeat, AgentId, LifecycleStatus, TaskRecord};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserDaemonDescriptor {
    pub discovery_ref: String,
    pub health_ref: String,
    pub isolation: String,
}

impl BrowserDaemonDescriptor {
    pub fn local(discovery_ref: impl Into<String>) -> Self {
        let discovery_ref = discovery_ref.into();
        Self {
            health_ref: format!("{discovery_ref}#health"),
            discovery_ref,
            isolation: "session_tab".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct WorkspaceAgentTile {
    pub agent_id: AgentId,
    pub area: String,
    pub status: LifecycleStatus,
    pub current_task: Option<TaskRecord>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct WorkspaceShellProjection {
    pub agents: BTreeMap<AgentId, WorkspaceAgentTile>,
}

impl WorkspaceShellProjection {
    pub fn from_ledger(projection: &LedgerProjection) -> Self {
        let mut shell = Self::default();
        for agent in projection.agents.values() {
            let heartbeat = projection.agent_heartbeats.get(&agent.agent_id);
            let task = heartbeat
                .and_then(|heartbeat| heartbeat.current_task_id.as_ref())
                .and_then(|task_id| projection.tasks.get(task_id))
                .cloned();
            shell.agents.insert(
                agent.agent_id.clone(),
                WorkspaceAgentTile {
                    agent_id: agent.agent_id.clone(),
                    area: heartbeat_area(heartbeat).unwrap_or_else(|| agent.lane_id.0.clone()),
                    status: heartbeat
                        .map(|heartbeat| heartbeat.status.clone())
                        .unwrap_or_else(|| agent.status.clone()),
                    current_task: task,
                },
            );
        }
        shell
    }
}

pub fn browser_daemon_plugin(descriptor: BrowserDaemonDescriptor) -> PluginManifest {
    PluginManifest::new(
        "browser-daemon",
        "Browser Daemon",
        "0.1.0",
        "External browser daemon boundary for isolated tab/session control.",
    )
    .with_kind(PluginKind::BrowserDaemon)
    .with_source(PluginSource::bundled("essence://plugins/browser-daemon"))
    .with_capability("browser_daemon")
    .with_metadata("discovery_ref", serde_json::json!(descriptor.discovery_ref))
    .with_metadata("health_ref", serde_json::json!(descriptor.health_ref))
    .with_metadata("isolation", serde_json::json!(descriptor.isolation))
}

fn heartbeat_area(heartbeat: Option<&AgentHeartbeat>) -> Option<String> {
    heartbeat
        .and_then(|heartbeat| heartbeat.lane_id.as_ref())
        .map(|lane_id| lane_id.0.clone())
}

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;
    use uuid::Uuid;

    use crate::protocol::{
        AgentHeartbeat, AgentId, AgentRecord, LaneId, LifecycleStatus, SessionId,
    };
    use crate::workspace::{
        browser_daemon_plugin, BrowserDaemonDescriptor, WorkspaceShellProjection,
    };

    #[test]
    fn projects_agents_into_workspace_tiles() {
        let session_id = SessionId(Uuid::new_v4());
        let agent_id = AgentId("researcher".to_string());
        let mut projection = crate::projection::LedgerProjection::default();
        projection.agents.insert(
            agent_id.clone(),
            AgentRecord {
                agent_id: agent_id.clone(),
                session_id: session_id.clone(),
                lane_id: LaneId("research".to_string()),
                role: "Research".to_string(),
                status: LifecycleStatus::Active,
                toolsets: Vec::new(),
                budget: None,
                metadata: Default::default(),
            },
        );
        projection.agent_heartbeats.insert(
            agent_id.clone(),
            AgentHeartbeat {
                agent_id: agent_id.clone(),
                session_id,
                status: LifecycleStatus::Running,
                seen_at: OffsetDateTime::now_utc(),
                lane_id: Some(LaneId("research".to_string())),
                current_run_id: None,
                current_task_id: None,
                note: None,
            },
        );

        let shell = WorkspaceShellProjection::from_ledger(&projection);
        let tile = shell.agents.get(&agent_id).unwrap();

        assert_eq!(tile.area, "research");
        assert_eq!(tile.status, LifecycleStatus::Running);
    }

    #[test]
    fn exposes_browser_daemon_as_plugin_boundary() {
        let plugin = browser_daemon_plugin(BrowserDaemonDescriptor::local(
            ".essence/browser-daemon.json",
        ));

        assert!(plugin.capabilities.contains("browser_daemon"));
        assert_eq!(
            plugin.metadata["isolation"],
            serde_json::json!("session_tab")
        );
    }
}
