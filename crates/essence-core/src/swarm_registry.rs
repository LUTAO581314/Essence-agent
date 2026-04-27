use std::collections::BTreeMap;

use crate::projection::LedgerProjection;
use crate::protocol::{AgentId, LifecycleStatus, SessionId};
use crate::swarm::SwarmAgentSpec;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct AgentRegistry {
    agents: BTreeMap<AgentId, SwarmAgentSpec>,
}

impl AgentRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, agent: SwarmAgentSpec) -> Option<SwarmAgentSpec> {
        self.agents.insert(agent.agent_id.clone(), agent)
    }

    pub fn get(&self, agent_id: &AgentId) -> Option<&SwarmAgentSpec> {
        self.agents.get(agent_id)
    }

    pub fn values(&self) -> impl Iterator<Item = &SwarmAgentSpec> {
        self.agents.values()
    }

    pub fn active_agents_for_session(
        &self,
        session_id: &SessionId,
        projection: &LedgerProjection,
    ) -> Vec<SwarmAgentSpec> {
        let mut agents = projection
            .agents
            .values()
            .filter(|agent| {
                agent.session_id == *session_id && agent.status == LifecycleStatus::Active
            })
            .cloned()
            .map(SwarmAgentSpec::from)
            .map(|agent| (agent.agent_id.clone(), agent))
            .collect::<BTreeMap<_, _>>();

        for agent in self.agents.values() {
            agents.insert(agent.agent_id.clone(), agent.clone());
        }

        agents.into_values().collect()
    }
}
