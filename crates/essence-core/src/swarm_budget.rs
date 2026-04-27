use std::collections::BTreeSet;

use crate::projection::LedgerProjection;
use crate::swarm::SwarmAgentSpec;

pub fn has_budget_remaining(agent: &SwarmAgentSpec, projection: &LedgerProjection) -> bool {
    let Some(budget) = &agent.budget else {
        return true;
    };

    if let Some(max_turns) = budget.max_turns {
        let turns = projection
            .runs
            .values()
            .filter(|run| run.agent_id.as_ref() == Some(&agent.agent_id))
            .count() as u32;
        if turns >= max_turns {
            return false;
        }
    }

    if let Some(max_tool_calls) = budget.max_tool_calls {
        let agent_run_ids = projection
            .runs
            .values()
            .filter(|run| run.agent_id.as_ref() == Some(&agent.agent_id))
            .map(|run| run.run_id.clone())
            .collect::<BTreeSet<_>>();
        let tool_calls = projection
            .tool_calls
            .values()
            .filter(|tool_call| {
                tool_call
                    .run_id
                    .as_ref()
                    .is_some_and(|run_id| agent_run_ids.contains(run_id))
            })
            .count() as u32;
        if tool_calls >= max_tool_calls {
            return false;
        }
    }

    true
}
