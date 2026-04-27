use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::control::{
    AgentHeartbeatRequest, ControlPlane, ControlResult, CreateTaskRequest, RegisterAgentRequest,
    SpawnSubagentRequest, StartRunRequest,
};
use crate::protocol::{
    AgentHeartbeat, AgentId, AgentRecord, LaneId, LifecycleStatus, RunMeta, SessionId,
    SubagentBudget, SubagentMeta, SubagentResult, TaskId, TaskPatch, TaskRecord, TriggerKind,
};
use crate::swarm_scheduler::SwarmSchedulerHandle;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SwarmAgentSpec {
    pub agent_id: AgentId,
    pub lane_id: LaneId,
    pub role: String,
    pub toolsets: Vec<String>,
    pub budget: Option<SubagentBudget>,
}

impl SwarmAgentSpec {
    pub fn native(
        agent_id: impl Into<String>,
        lane_id: impl Into<String>,
        role: impl Into<String>,
    ) -> Self {
        Self {
            agent_id: AgentId(agent_id.into()),
            lane_id: LaneId(lane_id.into()),
            role: role.into(),
            toolsets: Vec::new(),
            budget: None,
        }
    }

    pub fn with_toolset(mut self, toolset: impl Into<String>) -> Self {
        self.toolsets.push(toolset.into());
        self
    }

    pub fn with_budget(mut self, budget: SubagentBudget) -> Self {
        self.budget = Some(budget);
        self
    }

    fn to_register_request(&self, session_id: SessionId) -> RegisterAgentRequest {
        let mut request = RegisterAgentRequest::new(
            session_id,
            self.agent_id.0.clone(),
            self.lane_id.0.clone(),
            self.role.clone(),
        );
        for toolset in &self.toolsets {
            request = request.with_toolset(toolset.clone());
        }
        if let Some(budget) = self.budget.clone() {
            request = request.with_budget(budget);
        }
        request
    }
}

impl From<AgentRecord> for SwarmAgentSpec {
    fn from(agent: AgentRecord) -> Self {
        Self {
            agent_id: agent.agent_id,
            lane_id: agent.lane_id,
            role: agent.role,
            toolsets: agent.toolsets,
            budget: agent.budget,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DispatchedTask {
    pub task: TaskRecord,
    pub run: RunMeta,
    pub subagent: SubagentMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompletedDispatchedTask {
    pub task_patch: TaskPatch,
    pub run: RunMeta,
    pub subagent: SubagentMeta,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SwarmTick {
    pub dispatched: Vec<DispatchedTask>,
}

#[derive(Debug, Clone)]
pub struct SwarmRuntime {
    control: ControlPlane,
    agents: BTreeMap<AgentId, SwarmAgentSpec>,
}

impl SwarmRuntime {
    pub fn new(control: ControlPlane) -> Self {
        Self {
            control,
            agents: BTreeMap::new(),
        }
    }

    pub fn control(&self) -> &ControlPlane {
        &self.control
    }

    pub fn register_agent(
        &mut self,
        session_id: &SessionId,
        agent: SwarmAgentSpec,
    ) -> ControlResult<Option<SwarmAgentSpec>> {
        self.control
            .register_agent(agent.to_register_request(session_id.clone()))?;
        Ok(self.agents.insert(agent.agent_id.clone(), agent))
    }

    pub fn register_agent_local(&mut self, agent: SwarmAgentSpec) -> Option<SwarmAgentSpec> {
        self.agents.insert(agent.agent_id.clone(), agent)
    }

    pub fn local_agent(&self, agent_id: &AgentId) -> Option<&SwarmAgentSpec> {
        self.agents.get(agent_id)
    }

    pub fn agents(&self) -> impl Iterator<Item = &SwarmAgentSpec> {
        self.agents.values()
    }

    pub fn heartbeat(
        &self,
        session_id: &SessionId,
        agent_id: &AgentId,
        status: LifecycleStatus,
    ) -> ControlResult<Option<AgentHeartbeat>> {
        let Some(agent) = self.agent_for_session(session_id, agent_id)? else {
            return Ok(None);
        };

        Ok(Some(
            self.control.record_agent_heartbeat(
                AgentHeartbeatRequest::new(session_id.clone(), agent.agent_id.0.clone(), status)
                    .with_lane(agent.lane_id.0),
            )?,
        ))
    }

    pub fn enqueue_task(
        &self,
        session_id: SessionId,
        title: impl Into<String>,
        lane_id: impl Into<String>,
    ) -> ControlResult<TaskRecord> {
        self.control.create_task(
            CreateTaskRequest::new(session_id, title)
                .with_status(LifecycleStatus::Queued)
                .with_lane(lane_id),
        )
    }

    pub fn dispatch_next_task(
        &self,
        session_id: &SessionId,
        agent_id: &AgentId,
    ) -> ControlResult<Option<DispatchedTask>> {
        let Some(agent) = self.agent_for_session(session_id, agent_id)? else {
            return Ok(None);
        };
        let projection = self.control.projection(session_id)?;
        if !has_budget_remaining(&agent, &projection) {
            return Ok(None);
        }
        let Some(claim) = self
            .control
            .claim_next_task(session_id, agent_id.0.clone())?
        else {
            return Ok(None);
        };
        let projection = self.control.projection(session_id)?;
        let Some(task) = projection.tasks.get(&claim.task_id).cloned() else {
            return Ok(None);
        };
        let run = self.control.start_run(
            StartRunRequest::scheduler(session_id.clone())
                .with_lane(agent.lane_id.clone())
                .with_agent(agent.agent_id.clone()),
        )?;

        let mut spawn = SpawnSubagentRequest::native(
            session_id.clone(),
            &run,
            agent.lane_id.0.clone(),
            task.title.clone(),
        )
        .with_subagent_id(format!("{}-{}", agent.agent_id.0, task.task_id.0))
        .with_context_ref(format!("task://{}", task.task_id.0));
        for toolset in &agent.toolsets {
            spawn = spawn.with_toolset(toolset.clone());
        }
        if let Some(budget) = agent.budget.clone() {
            spawn = spawn.with_budget(budget);
        }
        let subagent = self.control.spawn_subagent(spawn)?;
        self.control.record_agent_heartbeat(
            AgentHeartbeatRequest::new(
                session_id.clone(),
                agent.agent_id.0.clone(),
                LifecycleStatus::Running,
            )
            .with_lane(agent.lane_id.0)
            .with_run(run.run_id.clone())
            .with_task(task.task_id.clone()),
        )?;

        Ok(Some(DispatchedTask {
            task,
            run,
            subagent,
        }))
    }

    pub fn tick_session(&self, session_id: &SessionId) -> ControlResult<SwarmTick> {
        let projection = self.control.projection(session_id)?;
        let mut dispatched = Vec::new();

        for agent in self.active_agents_for_session(session_id, &projection) {
            if projection
                .agent_heartbeats
                .get(&agent.agent_id)
                .is_some_and(|heartbeat| is_busy_status(&heartbeat.status))
            {
                continue;
            }
            if !has_budget_remaining(&agent, &projection) {
                continue;
            }
            if let Some(task) = self.dispatch_next_task(session_id, &agent.agent_id)? {
                dispatched.push(task);
            }
        }

        Ok(SwarmTick { dispatched })
    }

    pub fn start_scheduler_loop(
        &self,
        session_id: SessionId,
        interval: Duration,
    ) -> SwarmSchedulerHandle {
        SwarmSchedulerHandle::start(self.clone(), session_id, interval)
    }

    fn agent_for_session(
        &self,
        session_id: &SessionId,
        agent_id: &AgentId,
    ) -> ControlResult<Option<SwarmAgentSpec>> {
        if let Some(agent) = self.local_agent(agent_id) {
            return Ok(Some(agent.clone()));
        }
        Ok(self
            .control
            .projection(session_id)?
            .agents
            .get(agent_id)
            .filter(|agent| agent.status == LifecycleStatus::Active)
            .cloned()
            .map(SwarmAgentSpec::from))
    }

    fn active_agents_for_session(
        &self,
        session_id: &SessionId,
        projection: &crate::projection::LedgerProjection,
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

    pub fn complete_dispatched_task(
        &self,
        dispatched: &DispatchedTask,
        result: SubagentResult,
    ) -> ControlResult<CompletedDispatchedTask> {
        let subagent = self
            .control
            .complete_subagent_with_result(&dispatched.subagent, result)?;
        let task_patch = self.control.complete_task(&dispatched.task)?;
        let run = self.control.complete_run(&dispatched.run, None)?;
        let agent_id = dispatched
            .run
            .agent_id
            .clone()
            .unwrap_or_else(|| dispatched.subagent.subagent_id.clone());
        self.control.record_agent_heartbeat(
            AgentHeartbeatRequest::new(
                dispatched.subagent.session_id.clone(),
                agent_id.0,
                LifecycleStatus::Idle,
            )
            .with_lane(dispatched.subagent.lane_id.0.clone())
            .with_note("task completed"),
        )?;

        Ok(CompletedDispatchedTask {
            task_patch,
            run,
            subagent,
        })
    }

    pub fn cancel_dispatched_task(
        &self,
        dispatched: &DispatchedTask,
        reason: impl Into<String>,
    ) -> ControlResult<CompletedDispatchedTask> {
        let reason = reason.into();
        let subagent = self
            .control
            .cancel_subagent(&dispatched.subagent, reason.clone())?;
        let task_patch = TaskPatch {
            task_id: dispatched.task.task_id.clone(),
            title: None,
            status: Some(LifecycleStatus::Cancelled),
            updated_at: Some(time::OffsetDateTime::now_utc()),
            assignee: None,
            metadata: Default::default(),
        };
        self.control
            .update_task(&dispatched.task.session_id, task_patch.clone())?;
        let run = self.control.cancel_run(&dispatched.run, reason)?;
        let agent_id = dispatched
            .run
            .agent_id
            .clone()
            .unwrap_or_else(|| dispatched.subagent.subagent_id.clone());
        self.control.record_agent_heartbeat(
            AgentHeartbeatRequest::new(
                dispatched.subagent.session_id.clone(),
                agent_id.0,
                LifecycleStatus::Idle,
            )
            .with_lane(dispatched.subagent.lane_id.0.clone())
            .with_note("task cancelled"),
        )?;

        Ok(CompletedDispatchedTask {
            task_patch,
            run,
            subagent,
        })
    }
}

fn is_busy_status(status: &LifecycleStatus) -> bool {
    matches!(
        status,
        LifecycleStatus::Running | LifecycleStatus::WaitingTool | LifecycleStatus::WaitingApproval
    )
}

fn has_budget_remaining(
    agent: &SwarmAgentSpec,
    projection: &crate::projection::LedgerProjection,
) -> bool {
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
            .collect::<std::collections::BTreeSet<_>>();
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

impl StartRunRequest {
    pub fn scheduler(session_id: SessionId) -> Self {
        Self {
            session_id,
            trigger: TriggerKind::Scheduler,
            parent_run_id: None,
            lane_id: None,
            agent_id: None,
            model: None,
            input_message_ids: Vec::new(),
        }
    }

    pub fn with_lane(mut self, lane_id: LaneId) -> Self {
        self.lane_id = Some(lane_id);
        self
    }

    pub fn with_agent(mut self, agent_id: AgentId) -> Self {
        self.agent_id = Some(agent_id);
        self
    }
}

impl TaskRecord {
    pub fn id(&self) -> &TaskId {
        &self.task_id
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use uuid::Uuid;

    use crate::control::{ControlPlane, CreateSessionRequest, StartToolCallRequest};
    use crate::protocol::{AgentId, LifecycleStatus, SubagentBudget, SubagentResult, TriggerKind};
    use crate::swarm::{SwarmAgentSpec, SwarmRuntime};

    #[test]
    fn dispatches_and_completes_queued_task_for_registered_agent() {
        let root = std::env::temp_dir().join(format!("essence-swarm-{}", Uuid::new_v4()));
        let control = ControlPlane::new(&root);
        let session = control
            .create_session(CreateSessionRequest::interactive("."))
            .unwrap();
        let mut runtime = SwarmRuntime::new(control.clone());
        runtime
            .register_agent(
                &session.session_id,
                SwarmAgentSpec::native("researcher", "research", "Collect evidence")
                    .with_toolset("gitnexus")
                    .with_budget(SubagentBudget {
                        max_turns: Some(2),
                        max_tool_calls: Some(4),
                        max_tokens: None,
                    }),
            )
            .unwrap();
        runtime
            .enqueue_task(
                session.session_id.clone(),
                "Map upstream runtime references",
                "research",
            )
            .unwrap();

        let dispatched = runtime
            .dispatch_next_task(&session.session_id, &AgentId("researcher".to_string()))
            .unwrap()
            .unwrap();
        let completed = runtime
            .complete_dispatched_task(
                &dispatched,
                SubagentResult {
                    summary: "Mapped references.".to_string(),
                    artifact_refs: vec!["artifact://reference-map.md".to_string()],
                    usage: None,
                    error: None,
                },
            )
            .unwrap();

        let projection = control.projection(&session.session_id).unwrap();
        let projected_agent = projection
            .agents
            .get(&AgentId("researcher".to_string()))
            .unwrap();
        let projected_heartbeat = projection
            .agent_heartbeats
            .get(&AgentId("researcher".to_string()))
            .unwrap();
        let projected_task = projection.tasks.get(dispatched.task.id()).unwrap();
        let projected_run = projection.runs.get(&dispatched.run.run_id).unwrap();
        let projected_subagent = projection
            .subagents
            .get(&dispatched.subagent.subagent_id.0)
            .unwrap();

        assert_eq!(dispatched.run.trigger, TriggerKind::Scheduler);
        assert_eq!(
            dispatched.run.agent_id,
            Some(AgentId("researcher".to_string()))
        );
        assert_eq!(projected_agent.status, LifecycleStatus::Active);
        assert_eq!(projected_agent.role, "Collect evidence");
        assert_eq!(projected_heartbeat.status, LifecycleStatus::Idle);
        assert_eq!(projected_heartbeat.note.as_deref(), Some("task completed"));
        assert_eq!(projected_task.status, LifecycleStatus::Completed);
        assert_eq!(projected_run.status, LifecycleStatus::Completed);
        assert_eq!(projected_subagent.status, LifecycleStatus::Completed);
        assert_eq!(projected_subagent.toolsets, vec!["gitnexus".to_string()]);
        assert_eq!(
            projected_subagent.budget.as_ref().unwrap().max_turns,
            Some(2)
        );
        assert_eq!(
            projected_subagent.result.as_ref().unwrap().artifact_refs,
            vec!["artifact://reference-map.md".to_string()]
        );
        assert_eq!(
            completed.task_patch.status,
            Some(LifecycleStatus::Completed)
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn dispatches_with_agent_restored_from_ledger_projection() {
        let root = std::env::temp_dir().join(format!("essence-swarm-{}", Uuid::new_v4()));
        let control = ControlPlane::new(&root);
        let session = control
            .create_session(CreateSessionRequest::interactive("."))
            .unwrap();
        let mut first_runtime = SwarmRuntime::new(control.clone());
        first_runtime
            .register_agent(
                &session.session_id,
                SwarmAgentSpec::native("coder", "build", "Implement queued work")
                    .with_toolset("repo"),
            )
            .unwrap();
        first_runtime
            .enqueue_task(
                session.session_id.clone(),
                "Build durable registry",
                "build",
            )
            .unwrap();

        let restored_runtime = SwarmRuntime::new(control.clone());
        let dispatched = restored_runtime
            .dispatch_next_task(&session.session_id, &AgentId("coder".to_string()))
            .unwrap()
            .unwrap();

        assert_eq!(dispatched.run.agent_id, Some(AgentId("coder".to_string())));
        assert_eq!(dispatched.subagent.lane_id.0, "build");
        assert_eq!(dispatched.subagent.toolsets, vec!["repo".to_string()]);
        let projection = control.projection(&session.session_id).unwrap();
        let projected_heartbeat = projection
            .agent_heartbeats
            .get(&AgentId("coder".to_string()))
            .unwrap();
        assert_eq!(projected_heartbeat.status, LifecycleStatus::Running);
        assert_eq!(
            projected_heartbeat.current_run_id,
            Some(dispatched.run.run_id.clone())
        );
        assert_eq!(
            projected_heartbeat.current_task_id,
            Some(dispatched.task.task_id.clone())
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn records_idle_heartbeat_for_registered_agent() {
        let root = std::env::temp_dir().join(format!("essence-swarm-{}", Uuid::new_v4()));
        let control = ControlPlane::new(&root);
        let session = control
            .create_session(CreateSessionRequest::interactive("."))
            .unwrap();
        let mut runtime = SwarmRuntime::new(control.clone());
        runtime
            .register_agent(
                &session.session_id,
                SwarmAgentSpec::native("planner", "plan", "Plan work"),
            )
            .unwrap();

        let heartbeat = runtime
            .heartbeat(
                &session.session_id,
                &AgentId("planner".to_string()),
                LifecycleStatus::Idle,
            )
            .unwrap()
            .unwrap();
        let projection = control.projection(&session.session_id).unwrap();
        let projected = projection
            .agent_heartbeats
            .get(&AgentId("planner".to_string()))
            .unwrap();

        assert_eq!(heartbeat.status, LifecycleStatus::Idle);
        assert_eq!(
            projected.lane_id,
            Some(crate::protocol::LaneId("plan".to_string()))
        );
        assert_eq!(projected.status, LifecycleStatus::Idle);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn tick_dispatches_queued_tasks_to_idle_agents() {
        let root = std::env::temp_dir().join(format!("essence-swarm-{}", Uuid::new_v4()));
        let control = ControlPlane::new(&root);
        let session = control
            .create_session(CreateSessionRequest::interactive("."))
            .unwrap();
        let mut runtime = SwarmRuntime::new(control.clone());
        runtime
            .register_agent(
                &session.session_id,
                SwarmAgentSpec::native("researcher", "research", "Research"),
            )
            .unwrap();
        runtime
            .register_agent(
                &session.session_id,
                SwarmAgentSpec::native("reviewer", "review", "Review"),
            )
            .unwrap();
        runtime
            .heartbeat(
                &session.session_id,
                &AgentId("reviewer".to_string()),
                LifecycleStatus::Running,
            )
            .unwrap()
            .unwrap();
        runtime
            .enqueue_task(session.session_id.clone(), "Research task", "research")
            .unwrap();
        runtime
            .enqueue_task(session.session_id.clone(), "Review task", "review")
            .unwrap();

        let tick = runtime.tick_session(&session.session_id).unwrap();
        let projection = control.projection(&session.session_id).unwrap();
        let researcher_heartbeat = projection
            .agent_heartbeats
            .get(&AgentId("researcher".to_string()))
            .unwrap();
        let reviewer_heartbeat = projection
            .agent_heartbeats
            .get(&AgentId("reviewer".to_string()))
            .unwrap();

        assert_eq!(tick.dispatched.len(), 1);
        assert_eq!(
            tick.dispatched[0].run.agent_id,
            Some(AgentId("researcher".to_string()))
        );
        assert_eq!(researcher_heartbeat.status, LifecycleStatus::Running);
        assert_eq!(reviewer_heartbeat.status, LifecycleStatus::Running);
        assert_eq!(
            projection
                .tasks
                .values()
                .filter(|task| task.status == LifecycleStatus::Queued)
                .count(),
            1
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn cancels_dispatched_task_with_run_and_subagent() {
        let root = std::env::temp_dir().join(format!("essence-swarm-{}", Uuid::new_v4()));
        let control = ControlPlane::new(&root);
        let session = control
            .create_session(CreateSessionRequest::interactive("."))
            .unwrap();
        let mut runtime = SwarmRuntime::new(control.clone());
        runtime
            .register_agent(
                &session.session_id,
                SwarmAgentSpec::native("reviewer", "review", "Review code"),
            )
            .unwrap();
        runtime
            .enqueue_task(session.session_id.clone(), "Review kernel delta", "review")
            .unwrap();
        let dispatched = runtime
            .dispatch_next_task(&session.session_id, &AgentId("reviewer".to_string()))
            .unwrap()
            .unwrap();

        runtime
            .cancel_dispatched_task(&dispatched, "parent run cancelled")
            .unwrap();

        let projection = control.projection(&session.session_id).unwrap();
        let projected_task = projection.tasks.get(dispatched.task.id()).unwrap();
        let projected_run = projection.runs.get(&dispatched.run.run_id).unwrap();
        let projected_subagent = projection
            .subagents
            .get(&dispatched.subagent.subagent_id.0)
            .unwrap();
        let projected_heartbeat = projection
            .agent_heartbeats
            .get(&AgentId("reviewer".to_string()))
            .unwrap();

        assert_eq!(projected_task.status, LifecycleStatus::Cancelled);
        assert_eq!(projected_run.status, LifecycleStatus::Cancelled);
        assert_eq!(
            projected_run.stop_reason.as_deref(),
            Some("parent run cancelled")
        );
        assert_eq!(projected_subagent.status, LifecycleStatus::Cancelled);
        assert_eq!(
            projected_subagent.stop_reason.as_deref(),
            Some("parent run cancelled")
        );
        assert_eq!(projected_heartbeat.status, LifecycleStatus::Idle);
        assert_eq!(projected_heartbeat.note.as_deref(), Some("task cancelled"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn tick_skips_agents_after_turn_budget_is_exhausted() {
        let root = std::env::temp_dir().join(format!("essence-swarm-{}", Uuid::new_v4()));
        let control = ControlPlane::new(&root);
        let session = control
            .create_session(CreateSessionRequest::interactive("."))
            .unwrap();
        let mut runtime = SwarmRuntime::new(control.clone());
        runtime
            .register_agent(
                &session.session_id,
                SwarmAgentSpec::native("builder", "build", "Build").with_budget(SubagentBudget {
                    max_turns: Some(1),
                    max_tool_calls: None,
                    max_tokens: None,
                }),
            )
            .unwrap();
        runtime
            .enqueue_task(session.session_id.clone(), "First build task", "build")
            .unwrap();
        runtime
            .enqueue_task(session.session_id.clone(), "Second build task", "build")
            .unwrap();
        let first_tick = runtime.tick_session(&session.session_id).unwrap();
        runtime
            .complete_dispatched_task(
                &first_tick.dispatched[0],
                SubagentResult {
                    summary: "done".to_string(),
                    artifact_refs: Vec::new(),
                    usage: None,
                    error: None,
                },
            )
            .unwrap();

        let second_tick = runtime.tick_session(&session.session_id).unwrap();
        let projection = control.projection(&session.session_id).unwrap();

        assert_eq!(first_tick.dispatched.len(), 1);
        assert!(second_tick.dispatched.is_empty());
        assert_eq!(
            projection
                .tasks
                .values()
                .filter(|task| task.status == LifecycleStatus::Queued)
                .count(),
            1
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn tick_skips_agents_after_tool_call_budget_is_exhausted() {
        let root = std::env::temp_dir().join(format!("essence-swarm-{}", Uuid::new_v4()));
        let control = ControlPlane::new(&root);
        let session = control
            .create_session(CreateSessionRequest::interactive("."))
            .unwrap();
        let mut runtime = SwarmRuntime::new(control.clone());
        runtime
            .register_agent(
                &session.session_id,
                SwarmAgentSpec::native("tester", "test", "Test").with_budget(SubagentBudget {
                    max_turns: None,
                    max_tool_calls: Some(1),
                    max_tokens: None,
                }),
            )
            .unwrap();
        runtime
            .enqueue_task(session.session_id.clone(), "First test task", "test")
            .unwrap();
        runtime
            .enqueue_task(session.session_id.clone(), "Second test task", "test")
            .unwrap();
        let first_tick = runtime.tick_session(&session.session_id).unwrap();
        control
            .start_tool_call(
                StartToolCallRequest::new(session.session_id.clone(), "test.run", json!({}))
                    .for_run(&first_tick.dispatched[0].run),
            )
            .unwrap();
        runtime
            .complete_dispatched_task(
                &first_tick.dispatched[0],
                SubagentResult {
                    summary: "done".to_string(),
                    artifact_refs: Vec::new(),
                    usage: None,
                    error: None,
                },
            )
            .unwrap();

        let second_tick = runtime.tick_session(&session.session_id).unwrap();

        assert_eq!(first_tick.dispatched.len(), 1);
        assert!(second_tick.dispatched.is_empty());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn scheduler_loop_ticks_session_until_stopped() {
        let root = std::env::temp_dir().join(format!("essence-swarm-{}", Uuid::new_v4()));
        let control = ControlPlane::new(&root);
        let session = control
            .create_session(CreateSessionRequest::interactive("."))
            .unwrap();
        let mut runtime = SwarmRuntime::new(control.clone());
        runtime
            .register_agent(
                &session.session_id,
                SwarmAgentSpec::native("daemon", "background", "Background worker"),
            )
            .unwrap();
        runtime
            .enqueue_task(session.session_id.clone(), "Background task", "background")
            .unwrap();

        let handle = runtime.start_scheduler_loop(
            session.session_id.clone(),
            std::time::Duration::from_millis(10),
        );
        let projection = control.projection(&session.session_id).unwrap();
        let heartbeat = projection
            .agent_heartbeats
            .get(&AgentId("daemon".to_string()))
            .cloned()
            .expect("scheduler loop should emit a heartbeat before returning");
        handle.stop();

        assert_eq!(heartbeat.status, LifecycleStatus::Running);
        assert!(projection
            .runs
            .values()
            .any(|run| { run.agent_id.as_ref() == Some(&AgentId("daemon".to_string())) }));

        let _ = std::fs::remove_dir_all(root);
    }
}
