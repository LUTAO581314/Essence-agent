use chrono::{DateTime, Utc};
use moxi_contracts::EventResult;
use moxi_runtime::{
    RuntimeAdoptionAction, RuntimeAdoptionProbeRecord, RuntimeAttemptStage, RuntimeGraphSnapshot,
    RuntimeQuerySnapshot, RuntimeResumePlan, RuntimeTaskAttempt, TaskState,
};
use moxi_store::StoredRunObservation;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const OBSERVABILITY_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    RuntimeGraph,
    RuntimePlanner,
    RuntimeTask,
    RuntimeEvent,
    RuntimeAttempt,
    RuntimeAdoptionProbe,
    RuntimeResumePlan,
    LedgerEvent,
    Proof,
    StoreRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct EvidenceRef {
    pub source: EvidenceSource,
    pub id: String,
    pub graph_id: Option<String>,
    pub run_id: Option<String>,
    pub task_id: Option<String>,
    pub hash: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeFactKind {
    GraphPlanned,
    PlannerBound,
    TaskState,
    RuntimeEvent,
    AttemptStarted,
    AttemptCompleted,
    AttemptFailed,
    AdoptionProbeObserved,
    ResumeRecommendation,
    GraphCompleted,
    StoreRunState,
    PolicyDecisionRecorded,
    ApprovalGrantRecorded,
    ExecutionTicketRecorded,
    SandboxResultRecorded,
    ProofRecorded,
    LedgerEventRecorded,
    StoreRunCompleted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeFact {
    pub fact_id: String,
    pub kind: RuntimeFactKind,
    pub graph_id: String,
    pub run_id: Option<String>,
    pub task_id: Option<String>,
    pub message: String,
    pub evidence_refs: Vec<EvidenceRef>,
    pub timestamp: DateTime<Utc>,
    pub payload: Value,
}

struct RuntimeFactInput {
    kind: RuntimeFactKind,
    graph_id: String,
    run_id: Option<String>,
    task_id: Option<String>,
    message: String,
    evidence_refs: Vec<EvidenceRef>,
    timestamp: DateTime<Utc>,
    payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RunMetric {
    pub graph_id: String,
    pub task_count: usize,
    pub completed_task_count: usize,
    pub running_task_count: usize,
    pub failed_task_count: usize,
    pub awaiting_approval_task_count: usize,
    pub event_count: usize,
    pub attempt_count: usize,
    pub adoption_probe_count: usize,
    pub retry_ready_count: usize,
    pub inspection_required_count: usize,
    pub already_committed_count: usize,
    pub is_complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StoreRunMetric {
    pub run_id: String,
    pub policy_decision_count: usize,
    pub approval_grant_count: usize,
    pub execution_ticket_count: usize,
    pub sandbox_result_count: usize,
    pub proof_count: usize,
    pub ledger_event_count: usize,
    pub successful_ledger_event_count: usize,
    pub failed_ledger_event_count: usize,
    pub has_status: bool,
    pub is_complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RunTimeline {
    pub graph_id: String,
    pub facts: Vec<RuntimeFact>,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProjectionSnapshot {
    pub schema_version: u32,
    pub graph_id: String,
    pub facts: Vec<RuntimeFact>,
    pub timeline: RunTimeline,
    pub metrics: RunMetric,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StoreProjectionSnapshot {
    pub schema_version: u32,
    pub run_id: String,
    pub facts: Vec<RuntimeFact>,
    pub timeline: RunTimeline,
    pub metrics: StoreRunMetric,
    pub generated_at: DateTime<Utc>,
}

impl EvidenceRef {
    pub fn runtime_graph(graph_id: &str, graph: &impl Serialize) -> Self {
        Self::new(
            EvidenceSource::RuntimeGraph,
            graph_id,
            Some(graph_id.into()),
            None,
            None,
            Some(stable_hash(graph)),
        )
    }

    pub fn runtime_planner(
        graph_id: &str,
        plan_id: &str,
        intent_id: &str,
        planner: &impl Serialize,
    ) -> Self {
        Self::new(
            EvidenceSource::RuntimePlanner,
            plan_id,
            Some(graph_id.into()),
            Some(intent_id.into()),
            None,
            Some(stable_hash(planner)),
        )
    }

    pub fn runtime_task(graph_id: &str, task_id: &str, task: &impl Serialize) -> Self {
        Self::new(
            EvidenceSource::RuntimeTask,
            task_id,
            Some(graph_id.into()),
            None,
            Some(task_id.into()),
            Some(stable_hash(task)),
        )
    }

    pub fn runtime_event(event: &moxi_runtime::RuntimeEvent) -> Self {
        Self::new(
            EvidenceSource::RuntimeEvent,
            &event.event_id,
            event.graph_id.clone(),
            event.run_id.clone(),
            event.task_id.clone(),
            Some(stable_hash(event)),
        )
    }

    pub fn runtime_attempt(attempt: &RuntimeTaskAttempt) -> Self {
        Self::new(
            EvidenceSource::RuntimeAttempt,
            &attempt.attempt_id,
            Some(attempt.graph_id.clone()),
            Some(attempt.run_id.clone()),
            Some(attempt.task_id.clone()),
            Some(stable_hash(attempt)),
        )
    }

    pub fn runtime_adoption_probe(probe: &RuntimeAdoptionProbeRecord) -> Self {
        Self::new(
            EvidenceSource::RuntimeAdoptionProbe,
            &probe.probe_id,
            Some(probe.graph_id.clone()),
            None,
            Some(probe.result.task_id.clone()),
            Some(stable_hash(probe)),
        )
    }

    pub fn runtime_resume_plan(
        graph_id: &str,
        task_id: &str,
        resume_plan: &RuntimeResumePlan,
    ) -> Self {
        Self::new(
            EvidenceSource::RuntimeResumePlan,
            format!("{}:{task_id}", resume_plan.graph_id),
            Some(graph_id.into()),
            None,
            Some(task_id.into()),
            Some(stable_hash(resume_plan)),
        )
    }

    pub fn ledger_event(event: &moxi_contracts::LedgerEvent) -> Self {
        Self::new(
            EvidenceSource::LedgerEvent,
            &event.ledger_event_id,
            None,
            Some(event.run_id.clone()),
            None,
            Some(stable_hash(event)),
        )
    }

    pub fn proof(proof: &moxi_contracts::Proof) -> Self {
        Self::new(
            EvidenceSource::Proof,
            &proof.proof_id,
            None,
            Some(proof.run_id.clone()),
            None,
            Some(stable_hash(proof)),
        )
    }

    pub fn store_record(
        id: impl Into<String>,
        run_id: impl Into<String>,
        record: &impl Serialize,
    ) -> Self {
        Self::new(
            EvidenceSource::StoreRecord,
            id,
            None,
            Some(run_id.into()),
            None,
            Some(stable_hash(record)),
        )
    }

    fn new(
        source: EvidenceSource,
        id: impl Into<String>,
        graph_id: Option<String>,
        run_id: Option<String>,
        task_id: Option<String>,
        hash: Option<String>,
    ) -> Self {
        Self {
            source,
            id: id.into(),
            graph_id,
            run_id,
            task_id,
            hash,
        }
    }
}

impl ProjectionSnapshot {
    pub fn from_runtime_graph(
        snapshot: &RuntimeGraphSnapshot,
        resume_plan: Option<&RuntimeResumePlan>,
    ) -> Self {
        let generated_at = Utc::now();
        let facts = runtime_facts_from_graph_snapshot(snapshot, resume_plan);
        let graph_id = snapshot.graph.graph_id.clone();
        let timeline = RunTimeline {
            graph_id: graph_id.clone(),
            facts: facts.clone(),
            generated_at,
        };
        let metrics = RunMetric::from_graph_snapshot(snapshot, resume_plan);
        Self {
            schema_version: OBSERVABILITY_SCHEMA_VERSION,
            graph_id,
            facts,
            timeline,
            metrics,
            generated_at,
        }
    }

    pub fn from_runtime_query(snapshot: &RuntimeQuerySnapshot) -> Self {
        let generated_at = Utc::now();
        let facts = runtime_facts_from_query_snapshot(snapshot);
        let graph_id = snapshot.graph.graph_id.clone();
        let timeline = RunTimeline {
            graph_id: graph_id.clone(),
            facts: facts.clone(),
            generated_at,
        };
        let metrics = RunMetric::from_query_snapshot(snapshot);
        Self {
            schema_version: OBSERVABILITY_SCHEMA_VERSION,
            graph_id,
            facts,
            timeline,
            metrics,
            generated_at,
        }
    }
}

impl StoreProjectionSnapshot {
    pub fn from_store_observation(observation: &StoredRunObservation) -> Self {
        let generated_at = Utc::now();
        let facts = store_facts_from_observation(observation);
        let run_id = observation.run_id.clone();
        let timeline = RunTimeline {
            graph_id: run_id.clone(),
            facts: facts.clone(),
            generated_at,
        };
        let metrics = StoreRunMetric::from_store_observation(observation);
        Self {
            schema_version: OBSERVABILITY_SCHEMA_VERSION,
            run_id,
            facts,
            timeline,
            metrics,
            generated_at,
        }
    }
}

impl RunTimeline {
    pub fn from_facts(graph_id: impl Into<String>, facts: Vec<RuntimeFact>) -> Self {
        Self {
            graph_id: graph_id.into(),
            facts: sort_facts(facts),
            generated_at: Utc::now(),
        }
    }
}

impl StoreRunMetric {
    pub fn from_store_observation(observation: &StoredRunObservation) -> Self {
        let successful_ledger_event_count = observation
            .ledger_events
            .iter()
            .filter(|event| event.result == EventResult::Success)
            .count();
        let failed_ledger_event_count = observation
            .ledger_events
            .iter()
            .filter(|event| event.result == EventResult::Failed)
            .count();
        Self {
            run_id: observation.run_id.clone(),
            policy_decision_count: observation.policy_decisions.len(),
            approval_grant_count: observation.approval_grants.len(),
            execution_ticket_count: observation.execution_tickets.len(),
            sandbox_result_count: observation.sandbox_results.len(),
            proof_count: observation.proofs.len(),
            ledger_event_count: observation.ledger_events.len(),
            successful_ledger_event_count,
            failed_ledger_event_count,
            has_status: observation.status.is_some(),
            is_complete: observation
                .ledger_events
                .iter()
                .any(|event| event.result == EventResult::Success)
                || observation.status == Some(moxi_contracts::RunStatus::Completed),
        }
    }
}

impl RunMetric {
    pub fn from_graph_snapshot(
        snapshot: &RuntimeGraphSnapshot,
        resume_plan: Option<&RuntimeResumePlan>,
    ) -> Self {
        let retry_ready_count = resume_plan
            .map(|plan| count_recommendations(plan, RuntimeAdoptionAction::RetryReady))
            .unwrap_or(0);
        let inspection_required_count = resume_plan
            .map(|plan| count_recommendations(plan, RuntimeAdoptionAction::InspectRequired))
            .unwrap_or(0);
        let already_committed_count = resume_plan
            .map(|plan| count_recommendations(plan, RuntimeAdoptionAction::AlreadyCommitted))
            .unwrap_or(0);
        Self {
            graph_id: snapshot.graph.graph_id.clone(),
            task_count: snapshot.tasks.len(),
            completed_task_count: snapshot
                .tasks
                .iter()
                .filter(|task| task.task.state == TaskState::Completed)
                .count(),
            running_task_count: snapshot
                .tasks
                .iter()
                .filter(|task| task.task.state == TaskState::Running)
                .count(),
            failed_task_count: snapshot
                .tasks
                .iter()
                .filter(|task| task.task.state == TaskState::Failed)
                .count(),
            awaiting_approval_task_count: snapshot
                .tasks
                .iter()
                .filter(|task| task.task.state == TaskState::AwaitingApproval)
                .count(),
            event_count: snapshot.events.len(),
            attempt_count: snapshot.attempts.len(),
            adoption_probe_count: snapshot.adoption_probes.len(),
            retry_ready_count,
            inspection_required_count,
            already_committed_count,
            is_complete: resume_plan.map(|plan| plan.is_complete).unwrap_or_else(|| {
                !snapshot.tasks.is_empty()
                    && snapshot
                        .tasks
                        .iter()
                        .all(|task| task.task.state == TaskState::Completed)
            }),
        }
    }

    pub fn from_query_snapshot(snapshot: &RuntimeQuerySnapshot) -> Self {
        Self {
            graph_id: snapshot.graph.graph_id.clone(),
            task_count: snapshot.tasks.len(),
            completed_task_count: snapshot.graph.completed_count,
            running_task_count: snapshot.graph.running_count,
            failed_task_count: snapshot.graph.failed_count,
            awaiting_approval_task_count: snapshot.graph.awaiting_approval_count,
            event_count: snapshot.events.len(),
            attempt_count: snapshot.attempts.len(),
            adoption_probe_count: snapshot.adoption_probes.len(),
            retry_ready_count: count_recommendations(
                &snapshot.resume_plan,
                RuntimeAdoptionAction::RetryReady,
            ),
            inspection_required_count: count_recommendations(
                &snapshot.resume_plan,
                RuntimeAdoptionAction::InspectRequired,
            ),
            already_committed_count: count_recommendations(
                &snapshot.resume_plan,
                RuntimeAdoptionAction::AlreadyCommitted,
            ),
            is_complete: snapshot.graph.is_complete,
        }
    }
}

pub fn runtime_facts_from_graph_snapshot(
    snapshot: &RuntimeGraphSnapshot,
    resume_plan: Option<&RuntimeResumePlan>,
) -> Vec<RuntimeFact> {
    let graph_id = snapshot.graph.graph_id.clone();
    let mut facts = Vec::new();
    facts.push(RuntimeFact::new(RuntimeFactInput {
        kind: RuntimeFactKind::GraphPlanned,
        graph_id: graph_id.clone(),
        run_id: None,
        task_id: None,
        message: format!(
            "runtime graph {} planned with {} task(s)",
            snapshot.graph.graph_id,
            snapshot.graph.tasks.len()
        ),
        evidence_refs: vec![EvidenceRef::runtime_graph(&graph_id, &snapshot.graph)],
        timestamp: graph_timestamp(snapshot),
        payload: json!({
            "goal": snapshot.graph.goal,
            "path": snapshot.graph.path,
            "task_count": snapshot.graph.tasks.len(),
        }),
    }));

    if let Some(planner) = &snapshot.planner {
        facts.push(RuntimeFact::new(RuntimeFactInput {
            kind: RuntimeFactKind::PlannerBound,
            graph_id: graph_id.clone(),
            run_id: Some(planner.intent_id.clone()),
            task_id: None,
            message: format!(
                "planner {} bound intent {} to graph {}",
                planner.plan_id, planner.intent_id, planner.graph_id
            ),
            evidence_refs: vec![EvidenceRef::runtime_planner(
                &graph_id,
                &planner.plan_id,
                &planner.intent_id,
                planner,
            )],
            timestamp: planner.created_at,
            payload: json!({
                "plan_id": planner.plan_id,
                "intent_id": planner.intent_id,
                "source": planner.source,
                "step_count": planner.step_count,
                "plan_hash": planner.plan_hash,
            }),
        }));
    }

    for task in &snapshot.tasks {
        let task_id = task.task.task_id.clone();
        facts.push(RuntimeFact::new(RuntimeFactInput {
            kind: RuntimeFactKind::TaskState,
            graph_id: graph_id.clone(),
            run_id: None,
            task_id: Some(task_id.clone()),
            message: format!("task {task_id} is {:?}", task.task.state),
            evidence_refs: vec![EvidenceRef::runtime_task(&graph_id, &task_id, task)],
            timestamp: task.updated_at,
            payload: json!({
                "skill_id": task.task.skill_id,
                "capability_id": task.task.capability_id,
                "target": task.task.target,
                "risk_level": task.task.risk_level,
                "depends_on": task.task.depends_on,
                "state": task.task.state,
                "last_event_id": task.last_event_id,
                "last_stage": task.last_stage,
                "last_attempt_id": task.last_attempt_id,
                "idempotency_key": task.idempotency_key,
                "retry_safe": task.retry_safe,
                "message": task.message,
                "progress": task.progress,
            }),
        }));
    }

    for event in &snapshot.events {
        let fact_graph_id = event.graph_id.clone().unwrap_or_else(|| graph_id.clone());
        facts.push(RuntimeFact::new(RuntimeFactInput {
            kind: RuntimeFactKind::RuntimeEvent,
            graph_id: fact_graph_id,
            run_id: event.run_id.clone(),
            task_id: event.task_id.clone(),
            message: event.message.clone(),
            evidence_refs: vec![EvidenceRef::runtime_event(event)],
            timestamp: event.timestamp,
            payload: json!({
                "event_id": event.event_id,
                "stage": event.stage,
                "progress": event.progress,
            }),
        }));
    }

    for attempt in &snapshot.attempts {
        facts.push(attempt_fact(attempt));
    }

    for probe in &snapshot.adoption_probes {
        facts.push(adoption_probe_fact(probe));
    }

    if let Some(resume_plan) = resume_plan {
        facts.extend(resume_plan_facts(resume_plan));
        if resume_plan.is_complete {
            facts.push(RuntimeFact::new(RuntimeFactInput {
                kind: RuntimeFactKind::GraphCompleted,
                graph_id: graph_id.clone(),
                run_id: None,
                task_id: None,
                message: format!("runtime graph {} is complete", resume_plan.graph_id),
                evidence_refs: vec![EvidenceRef::runtime_resume_plan(
                    &graph_id,
                    "__graph__",
                    resume_plan,
                )],
                timestamp: graph_timestamp(snapshot),
                payload: json!({
                    "completed_task_ids": resume_plan.completed_task_ids,
                }),
            }));
        }
    }

    sort_facts(facts)
}

pub fn runtime_facts_from_query_snapshot(snapshot: &RuntimeQuerySnapshot) -> Vec<RuntimeFact> {
    let graph_id = snapshot.graph.graph_id.clone();
    let generated_at = Utc::now();
    let mut facts = Vec::new();
    facts.push(RuntimeFact::new(RuntimeFactInput {
        kind: RuntimeFactKind::GraphPlanned,
        graph_id: graph_id.clone(),
        run_id: None,
        task_id: None,
        message: format!(
            "runtime graph {} has {} task(s)",
            snapshot.graph.graph_id, snapshot.graph.task_count
        ),
        evidence_refs: vec![EvidenceRef::new(
            EvidenceSource::RuntimeGraph,
            &snapshot.graph.graph_id,
            Some(graph_id.clone()),
            None,
            None,
            Some(stable_hash(&snapshot.graph)),
        )],
        timestamp: generated_at,
        payload: json!({
            "goal": snapshot.graph.goal,
            "path": snapshot.graph.path,
            "task_count": snapshot.graph.task_count,
            "is_complete": snapshot.graph.is_complete,
            "policy_profile": snapshot.policy_profile,
            "event_cursor": snapshot.event_cursor,
        }),
    }));

    if let Some(planner) = &snapshot.planner {
        facts.push(RuntimeFact::new(RuntimeFactInput {
            kind: RuntimeFactKind::PlannerBound,
            graph_id: graph_id.clone(),
            run_id: Some(planner.intent_id.clone()),
            task_id: None,
            message: format!(
                "planner {} bound intent {} to graph {}",
                planner.plan_id, planner.intent_id, planner.graph_id
            ),
            evidence_refs: vec![EvidenceRef::runtime_planner(
                &graph_id,
                &planner.plan_id,
                &planner.intent_id,
                planner,
            )],
            timestamp: planner.created_at,
            payload: json!({
                "plan_id": planner.plan_id,
                "intent_id": planner.intent_id,
                "source": planner.source,
                "step_count": planner.step_count,
                "plan_hash": planner.plan_hash,
            }),
        }));
    }

    for task in &snapshot.tasks {
        facts.push(RuntimeFact::new(RuntimeFactInput {
            kind: RuntimeFactKind::TaskState,
            graph_id: graph_id.clone(),
            run_id: None,
            task_id: Some(task.task_id.clone()),
            message: format!("task {} is {:?}", task.task_id, task.state),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::RuntimeTask,
                &task.task_id,
                Some(graph_id.clone()),
                None,
                Some(task.task_id.clone()),
                Some(stable_hash(task)),
            )],
            timestamp: task.updated_at,
            payload: json!({
                "skill_id": task.skill_id,
                "capability_id": task.capability_id,
                "target": task.target,
                "state": task.state,
                "last_stage": task.last_stage,
                "progress": task.progress,
                "message": task.message,
                "idempotency_key": task.idempotency_key,
                "retry_safe": task.retry_safe,
                "blocker": task.blocker,
            }),
        }));
    }

    for event in &snapshot.events {
        facts.push(RuntimeFact::new(RuntimeFactInput {
            kind: RuntimeFactKind::RuntimeEvent,
            graph_id: event.graph_id.clone().unwrap_or_else(|| graph_id.clone()),
            run_id: event.run_id.clone(),
            task_id: event.task_id.clone(),
            message: event.message.clone(),
            evidence_refs: vec![EvidenceRef::runtime_event(event)],
            timestamp: event.timestamp,
            payload: json!({
                "event_id": event.event_id,
                "stage": event.stage,
                "progress": event.progress,
            }),
        }));
    }

    for attempt in &snapshot.attempts {
        facts.push(attempt_fact(attempt));
    }
    for probe in &snapshot.adoption_probes {
        facts.push(adoption_probe_fact(probe));
    }
    facts.extend(resume_plan_facts(&snapshot.resume_plan));
    if snapshot.resume_plan.is_complete {
        facts.push(RuntimeFact::new(RuntimeFactInput {
            kind: RuntimeFactKind::GraphCompleted,
            graph_id: graph_id.clone(),
            run_id: None,
            task_id: None,
            message: format!(
                "runtime graph {} is complete",
                snapshot.resume_plan.graph_id
            ),
            evidence_refs: vec![EvidenceRef::runtime_resume_plan(
                &graph_id,
                "__graph__",
                &snapshot.resume_plan,
            )],
            timestamp: generated_at,
            payload: json!({
                "completed_task_ids": snapshot.resume_plan.completed_task_ids,
            }),
        }));
    }

    sort_facts(facts)
}

pub fn store_facts_from_observation(observation: &StoredRunObservation) -> Vec<RuntimeFact> {
    let run_id = observation.run_id.clone();
    let mut facts = Vec::new();

    if let Some(status) = observation.status {
        facts.push(RuntimeFact::new(RuntimeFactInput {
            kind: RuntimeFactKind::StoreRunState,
            graph_id: run_id.clone(),
            run_id: Some(run_id.clone()),
            task_id: None,
            message: format!("store run {run_id} status is {status:?}"),
            evidence_refs: vec![EvidenceRef::store_record(
                format!("run_state:{run_id}"),
                &run_id,
                &status,
            )],
            timestamp: store_observation_timestamp(observation),
            payload: json!({
                "run_id": run_id,
                "status": status,
            }),
        }));
    }

    for policy in &observation.policy_decisions {
        facts.push(RuntimeFact::new(RuntimeFactInput {
            kind: RuntimeFactKind::PolicyDecisionRecorded,
            graph_id: run_id.clone(),
            run_id: Some(policy.run_id.clone()),
            task_id: None,
            message: format!(
                "policy decision {} recorded {:?} for {}",
                policy.decision_id, policy.decision, policy.capability_id
            ),
            evidence_refs: vec![EvidenceRef::store_record(
                format!("policy_decision:{}", policy.decision_id),
                &policy.run_id,
                policy,
            )],
            timestamp: policy.expires_at,
            payload: json!({
                "decision_id": policy.decision_id,
                "delta_id": policy.delta_id,
                "actor_id": policy.actor_id,
                "capability_id": policy.capability_id,
                "decision": policy.decision,
                "risk_level": policy.risk_level,
                "reasons": policy.reasons,
                "required_approval": policy.required_approval,
                "expires_at": policy.expires_at,
            }),
        }));
    }

    for grant in &observation.approval_grants {
        facts.push(RuntimeFact::new(RuntimeFactInput {
            kind: RuntimeFactKind::ApprovalGrantRecorded,
            graph_id: run_id.clone(),
            run_id: Some(grant.run_id.clone()),
            task_id: None,
            message: format!(
                "approval grant {} recorded for policy {}",
                grant.grant_id, grant.policy_decision_ref
            ),
            evidence_refs: vec![EvidenceRef::store_record(
                format!("approval_grant:{}", grant.grant_id),
                &grant.run_id,
                grant,
            )],
            timestamp: grant.granted_at,
            payload: json!({
                "grant_id": grant.grant_id,
                "delta_id": grant.delta_id,
                "policy_decision_ref": grant.policy_decision_ref,
                "capability_id": grant.capability_id,
                "approver_id": grant.approver_id,
                "reason": grant.reason,
                "expires_at": grant.expires_at,
            }),
        }));
    }

    for ticket in &observation.execution_tickets {
        facts.push(RuntimeFact::new(RuntimeFactInput {
            kind: RuntimeFactKind::ExecutionTicketRecorded,
            graph_id: run_id.clone(),
            run_id: Some(ticket.run_id.clone()),
            task_id: None,
            message: format!(
                "execution ticket {} recorded for {}",
                ticket.ticket_id, ticket.capability_id
            ),
            evidence_refs: vec![EvidenceRef::store_record(
                format!("execution_ticket:{}", ticket.ticket_id),
                &ticket.run_id,
                ticket,
            )],
            timestamp: ticket.expires_at,
            payload: json!({
                "ticket_id": ticket.ticket_id,
                "delta_id": ticket.delta_id,
                "policy_decision_ref": ticket.policy_decision_ref,
                "capability_id": ticket.capability_id,
                "capability_contract_ref": ticket.capability_contract_ref,
                "executor_ref": ticket.executor_ref,
                "executor_version": ticket.executor_version,
                "executor_isolation": ticket.executor_isolation,
                "actor_id": ticket.actor_id,
                "expires_at": ticket.expires_at,
            }),
        }));
    }

    for result in &observation.sandbox_results {
        facts.push(RuntimeFact::new(RuntimeFactInput {
            kind: RuntimeFactKind::SandboxResultRecorded,
            graph_id: run_id.clone(),
            run_id: Some(result.run_id.clone()),
            task_id: None,
            message: format!(
                "sandbox result for ticket {} recorded success={}",
                result.ticket_id, result.success
            ),
            evidence_refs: vec![EvidenceRef::store_record(
                format!("sandbox_result:{}", result.ticket_id),
                &result.run_id,
                result,
            )],
            timestamp: result.finished_at,
            payload: json!({
                "ticket_id": result.ticket_id,
                "capability_id": result.capability_id,
                "policy_decision_ref": result.policy_decision_ref,
                "capability_contract_ref": result.capability_contract_ref,
                "executor_ref": result.executor_ref,
                "success": result.success,
                "input_hash": result.input_hash,
                "output_hash": result.output_hash,
                "started_at": result.started_at,
                "finished_at": result.finished_at,
                "error": result.error,
            }),
        }));
    }

    for proof in &observation.proofs {
        facts.push(RuntimeFact::new(RuntimeFactInput {
            kind: RuntimeFactKind::ProofRecorded,
            graph_id: run_id.clone(),
            run_id: Some(proof.run_id.clone()),
            task_id: None,
            message: format!(
                "proof {} recorded from {}",
                proof.proof_id, proof.source_ref
            ),
            evidence_refs: vec![EvidenceRef::proof(proof)],
            timestamp: proof.collected_at,
            payload: json!({
                "proof_id": proof.proof_id,
                "policy_decision_ref": proof.policy_decision_ref,
                "capability_contract_ref": proof.capability_contract_ref,
                "executor_ref": proof.executor_ref,
                "source_type": proof.source_type,
                "source_ref": proof.source_ref,
                "hash": proof.hash,
                "claim": proof.claim,
                "confidence": proof.confidence,
                "input_hash": proof.input_hash,
                "output_hash": proof.output_hash,
            }),
        }));
    }

    for event in &observation.ledger_events {
        facts.push(RuntimeFact::new(RuntimeFactInput {
            kind: RuntimeFactKind::LedgerEventRecorded,
            graph_id: run_id.clone(),
            run_id: Some(event.run_id.clone()),
            task_id: None,
            message: format!(
                "ledger event {} recorded {:?} for {}",
                event.ledger_event_id, event.result, event.capability_id
            ),
            evidence_refs: vec![EvidenceRef::ledger_event(event)],
            timestamp: event.timestamp,
            payload: json!({
                "ledger_event_id": event.ledger_event_id,
                "event_type": event.event_type,
                "actor_id": event.actor_id,
                "resource_ref": event.resource_ref,
                "delta_id": event.delta_id,
                "capability_id": event.capability_id,
                "policy_decision_ref": event.policy_decision_ref,
                "execution_ticket_ref": event.execution_ticket_ref,
                "proof_refs": event.proof_refs,
                "input_hash": event.input_hash,
                "output_hash": event.output_hash,
                "previous_event_hash": event.previous_event_hash,
                "event_hash": event.event_hash,
                "result": event.result,
            }),
        }));
    }

    if observation
        .ledger_events
        .iter()
        .any(|event| event.result == EventResult::Success)
    {
        facts.push(RuntimeFact::new(RuntimeFactInput {
            kind: RuntimeFactKind::StoreRunCompleted,
            graph_id: run_id.clone(),
            run_id: Some(run_id.clone()),
            task_id: None,
            message: format!("store run {run_id} has successful ledger evidence"),
            evidence_refs: observation
                .ledger_events
                .iter()
                .filter(|event| event.result == EventResult::Success)
                .map(EvidenceRef::ledger_event)
                .collect(),
            timestamp: store_observation_timestamp(observation),
            payload: json!({
                "run_id": run_id,
                "successful_ledger_event_count": observation
                    .ledger_events
                    .iter()
                    .filter(|event| event.result == EventResult::Success)
                    .count(),
            }),
        }));
    }

    sort_facts(facts)
}

impl RuntimeFact {
    fn new(input: RuntimeFactInput) -> Self {
        let RuntimeFactInput {
            kind,
            graph_id,
            run_id,
            task_id,
            message,
            evidence_refs,
            timestamp,
            payload,
        } = input;
        let fact_id = fact_id(
            &kind,
            &graph_id,
            run_id.as_deref(),
            task_id.as_deref(),
            &payload,
        );
        Self {
            fact_id,
            kind,
            graph_id,
            run_id,
            task_id,
            message,
            evidence_refs,
            timestamp,
            payload,
        }
    }
}

fn attempt_fact(attempt: &RuntimeTaskAttempt) -> RuntimeFact {
    let kind = match attempt.stage {
        RuntimeAttemptStage::Started => RuntimeFactKind::AttemptStarted,
        RuntimeAttemptStage::Completed => RuntimeFactKind::AttemptCompleted,
        RuntimeAttemptStage::Failed => RuntimeFactKind::AttemptFailed,
    };
    RuntimeFact::new(RuntimeFactInput {
        kind,
        graph_id: attempt.graph_id.clone(),
        run_id: Some(attempt.run_id.clone()),
        task_id: Some(attempt.task_id.clone()),
        message: format!("attempt {} is {:?}", attempt.attempt_id, attempt.stage),
        evidence_refs: vec![EvidenceRef::runtime_attempt(attempt)],
        timestamp: attempt.created_at,
        payload: json!({
            "attempt_id": attempt.attempt_id,
            "capability_id": attempt.capability_id,
            "idempotency_key": attempt.idempotency_key,
            "retry_safe": attempt.retry_safe,
            "stage": attempt.stage,
            "ticket_id": attempt.ticket_id,
            "ledger_event_id": attempt.ledger_event_id,
            "error": attempt.error,
        }),
    })
}

fn adoption_probe_fact(probe: &RuntimeAdoptionProbeRecord) -> RuntimeFact {
    RuntimeFact::new(RuntimeFactInput {
        kind: RuntimeFactKind::AdoptionProbeObserved,
        graph_id: probe.graph_id.clone(),
        run_id: None,
        task_id: Some(probe.result.task_id.clone()),
        message: probe
            .result
            .message
            .clone()
            .unwrap_or_else(|| format!("adoption probe {} observed", probe.probe_id)),
        evidence_refs: vec![EvidenceRef::runtime_adoption_probe(probe)],
        timestamp: probe.recorded_at,
        payload: json!({
            "probe_id": probe.probe_id,
            "attempt_id": probe.result.attempt_id,
            "idempotency_key": probe.result.idempotency_key,
            "status": probe.result.status,
            "provider_ref": probe.result.provider_ref,
            "evidence_ref": probe.result.evidence_ref,
            "observed_at": probe.result.observed_at,
        }),
    })
}

fn resume_plan_facts(resume_plan: &RuntimeResumePlan) -> Vec<RuntimeFact> {
    resume_plan
        .adoption_recommendations
        .iter()
        .map(|(task_id, recommendation)| {
            RuntimeFact::new(RuntimeFactInput {
                kind: RuntimeFactKind::ResumeRecommendation,
                graph_id: resume_plan.graph_id.clone(),
                run_id: None,
                task_id: Some(task_id.clone()),
                message: recommendation.reason.clone(),
                evidence_refs: vec![EvidenceRef::runtime_resume_plan(
                    &resume_plan.graph_id,
                    task_id,
                    resume_plan,
                )],
                timestamp: Utc::now(),
                payload: json!({
                    "task_id": recommendation.task_id,
                    "action": recommendation.action,
                    "reason": recommendation.reason,
                    "attempt_id": recommendation.attempt_id,
                    "idempotency_key": recommendation.idempotency_key,
                    "ticket_id": recommendation.ticket_id,
                    "ledger_event_id": recommendation.ledger_event_id,
                    "provider_probe": recommendation.provider_probe,
                    "blocker": resume_plan.blockers.get(task_id),
                    "running_task_policy": resume_plan.running_task_policy,
                }),
            })
        })
        .collect()
}

fn graph_timestamp(snapshot: &RuntimeGraphSnapshot) -> DateTime<Utc> {
    snapshot
        .planner
        .as_ref()
        .map(|planner| planner.created_at)
        .or_else(|| snapshot.events.iter().map(|event| event.timestamp).min())
        .or_else(|| snapshot.tasks.iter().map(|task| task.updated_at).min())
        .or_else(|| {
            snapshot
                .attempts
                .iter()
                .map(|attempt| attempt.created_at)
                .min()
        })
        .or_else(|| {
            snapshot
                .adoption_probes
                .iter()
                .map(|probe| probe.recorded_at)
                .min()
        })
        .unwrap_or_else(Utc::now)
}

fn store_observation_timestamp(observation: &StoredRunObservation) -> DateTime<Utc> {
    observation
        .ledger_events
        .iter()
        .map(|event| event.timestamp)
        .chain(observation.proofs.iter().map(|proof| proof.collected_at))
        .chain(
            observation
                .sandbox_results
                .iter()
                .map(|result| result.finished_at),
        )
        .chain(
            observation
                .approval_grants
                .iter()
                .map(|grant| grant.granted_at),
        )
        .min()
        .unwrap_or_else(Utc::now)
}

fn count_recommendations(plan: &RuntimeResumePlan, action: RuntimeAdoptionAction) -> usize {
    plan.adoption_recommendations
        .values()
        .filter(|recommendation| recommendation.action == action)
        .count()
}

fn sort_facts(mut facts: Vec<RuntimeFact>) -> Vec<RuntimeFact> {
    facts.sort_by(|left, right| {
        left.timestamp
            .cmp(&right.timestamp)
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| left.graph_id.cmp(&right.graph_id))
            .then_with(|| left.task_id.cmp(&right.task_id))
            .then_with(|| left.run_id.cmp(&right.run_id))
            .then_with(|| left.fact_id.cmp(&right.fact_id))
    });
    facts
}

fn fact_id(
    kind: &RuntimeFactKind,
    graph_id: &str,
    run_id: Option<&str>,
    task_id: Option<&str>,
    payload: &Value,
) -> String {
    let bytes = serde_json::to_vec(&json!({
        "kind": kind,
        "graph_id": graph_id,
        "run_id": run_id,
        "task_id": task_id,
        "payload": payload,
    }))
    .expect("fact id payload serializes");
    format!("fact_{}", hex::encode(Sha256::digest(bytes)))
}

fn stable_hash(value: &impl Serialize) -> String {
    let bytes = serde_json::to_vec(value).expect("observability evidence serializes");
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use moxi_contracts::{
        Confidence, Decision, DeltaTarget, EventResult, ExecutionTicket, ExecutorIsolation,
        PolicyDecision, Proof, ResourceType, RetryPolicy, RiskLevel, RunStatus, SandboxResult,
    };
    use moxi_runtime::{
        PlannerConstraint, PlannerPlan, PlannerSource, PlannerStep, ResumeBlocker,
        RunningTaskPolicy, RuntimeAdoptionProbeResult, RuntimeAdoptionProbeStatus,
        RuntimeAdoptionRecommendation, RuntimeEvent, RuntimePath, RuntimePlannerRecord,
        RuntimeStage, RuntimeTaskRecord, TaskGraph, TaskNode,
    };
    use std::collections::BTreeMap;

    fn at(second: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 5, 25, 12, 0, second)
            .single()
            .unwrap()
    }

    fn graph() -> TaskGraph {
        TaskGraph {
            graph_id: "graph.observe".into(),
            goal: "read and summarize".into(),
            path: RuntimePath::TaskPath,
            tasks: vec![task_node("task.read", TaskState::Completed)],
        }
    }

    fn target() -> DeltaTarget {
        DeltaTarget {
            resource_type: ResourceType::File,
            resource_ref: "README.md".into(),
        }
    }

    fn task_node(task_id: &str, state: TaskState) -> TaskNode {
        TaskNode {
            task_id: task_id.into(),
            skill_id: Some("skill.file.read".into()),
            capability_id: "file.read".into(),
            target: target(),
            input: json!({"path": "README.md"}),
            risk_level: RiskLevel::Low,
            depends_on: vec![],
            state,
        }
    }

    fn planner_record(graph: &TaskGraph) -> RuntimePlannerRecord {
        let plan = PlannerPlan {
            plan_id: "plan.observe".into(),
            intent_id: "intent.observe".into(),
            goal: graph.goal.clone(),
            source: PlannerSource::Deterministic,
            constraints: vec![PlannerConstraint {
                constraint_id: "p0_chain".into(),
                description: "effects must go through P0".into(),
            }],
            steps: vec![PlannerStep {
                step_id: "step.read".into(),
                skill_id: Some("skill.file.read".into()),
                capability_id: "file.read".into(),
                target: target(),
                input: json!({"path": "README.md"}),
                risk_level: RiskLevel::Low,
                depends_on: vec![],
                rationale: "fixture".into(),
            }],
        };
        RuntimePlannerRecord {
            plan_id: plan.plan_id.clone(),
            graph_id: graph.graph_id.clone(),
            intent_id: plan.intent_id.clone(),
            source: plan.source,
            step_count: plan.steps.len(),
            plan_hash: "sha256:planner".into(),
            plan,
            created_at: at(1),
        }
    }

    fn task_record(task: TaskNode, updated_at: DateTime<Utc>) -> RuntimeTaskRecord {
        RuntimeTaskRecord {
            graph_id: "graph.observe".into(),
            task,
            last_event_id: Some("evt.done".into()),
            last_stage: Some(RuntimeStage::Completed),
            last_attempt_id: Some("attempt.read".into()),
            idempotency_key: Some("idem.read".into()),
            retry_safe: Some(true),
            message: Some("done".into()),
            progress: 1.0,
            updated_at,
        }
    }

    fn attempt(stage: RuntimeAttemptStage, created_at: DateTime<Utc>) -> RuntimeTaskAttempt {
        RuntimeTaskAttempt {
            attempt_id: "attempt.read".into(),
            graph_id: "graph.observe".into(),
            task_id: "task.read".into(),
            run_id: "run.read".into(),
            capability_id: "file.read".into(),
            idempotency_key: "idem.read".into(),
            retry_safe: true,
            stage,
            ticket_id: Some("ticket.read".into()),
            ledger_event_id: Some("ledger.read".into()),
            error: None,
            created_at,
        }
    }

    fn probe(recorded_at: DateTime<Utc>) -> RuntimeAdoptionProbeRecord {
        RuntimeAdoptionProbeRecord {
            probe_id: "probe.read".into(),
            graph_id: "graph.observe".into(),
            result: RuntimeAdoptionProbeResult {
                task_id: "task.read".into(),
                attempt_id: "attempt.read".into(),
                idempotency_key: "idem.read".into(),
                status: RuntimeAdoptionProbeStatus::Committed,
                provider_ref: Some("provider:file".into()),
                evidence_ref: Some("evidence:commit".into()),
                message: Some("committed".into()),
                observed_at: at(5),
            },
            recorded_at,
        }
    }

    fn resume_plan() -> RuntimeResumePlan {
        let mut blockers = BTreeMap::new();
        blockers.insert("task.read".into(), ResumeBlocker::AlreadyFinished);
        let mut adoption_recommendations = BTreeMap::new();
        adoption_recommendations.insert(
            "task.read".into(),
            RuntimeAdoptionRecommendation {
                task_id: "task.read".into(),
                action: RuntimeAdoptionAction::AlreadyCommitted,
                reason: "latest attempt already has a ledger event reference".into(),
                attempt_id: Some("attempt.read".into()),
                idempotency_key: Some("idem.read".into()),
                ticket_id: Some("ticket.read".into()),
                ledger_event_id: Some("ledger.read".into()),
                provider_probe: None,
            },
        );
        RuntimeResumePlan {
            graph_id: "graph.observe".into(),
            completed_task_ids: vec!["task.read".into()],
            ready_task_ids: vec![],
            blocked_task_ids: vec![],
            running_task_ids: vec![],
            awaiting_approval_task_ids: vec![],
            failed_task_ids: vec![],
            blockers,
            adoption_recommendations,
            running_task_policy: RunningTaskPolicy::RequireInspection,
            is_complete: true,
        }
    }

    fn snapshot() -> RuntimeGraphSnapshot {
        let graph = graph();
        RuntimeGraphSnapshot {
            planner: Some(planner_record(&graph)),
            tasks: vec![task_record(
                task_node("task.read", TaskState::Completed),
                at(3),
            )],
            events: vec![RuntimeEvent {
                event_id: "evt.done".into(),
                graph_id: Some("graph.observe".into()),
                run_id: Some("run.read".into()),
                task_id: Some("task.read".into()),
                stage: RuntimeStage::Completed,
                message: "task completed".into(),
                progress: 1.0,
                timestamp: at(4),
            }],
            attempts: vec![attempt(RuntimeAttemptStage::Completed, at(2))],
            adoption_probes: vec![probe(at(6))],
            graph,
        }
    }

    fn policy_decision() -> PolicyDecision {
        PolicyDecision {
            decision_id: "pd.store".into(),
            run_id: "run.store".into(),
            delta_id: "delta.store".into(),
            actor_id: "kernel".into(),
            capability_id: "file.read".into(),
            decision: Decision::Allow,
            risk_level: RiskLevel::Low,
            reasons: vec!["read-only capability".into()],
            required_approval: None,
            expires_at: at(8),
        }
    }

    fn execution_ticket() -> ExecutionTicket {
        ExecutionTicket {
            ticket_id: "ticket.store".into(),
            run_id: "run.store".into(),
            delta_id: "delta.store".into(),
            policy_decision_ref: "pd.store".into(),
            capability_contract_ref: "file.read".into(),
            capability_contract_hash: "contract_hash".into(),
            executor_ref: "moxi.builtin.fs.file_read".into(),
            executor_version: "0.2.0".into(),
            executor_artifact_hash: "sha256:artifact".into(),
            executor_signature_ref: "builtin://signature".into(),
            executor_signing_key_ref: "builtin://key".into(),
            executor_manifest_hash: "manifest_hash".into(),
            executor_isolation: ExecutorIsolation::InProcessTrusted,
            retry_policy: RetryPolicy::default(),
            sandbox_profile_ref: "fs-readonly".into(),
            actor_id: "kernel".into(),
            capability_id: "file.read".into(),
            expires_at: at(9),
        }
    }

    fn sandbox_result() -> SandboxResult {
        SandboxResult {
            ticket_id: "ticket.store".into(),
            run_id: "run.store".into(),
            capability_id: "file.read".into(),
            policy_decision_ref: "pd.store".into(),
            capability_contract_ref: "file.read".into(),
            capability_contract_hash: "contract_hash".into(),
            executor_ref: "moxi.builtin.fs.file_read".into(),
            executor_version: "0.2.0".into(),
            executor_artifact_hash: "sha256:artifact".into(),
            executor_signature_ref: "builtin://signature".into(),
            executor_signing_key_ref: "builtin://key".into(),
            executor_manifest_hash: "manifest_hash".into(),
            gateway_decision_ref: Some("gateway.store".into()),
            input_hash: "input_hash".into(),
            success: true,
            output: json!({"content": "hello"}),
            error: None,
            started_at: at(10),
            finished_at: at(11),
            output_hash: "output_hash".into(),
        }
    }

    fn proof() -> Proof {
        Proof {
            proof_id: "proof.store".into(),
            run_id: "run.store".into(),
            policy_decision_ref: "pd.store".into(),
            capability_contract_ref: "file.read".into(),
            capability_contract_hash: "contract_hash".into(),
            executor_ref: "moxi.builtin.fs.file_read".into(),
            executor_version: "0.2.0".into(),
            executor_artifact_hash: "sha256:artifact".into(),
            executor_signature_ref: "builtin://signature".into(),
            executor_signing_key_ref: "builtin://key".into(),
            executor_manifest_hash: "manifest_hash".into(),
            gateway_decision_ref: Some("gateway.store".into()),
            input_hash: "input_hash".into(),
            output_hash: "output_hash".into(),
            source_type: "sandbox_result".into(),
            source_ref: "ticket.store".into(),
            hash: "proof_hash".into(),
            claim: "file.read completed".into(),
            confidence: Confidence::High,
            collected_at: at(12),
        }
    }

    fn ledger_event() -> moxi_contracts::LedgerEvent {
        moxi_contracts::LedgerEvent {
            ledger_event_id: "ledger.store".into(),
            run_id: "run.store".into(),
            event_type: "tool.executed".into(),
            actor_id: "kernel".into(),
            resource_ref: "README.md".into(),
            delta_id: "delta.store".into(),
            capability_id: "file.read".into(),
            policy_decision_ref: "pd.store".into(),
            execution_ticket_ref: "ticket.store".into(),
            capability_contract_ref: "file.read".into(),
            capability_contract_hash: "contract_hash".into(),
            executor_ref: "moxi.builtin.fs.file_read".into(),
            executor_version: "0.2.0".into(),
            executor_artifact_hash: "sha256:artifact".into(),
            executor_signature_ref: "builtin://signature".into(),
            executor_signing_key_ref: "builtin://key".into(),
            executor_manifest_hash: "manifest_hash".into(),
            gateway_decision_ref: Some("gateway.store".into()),
            proof_refs: vec!["proof.store".into()],
            input_hash: "input_hash".into(),
            output_hash: "output_hash".into(),
            previous_event_hash: String::new(),
            event_hash: "event_hash".into(),
            result: EventResult::Success,
            timestamp: at(13),
        }
    }

    fn store_observation() -> StoredRunObservation {
        StoredRunObservation {
            run_id: "run.store".into(),
            status: Some(RunStatus::Completed),
            policy_decisions: vec![policy_decision()],
            approval_grants: vec![],
            execution_tickets: vec![execution_ticket()],
            sandbox_results: vec![sandbox_result()],
            proofs: vec![proof()],
            ledger_events: vec![ledger_event()],
        }
    }

    #[test]
    fn graph_projection_emits_facts_with_evidence() {
        let projection = ProjectionSnapshot::from_runtime_graph(&snapshot(), Some(&resume_plan()));

        assert_eq!(projection.schema_version, OBSERVABILITY_SCHEMA_VERSION);
        assert_eq!(projection.graph_id, "graph.observe");
        assert_eq!(projection.metrics.task_count, 1);
        assert_eq!(projection.metrics.completed_task_count, 1);
        assert_eq!(projection.metrics.already_committed_count, 1);
        assert!(projection
            .facts
            .iter()
            .any(|fact| fact.kind == RuntimeFactKind::PlannerBound));
        assert!(projection
            .facts
            .iter()
            .any(|fact| fact.kind == RuntimeFactKind::RuntimeEvent));
        assert!(projection
            .facts
            .iter()
            .any(|fact| fact.kind == RuntimeFactKind::AdoptionProbeObserved));
        assert!(projection
            .facts
            .iter()
            .all(|fact| !fact.evidence_refs.is_empty()));
        assert!(projection
            .facts
            .iter()
            .flat_map(|fact| &fact.evidence_refs)
            .all(|evidence| evidence
                .hash
                .as_deref()
                .unwrap_or("")
                .starts_with("sha256:")));
    }

    #[test]
    fn store_projection_emits_p0_facts_with_evidence() {
        let projection = StoreProjectionSnapshot::from_store_observation(&store_observation());
        let kinds = projection
            .facts
            .iter()
            .map(|fact| fact.kind)
            .collect::<Vec<_>>();

        assert_eq!(projection.schema_version, OBSERVABILITY_SCHEMA_VERSION);
        assert_eq!(projection.run_id, "run.store");
        assert_eq!(projection.metrics.policy_decision_count, 1);
        assert_eq!(projection.metrics.execution_ticket_count, 1);
        assert_eq!(projection.metrics.sandbox_result_count, 1);
        assert_eq!(projection.metrics.proof_count, 1);
        assert_eq!(projection.metrics.ledger_event_count, 1);
        assert_eq!(projection.metrics.successful_ledger_event_count, 1);
        assert!(projection.metrics.is_complete);
        assert!(kinds.contains(&RuntimeFactKind::StoreRunState));
        assert!(kinds.contains(&RuntimeFactKind::PolicyDecisionRecorded));
        assert!(kinds.contains(&RuntimeFactKind::ExecutionTicketRecorded));
        assert!(kinds.contains(&RuntimeFactKind::SandboxResultRecorded));
        assert!(kinds.contains(&RuntimeFactKind::ProofRecorded));
        assert!(kinds.contains(&RuntimeFactKind::LedgerEventRecorded));
        assert!(kinds.contains(&RuntimeFactKind::StoreRunCompleted));
        assert!(projection
            .facts
            .iter()
            .all(|fact| fact.run_id.as_deref() == Some("run.store")));
        assert!(projection
            .facts
            .iter()
            .all(|fact| !fact.evidence_refs.is_empty()));
    }

    #[test]
    fn facts_are_sorted_deterministically() {
        let facts = runtime_facts_from_graph_snapshot(&snapshot(), Some(&resume_plan()));
        let mut sorted = facts.clone();
        sorted.sort_by(|left, right| {
            left.timestamp
                .cmp(&right.timestamp)
                .then_with(|| left.kind.cmp(&right.kind))
                .then_with(|| left.graph_id.cmp(&right.graph_id))
                .then_with(|| left.task_id.cmp(&right.task_id))
                .then_with(|| left.run_id.cmp(&right.run_id))
                .then_with(|| left.fact_id.cmp(&right.fact_id))
        });

        assert_eq!(facts, sorted);
    }

    #[test]
    fn failed_attempt_fact_retains_error_and_task_identity() {
        let mut snapshot = snapshot();
        snapshot.tasks = vec![task_record(
            task_node("task.read", TaskState::Failed),
            at(3),
        )];
        snapshot.attempts = vec![RuntimeTaskAttempt {
            stage: RuntimeAttemptStage::Failed,
            ticket_id: None,
            ledger_event_id: None,
            error: Some("executor crashed".into()),
            ..attempt(RuntimeAttemptStage::Failed, at(2))
        }];
        let facts = runtime_facts_from_graph_snapshot(&snapshot, None);
        let failed = facts
            .iter()
            .find(|fact| fact.kind == RuntimeFactKind::AttemptFailed)
            .unwrap();

        assert_eq!(failed.graph_id, "graph.observe");
        assert_eq!(failed.run_id.as_deref(), Some("run.read"));
        assert_eq!(failed.task_id.as_deref(), Some("task.read"));
        assert_eq!(failed.payload["error"].as_str(), Some("executor crashed"));
    }
}
