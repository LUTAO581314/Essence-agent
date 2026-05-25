use chrono::{DateTime, Utc};
use moxi_runtime::{
    RuntimeAdoptionAction, RuntimeAdoptionProbeRecord, RuntimeAttemptStage, RuntimeGraphSnapshot,
    RuntimeQuerySnapshot, RuntimeResumePlan, RuntimeTaskAttempt, TaskState,
};
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

impl RunTimeline {
    pub fn from_facts(graph_id: impl Into<String>, facts: Vec<RuntimeFact>) -> Self {
        Self {
            graph_id: graph_id.into(),
            facts: sort_facts(facts),
            generated_at: Utc::now(),
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
    use moxi_contracts::{DeltaTarget, ResourceType, RiskLevel};
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
