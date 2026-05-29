use chrono::{DateTime, Utc};
use moxi_observability::{
    EvidenceRef, ProjectionSnapshot, RuntimeFact, RuntimeFactKind, StoreProjectionSnapshot,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const EVAL_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EvalCaseKind {
    P0ReplayAudit,
    PolicyBypassAttempt,
    PromptInjectionDataOnlyBoundary,
    ToolFeedbackInjection,
    MemoryContaminationPlaceholder,
    SwarmMergeWithoutEvidencePlaceholder,
    LatencyHotpathBenchmarkPlaceholder,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EvalSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EvalStatus {
    Passed,
    Failed,
    Skipped,
    NeedsReview,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReplayProfile {
    pub profile_id: String,
    pub description: String,
    pub source_projection_ref: Option<String>,
    pub required_fact_kinds: Vec<RuntimeFactKind>,
    pub fail_on_missing_evidence: bool,
    pub allow_placeholder_cases: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvalCase {
    pub case_id: String,
    pub kind: EvalCaseKind,
    pub title: String,
    pub description: String,
    pub severity: EvalSeverity,
    pub source_graph_id: Option<String>,
    pub source_run_id: Option<String>,
    pub fact_ids: Vec<String>,
    pub evidence_refs: Vec<EvidenceRef>,
    pub expected_fact_kinds: Vec<RuntimeFactKind>,
    pub payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvalSuite {
    pub suite_id: String,
    pub schema_version: u32,
    pub replay_profile: ReplayProfile,
    pub cases: Vec<EvalCase>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvalRun {
    pub run_id: String,
    pub suite_id: String,
    pub case_results: Vec<EvalCaseResult>,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvalCaseResult {
    pub case_id: String,
    pub status: EvalStatus,
    pub severity: EvalSeverity,
    pub findings: Vec<SafetyFinding>,
    pub evidence_refs: Vec<EvidenceRef>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvalScore {
    pub total_cases: usize,
    pub passed_cases: usize,
    pub failed_cases: usize,
    pub skipped_cases: usize,
    pub needs_review_cases: usize,
    pub critical_findings: usize,
    pub high_findings: usize,
    pub adaptive_promotion_allowed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RegressionReport {
    pub report_id: String,
    pub suite_id: String,
    pub eval_run_id: String,
    pub score: EvalScore,
    pub findings: Vec<SafetyFinding>,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SafetyFinding {
    pub finding_id: String,
    pub case_id: String,
    pub severity: EvalSeverity,
    pub title: String,
    pub message: String,
    pub evidence_refs: Vec<EvidenceRef>,
}

impl ReplayProfile {
    pub fn p0_replay_audit(source_projection_ref: impl Into<String>) -> Self {
        Self {
            profile_id: "p0.replay.audit.v1".into(),
            description: "Require P0 store/ledger facts before adaptive promotion.".into(),
            source_projection_ref: Some(source_projection_ref.into()),
            required_fact_kinds: vec![
                RuntimeFactKind::PolicyDecisionRecorded,
                RuntimeFactKind::ExecutionTicketRecorded,
                RuntimeFactKind::SandboxResultRecorded,
                RuntimeFactKind::ProofRecorded,
                RuntimeFactKind::LedgerEventRecorded,
            ],
            fail_on_missing_evidence: true,
            allow_placeholder_cases: true,
        }
    }
}

impl EvalSuite {
    pub fn from_store_projection(
        suite_id: impl Into<String>,
        projection: &StoreProjectionSnapshot,
    ) -> Self {
        let suite_id = suite_id.into();
        let replay_profile = ReplayProfile::p0_replay_audit(format!("store:{}", projection.run_id));
        let cases = vec![EvalCase::p0_replay_audit(
            &suite_id,
            Some(projection.run_id.clone()),
            &projection.facts,
            &replay_profile.required_fact_kinds,
        )];
        Self {
            suite_id,
            schema_version: EVAL_SCHEMA_VERSION,
            replay_profile,
            cases,
            created_at: Utc::now(),
        }
    }

    pub fn from_projection(snapshot: &ProjectionSnapshot) -> Self {
        let suite_id = format!("eval.runtime.{}", snapshot.graph_id);
        let replay_profile = ReplayProfile {
            profile_id: "runtime.fact.regression.v1".into(),
            description: "Require runtime facts to preserve replayable graph evidence.".into(),
            source_projection_ref: Some(format!("runtime:{}", snapshot.graph_id)),
            required_fact_kinds: vec![
                RuntimeFactKind::GraphPlanned,
                RuntimeFactKind::PlannerBound,
                RuntimeFactKind::TaskState,
            ],
            fail_on_missing_evidence: true,
            allow_placeholder_cases: true,
        };
        let cases = vec![EvalCase::runtime_fact_regression(
            &suite_id,
            snapshot.graph_id.clone(),
            &snapshot.facts,
            &replay_profile.required_fact_kinds,
        )];
        Self {
            suite_id,
            schema_version: EVAL_SCHEMA_VERSION,
            replay_profile,
            cases,
            created_at: Utc::now(),
        }
    }

    pub fn with_security_placeholders(mut self) -> Self {
        self.cases.extend([
            EvalCase::placeholder(
                &self.suite_id,
                EvalCaseKind::PolicyBypassAttempt,
                "policy bypass attempt must fail closed",
                EvalSeverity::Critical,
            ),
            EvalCase::placeholder(
                &self.suite_id,
                EvalCaseKind::PromptInjectionDataOnlyBoundary,
                "prompt injection remains data-only",
                EvalSeverity::High,
            ),
            EvalCase::placeholder(
                &self.suite_id,
                EvalCaseKind::ToolFeedbackInjection,
                "tool feedback cannot become authority",
                EvalSeverity::High,
            ),
            EvalCase::placeholder(
                &self.suite_id,
                EvalCaseKind::MemoryContaminationPlaceholder,
                "memory contamination requires review",
                EvalSeverity::Medium,
            ),
            EvalCase::placeholder(
                &self.suite_id,
                EvalCaseKind::SwarmMergeWithoutEvidencePlaceholder,
                "swarm merge requires evidence",
                EvalSeverity::Medium,
            ),
            EvalCase::placeholder(
                &self.suite_id,
                EvalCaseKind::LatencyHotpathBenchmarkPlaceholder,
                "latency hotpath needs measured budget facts",
                EvalSeverity::Low,
            ),
        ]);
        self
    }

    pub fn run_regression(&self) -> EvalRun {
        let started_at = Utc::now();
        let case_results = self
            .cases
            .iter()
            .map(|case| evaluate_case(case, &self.replay_profile))
            .collect::<Vec<_>>();
        let finished_at = Utc::now();
        EvalRun {
            run_id: stable_id("eval_run", &(self.suite_id.as_str(), &case_results)),
            suite_id: self.suite_id.clone(),
            case_results,
            started_at,
            finished_at,
        }
    }
}

impl EvalCase {
    fn p0_replay_audit(
        suite_id: &str,
        source_run_id: Option<String>,
        facts: &[RuntimeFact],
        expected_fact_kinds: &[RuntimeFactKind],
    ) -> Self {
        let relevant_facts = facts
            .iter()
            .filter(|fact| {
                expected_fact_kinds.contains(&fact.kind)
                    || fact.kind == RuntimeFactKind::StoreRunCompleted
            })
            .collect::<Vec<_>>();
        let fact_ids = relevant_facts
            .iter()
            .map(|fact| fact.fact_id.clone())
            .collect::<Vec<_>>();
        let evidence_refs = evidence_refs_from_facts(&relevant_facts);
        let case_id = stable_id("eval_case", &(suite_id, "p0_replay_audit", &fact_ids));
        Self {
            case_id,
            kind: EvalCaseKind::P0ReplayAudit,
            title: "P0 replay/audit facts remain complete".into(),
            description: "Checks that persisted P0 facts include policy, ticket, sandbox result, proof, and ledger evidence.".into(),
            severity: EvalSeverity::Critical,
            source_graph_id: None,
            source_run_id,
            fact_ids,
            evidence_refs,
            expected_fact_kinds: expected_fact_kinds.to_vec(),
            payload: json!({
                "required_fact_kinds": expected_fact_kinds,
                "observed_fact_kinds": relevant_facts
                    .iter()
                    .map(|fact| fact.kind)
                    .collect::<Vec<_>>(),
            }),
        }
    }

    fn runtime_fact_regression(
        suite_id: &str,
        source_graph_id: String,
        facts: &[RuntimeFact],
        expected_fact_kinds: &[RuntimeFactKind],
    ) -> Self {
        let relevant_facts = facts
            .iter()
            .filter(|fact| expected_fact_kinds.contains(&fact.kind))
            .collect::<Vec<_>>();
        let fact_ids = relevant_facts
            .iter()
            .map(|fact| fact.fact_id.clone())
            .collect::<Vec<_>>();
        let evidence_refs = evidence_refs_from_facts(&relevant_facts);
        let case_id = stable_id(
            "eval_case",
            &(suite_id, "runtime_fact_regression", &fact_ids),
        );
        Self {
            case_id,
            kind: EvalCaseKind::P0ReplayAudit,
            title: "runtime facts remain replayable".into(),
            description:
                "Checks that runtime projection facts preserve planning and task-state evidence."
                    .into(),
            severity: EvalSeverity::High,
            source_graph_id: Some(source_graph_id),
            source_run_id: None,
            fact_ids,
            evidence_refs,
            expected_fact_kinds: expected_fact_kinds.to_vec(),
            payload: json!({
                "required_fact_kinds": expected_fact_kinds,
                "observed_fact_kinds": relevant_facts
                    .iter()
                    .map(|fact| fact.kind)
                    .collect::<Vec<_>>(),
            }),
        }
    }

    fn placeholder(
        suite_id: &str,
        kind: EvalCaseKind,
        title: impl Into<String>,
        severity: EvalSeverity,
    ) -> Self {
        let title = title.into();
        Self {
            case_id: stable_id("eval_case", &(suite_id, kind, title.as_str())),
            kind,
            title,
            description: "Placeholder case keeps the regression surface visible until a concrete fixture is added.".into(),
            severity,
            source_graph_id: None,
            source_run_id: None,
            fact_ids: Vec::new(),
            evidence_refs: Vec::new(),
            expected_fact_kinds: Vec::new(),
            payload: json!({
                "placeholder": true,
            }),
        }
    }
}

impl RegressionReport {
    pub fn from_eval_run(run: &EvalRun) -> Self {
        let findings = run
            .case_results
            .iter()
            .flat_map(|result| result.findings.clone())
            .collect::<Vec<_>>();
        let score = EvalScore::from_case_results(&run.case_results);
        Self {
            report_id: stable_id("regression_report", &(run.suite_id.as_str(), &run.run_id)),
            suite_id: run.suite_id.clone(),
            eval_run_id: run.run_id.clone(),
            score,
            findings,
            generated_at: Utc::now(),
        }
    }
}

impl EvalScore {
    pub fn from_case_results(results: &[EvalCaseResult]) -> Self {
        let total_cases = results.len();
        let passed_cases = results
            .iter()
            .filter(|result| result.status == EvalStatus::Passed)
            .count();
        let failed_cases = results
            .iter()
            .filter(|result| result.status == EvalStatus::Failed)
            .count();
        let skipped_cases = results
            .iter()
            .filter(|result| result.status == EvalStatus::Skipped)
            .count();
        let needs_review_cases = results
            .iter()
            .filter(|result| result.status == EvalStatus::NeedsReview)
            .count();
        let critical_findings = results
            .iter()
            .flat_map(|result| &result.findings)
            .filter(|finding| finding.severity == EvalSeverity::Critical)
            .count();
        let high_findings = results
            .iter()
            .flat_map(|result| &result.findings)
            .filter(|finding| finding.severity == EvalSeverity::High)
            .count();
        let adaptive_promotion_allowed =
            failed_cases == 0 && critical_findings == 0 && high_findings == 0;
        Self {
            total_cases,
            passed_cases,
            failed_cases,
            skipped_cases,
            needs_review_cases,
            critical_findings,
            high_findings,
            adaptive_promotion_allowed,
        }
    }
}

fn evaluate_case(case: &EvalCase, profile: &ReplayProfile) -> EvalCaseResult {
    if is_placeholder(case) {
        return EvalCaseResult {
            case_id: case.case_id.clone(),
            status: if profile.allow_placeholder_cases {
                EvalStatus::Skipped
            } else {
                EvalStatus::NeedsReview
            },
            severity: case.severity,
            findings: Vec::new(),
            evidence_refs: Vec::new(),
            message: "placeholder case is waiting for a concrete fixture".into(),
        };
    }

    let missing_evidence = profile.fail_on_missing_evidence && case.evidence_refs.is_empty();
    let missing_facts = case
        .expected_fact_kinds
        .iter()
        .filter(|kind| !case.payload_has_fact_kind(kind))
        .copied()
        .collect::<Vec<_>>();

    if missing_evidence || !missing_facts.is_empty() {
        let finding = SafetyFinding {
            finding_id: stable_id(
                "finding",
                &(case.case_id.as_str(), missing_evidence, &missing_facts),
            ),
            case_id: case.case_id.clone(),
            severity: case.severity,
            title: "required regression evidence is incomplete".into(),
            message: format!(
                "missing_evidence={missing_evidence}; missing_fact_kinds={missing_facts:?}"
            ),
            evidence_refs: case.evidence_refs.clone(),
        };
        return EvalCaseResult {
            case_id: case.case_id.clone(),
            status: EvalStatus::Failed,
            severity: case.severity,
            findings: vec![finding],
            evidence_refs: case.evidence_refs.clone(),
            message: "required regression evidence is incomplete".into(),
        };
    }

    EvalCaseResult {
        case_id: case.case_id.clone(),
        status: EvalStatus::Passed,
        severity: case.severity,
        findings: Vec::new(),
        evidence_refs: case.evidence_refs.clone(),
        message: "required regression facts and evidence are present".into(),
    }
}

trait EvalCasePayloadExt {
    fn payload_has_fact_kind(&self, kind: &RuntimeFactKind) -> bool;
}

impl EvalCasePayloadExt for EvalCase {
    fn payload_has_fact_kind(&self, kind: &RuntimeFactKind) -> bool {
        self.expected_fact_kinds.contains(kind)
            && self
                .payload
                .get("observed_fact_kinds")
                .and_then(Value::as_array)
                .map(|items| {
                    let wanted = serde_json::to_value(kind).expect("RuntimeFactKind serializes");
                    items.iter().any(|item| item == &wanted)
                })
                .unwrap_or(false)
            && !self.fact_ids.is_empty()
    }
}

fn is_placeholder(case: &EvalCase) -> bool {
    case.payload
        .get("placeholder")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn evidence_refs_from_facts(facts: &[&RuntimeFact]) -> Vec<EvidenceRef> {
    let mut evidence_refs = facts
        .iter()
        .flat_map(|fact| fact.evidence_refs.clone())
        .collect::<Vec<_>>();
    evidence_refs.sort();
    evidence_refs.dedup();
    evidence_refs
}

fn stable_id(prefix: &str, value: &impl Serialize) -> String {
    let json = serde_json::to_vec(value).expect("stable id input should serialize");
    let digest = Sha256::digest(json);
    format!("{prefix}.{}", hex::encode(&digest[..8]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use moxi_observability::{
        EvidenceSource, RunTimeline, RuntimeFact, RuntimeFactKind, StoreRunMetric,
    };

    fn at(second: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 5, 26, 0, 0, second)
            .single()
            .unwrap()
    }

    fn evidence(id: &str) -> EvidenceRef {
        EvidenceRef {
            source: EvidenceSource::LedgerEvent,
            id: id.into(),
            graph_id: None,
            run_id: Some("run.eval".into()),
            task_id: None,
            hash: Some(format!("sha256:{id}")),
        }
    }

    fn fact(kind: RuntimeFactKind, id: &str) -> RuntimeFact {
        RuntimeFact {
            fact_id: id.into(),
            kind,
            graph_id: "run.eval".into(),
            run_id: Some("run.eval".into()),
            task_id: None,
            message: format!("{kind:?}"),
            evidence_refs: vec![evidence(id)],
            timestamp: at(1),
            payload: json!({ "id": id }),
        }
    }

    fn store_projection() -> StoreProjectionSnapshot {
        let facts = vec![
            fact(RuntimeFactKind::PolicyDecisionRecorded, "fact.policy"),
            fact(RuntimeFactKind::ExecutionTicketRecorded, "fact.ticket"),
            fact(RuntimeFactKind::SandboxResultRecorded, "fact.sandbox"),
            fact(RuntimeFactKind::ProofRecorded, "fact.proof"),
            fact(RuntimeFactKind::LedgerEventRecorded, "fact.ledger"),
            fact(RuntimeFactKind::StoreRunCompleted, "fact.complete"),
        ];
        StoreProjectionSnapshot {
            schema_version: 1,
            run_id: "run.eval".into(),
            timeline: RunTimeline {
                graph_id: "run.eval".into(),
                facts: facts.clone(),
                generated_at: at(2),
            },
            metrics: StoreRunMetric {
                run_id: "run.eval".into(),
                policy_decision_count: 1,
                approval_grant_count: 0,
                execution_ticket_count: 1,
                sandbox_result_count: 1,
                proof_count: 1,
                ledger_event_count: 1,
                successful_ledger_event_count: 1,
                failed_ledger_event_count: 0,
                has_status: true,
                is_complete: true,
            },
            facts,
            generated_at: at(2),
        }
    }

    #[test]
    fn builds_eval_suite_from_store_projection() {
        let suite = EvalSuite::from_store_projection("suite.eval", &store_projection());

        assert_eq!(suite.schema_version, EVAL_SCHEMA_VERSION);
        assert_eq!(suite.cases.len(), 1);
        assert_eq!(suite.cases[0].kind, EvalCaseKind::P0ReplayAudit);
        assert_eq!(suite.cases[0].fact_ids.len(), 6);
        assert!(!suite.cases[0].evidence_refs.is_empty());
    }

    #[test]
    fn regression_report_allows_promotion_when_required_facts_exist() {
        let suite = EvalSuite::from_store_projection("suite.eval", &store_projection())
            .with_security_placeholders();
        let run = suite.run_regression();
        let report = RegressionReport::from_eval_run(&run);

        assert_eq!(report.score.total_cases, 7);
        assert_eq!(report.score.passed_cases, 1);
        assert_eq!(report.score.skipped_cases, 6);
        assert_eq!(report.score.failed_cases, 0);
        assert!(report.score.adaptive_promotion_allowed);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn missing_p0_evidence_blocks_adaptive_promotion() {
        let mut projection = store_projection();
        projection
            .facts
            .retain(|fact| fact.kind != RuntimeFactKind::ProofRecorded);
        let suite = EvalSuite::from_store_projection("suite.eval", &projection);
        let run = suite.run_regression();
        let report = RegressionReport::from_eval_run(&run);

        assert_eq!(report.score.failed_cases, 1);
        assert!(!report.score.adaptive_promotion_allowed);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].severity, EvalSeverity::Critical);
    }
}
