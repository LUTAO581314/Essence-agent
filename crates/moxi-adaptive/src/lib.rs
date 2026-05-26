use chrono::{DateTime, Utc};
use moxi_contracts::RiskLevel;
use moxi_eval::{EvalSeverity, RegressionReport};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const ADAPTIVE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Error, PartialEq)]
pub enum AdaptiveError {
    #[error("adaptive proposal requires eval evidence")]
    MissingEvalEvidence,
    #[error("adaptive proposal is blocked by regression report")]
    RegressionBlocked,
    #[error("adaptive cannot directly change P0 policy or capability contracts")]
    ProtectedDeltaRequiresGovernance,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum OptimizationDeltaKind {
    Prompt,
    Route,
    SkillRoute,
    Planner,
    MemoryPolicy,
    Swarm,
    PolicyPack,
    Capability,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OptimizationDeltaStatus {
    Proposed,
    NeedsGovernance,
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RootCauseHypothesis {
    pub hypothesis_id: String,
    pub title: String,
    pub description: String,
    pub severity: EvalSeverity,
    pub evidence_refs: Vec<String>,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReflectionReport {
    pub report_id: String,
    pub source_regression_report_id: String,
    pub summary: String,
    pub hypotheses: Vec<RootCauseHypothesis>,
    pub eval_evidence_refs: Vec<String>,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OptimizationDelta {
    pub delta_id: String,
    pub kind: OptimizationDeltaKind,
    pub target_ref: String,
    pub summary: String,
    pub payload: Value,
    pub risk_level: RiskLevel,
    pub evidence_refs: Vec<String>,
    pub status: OptimizationDeltaStatus,
    pub requires_human_approval: bool,
    pub cannot_modify_p0_directly: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExperimentPlan {
    pub experiment_id: String,
    pub delta_id: String,
    pub control_ref: String,
    pub treatment_ref: String,
    pub success_metric: String,
    pub minimum_eval_cases: usize,
    pub rollout_percent: u8,
    pub evidence_refs: Vec<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExperimentResult {
    pub result_id: String,
    pub experiment_id: String,
    pub passed: bool,
    pub score_delta: f32,
    pub regression_report_id: String,
    pub evidence_refs: Vec<String>,
    pub finished_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct AdaptiveController;

impl AdaptiveController {
    pub fn reflect(report: &RegressionReport) -> Result<ReflectionReport, AdaptiveError> {
        if report.eval_run_id.trim().is_empty() {
            return Err(AdaptiveError::MissingEvalEvidence);
        }
        let eval_evidence_refs = vec![report.eval_run_id.clone(), report.report_id.clone()];
        let hypotheses = report
            .findings
            .iter()
            .map(|finding| RootCauseHypothesis {
                hypothesis_id: stable_id(
                    "root_cause",
                    &(report.report_id.as_str(), finding.finding_id.as_str()),
                ),
                title: finding.title.clone(),
                description: finding.message.clone(),
                severity: finding.severity,
                evidence_refs: finding
                    .evidence_refs
                    .iter()
                    .map(|evidence| evidence.id.clone())
                    .collect(),
                confidence: match finding.severity {
                    EvalSeverity::Critical | EvalSeverity::High => 0.9,
                    EvalSeverity::Medium => 0.7,
                    _ => 0.5,
                },
            })
            .collect::<Vec<_>>();
        Ok(ReflectionReport {
            report_id: stable_id("reflection", &report.report_id),
            source_regression_report_id: report.report_id.clone(),
            summary: format!(
                "{} findings, adaptive promotion allowed: {}",
                report.findings.len(),
                report.score.adaptive_promotion_allowed
            ),
            hypotheses,
            eval_evidence_refs,
            generated_at: Utc::now(),
        })
    }

    pub fn propose_delta(
        reflection: &ReflectionReport,
        kind: OptimizationDeltaKind,
        target_ref: impl Into<String>,
        summary: impl Into<String>,
        payload: Value,
        risk_level: RiskLevel,
    ) -> Result<OptimizationDelta, AdaptiveError> {
        if reflection.eval_evidence_refs.is_empty() {
            return Err(AdaptiveError::MissingEvalEvidence);
        }
        let protected = matches!(
            kind,
            OptimizationDeltaKind::PolicyPack | OptimizationDeltaKind::Capability
        );
        let status = if protected {
            OptimizationDeltaStatus::NeedsGovernance
        } else {
            OptimizationDeltaStatus::Proposed
        };
        let target_ref = target_ref.into();
        let summary = summary.into();
        Ok(OptimizationDelta {
            delta_id: stable_id(
                "optimization_delta",
                &(
                    reflection.report_id.as_str(),
                    &kind,
                    target_ref.as_str(),
                    &payload,
                ),
            ),
            kind,
            target_ref,
            summary,
            payload,
            risk_level,
            evidence_refs: reflection.eval_evidence_refs.clone(),
            status,
            requires_human_approval: protected || risk_level >= RiskLevel::High,
            cannot_modify_p0_directly: true,
            created_at: Utc::now(),
        })
    }

    pub fn experiment_plan(
        delta: &OptimizationDelta,
        control_ref: impl Into<String>,
        treatment_ref: impl Into<String>,
        success_metric: impl Into<String>,
    ) -> Result<ExperimentPlan, AdaptiveError> {
        if delta.evidence_refs.is_empty() {
            return Err(AdaptiveError::MissingEvalEvidence);
        }
        Ok(ExperimentPlan {
            experiment_id: stable_id("experiment", &delta.delta_id),
            delta_id: delta.delta_id.clone(),
            control_ref: control_ref.into(),
            treatment_ref: treatment_ref.into(),
            success_metric: success_metric.into(),
            minimum_eval_cases: 1,
            rollout_percent: 5,
            evidence_refs: delta.evidence_refs.clone(),
            created_at: Utc::now(),
        })
    }

    pub fn experiment_result(
        plan: &ExperimentPlan,
        regression_report: &RegressionReport,
        score_delta: f32,
    ) -> ExperimentResult {
        let passed = regression_report.score.adaptive_promotion_allowed && score_delta >= 0.0;
        ExperimentResult {
            result_id: stable_id(
                "experiment_result",
                &(
                    plan.experiment_id.as_str(),
                    regression_report.report_id.as_str(),
                ),
            ),
            experiment_id: plan.experiment_id.clone(),
            passed,
            score_delta,
            regression_report_id: regression_report.report_id.clone(),
            evidence_refs: vec![
                regression_report.report_id.clone(),
                regression_report.eval_run_id.clone(),
            ],
            finished_at: Utc::now(),
        }
    }
}

pub fn adaptive_eval_payload(delta: &OptimizationDelta) -> Value {
    json!({
        "delta_id": delta.delta_id,
        "kind": delta.kind,
        "target_ref": delta.target_ref,
        "requires_human_approval": delta.requires_human_approval,
        "cannot_modify_p0_directly": delta.cannot_modify_p0_directly,
        "evidence_refs": delta.evidence_refs,
    })
}

fn stable_id(prefix: &str, value: &impl Serialize) -> String {
    let json = serde_json::to_vec(value).expect("stable id input should serialize");
    let digest = Sha256::digest(json);
    format!("{prefix}.{}", hex::encode(&digest[..8]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use moxi_eval::{EvalScore, EvalSeverity, SafetyFinding};

    fn passing_report() -> RegressionReport {
        RegressionReport {
            report_id: "report.pass".into(),
            suite_id: "suite".into(),
            eval_run_id: "eval.run".into(),
            score: EvalScore {
                total_cases: 2,
                passed_cases: 2,
                failed_cases: 0,
                skipped_cases: 0,
                needs_review_cases: 0,
                critical_findings: 0,
                high_findings: 0,
                adaptive_promotion_allowed: true,
            },
            findings: vec![],
            generated_at: Utc::now(),
        }
    }

    fn failing_report() -> RegressionReport {
        let mut report = passing_report();
        report.report_id = "report.fail".into();
        report.score.adaptive_promotion_allowed = false;
        report.score.high_findings = 1;
        report.findings = vec![SafetyFinding {
            finding_id: "finding.1".into(),
            case_id: "case.1".into(),
            severity: EvalSeverity::High,
            title: "route regression".into(),
            message: "model route exceeded risk budget".into(),
            evidence_refs: vec![],
        }];
        report
    }

    #[test]
    fn reflection_uses_eval_evidence() {
        let reflection = AdaptiveController::reflect(&failing_report()).unwrap();

        assert_eq!(reflection.hypotheses.len(), 1);
        assert!(reflection.eval_evidence_refs.contains(&"eval.run".into()));
    }

    #[test]
    fn route_delta_is_proposed_but_cannot_modify_p0_directly() {
        let reflection = AdaptiveController::reflect(&passing_report()).unwrap();
        let delta = AdaptiveController::propose_delta(
            &reflection,
            OptimizationDeltaKind::Route,
            "model.gateway.default",
            "prefer local model for low-risk chat",
            json!({"prefer_local": true}),
            RiskLevel::Low,
        )
        .unwrap();

        assert_eq!(delta.status, OptimizationDeltaStatus::Proposed);
        assert!(delta.cannot_modify_p0_directly);
        assert!(!delta.requires_human_approval);
    }

    #[test]
    fn policy_delta_requires_governance_and_human_approval() {
        let reflection = AdaptiveController::reflect(&passing_report()).unwrap();
        let delta = AdaptiveController::propose_delta(
            &reflection,
            OptimizationDeltaKind::PolicyPack,
            "policy.default",
            "tighten high-risk approval threshold",
            json!({"approval_required_at_or_above": "medium"}),
            RiskLevel::High,
        )
        .unwrap();

        assert_eq!(delta.status, OptimizationDeltaStatus::NeedsGovernance);
        assert!(delta.requires_human_approval);
        assert!(delta.cannot_modify_p0_directly);
    }

    #[test]
    fn experiment_plan_and_result_bind_back_to_eval() {
        let reflection = AdaptiveController::reflect(&passing_report()).unwrap();
        let delta = AdaptiveController::propose_delta(
            &reflection,
            OptimizationDeltaKind::MemoryPolicy,
            "memory.retention",
            "reduce session retention",
            json!({"retention": "session"}),
            RiskLevel::Medium,
        )
        .unwrap();
        let plan = AdaptiveController::experiment_plan(
            &delta,
            "memory.policy.current",
            "memory.policy.treatment",
            "regression_pass_rate",
        )
        .unwrap();
        let result = AdaptiveController::experiment_result(&plan, &passing_report(), 0.1);

        assert!(result.passed);
        assert_eq!(result.experiment_id, plan.experiment_id);
        assert_eq!(
            adaptive_eval_payload(&delta)["cannot_modify_p0_directly"],
            true
        );
    }
}
