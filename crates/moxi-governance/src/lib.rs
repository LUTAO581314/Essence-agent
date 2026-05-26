use chrono::{DateTime, Utc};
use moxi_adaptive::{
    ExperimentResult, OptimizationDelta, OptimizationDeltaKind, OptimizationDeltaStatus,
};
use moxi_contracts::{ApprovalPolicy, RiskLevel};
use moxi_eval::EvalSeverity;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const GOVERNANCE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Error, PartialEq)]
pub enum GovernanceError {
    #[error("governance decision requires eval evidence")]
    MissingEvidence,
    #[error("experiment did not pass")]
    ExperimentFailed,
    #[error("protected delta requires human approval")]
    HumanApprovalRequired,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PromotionDecisionKind {
    Approved,
    Rejected,
    NeedsHumanApproval,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvolutionEventKind {
    PromotionDecided,
    RolloutPlanned,
    RollbackPlanned,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PromotionDecision {
    pub decision_id: String,
    pub delta_id: String,
    pub experiment_result_id: String,
    pub decision: PromotionDecisionKind,
    pub approval_policy: ApprovalPolicy,
    pub risk_level: RiskLevel,
    pub reasons: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub decided_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RolloutPlan {
    pub rollout_id: String,
    pub delta_id: String,
    pub decision_id: String,
    pub stages: Vec<RolloutStage>,
    pub rollback_ref: Option<String>,
    pub evidence_refs: Vec<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RolloutStage {
    pub stage_id: String,
    pub percent: u8,
    pub min_eval_pass_rate: f32,
    pub hold_minutes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RollbackPlan {
    pub rollback_id: String,
    pub delta_id: String,
    pub rollout_id: Option<String>,
    pub reason: String,
    pub evidence_refs: Vec<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvolutionEvent {
    pub event_id: String,
    pub kind: EvolutionEventKind,
    pub target_ref: String,
    pub summary: String,
    pub evidence_refs: Vec<String>,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvolutionLedger {
    pub ledger_id: String,
    pub schema_version: u32,
    pub events: Vec<EvolutionEvent>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct GovernanceController;

impl GovernanceController {
    pub fn decide_promotion(
        delta: &OptimizationDelta,
        result: &ExperimentResult,
        human_approval_ref: Option<String>,
    ) -> Result<PromotionDecision, GovernanceError> {
        if delta.evidence_refs.is_empty() || result.evidence_refs.is_empty() {
            return Err(GovernanceError::MissingEvidence);
        }
        if !result.passed {
            return Err(GovernanceError::ExperimentFailed);
        }
        let protected = matches!(
            delta.kind,
            OptimizationDeltaKind::PolicyPack | OptimizationDeltaKind::Capability
        );
        let needs_human = delta.requires_human_approval
            || protected
            || delta.risk_level >= RiskLevel::High
            || delta.status == OptimizationDeltaStatus::NeedsGovernance;
        let decision = if needs_human && human_approval_ref.is_none() {
            PromotionDecisionKind::NeedsHumanApproval
        } else {
            PromotionDecisionKind::Approved
        };
        let mut evidence_refs = delta.evidence_refs.clone();
        evidence_refs.extend(result.evidence_refs.clone());
        if let Some(ref approval_ref) = human_approval_ref {
            evidence_refs.push(approval_ref.clone());
        }
        evidence_refs.sort();
        evidence_refs.dedup();
        Ok(PromotionDecision {
            decision_id: stable_id(
                "promotion",
                &(
                    delta.delta_id.as_str(),
                    result.result_id.as_str(),
                    human_approval_ref.as_deref(),
                ),
            ),
            delta_id: delta.delta_id.clone(),
            experiment_result_id: result.result_id.clone(),
            decision,
            approval_policy: if needs_human {
                ApprovalPolicy::Human
            } else {
                ApprovalPolicy::None
            },
            risk_level: delta.risk_level,
            reasons: vec![format!(
                "experiment passed with score delta {}",
                result.score_delta
            )],
            evidence_refs,
            decided_at: Utc::now(),
        })
    }

    pub fn rollout_plan(
        decision: &PromotionDecision,
        delta: &OptimizationDelta,
    ) -> Result<RolloutPlan, GovernanceError> {
        if decision.evidence_refs.is_empty() {
            return Err(GovernanceError::MissingEvidence);
        }
        if decision.decision == PromotionDecisionKind::NeedsHumanApproval {
            return Err(GovernanceError::HumanApprovalRequired);
        }
        Ok(RolloutPlan {
            rollout_id: stable_id(
                "rollout",
                &(decision.decision_id.as_str(), delta.delta_id.as_str()),
            ),
            delta_id: delta.delta_id.clone(),
            decision_id: decision.decision_id.clone(),
            stages: vec![
                RolloutStage {
                    stage_id: "stage.5".into(),
                    percent: 5,
                    min_eval_pass_rate: 1.0,
                    hold_minutes: 30,
                },
                RolloutStage {
                    stage_id: "stage.25".into(),
                    percent: 25,
                    min_eval_pass_rate: 1.0,
                    hold_minutes: 60,
                },
            ],
            rollback_ref: Some(format!("rollback:{}", delta.delta_id)),
            evidence_refs: decision.evidence_refs.clone(),
            created_at: Utc::now(),
        })
    }

    pub fn rollback_plan(
        delta: &OptimizationDelta,
        rollout: Option<&RolloutPlan>,
        reason: impl Into<String>,
        evidence_refs: Vec<String>,
    ) -> Result<RollbackPlan, GovernanceError> {
        if evidence_refs.is_empty() {
            return Err(GovernanceError::MissingEvidence);
        }
        let rollout_id = rollout.map(|plan| plan.rollout_id.clone());
        Ok(RollbackPlan {
            rollback_id: stable_id(
                "rollback",
                &(
                    delta.delta_id.as_str(),
                    rollout_id.as_deref(),
                    &evidence_refs,
                ),
            ),
            delta_id: delta.delta_id.clone(),
            rollout_id,
            reason: reason.into(),
            evidence_refs,
            created_at: Utc::now(),
        })
    }
}

impl EvolutionLedger {
    pub fn new(ledger_id: impl Into<String>) -> Self {
        Self {
            ledger_id: ledger_id.into(),
            schema_version: GOVERNANCE_SCHEMA_VERSION,
            events: Vec::new(),
            created_at: Utc::now(),
        }
    }

    pub fn record_promotion(&mut self, decision: &PromotionDecision) {
        self.events.push(EvolutionEvent {
            event_id: stable_id("evolution_event", &(decision.decision_id.as_str(), 1_u8)),
            kind: EvolutionEventKind::PromotionDecided,
            target_ref: decision.delta_id.clone(),
            summary: format!("promotion decision: {:?}", decision.decision),
            evidence_refs: decision.evidence_refs.clone(),
            occurred_at: Utc::now(),
        });
    }

    pub fn record_rollout(&mut self, rollout: &RolloutPlan) {
        self.events.push(EvolutionEvent {
            event_id: stable_id("evolution_event", &(rollout.rollout_id.as_str(), 2_u8)),
            kind: EvolutionEventKind::RolloutPlanned,
            target_ref: rollout.delta_id.clone(),
            summary: format!("rollout planned with {} stages", rollout.stages.len()),
            evidence_refs: rollout.evidence_refs.clone(),
            occurred_at: Utc::now(),
        });
    }

    pub fn record_rollback(&mut self, rollback: &RollbackPlan) {
        self.events.push(EvolutionEvent {
            event_id: stable_id("evolution_event", &(rollback.rollback_id.as_str(), 3_u8)),
            kind: EvolutionEventKind::RollbackPlanned,
            target_ref: rollback.delta_id.clone(),
            summary: rollback.reason.clone(),
            evidence_refs: rollback.evidence_refs.clone(),
            occurred_at: Utc::now(),
        });
    }
}

pub fn governance_safety_summary(decision: &PromotionDecision) -> EvalSeverity {
    match decision.decision {
        PromotionDecisionKind::Approved if decision.risk_level >= RiskLevel::High => {
            EvalSeverity::High
        }
        PromotionDecisionKind::NeedsHumanApproval => EvalSeverity::Medium,
        PromotionDecisionKind::Rejected => EvalSeverity::High,
        PromotionDecisionKind::Approved => EvalSeverity::Info,
    }
}

fn stable_id(prefix: &str, value: &impl Serialize) -> String {
    let json = serde_json::to_vec(value).expect("stable id input should serialize");
    let digest = Sha256::digest(json);
    format!("{prefix}.{}", hex::encode(&digest[..8]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use moxi_adaptive::{OptimizationDeltaKind, OptimizationDeltaStatus};
    use serde_json::json;

    fn delta(kind: OptimizationDeltaKind, risk_level: RiskLevel) -> OptimizationDelta {
        OptimizationDelta {
            delta_id: "delta.1".into(),
            kind,
            target_ref: "target".into(),
            summary: "safe improvement".into(),
            payload: json!({"value": true}),
            risk_level,
            evidence_refs: vec!["eval.run".into(), "report.1".into()],
            status: if matches!(
                kind,
                OptimizationDeltaKind::PolicyPack | OptimizationDeltaKind::Capability
            ) {
                OptimizationDeltaStatus::NeedsGovernance
            } else {
                OptimizationDeltaStatus::Proposed
            },
            requires_human_approval: risk_level >= RiskLevel::High
                || matches!(
                    kind,
                    OptimizationDeltaKind::PolicyPack | OptimizationDeltaKind::Capability
                ),
            cannot_modify_p0_directly: true,
            created_at: Utc::now(),
        }
    }

    fn result(passed: bool) -> ExperimentResult {
        ExperimentResult {
            result_id: "result.1".into(),
            experiment_id: "experiment.1".into(),
            passed,
            score_delta: if passed { 0.1 } else { -0.2 },
            regression_report_id: "report.1".into(),
            evidence_refs: vec!["report.1".into(), "eval.run".into()],
            finished_at: Utc::now(),
        }
    }

    #[test]
    fn low_risk_delta_can_be_promoted_and_rolled_out() {
        let delta = delta(OptimizationDeltaKind::Route, RiskLevel::Low);
        let decision = GovernanceController::decide_promotion(&delta, &result(true), None).unwrap();
        let rollout = GovernanceController::rollout_plan(&decision, &delta).unwrap();

        assert_eq!(decision.decision, PromotionDecisionKind::Approved);
        assert_eq!(rollout.stages.len(), 2);
        assert_eq!(governance_safety_summary(&decision), EvalSeverity::Info);
    }

    #[test]
    fn protected_delta_needs_human_approval() {
        let delta = delta(OptimizationDeltaKind::PolicyPack, RiskLevel::High);
        let decision = GovernanceController::decide_promotion(&delta, &result(true), None).unwrap();

        assert_eq!(decision.decision, PromotionDecisionKind::NeedsHumanApproval);
        assert!(GovernanceController::rollout_plan(&decision, &delta).is_err());
    }

    #[test]
    fn human_approved_protected_delta_can_rollout_but_stays_evidenced() {
        let delta = delta(OptimizationDeltaKind::PolicyPack, RiskLevel::High);
        let decision = GovernanceController::decide_promotion(
            &delta,
            &result(true),
            Some("approval.owner".into()),
        )
        .unwrap();
        let rollout = GovernanceController::rollout_plan(&decision, &delta).unwrap();

        assert_eq!(decision.decision, PromotionDecisionKind::Approved);
        assert!(rollout.evidence_refs.contains(&"approval.owner".into()));
        assert_eq!(governance_safety_summary(&decision), EvalSeverity::High);
    }

    #[test]
    fn failed_experiment_blocks_promotion() {
        let delta = delta(OptimizationDeltaKind::Planner, RiskLevel::Medium);
        let error =
            GovernanceController::decide_promotion(&delta, &result(false), None).unwrap_err();

        assert_eq!(error, GovernanceError::ExperimentFailed);
    }

    #[test]
    fn rollback_and_evolution_ledger_record_all_governance_steps() {
        let delta = delta(OptimizationDeltaKind::Swarm, RiskLevel::Medium);
        let decision = GovernanceController::decide_promotion(&delta, &result(true), None).unwrap();
        let rollout = GovernanceController::rollout_plan(&decision, &delta).unwrap();
        let rollback = GovernanceController::rollback_plan(
            &delta,
            Some(&rollout),
            "regression during canary",
            vec!["eval.regression".into()],
        )
        .unwrap();
        let mut ledger = EvolutionLedger::new("evolution.ledger");

        ledger.record_promotion(&decision);
        ledger.record_rollout(&rollout);
        ledger.record_rollback(&rollback);

        assert_eq!(ledger.events.len(), 3);
        assert_eq!(ledger.events[2].kind, EvolutionEventKind::RollbackPlanned);
    }
}
