use chrono::{DateTime, Utc};
use moxi_contracts::{Decision, RiskLevel};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const HOTPATH_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Error, PartialEq)]
pub enum HotPathError {
    #[error("latency budget must include at least one SLO class")]
    MissingSloClass,
    #[error("cache entry is outside request scope")]
    CacheScopeMismatch,
    #[error("cache entry is stale")]
    CacheStale,
    #[error("cache entry risk is too high for hot path")]
    CacheRiskTooHigh,
    #[error("latency snapshot requires samples")]
    MissingSamples,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HotPathKind {
    Ack,
    EarlyDeny,
    Route,
    ExactCacheHit,
    TemplateCacheHit,
    DeferToTaskPath,
    DeferToTrustedExecution,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SloClass {
    FiveMsAck,
    TenMsRoute,
    FiftyMsCache,
    TwoHundredMsFirstStatus,
    TaskPath,
    TrustedExecutionPath,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CacheKind {
    Exact,
    Template,
    Semantic,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CacheSafety {
    Deterministic,
    ScopedTemplate,
    SemanticNeedsReview,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DegradeAction {
    ReturnAck,
    ReturnCachedStatus,
    AskClarifyingQuestion,
    SwitchToTaskPath,
    SwitchToTrustedExecution,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LatencyBudget {
    pub budget_id: String,
    pub slo_class: SloClass,
    pub max_first_packet_ms: u64,
    pub max_route_ms: u64,
    pub max_cache_lookup_ms: u64,
    pub max_queue_wait_ms: u64,
    pub require_status_stream_after_ms: u64,
    pub require_stage_progress_after_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HotPathRequest {
    pub request_id: String,
    pub tenant_id: String,
    pub user_id: String,
    pub intent_ref: Option<String>,
    pub goal_hash: String,
    pub scope_ref: String,
    pub risk_level: RiskLevel,
    pub requested_capabilities: Vec<String>,
    pub cache_key: Option<String>,
    pub deadline_ms: u64,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CacheEntry {
    pub cache_key: String,
    pub kind: CacheKind,
    pub safety: CacheSafety,
    pub scope_ref: String,
    pub value_hash: String,
    pub evidence_refs: Vec<String>,
    pub risk_level: RiskLevel,
    pub freshness_ms: u64,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HotPathDecision {
    pub decision_id: String,
    pub request_id: String,
    pub kind: HotPathKind,
    pub decision: Decision,
    pub slo_class: SloClass,
    pub first_packet_budget_ms: u64,
    pub expected_first_packet_ms: u64,
    pub selected_cache_key: Option<String>,
    pub route_ref: Option<String>,
    pub degrade_plan_ref: Option<String>,
    pub evidence_refs: Vec<String>,
    pub reasons: Vec<String>,
    pub cannot_execute_tools: bool,
    pub cannot_authorize: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DegradePlan {
    pub plan_id: String,
    pub request_id: String,
    pub deadline_ms: u64,
    pub actions: Vec<DegradeAction>,
    pub reason: String,
    pub evidence_refs: Vec<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LatencySample {
    pub sample_id: String,
    pub decision_id: String,
    pub slo_class: SloClass,
    pub first_packet_ms: u64,
    pub route_ms: u64,
    pub cache_lookup_ms: u64,
    pub queue_wait_ms: u64,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LatencySnapshot {
    pub snapshot_id: String,
    pub slo_class: SloClass,
    pub sample_count: usize,
    pub p50_first_packet_ms: u64,
    pub p95_first_packet_ms: u64,
    pub p99_first_packet_ms: u64,
    pub max_first_packet_ms: u64,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HotPathFact {
    pub fact_id: String,
    pub decision_id: String,
    pub kind: HotPathKind,
    pub slo_class: SloClass,
    pub expected_first_packet_ms: u64,
    pub cache_hit: bool,
    pub evidence_refs: Vec<String>,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct HotPathController {
    pub budgets: Vec<LatencyBudget>,
}

struct HotDecisionParts {
    kind: HotPathKind,
    decision: Decision,
    slo_class: SloClass,
    selected_cache_key: Option<String>,
    reasons: Vec<String>,
    evidence_refs: Vec<String>,
}

impl HotPathController {
    pub fn new(budgets: Vec<LatencyBudget>) -> Result<Self, HotPathError> {
        if budgets.is_empty() {
            return Err(HotPathError::MissingSloClass);
        }
        Ok(Self { budgets })
    }

    pub fn decide(
        &self,
        request: &HotPathRequest,
        cache_entry: Option<&CacheEntry>,
    ) -> Result<HotPathDecision, HotPathError> {
        if request.risk_level >= RiskLevel::High {
            return Ok(self.defer(
                request,
                HotPathKind::DeferToTrustedExecution,
                SloClass::TrustedExecutionPath,
                "high-risk request must enter trusted execution path",
            ));
        }

        if request.requested_capabilities.is_empty() {
            return Ok(self.hot_decision(
                request,
                HotDecisionParts {
                    kind: HotPathKind::Ack,
                    decision: Decision::Allow,
                    slo_class: SloClass::FiveMsAck,
                    selected_cache_key: None,
                    reasons: vec!["request accepted; no capability decision needed yet".into()],
                    evidence_refs: vec![request.request_id.clone()],
                },
            ));
        }

        if request
            .requested_capabilities
            .iter()
            .any(|capability| capability == "network.write" || capability == "shell.exec")
        {
            return Ok(self.hot_decision(
                request,
                HotDecisionParts {
                    kind: HotPathKind::EarlyDeny,
                    decision: Decision::Deny,
                    slo_class: SloClass::FiveMsAck,
                    selected_cache_key: None,
                    reasons: vec!["unsafe capability is denied before task planning".into()],
                    evidence_refs: vec![request.request_id.clone()],
                },
            ));
        }

        if let Some(entry) = cache_entry {
            self.validate_cache_entry(request, entry)?;
            if entry.safety != CacheSafety::SemanticNeedsReview {
                return Ok(self.hot_decision(
                    request,
                    HotDecisionParts {
                        kind: match entry.kind {
                            CacheKind::Exact => HotPathKind::ExactCacheHit,
                            CacheKind::Template => HotPathKind::TemplateCacheHit,
                            CacheKind::Semantic => HotPathKind::DeferToTaskPath,
                        },
                        decision: Decision::Allow,
                        slo_class: SloClass::FiftyMsCache,
                        selected_cache_key: Some(entry.cache_key.clone()),
                        reasons: vec!["bounded cache hit can return first packet".into()],
                        evidence_refs: entry.evidence_refs.clone(),
                    },
                ));
            }
        }

        if request.deadline_ms <= self.budget(SloClass::TenMsRoute).max_route_ms {
            return Ok(self.hot_decision(
                request,
                HotDecisionParts {
                    kind: HotPathKind::Route,
                    decision: Decision::Allow,
                    slo_class: SloClass::TenMsRoute,
                    selected_cache_key: None,
                    reasons: vec!["low-risk request can be routed before model execution".into()],
                    evidence_refs: vec![request.request_id.clone()],
                },
            ));
        }

        Ok(self.defer(
            request,
            HotPathKind::DeferToTaskPath,
            SloClass::TaskPath,
            "request needs normal task path after first status",
        ))
    }

    pub fn degrade_plan(
        &self,
        request: &HotPathRequest,
        decision: &HotPathDecision,
    ) -> DegradePlan {
        let actions = match decision.kind {
            HotPathKind::Ack | HotPathKind::Route => {
                vec![DegradeAction::ReturnAck, DegradeAction::SwitchToTaskPath]
            }
            HotPathKind::ExactCacheHit | HotPathKind::TemplateCacheHit => vec![
                DegradeAction::ReturnCachedStatus,
                DegradeAction::SwitchToTaskPath,
            ],
            HotPathKind::EarlyDeny => vec![DegradeAction::Deny],
            HotPathKind::DeferToTrustedExecution => vec![
                DegradeAction::ReturnAck,
                DegradeAction::SwitchToTrustedExecution,
            ],
            HotPathKind::DeferToTaskPath => {
                vec![DegradeAction::ReturnAck, DegradeAction::SwitchToTaskPath]
            }
        };
        DegradePlan {
            plan_id: stable_id(
                "degrade_plan",
                &(
                    request.request_id.as_str(),
                    decision.decision_id.as_str(),
                    &actions,
                ),
            ),
            request_id: request.request_id.clone(),
            deadline_ms: request.deadline_ms,
            actions,
            reason: format!("degrade from {:?}", decision.kind),
            evidence_refs: decision.evidence_refs.clone(),
            created_at: Utc::now(),
        }
    }

    pub fn snapshot(
        &self,
        slo_class: SloClass,
        samples: &[LatencySample],
    ) -> Result<LatencySnapshot, HotPathError> {
        let mut values = samples
            .iter()
            .filter(|sample| sample.slo_class == slo_class)
            .map(|sample| sample.first_packet_ms)
            .collect::<Vec<_>>();
        if values.is_empty() {
            return Err(HotPathError::MissingSamples);
        }
        values.sort_unstable();
        let sample_count = values.len();
        Ok(LatencySnapshot {
            snapshot_id: stable_id("latency_snapshot", &(slo_class, &values)),
            slo_class,
            sample_count,
            p50_first_packet_ms: percentile(&values, 50),
            p95_first_packet_ms: percentile(&values, 95),
            p99_first_packet_ms: percentile(&values, 99),
            max_first_packet_ms: *values.last().expect("values is not empty"),
            generated_at: Utc::now(),
        })
    }

    fn validate_cache_entry(
        &self,
        request: &HotPathRequest,
        entry: &CacheEntry,
    ) -> Result<(), HotPathError> {
        if entry.scope_ref != request.scope_ref {
            return Err(HotPathError::CacheScopeMismatch);
        }
        if entry.freshness_ms == 0 {
            return Err(HotPathError::CacheStale);
        }
        if entry.risk_level > request.risk_level || entry.risk_level >= RiskLevel::High {
            return Err(HotPathError::CacheRiskTooHigh);
        }
        Ok(())
    }

    fn hot_decision(&self, request: &HotPathRequest, parts: HotDecisionParts) -> HotPathDecision {
        let budget = self.budget(parts.slo_class);
        HotPathDecision {
            decision_id: stable_id(
                "hotpath_decision",
                &(
                    request.request_id.as_str(),
                    parts.kind,
                    parts.decision,
                    parts.slo_class,
                    &parts.selected_cache_key,
                ),
            ),
            request_id: request.request_id.clone(),
            kind: parts.kind,
            decision: parts.decision,
            slo_class: parts.slo_class,
            first_packet_budget_ms: budget.max_first_packet_ms,
            expected_first_packet_ms: expected_first_packet_ms(parts.kind, budget),
            selected_cache_key: parts.selected_cache_key,
            route_ref: request.intent_ref.clone(),
            degrade_plan_ref: None,
            evidence_refs: parts.evidence_refs,
            reasons: parts.reasons,
            cannot_execute_tools: true,
            cannot_authorize: true,
            created_at: Utc::now(),
        }
    }

    fn defer(
        &self,
        request: &HotPathRequest,
        kind: HotPathKind,
        slo_class: SloClass,
        reason: impl Into<String>,
    ) -> HotPathDecision {
        self.hot_decision(
            request,
            HotDecisionParts {
                kind,
                decision: if kind == HotPathKind::DeferToTrustedExecution {
                    Decision::RequireApproval
                } else {
                    Decision::Allow
                },
                slo_class,
                selected_cache_key: None,
                reasons: vec![reason.into()],
                evidence_refs: vec![request.request_id.clone()],
            },
        )
    }

    fn budget(&self, slo_class: SloClass) -> &LatencyBudget {
        self.budgets
            .iter()
            .find(|budget| budget.slo_class == slo_class)
            .or_else(|| self.budgets.first())
            .expect("HotPathController requires at least one budget")
    }
}

impl Default for LatencyBudget {
    fn default() -> Self {
        Self {
            budget_id: "latency.five_ms_ack".into(),
            slo_class: SloClass::FiveMsAck,
            max_first_packet_ms: 5,
            max_route_ms: 10,
            max_cache_lookup_ms: 50,
            max_queue_wait_ms: 5,
            require_status_stream_after_ms: 3_000,
            require_stage_progress_after_ms: 10_000,
        }
    }
}

pub fn standard_latency_budgets() -> Vec<LatencyBudget> {
    vec![
        LatencyBudget::default(),
        LatencyBudget {
            budget_id: "latency.ten_ms_route".into(),
            slo_class: SloClass::TenMsRoute,
            max_first_packet_ms: 10,
            max_route_ms: 10,
            max_cache_lookup_ms: 50,
            max_queue_wait_ms: 5,
            require_status_stream_after_ms: 3_000,
            require_stage_progress_after_ms: 10_000,
        },
        LatencyBudget {
            budget_id: "latency.fifty_ms_cache".into(),
            slo_class: SloClass::FiftyMsCache,
            max_first_packet_ms: 50,
            max_route_ms: 10,
            max_cache_lookup_ms: 50,
            max_queue_wait_ms: 5,
            require_status_stream_after_ms: 3_000,
            require_stage_progress_after_ms: 10_000,
        },
        LatencyBudget {
            budget_id: "latency.first_status".into(),
            slo_class: SloClass::TwoHundredMsFirstStatus,
            max_first_packet_ms: 200,
            max_route_ms: 50,
            max_cache_lookup_ms: 50,
            max_queue_wait_ms: 50,
            require_status_stream_after_ms: 3_000,
            require_stage_progress_after_ms: 10_000,
        },
        LatencyBudget {
            budget_id: "latency.task_path".into(),
            slo_class: SloClass::TaskPath,
            max_first_packet_ms: 200,
            max_route_ms: 100,
            max_cache_lookup_ms: 50,
            max_queue_wait_ms: 100,
            require_status_stream_after_ms: 3_000,
            require_stage_progress_after_ms: 10_000,
        },
        LatencyBudget {
            budget_id: "latency.trusted_execution".into(),
            slo_class: SloClass::TrustedExecutionPath,
            max_first_packet_ms: 200,
            max_route_ms: 100,
            max_cache_lookup_ms: 50,
            max_queue_wait_ms: 100,
            require_status_stream_after_ms: 3_000,
            require_stage_progress_after_ms: 10_000,
        },
    ]
}

pub fn fact_from_decision(decision: &HotPathDecision) -> HotPathFact {
    HotPathFact {
        fact_id: stable_id("hotpath_fact", &decision.decision_id),
        decision_id: decision.decision_id.clone(),
        kind: decision.kind,
        slo_class: decision.slo_class,
        expected_first_packet_ms: decision.expected_first_packet_ms,
        cache_hit: matches!(
            decision.kind,
            HotPathKind::ExactCacheHit | HotPathKind::TemplateCacheHit
        ),
        evidence_refs: decision.evidence_refs.clone(),
        observed_at: Utc::now(),
    }
}

fn expected_first_packet_ms(kind: HotPathKind, budget: &LatencyBudget) -> u64 {
    match kind {
        HotPathKind::Ack | HotPathKind::EarlyDeny => budget.max_first_packet_ms.min(5),
        HotPathKind::Route => budget.max_route_ms.min(budget.max_first_packet_ms),
        HotPathKind::ExactCacheHit | HotPathKind::TemplateCacheHit => {
            budget.max_cache_lookup_ms.min(budget.max_first_packet_ms)
        }
        HotPathKind::DeferToTaskPath | HotPathKind::DeferToTrustedExecution => {
            budget.max_first_packet_ms
        }
    }
}

fn percentile(values: &[u64], percentile: usize) -> u64 {
    let rank = (values.len() * percentile).div_ceil(100).max(1);
    let index = rank.saturating_sub(1);
    values[index.min(values.len() - 1)]
}

fn stable_id(prefix: &str, value: &impl Serialize) -> String {
    let json = serde_json::to_vec(value).expect("stable id input should serialize");
    let digest = Sha256::digest(json);
    format!("{prefix}.{}", hex::encode(&digest[..8]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn controller() -> HotPathController {
        HotPathController::new(standard_latency_budgets()).unwrap()
    }

    fn request(risk_level: RiskLevel) -> HotPathRequest {
        HotPathRequest {
            request_id: "hot.req.1".into(),
            tenant_id: "tenant.a".into(),
            user_id: "user.1".into(),
            intent_ref: Some("intent.1".into()),
            goal_hash: "sha256:goal".into(),
            scope_ref: "tenant.a/project.moxi".into(),
            risk_level,
            requested_capabilities: vec!["file.read".into()],
            cache_key: Some("cache.intent.1".into()),
            deadline_ms: 10,
            created_at: Utc::now(),
        }
    }

    fn cache_entry() -> CacheEntry {
        CacheEntry {
            cache_key: "cache.intent.1".into(),
            kind: CacheKind::Exact,
            safety: CacheSafety::Deterministic,
            scope_ref: "tenant.a/project.moxi".into(),
            value_hash: "sha256:cached".into(),
            evidence_refs: vec!["eval.cache.safe".into()],
            risk_level: RiskLevel::Low,
            freshness_ms: 1_000,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn low_risk_exact_cache_hit_returns_bounded_first_packet_fact() {
        let decision = controller()
            .decide(&request(RiskLevel::Low), Some(&cache_entry()))
            .unwrap();
        let fact = fact_from_decision(&decision);

        assert_eq!(decision.kind, HotPathKind::ExactCacheHit);
        assert_eq!(decision.slo_class, SloClass::FiftyMsCache);
        assert!(decision.cannot_execute_tools);
        assert!(decision.cannot_authorize);
        assert!(fact.cache_hit);
    }

    #[test]
    fn high_risk_request_goes_to_trusted_execution_path() {
        let decision = controller()
            .decide(&request(RiskLevel::High), None)
            .unwrap();

        assert_eq!(decision.kind, HotPathKind::DeferToTrustedExecution);
        assert_eq!(decision.decision, Decision::RequireApproval);
        assert_eq!(decision.slo_class, SloClass::TrustedExecutionPath);
    }

    #[test]
    fn unsafe_capability_is_denied_in_five_ms_class() {
        let mut request = request(RiskLevel::Low);
        request.requested_capabilities = vec!["shell.exec".into()];
        let decision = controller().decide(&request, None).unwrap();

        assert_eq!(decision.kind, HotPathKind::EarlyDeny);
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(decision.slo_class, SloClass::FiveMsAck);
        assert!(decision.expected_first_packet_ms <= 5);
    }

    #[test]
    fn cache_scope_risk_and_freshness_are_enforced() {
        let mut scoped = cache_entry();
        scoped.scope_ref = "other.scope".into();
        assert_eq!(
            controller()
                .decide(&request(RiskLevel::Low), Some(&scoped))
                .unwrap_err(),
            HotPathError::CacheScopeMismatch
        );

        let mut stale = cache_entry();
        stale.freshness_ms = 0;
        assert_eq!(
            controller()
                .decide(&request(RiskLevel::Low), Some(&stale))
                .unwrap_err(),
            HotPathError::CacheStale
        );

        let mut risky = cache_entry();
        risky.risk_level = RiskLevel::High;
        assert_eq!(
            controller()
                .decide(&request(RiskLevel::Low), Some(&risky))
                .unwrap_err(),
            HotPathError::CacheRiskTooHigh
        );
    }

    #[test]
    fn semantic_cache_needs_task_path_review() {
        let mut entry = cache_entry();
        entry.kind = CacheKind::Semantic;
        entry.safety = CacheSafety::SemanticNeedsReview;
        let decision = controller()
            .decide(&request(RiskLevel::Low), Some(&entry))
            .unwrap();

        assert_eq!(decision.kind, HotPathKind::Route);
        assert_eq!(decision.slo_class, SloClass::TenMsRoute);
    }

    #[test]
    fn degrade_plan_preserves_no_execution_boundary() {
        let controller = controller();
        let request = request(RiskLevel::Medium);
        let decision = controller.decide(&request, None).unwrap();
        let plan = controller.degrade_plan(&request, &decision);

        assert!(plan.actions.contains(&DegradeAction::ReturnAck));
        assert!(plan.actions.contains(&DegradeAction::SwitchToTaskPath));
        assert_eq!(plan.evidence_refs, decision.evidence_refs);
    }

    #[test]
    fn latency_snapshot_reports_percentiles() {
        let samples = [1, 2, 3, 4, 5, 8, 13, 21, 34, 55]
            .iter()
            .enumerate()
            .map(|(index, value)| LatencySample {
                sample_id: format!("sample.{index}"),
                decision_id: "decision.1".into(),
                slo_class: SloClass::FiveMsAck,
                first_packet_ms: *value,
                route_ms: 1,
                cache_lookup_ms: 1,
                queue_wait_ms: 0,
                observed_at: Utc::now(),
            })
            .collect::<Vec<_>>();
        let snapshot = controller()
            .snapshot(SloClass::FiveMsAck, &samples)
            .unwrap();

        assert_eq!(snapshot.sample_count, 10);
        assert_eq!(snapshot.p50_first_packet_ms, 5);
        assert_eq!(snapshot.p95_first_packet_ms, 55);
        assert_eq!(snapshot.p99_first_packet_ms, 55);
        assert_eq!(snapshot.max_first_packet_ms, 55);
    }
}
