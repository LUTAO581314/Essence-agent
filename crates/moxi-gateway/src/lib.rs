use moxi_contracts::{PermissionMode, RiskLevel};
use moxi_entry::{EntryChannel, EntryIntentCandidate, NormalizedEntry};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error, PartialEq)]
pub enum GatewayError {
    #[error("gateway denied request: {0:?}")]
    Denied(Box<GatewayDecision>),
}

pub type GatewayResult<T> = Result<T, GatewayError>;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct Redaction {
    pub marker: String,
    pub replacement: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct GatewayDecision {
    pub gateway_decision_id: String,
    pub request_id: String,
    pub tenant_id: String,
    pub user_id: String,
    pub allowed: bool,
    pub risk_level: RiskLevel,
    pub reasons: Vec<String>,
    pub redactions: Vec<Redaction>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct TrustedEntry {
    pub channel: EntryChannel,
    pub request_id: String,
    pub session_id: Option<String>,
    pub source_ref: Option<String>,
    pub permission_mode: PermissionMode,
    pub candidate: EntryIntentCandidate,
    pub gateway_decision: GatewayDecision,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct GatewayConfig {
    pub allowed_tenants: Vec<String>,
    pub blocked_users: Vec<String>,
    pub max_goal_chars: usize,
    pub max_requests_per_principal: u32,
    pub blocked_goal_terms: Vec<String>,
    pub secret_markers: Vec<String>,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            allowed_tenants: Vec::new(),
            blocked_users: Vec::new(),
            max_goal_chars: 4_000,
            max_requests_per_principal: 100,
            blocked_goal_terms: vec![
                "ignore previous instructions".into(),
                "bypass policy".into(),
                "disable safety".into(),
            ],
            secret_markers: vec!["sk-".into(), "ghp_".into(), "gho_".into(), "xoxb-".into()],
        }
    }
}

pub struct Gateway {
    config: GatewayConfig,
    request_counts: HashMap<String, u32>,
}

impl Default for Gateway {
    fn default() -> Self {
        Self::new(GatewayConfig::default())
    }
}

impl Gateway {
    pub fn new(config: GatewayConfig) -> Self {
        Self {
            config,
            request_counts: HashMap::new(),
        }
    }

    pub fn admit(&mut self, entry: NormalizedEntry) -> GatewayResult<TrustedEntry> {
        let mut reasons = Vec::new();
        let mut candidate = entry.candidate;
        let mut risk_level = candidate.risk_level;

        if !self.config.allowed_tenants.is_empty()
            && !self
                .config
                .allowed_tenants
                .iter()
                .any(|tenant| tenant == &candidate.tenant_id)
        {
            reasons.push("tenant is not trusted by this gateway".into());
        }

        if self
            .config
            .blocked_users
            .iter()
            .any(|user| user == &candidate.user_id)
        {
            reasons.push("user is blocked by this gateway".into());
        }

        if candidate.goal.chars().count() > self.config.max_goal_chars {
            reasons.push("goal exceeds gateway input size limit".into());
        }

        let principal = format!("{}:{}", candidate.tenant_id, candidate.user_id);
        let request_count = self.request_counts.entry(principal).or_insert(0);
        if *request_count >= self.config.max_requests_per_principal {
            reasons.push("principal exceeded gateway request limit".into());
        } else {
            *request_count += 1;
        }

        let lowered_goal = candidate.goal.to_ascii_lowercase();
        for term in &self.config.blocked_goal_terms {
            if lowered_goal.contains(&term.to_ascii_lowercase()) {
                reasons.push(format!("goal contains blocked term: {term}"));
            }
        }

        let (goal, redactions) = redact_goal(&candidate.goal, &self.config.secret_markers);
        if !redactions.is_empty() && risk_level < RiskLevel::Medium {
            risk_level = RiskLevel::Medium;
        }
        candidate.goal = goal;
        candidate.risk_level = risk_level;

        if reasons.is_empty() {
            reasons.push("gateway trust checks passed".into());
        }

        let decision = GatewayDecision {
            gateway_decision_id: format!("gd_{}", Uuid::new_v4()),
            request_id: entry.request_id.clone(),
            tenant_id: candidate.tenant_id.clone(),
            user_id: candidate.user_id.clone(),
            allowed: reasons.len() == 1 && reasons[0] == "gateway trust checks passed",
            risk_level,
            reasons,
            redactions,
        };

        if !decision.allowed {
            return Err(GatewayError::Denied(Box::new(decision)));
        }

        Ok(TrustedEntry {
            channel: entry.channel,
            request_id: entry.request_id,
            session_id: entry.session_id,
            source_ref: entry.source_ref,
            permission_mode: entry.permission_mode,
            candidate,
            gateway_decision: decision,
        })
    }
}

pub fn admit_entry(entry: NormalizedEntry) -> GatewayResult<TrustedEntry> {
    Gateway::default().admit(entry)
}

fn redact_goal(goal: &str, markers: &[String]) -> (String, Vec<Redaction>) {
    let mut redactions = Vec::new();
    let words = goal
        .split_whitespace()
        .map(|word| {
            let lowered = word.to_ascii_lowercase();
            if let Some(marker) = markers
                .iter()
                .find(|marker| lowered.starts_with(&marker.to_ascii_lowercase()))
            {
                redactions.push(Redaction {
                    marker: marker.clone(),
                    replacement: "[REDACTED_SECRET]".into(),
                });
                "[REDACTED_SECRET]".to_owned()
            } else {
                word.to_owned()
            }
        })
        .collect::<Vec<_>>();

    (words.join(" "), redactions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use moxi_entry::{normalize_entry, EntryChannel, EntryRequest};

    #[test]
    fn admits_normalized_entry_after_trust_checks() {
        let request = EntryRequest::new(
            EntryChannel::Cli,
            "tenant_a",
            "user_a",
            "/workspace",
            "read project status",
        );

        let trusted = admit_entry(normalize_entry(request).unwrap()).unwrap();

        assert!(trusted.gateway_decision.allowed);
        assert_eq!(trusted.candidate.goal, "read project status");
    }

    #[test]
    fn denies_untrusted_tenant() {
        let request = EntryRequest::new(
            EntryChannel::HttpApi,
            "tenant_b",
            "user_a",
            "/workspace",
            "read project status",
        );
        let mut gateway = Gateway::new(GatewayConfig {
            allowed_tenants: vec!["tenant_a".into()],
            ..Default::default()
        });

        let error = gateway
            .admit(normalize_entry(request).unwrap())
            .unwrap_err();

        assert!(matches!(error, GatewayError::Denied(decision) if !decision.allowed));
    }

    #[test]
    fn redacts_secret_markers_and_escalates_risk() {
        let request = EntryRequest::new(
            EntryChannel::Sdk,
            "tenant_a",
            "user_a",
            "/workspace",
            "read token sk-example",
        );

        let trusted = admit_entry(normalize_entry(request).unwrap()).unwrap();

        assert_eq!(trusted.candidate.goal, "read token [REDACTED_SECRET]");
        assert_eq!(trusted.candidate.risk_level, RiskLevel::Medium);
        assert_eq!(trusted.gateway_decision.redactions.len(), 1);
    }
}
