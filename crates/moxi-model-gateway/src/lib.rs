use chrono::{DateTime, Utc};
use moxi_contracts::{
    Confidence, Intent, ModelCapabilityKind, ModelGatewayManifest, RiskLevel,
    UnderstandingProposal, UnderstandingProposalKind,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::Duration;
use thiserror::Error;

pub const MODEL_GATEWAY_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Error, PartialEq)]
pub enum ModelGatewayError {
    #[error("model gateway has no available providers")]
    NoProviders,
    #[error("model gateway provider not found: {0}")]
    ProviderNotFound(String),
    #[error("model gateway refuses to downgrade high-risk intent to insufficient provider: {0}")]
    UnsafeDowngrade(String),
    #[error("structured output schema validation failed: {0}")]
    SchemaValidation(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ModelProviderLocality {
    Local,
    Cloud,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModelProviderDescriptor {
    pub provider_ref: String,
    pub model_ref: String,
    pub locality: ModelProviderLocality,
    pub capability_kinds: Vec<ModelCapabilityKind>,
    pub max_risk_level: RiskLevel,
    pub max_input_tokens: u32,
    pub max_output_tokens: u32,
    pub cost_per_1k_input_cents: u32,
    pub cost_per_1k_output_cents: u32,
    pub p95_latency_ms: u64,
    pub supports_structured_output: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModelRouteRequest {
    pub request_id: String,
    pub intent: Intent,
    pub required_capability: ModelCapabilityKind,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub prefer_local: bool,
    pub max_cost_cents: u32,
    pub max_latency_ms: u64,
    pub require_structured_output: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModelRouteDecision {
    pub decision_id: String,
    pub request_id: String,
    pub selected_provider_ref: String,
    pub selected_model_ref: String,
    pub fallback_provider_refs: Vec<String>,
    pub estimated_cost_cents: u32,
    pub estimated_latency_ms: u64,
    pub redaction_applied: bool,
    pub reasons: Vec<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StructuredOutputAttempt {
    pub attempt_id: String,
    pub decision_id: String,
    pub schema_ref: String,
    pub attempt_index: u32,
    pub valid: bool,
    pub error: Option<String>,
    pub output_hash: Option<String>,
    pub finished_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModelGatewayFact {
    pub fact_id: String,
    pub decision_id: String,
    pub provider_ref: String,
    pub model_ref: String,
    pub estimated_cost_cents: u32,
    pub estimated_latency_ms: u64,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct ModelGateway {
    pub manifest: ModelGatewayManifest,
    pub providers: Vec<ModelProviderDescriptor>,
}

impl ModelGateway {
    pub fn new(
        manifest: ModelGatewayManifest,
        providers: Vec<ModelProviderDescriptor>,
    ) -> Result<Self, ModelGatewayError> {
        if providers.is_empty() {
            return Err(ModelGatewayError::NoProviders);
        }
        Ok(Self {
            manifest,
            providers,
        })
    }

    pub fn route(
        &self,
        request: &ModelRouteRequest,
    ) -> Result<ModelRouteDecision, ModelGatewayError> {
        let mut candidates = self
            .providers
            .iter()
            .filter(|provider| self.manifest.provider_refs.contains(&provider.provider_ref))
            .filter(|provider| {
                provider
                    .capability_kinds
                    .contains(&request.required_capability)
            })
            .filter(|provider| {
                !request.require_structured_output || provider.supports_structured_output
            })
            .filter(|provider| provider.max_risk_level >= request.intent.risk_level)
            .map(|provider| {
                let cost =
                    estimate_cost_cents(provider, request.input_tokens, request.output_tokens);
                let mut score = provider.p95_latency_ms + u64::from(cost) * 10;
                if request.prefer_local && provider.locality == ModelProviderLocality::Local {
                    score = score.saturating_sub(100);
                }
                (score, cost, provider)
            })
            .collect::<Vec<_>>();

        if candidates.is_empty() {
            let weaker = self
                .providers
                .iter()
                .find(|provider| {
                    provider
                        .capability_kinds
                        .contains(&request.required_capability)
                })
                .map(|provider| provider.provider_ref.clone())
                .unwrap_or_else(|| request.required_capability_label());
            if request.intent.risk_level >= RiskLevel::High {
                return Err(ModelGatewayError::UnsafeDowngrade(weaker));
            }
            return Err(ModelGatewayError::ProviderNotFound(weaker));
        }

        candidates.sort_by_key(|(score, _, provider)| (*score, provider.provider_ref.clone()));
        let (_, estimated_cost_cents, selected) = candidates[0];
        let fallback_provider_refs = candidates
            .iter()
            .skip(1)
            .filter(|(_, cost, provider)| {
                *cost <= request.max_cost_cents && provider.p95_latency_ms <= request.max_latency_ms
            })
            .map(|(_, _, provider)| provider.provider_ref.clone())
            .collect::<Vec<_>>();
        let mut reasons = vec![format!(
            "selected {} for {:?}",
            selected.provider_ref, request.required_capability
        )];
        if request.prefer_local && selected.locality == ModelProviderLocality::Local {
            reasons.push("local provider preferred".into());
        }
        if estimated_cost_cents > request.max_cost_cents {
            reasons.push("estimated cost exceeds requested soft budget".into());
        }
        if selected.p95_latency_ms > request.max_latency_ms {
            reasons.push("estimated latency exceeds requested soft budget".into());
        }

        Ok(ModelRouteDecision {
            decision_id: stable_id(
                "model_route",
                &(request.request_id.as_str(), selected.provider_ref.as_str()),
            ),
            request_id: request.request_id.clone(),
            selected_provider_ref: selected.provider_ref.clone(),
            selected_model_ref: selected.model_ref.clone(),
            fallback_provider_refs,
            estimated_cost_cents,
            estimated_latency_ms: selected.p95_latency_ms,
            redaction_applied: self.manifest.redaction_policy_ref.is_some(),
            reasons,
            created_at: Utc::now(),
        })
    }
}

impl ModelRouteRequest {
    fn required_capability_label(&self) -> String {
        format!("{:?}", self.required_capability)
    }
}

pub fn validate_structured_output(
    decision: &ModelRouteDecision,
    schema_ref: impl Into<String>,
    schema: &Value,
    output: &Value,
    attempt_index: u32,
) -> StructuredOutputAttempt {
    let schema_ref = schema_ref.into();
    let validation = jsonschema::JSONSchema::compile(schema)
        .map_err(|error| error.to_string())
        .and_then(|compiled| {
            compiled.validate(output).map_err(|errors| {
                errors
                    .map(|error| error.to_string())
                    .collect::<Vec<_>>()
                    .join("; ")
            })
        });
    let (valid, error) = match validation {
        Ok(()) => (true, None),
        Err(error) => (false, Some(error)),
    };
    StructuredOutputAttempt {
        attempt_id: stable_id(
            "structured_output",
            &(
                decision.decision_id.as_str(),
                schema_ref.as_str(),
                attempt_index,
                output,
            ),
        ),
        decision_id: decision.decision_id.clone(),
        schema_ref,
        attempt_index,
        valid,
        error,
        output_hash: Some(stable_hash(output)),
        finished_at: Utc::now(),
    }
}

pub fn fact_from_route(
    decision: &ModelRouteDecision,
    request: &ModelRouteRequest,
) -> ModelGatewayFact {
    ModelGatewayFact {
        fact_id: stable_id(
            "model_fact",
            &(
                decision.decision_id.as_str(),
                request.input_tokens,
                request.output_tokens,
            ),
        ),
        decision_id: decision.decision_id.clone(),
        provider_ref: decision.selected_provider_ref.clone(),
        model_ref: decision.selected_model_ref.clone(),
        estimated_cost_cents: decision.estimated_cost_cents,
        estimated_latency_ms: decision.estimated_latency_ms,
        input_tokens: request.input_tokens,
        output_tokens: request.output_tokens,
        observed_at: Utc::now(),
    }
}

pub fn understanding_proposal_from_route(
    decision: &ModelRouteDecision,
    intent: &Intent,
    summary: impl Into<String>,
    proposed_steps: Vec<String>,
    suggested_capabilities: Vec<String>,
) -> UnderstandingProposal {
    UnderstandingProposal {
        proposal_id: stable_id(
            "understanding",
            &(decision.decision_id.as_str(), intent.intent_id.as_str()),
        ),
        intent_id: intent.intent_id.clone(),
        kind: if proposed_steps.is_empty() {
            UnderstandingProposalKind::Clarification
        } else {
            UnderstandingProposalKind::TaskDecomposition
        },
        summary: summary.into(),
        proposed_steps,
        suggested_capabilities,
        risk_level: intent.risk_level,
        confidence: Confidence::Medium,
        evidence_refs: vec![decision.decision_id.clone()],
        cannot_authorize: true,
    }
}

pub fn retry_delay(attempt: &StructuredOutputAttempt) -> Option<Duration> {
    if attempt.valid {
        None
    } else {
        Some(Duration::from_millis(
            100 * u64::from(attempt.attempt_index.max(1)),
        ))
    }
}

fn estimate_cost_cents(
    provider: &ModelProviderDescriptor,
    input_tokens: u32,
    output_tokens: u32,
) -> u32 {
    let input_cost = input_tokens
        .saturating_mul(provider.cost_per_1k_input_cents)
        .div_ceil(1000);
    let output_cost = output_tokens
        .saturating_mul(provider.cost_per_1k_output_cents)
        .div_ceil(1000);
    input_cost.saturating_add(output_cost)
}

fn stable_id(prefix: &str, value: &impl Serialize) -> String {
    let json = serde_json::to_vec(value).expect("stable id input should serialize");
    let digest = Sha256::digest(json);
    format!("{prefix}.{}", hex::encode(&digest[..8]))
}

fn stable_hash(value: &impl Serialize) -> String {
    let json = serde_json::to_vec(value).expect("stable hash input should serialize");
    let digest = Sha256::digest(json);
    format!("sha256:{}", hex::encode(digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use moxi_contracts::Budget;
    use serde_json::json;

    fn manifest() -> ModelGatewayManifest {
        ModelGatewayManifest {
            gateway_id: "gateway.default".into(),
            gateway_version: "0.1.0".into(),
            provider_refs: vec!["local.small".into(), "cloud.reasoning".into()],
            capability_kinds: vec![ModelCapabilityKind::Chat, ModelCapabilityKind::Reasoning],
            default_model_ref: Some("local-small".into()),
            fallback_policy_ref: Some("fallback.default".into()),
            cost_policy_ref: Some("cost.default".into()),
            redaction_policy_ref: Some("redact.before_model".into()),
        }
    }

    fn providers() -> Vec<ModelProviderDescriptor> {
        vec![
            ModelProviderDescriptor {
                provider_ref: "local.small".into(),
                model_ref: "local-small".into(),
                locality: ModelProviderLocality::Local,
                capability_kinds: vec![ModelCapabilityKind::Chat],
                max_risk_level: RiskLevel::Medium,
                max_input_tokens: 4096,
                max_output_tokens: 1024,
                cost_per_1k_input_cents: 0,
                cost_per_1k_output_cents: 0,
                p95_latency_ms: 80,
                supports_structured_output: true,
            },
            ModelProviderDescriptor {
                provider_ref: "cloud.reasoning".into(),
                model_ref: "cloud-reasoning".into(),
                locality: ModelProviderLocality::Cloud,
                capability_kinds: vec![ModelCapabilityKind::Chat, ModelCapabilityKind::Reasoning],
                max_risk_level: RiskLevel::Critical,
                max_input_tokens: 128_000,
                max_output_tokens: 4096,
                cost_per_1k_input_cents: 2,
                cost_per_1k_output_cents: 8,
                p95_latency_ms: 900,
                supports_structured_output: true,
            },
        ]
    }

    fn intent(risk_level: RiskLevel) -> Intent {
        Intent {
            intent_id: "intent.model".into(),
            tenant_id: "tenant".into(),
            user_id: "user".into(),
            gateway_decision_ref: Some("gateway.decision".into()),
            goal: "plan safe work".into(),
            requested_capabilities: vec!["file.read".into()],
            risk_level,
            workspace_root: ".".into(),
            budget: Budget::default(),
        }
    }

    fn request(
        required_capability: ModelCapabilityKind,
        risk_level: RiskLevel,
    ) -> ModelRouteRequest {
        ModelRouteRequest {
            request_id: "route.request".into(),
            intent: intent(risk_level),
            required_capability,
            input_tokens: 1200,
            output_tokens: 400,
            prefer_local: true,
            max_cost_cents: 50,
            max_latency_ms: 500,
            require_structured_output: true,
        }
    }

    #[test]
    fn routes_low_risk_chat_to_local_provider() {
        let gateway = ModelGateway::new(manifest(), providers()).unwrap();
        let decision = gateway
            .route(&request(ModelCapabilityKind::Chat, RiskLevel::Low))
            .unwrap();

        assert_eq!(decision.selected_provider_ref, "local.small");
        assert!(decision.redaction_applied);
        assert_eq!(decision.estimated_cost_cents, 0);
    }

    #[test]
    fn routes_reasoning_to_cloud_provider_with_cost_latency_fact() {
        let gateway = ModelGateway::new(manifest(), providers()).unwrap();
        let request = request(ModelCapabilityKind::Reasoning, RiskLevel::Medium);
        let decision = gateway.route(&request).unwrap();
        let fact = fact_from_route(&decision, &request);

        assert_eq!(decision.selected_provider_ref, "cloud.reasoning");
        assert_eq!(fact.provider_ref, "cloud.reasoning");
        assert!(fact.estimated_cost_cents > 0);
        assert_eq!(fact.input_tokens, 1200);
    }

    #[test]
    fn refuses_high_risk_downgrade_to_insufficient_provider() {
        let mut providers = providers();
        providers.retain(|provider| provider.provider_ref == "local.small");
        let gateway = ModelGateway::new(manifest(), providers).unwrap();

        let error = gateway
            .route(&request(ModelCapabilityKind::Chat, RiskLevel::High))
            .unwrap_err();

        assert!(matches!(error, ModelGatewayError::UnsafeDowngrade(_)));
    }

    #[test]
    fn structured_output_validation_records_retry_attempts() {
        let decision = ModelRouteDecision {
            decision_id: "route.1".into(),
            request_id: "request.1".into(),
            selected_provider_ref: "local.small".into(),
            selected_model_ref: "local-small".into(),
            fallback_provider_refs: vec![],
            estimated_cost_cents: 0,
            estimated_latency_ms: 80,
            redaction_applied: true,
            reasons: vec![],
            created_at: Utc::now(),
        };
        let schema = json!({
            "type": "object",
            "required": ["answer"],
            "properties": {
                "answer": { "type": "string" }
            }
        });
        let invalid =
            validate_structured_output(&decision, "answer.schema", &schema, &json!({}), 1);
        let valid = validate_structured_output(
            &decision,
            "answer.schema",
            &schema,
            &json!({"answer": "ok"}),
            2,
        );

        assert!(!invalid.valid);
        assert!(retry_delay(&invalid).is_some());
        assert!(valid.valid);
        assert!(retry_delay(&valid).is_none());
    }

    #[test]
    fn understanding_proposal_cannot_authorize() {
        let gateway = ModelGateway::new(manifest(), providers()).unwrap();
        let request = request(ModelCapabilityKind::Chat, RiskLevel::Medium);
        let decision = gateway.route(&request).unwrap();
        let proposal = understanding_proposal_from_route(
            &decision,
            &request.intent,
            "split into read-only planning steps",
            vec!["inspect files".into(), "summarize risks".into()],
            vec!["file.read".into()],
        );

        assert!(proposal.cannot_authorize);
        assert_eq!(proposal.risk_level, RiskLevel::Medium);
        assert_eq!(proposal.kind, UnderstandingProposalKind::TaskDecomposition);
    }
}
