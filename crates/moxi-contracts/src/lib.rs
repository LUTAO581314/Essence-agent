use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq, PartialOrd, Ord,
)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum PermissionMode {
    #[default]
    ReadOnly,
    WorkspaceWrite,
    Networked,
    Privileged,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny,
    RequireApproval,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Created,
    Admitted,
    RunningHeartbeat,
    AwaitingApproval,
    Executing,
    Observing,
    Verifying,
    Persisting,
    Completed,
    Failed,
    Cancelled,
    Blocked,
    RolledBack,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResourceType {
    File,
    Network,
    Memory,
    Workflow,
    Plugin,
    Credential,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeltaState {
    Draft,
    PolicyChecked,
    Approved,
    Rejected,
    Executing,
    Observed,
    Verified,
    Committed,
    RolledBack,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalPolicy {
    Human,
    Quorum,
    Admin,
    None,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventResult {
    Success,
    Failed,
    Blocked,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warn,
    Error,
    Critical,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    UserInputError,
    PolicyDenied,
    SafetyBlocked,
    ModelError,
    ToolError,
    PluginError,
    ResourceLimit,
    DependencyError,
    SystemError,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct Budget {
    pub max_steps: u32,
    pub max_heartbeats: u32,
    pub max_tool_calls: u32,
    pub max_cost_cents: u32,
    pub timeout_ms: u64,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            max_steps: 20,
            max_heartbeats: 10,
            max_tool_calls: 30,
            max_cost_cents: 100,
            timeout_ms: 10_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct Intent {
    pub intent_id: String,
    pub tenant_id: String,
    pub user_id: String,
    pub goal: String,
    pub requested_capabilities: Vec<String>,
    pub risk_level: RiskLevel,
    pub workspace_root: String,
    pub budget: Budget,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct RunContract {
    pub run_id: String,
    pub intent_id: String,
    pub tenant_id: String,
    pub user_id: String,
    pub risk_level: RiskLevel,
    pub permission_mode: PermissionMode,
    pub status_ref: String,
    pub budget: Budget,
    pub required_capabilities: Vec<String>,
    pub checkpoint_ref: Option<String>,
    pub approval_ref: Option<String>,
    pub ledger_scope: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct StateTransition {
    pub transition_id: String,
    pub run_id: String,
    pub from_state: Option<RunStatus>,
    pub to_state: RunStatus,
    pub command_source: String,
    pub reason: String,
    pub policy_decision_ref: Option<String>,
    pub ledger_event_ref: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct DeltaTarget {
    pub resource_type: ResourceType,
    pub resource_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct WorldDelta {
    pub delta_id: String,
    pub run_id: String,
    pub proposed_by: String,
    pub capability_id: String,
    pub state: DeltaState,
    pub target: DeltaTarget,
    pub change_summary: String,
    pub preconditions: Vec<String>,
    pub patch_ref: Option<String>,
    pub evidence_refs: Vec<String>,
    pub risk_level: RiskLevel,
    pub rollback_plan_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct Permissions {
    pub resources: Vec<String>,
    pub denied: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Default)]
pub struct RetryPolicy {
    pub max_retries: u32,
    pub retry_non_idempotent: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct CapabilityContract {
    pub capability_id: String,
    pub provider: String,
    pub input_schema: Value,
    pub output_schema: Value,
    pub error_schema: Value,
    pub permissions: Permissions,
    pub sandbox_profile: String,
    pub risk_level: RiskLevel,
    pub timeout_ms: u64,
    pub retry_policy: RetryPolicy,
    pub audit_required: bool,
    pub proof_required: bool,
    pub rollback_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct RequiredApproval {
    pub approval_policy: ApprovalPolicy,
    pub approval_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct ApprovalGrant {
    pub grant_id: String,
    pub run_id: String,
    pub delta_id: String,
    pub policy_decision_ref: String,
    pub capability_id: String,
    pub approver_id: String,
    pub reason: String,
    pub granted_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct PolicyDecision {
    pub decision_id: String,
    pub run_id: String,
    pub delta_id: String,
    pub actor_id: String,
    pub capability_id: String,
    pub decision: Decision,
    pub risk_level: RiskLevel,
    pub reasons: Vec<String>,
    pub required_approval: Option<RequiredApproval>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct ExecutionTicket {
    pub ticket_id: String,
    pub run_id: String,
    pub delta_id: String,
    pub policy_decision_ref: String,
    pub capability_contract_ref: String,
    pub sandbox_profile_ref: String,
    pub actor_id: String,
    pub capability_id: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct SandboxInput {
    pub capability_id: String,
    pub payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct SandboxResult {
    pub ticket_id: String,
    pub run_id: String,
    pub capability_id: String,
    pub success: bool,
    pub output: Value,
    pub error: Option<StructuredError>,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub output_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct Proof {
    pub proof_id: String,
    pub run_id: String,
    pub source_type: String,
    pub source_ref: String,
    pub hash: String,
    pub claim: String,
    pub confidence: Confidence,
    pub collected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct LedgerEvent {
    pub ledger_event_id: String,
    pub run_id: String,
    pub event_type: String,
    pub actor_id: String,
    pub resource_ref: String,
    pub delta_id: String,
    pub capability_id: String,
    pub policy_decision_ref: String,
    pub proof_refs: Vec<String>,
    pub input_hash: String,
    pub output_hash: String,
    pub previous_event_hash: String,
    pub event_hash: String,
    pub result: EventResult,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct StructuredError {
    pub code: ErrorCode,
    pub severity: Severity,
    pub retryable: bool,
    pub rollback_required: bool,
    pub user_visible_message: String,
    pub internal_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct RunResult {
    pub run_id: String,
    pub state: RunStatus,
    pub proof_refs: Vec<String>,
    pub ledger_refs: Vec<String>,
}

pub fn schema_for<T: JsonSchema>() -> Value {
    serde_json::to_value(schemars::schema_for!(T)).expect("schema serialization cannot fail")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_contract_roundtrips_json() {
        let contract = RunContract {
            run_id: "run_1".into(),
            intent_id: "intent_1".into(),
            tenant_id: "tenant_a".into(),
            user_id: "user_a".into(),
            risk_level: RiskLevel::Low,
            permission_mode: PermissionMode::ReadOnly,
            status_ref: "state_run_1".into(),
            budget: Budget::default(),
            required_capabilities: vec!["file.read".into()],
            checkpoint_ref: None,
            approval_ref: None,
            ledger_scope: "run".into(),
            created_at: Utc::now(),
        };

        let serialized = serde_json::to_string(&contract).unwrap();
        let parsed: RunContract = serde_json::from_str(&serialized).unwrap();

        assert_eq!(contract, parsed);
    }

    #[test]
    fn exposes_json_schema() {
        let schema = schema_for::<CapabilityContract>();
        assert_eq!(schema["type"], "object");
        assert!(schema["definitions"].is_object());
    }
}
