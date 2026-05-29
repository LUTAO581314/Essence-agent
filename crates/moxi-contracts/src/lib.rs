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
    TimedOut,
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalPolicy {
    #[default]
    Human,
    Quorum,
    Admin,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct PolicyConfig {
    pub require_declared_capabilities: bool,
    pub denied_capabilities: Vec<String>,
    pub approval_required_capabilities: Vec<String>,
    pub denied_resource_patterns: Vec<String>,
    pub approval_required_resource_patterns: Vec<String>,
    pub approval_required_at_or_above: Option<RiskLevel>,
    pub deny_at_or_above: Option<RiskLevel>,
    pub approval_policy: ApprovalPolicy,
    pub approval_ref: Option<String>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            require_declared_capabilities: true,
            denied_capabilities: Vec::new(),
            approval_required_capabilities: Vec::new(),
            denied_resource_patterns: Vec::new(),
            approval_required_resource_patterns: Vec::new(),
            approval_required_at_or_above: Some(RiskLevel::High),
            deny_at_or_above: None,
            approval_policy: ApprovalPolicy::Human,
            approval_ref: None,
        }
    }
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutorIsolation {
    InProcessTrusted,
    ProcessSandbox,
    RemoteSandbox,
    BrowserSandbox,
    ModelGateway,
    PluginHost,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ModuleKind {
    Core,
    Runtime,
    Skill,
    Shell,
    Connector,
    Memory,
    Model,
    Policy,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ModuleStability {
    Experimental,
    Preview,
    Stable,
    Deprecated,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SkillInvocationMode {
    InProcess,
    Process,
    Remote,
    Browser,
    Model,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SubagentMode {
    Delegate,
    Collaborate,
    Review,
    Monitor,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MemoryAccessMode {
    Read,
    Write,
    Search,
    Summarize,
    Forget,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ModelCapabilityKind {
    Chat,
    Reasoning,
    Embedding,
    Vision,
    Audio,
    Rerank,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ShellSurface {
    Cli,
    Ide,
    Desktop,
    Web,
    Mobile,
    Api,
    Mcp,
    DigitalHuman,
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
    pub gateway_decision_ref: Option<String>,
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
    pub gateway_decision_ref: Option<String>,
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
    pub capability_version: String,
    pub provider: String,
    pub provider_identity: String,
    pub manifest_ref: Option<String>,
    pub signature_ref: Option<String>,
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
pub struct ExecutorManifest {
    pub executor_id: String,
    pub capability_id: String,
    pub capability_contract_hash: String,
    pub provider_identity: String,
    pub executor_version: String,
    pub artifact_hash: String,
    pub signing_key_ref: String,
    pub isolation: ExecutorIsolation,
    pub sandbox_profile: String,
    pub manifest_ref: Option<String>,
    pub signature_ref: Option<String>,
    pub attestation_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct ModuleManifest {
    pub module_id: String,
    pub module_version: String,
    pub kind: ModuleKind,
    pub stability: ModuleStability,
    pub owner: String,
    pub summary: String,
    pub required_capabilities: Vec<String>,
    pub provided_capabilities: Vec<String>,
    pub required_modules: Vec<String>,
    pub policy_profile_ref: Option<String>,
    pub manifest_ref: Option<String>,
    pub signature_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct SkillManifest {
    pub skill_id: String,
    pub skill_version: String,
    pub module_ref: String,
    pub invocation_mode: SkillInvocationMode,
    pub entrypoint_ref: String,
    pub required_capabilities: Vec<String>,
    pub provided_capabilities: Vec<String>,
    pub input_schema: Value,
    pub output_schema: Value,
    pub permission_mode: PermissionMode,
    pub risk_level: RiskLevel,
    pub proof_required: bool,
    pub approval_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct SubagentManifest {
    pub agent_id: String,
    pub agent_version: String,
    pub role: String,
    pub mode: SubagentMode,
    pub allowed_capabilities: Vec<String>,
    pub required_skills: Vec<String>,
    pub memory_scopes: Vec<String>,
    pub max_parallel_tasks: u32,
    pub ledger_scope: String,
    pub policy_profile_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct MemoryProviderManifest {
    pub provider_id: String,
    pub provider_version: String,
    pub storage_ref: String,
    pub access_modes: Vec<MemoryAccessMode>,
    pub scopes: Vec<String>,
    pub source_tracking_required: bool,
    pub ledger_binding_required: bool,
    pub retention_policy_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct ModelGatewayManifest {
    pub gateway_id: String,
    pub gateway_version: String,
    pub provider_refs: Vec<String>,
    pub capability_kinds: Vec<ModelCapabilityKind>,
    pub default_model_ref: Option<String>,
    pub fallback_policy_ref: Option<String>,
    pub cost_policy_ref: Option<String>,
    pub redaction_policy_ref: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UnderstandingProposalKind {
    Clarification,
    TaskDecomposition,
    RiskWarning,
    CapabilitySuggestion,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct UnderstandingProposal {
    pub proposal_id: String,
    pub intent_id: String,
    pub kind: UnderstandingProposalKind,
    pub summary: String,
    pub proposed_steps: Vec<String>,
    pub suggested_capabilities: Vec<String>,
    pub risk_level: RiskLevel,
    pub confidence: Confidence,
    pub evidence_refs: Vec<String>,
    pub cannot_authorize: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct ShellAdapterManifest {
    pub shell_id: String,
    pub shell_version: String,
    pub surface: ShellSurface,
    pub entry_channels: Vec<String>,
    pub supported_permission_modes: Vec<PermissionMode>,
    pub required_capabilities: Vec<String>,
    pub projection_refs: Vec<String>,
    pub approval_surface_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct AgentPersonaManifest {
    pub persona_id: String,
    pub persona_version: String,
    pub display_name: String,
    pub role: String,
    pub tone_profile_ref: Option<String>,
    pub allowed_modules: Vec<String>,
    pub allowed_skills: Vec<String>,
    pub memory_scopes: Vec<String>,
    pub policy_profile_ref: Option<String>,
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
    pub capability_contract_hash: String,
    pub executor_ref: String,
    pub executor_version: String,
    pub executor_artifact_hash: String,
    pub executor_signature_ref: String,
    pub executor_signing_key_ref: String,
    pub executor_manifest_hash: String,
    pub executor_isolation: ExecutorIsolation,
    pub retry_policy: RetryPolicy,
    pub sandbox_profile_ref: String,
    pub actor_id: String,
    pub capability_id: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct RuntimeInputMetadata {
    pub idempotency_key: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct SandboxInput {
    pub capability_id: String,
    pub payload: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_metadata: Option<RuntimeInputMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct SandboxResult {
    pub ticket_id: String,
    pub run_id: String,
    pub capability_id: String,
    pub policy_decision_ref: String,
    pub capability_contract_ref: String,
    pub capability_contract_hash: String,
    pub executor_ref: String,
    pub executor_version: String,
    pub executor_artifact_hash: String,
    pub executor_signature_ref: String,
    pub executor_signing_key_ref: String,
    pub executor_manifest_hash: String,
    pub gateway_decision_ref: Option<String>,
    pub input_hash: String,
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
    pub policy_decision_ref: String,
    pub capability_contract_ref: String,
    pub capability_contract_hash: String,
    pub executor_ref: String,
    pub executor_version: String,
    pub executor_artifact_hash: String,
    pub executor_signature_ref: String,
    pub executor_signing_key_ref: String,
    pub executor_manifest_hash: String,
    pub gateway_decision_ref: Option<String>,
    pub input_hash: String,
    pub output_hash: String,
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
    pub execution_ticket_ref: String,
    pub capability_contract_ref: String,
    pub capability_contract_hash: String,
    pub executor_ref: String,
    pub executor_version: String,
    pub executor_artifact_hash: String,
    pub executor_signature_ref: String,
    pub executor_signing_key_ref: String,
    pub executor_manifest_hash: String,
    pub gateway_decision_ref: Option<String>,
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
            gateway_decision_ref: None,
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

    #[test]
    fn policy_config_defaults_roundtrip_json() {
        let config = PolicyConfig::default();

        assert!(config.require_declared_capabilities);
        assert_eq!(config.approval_required_at_or_above, Some(RiskLevel::High));
        assert_eq!(config.approval_policy, ApprovalPolicy::Human);

        let serialized = serde_json::to_string(&config).unwrap();
        let parsed: PolicyConfig = serde_json::from_str(&serialized).unwrap();

        assert_eq!(config, parsed);
    }

    #[test]
    fn extension_manifests_roundtrip_json() {
        let skill = SkillManifest {
            skill_id: "skill.file.read".into(),
            skill_version: "0.1.0".into(),
            module_ref: "module.files".into(),
            invocation_mode: SkillInvocationMode::Process,
            entrypoint_ref: "bin/moxi-file-skill".into(),
            required_capabilities: vec!["file.read".into()],
            provided_capabilities: vec!["skill.file.read".into()],
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: serde_json::json!({"type": "object"}),
            permission_mode: PermissionMode::ReadOnly,
            risk_level: RiskLevel::Low,
            proof_required: true,
            approval_required: false,
        };

        let serialized = serde_json::to_string(&skill).unwrap();
        let parsed: SkillManifest = serde_json::from_str(&serialized).unwrap();

        assert_eq!(skill, parsed);
    }

    #[test]
    fn exposes_extension_manifest_schemas() {
        assert_eq!(schema_for::<ModuleManifest>()["type"], "object");
        assert_eq!(schema_for::<SubagentManifest>()["type"], "object");
        assert_eq!(schema_for::<MemoryProviderManifest>()["type"], "object");
        assert_eq!(schema_for::<ModelGatewayManifest>()["type"], "object");
        assert_eq!(schema_for::<UnderstandingProposal>()["type"], "object");
        assert_eq!(schema_for::<ShellAdapterManifest>()["type"], "object");
        assert_eq!(schema_for::<AgentPersonaManifest>()["type"], "object");
    }
}
