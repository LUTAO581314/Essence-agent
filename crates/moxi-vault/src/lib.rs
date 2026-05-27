use chrono::{DateTime, Utc};
use moxi_contracts::{ApprovalPolicy, PermissionMode, RiskLevel};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const VAULT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Error, PartialEq)]
pub enum VaultError {
    #[error("secret use request requires evidence")]
    MissingEvidence,
    #[error("credential reference belongs to another tenant")]
    TenantMismatch,
    #[error("credential reference is expired")]
    CredentialExpired,
    #[error("credential reference must not contain raw secret material")]
    RawSecretMaterial,
    #[error("quorum approval does not satisfy policy")]
    InvalidApproval,
    #[error("audit export requires event references")]
    MissingAuditEvents,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SecretUseDecisionKind {
    Allowed,
    Denied,
    RequiresApproval,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SecretMaterialPolicy {
    ReferenceOnly,
    ExecutorInjected,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SignatureVerificationKind {
    Verified,
    Rejected,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BreakGlassDecisionKind {
    Allowed,
    Denied,
    RequiresApproval,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditExportRecordKind {
    Run,
    CredentialUse,
    SignatureVerification,
    BreakGlass,
    P1ExecutionReadiness,
    Evolution,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ProductionReadinessDecisionKind {
    Ready,
    Blocked,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ProductionAdapterVerificationKind {
    Verified,
    Rejected,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ProductionAuthDecisionKind {
    Verified,
    Rejected,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ExternalSecretManagerDecisionKind {
    Verified,
    Rejected,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum CryptographicVerifierDecisionKind {
    Verified,
    Rejected,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum HardenedSandboxDecisionKind {
    Verified,
    Rejected,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RotationEnforcementDecisionKind {
    Verified,
    Rejected,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SecretInjectionDecisionKind {
    Verified,
    Rejected,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceExportDeliveryDecisionKind {
    Verified,
    Rejected,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum TrustRootStorageDecisionKind {
    Verified,
    Rejected,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ProductionReadinessGate {
    ProductionAuth,
    ExternalSecretManager,
    CryptographicVerifier,
    HardenedSandbox,
    SecretInjection,
    RotationEnforcement,
    TenantPolicy,
    ExecutorTrustRoots,
    ComplianceAuditExport,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ProductionAdapterKind {
    AuthProvider,
    ExternalSecretManager,
    CryptographicVerifier,
    HardenedSandbox,
    SecretInjection,
    RotationEnforcement,
    ComplianceAuditExport,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum P1ExecutionMode {
    LocalReadOnly,
    Production,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum P1ExecutionReadinessDecisionKind {
    Ready,
    Blocked,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum P1ExecutionReadinessGate {
    TenantPolicy,
    CapabilityScope,
    PermissionMode,
    RiskCeiling,
    CredentialUse,
    ProductionReadiness,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CredentialRef {
    pub credential_id: String,
    pub tenant_id: String,
    pub vault_provider_ref: String,
    pub external_secret_ref: String,
    pub purpose: String,
    pub allowed_capabilities: Vec<String>,
    pub allowed_resource_patterns: Vec<String>,
    pub risk_ceiling: RiskLevel,
    pub approval_required_at_or_above: Option<RiskLevel>,
    pub material_policy: SecretMaterialPolicy,
    pub fingerprint: String,
    pub rotation_ref: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RotationEnforcementDecision {
    pub decision_id: String,
    pub tenant_id: String,
    pub credential_id: String,
    pub rotation_ref: Option<String>,
    pub rotation_policy_ref: Option<String>,
    pub adapter_decision_ref: Option<String>,
    pub decision: RotationEnforcementDecisionKind,
    pub reasons: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub verified_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecretUseRequest {
    pub request_id: String,
    pub run_id: String,
    pub tenant_id: String,
    pub actor_id: String,
    pub capability_id: String,
    pub resource_ref: String,
    pub credential_id: String,
    pub purpose: String,
    pub risk_level: RiskLevel,
    pub evidence_refs: Vec<String>,
    pub requested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecretUseDecision {
    pub decision_id: String,
    pub request_id: String,
    pub credential_id: String,
    pub decision: SecretUseDecisionKind,
    pub approval_policy: ApprovalPolicy,
    pub approval_ref: Option<String>,
    pub reasons: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub raw_secret_visible_to_model: bool,
    pub raw_secret_visible_to_logs: bool,
    pub raw_secret_persisted: bool,
    pub decided_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecretInjectionEvidence {
    pub evidence_id: String,
    pub tenant_id: String,
    pub credential_id: String,
    pub secret_use_decision_id: String,
    pub secret_injection_profile_ref: String,
    pub hardened_sandbox_profile_ref: String,
    pub adapter_decision_ref: String,
    pub injection_receipt_ref: String,
    pub executor_ref: String,
    pub run_id: String,
    pub attestation_ref: String,
    pub delivered_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecretInjectionDecision {
    pub decision_id: String,
    pub tenant_id: String,
    pub credential_id: String,
    pub secret_use_decision_id: String,
    pub secret_injection_profile_ref: String,
    pub hardened_sandbox_profile_ref: String,
    pub decision: SecretInjectionDecisionKind,
    pub reasons: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub verified_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrustRoot {
    pub root_id: String,
    pub tenant_id: String,
    pub issuer: String,
    pub algorithm: String,
    pub signing_key_ref: String,
    pub fingerprint: String,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub revoked: bool,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrustRootRecord {
    pub record_id: String,
    pub tenant_id: String,
    pub root_id: String,
    pub signing_key_ref: String,
    pub trust_root_hash: String,
    pub trust_root: TrustRoot,
    pub evidence_refs: Vec<String>,
    pub sealed_by: String,
    pub sealed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrustRootStorageEvidence {
    pub evidence_id: String,
    pub tenant_id: String,
    pub record_id: String,
    pub trust_root_hash: String,
    pub storage_provider_ref: String,
    pub storage_location_ref: String,
    pub attestation_ref: String,
    pub receipt_ref: String,
    pub replica_set_ref: String,
    pub retention_policy_ref: String,
    pub stored_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrustRootStorageDecision {
    pub decision_id: String,
    pub tenant_id: String,
    pub record_id: String,
    pub root_id: String,
    pub trust_root_hash: String,
    pub storage_provider_ref: String,
    pub decision: TrustRootStorageDecisionKind,
    pub reasons: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub verified_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExecutorSignature {
    pub signature_id: String,
    pub tenant_id: String,
    pub executor_ref: String,
    pub executor_version: String,
    pub artifact_hash: String,
    pub manifest_hash: String,
    pub signing_key_ref: String,
    pub signature_ref: String,
    pub signed_at: DateTime<Utc>,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignatureVerificationDecision {
    pub decision_id: String,
    pub signature_id: String,
    pub tenant_id: String,
    pub executor_ref: String,
    pub decision: SignatureVerificationKind,
    pub trust_root_ref: Option<String>,
    pub can_issue_high_risk_ticket: bool,
    pub reasons: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub verified_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TenantPolicyPack {
    pub pack_id: String,
    pub tenant_id: String,
    pub policy_version: String,
    pub credential_scope_refs: Vec<String>,
    pub high_risk_requires_quorum: bool,
    pub quorum_approvers: u8,
    pub break_glass_enabled: bool,
    pub break_glass_allowed_roles: Vec<String>,
    pub break_glass_allowed_capabilities: Vec<String>,
    pub audit_export_required: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TenantPolicyPackRecord {
    pub record_id: String,
    pub tenant_id: String,
    pub pack_id: String,
    pub policy_version: String,
    pub policy_hash: String,
    pub policy: TenantPolicyPack,
    pub evidence_refs: Vec<String>,
    pub sealed_by: String,
    pub sealed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QuorumApproval {
    pub approval_id: String,
    pub request_ref: String,
    pub tenant_id: String,
    pub approver_ids: Vec<String>,
    pub required_approvers: u8,
    pub reason: String,
    pub granted_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BreakGlassRequest {
    pub request_id: String,
    pub tenant_id: String,
    pub actor_id: String,
    pub actor_roles: Vec<String>,
    pub run_id: String,
    pub reason: String,
    pub requested_capabilities: Vec<String>,
    pub risk_level: RiskLevel,
    pub evidence_refs: Vec<String>,
    pub requested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BreakGlassDecision {
    pub decision_id: String,
    pub request_id: String,
    pub decision: BreakGlassDecisionKind,
    pub approval_ref: Option<String>,
    pub audit_required: bool,
    pub reasons: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub decided_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditExportRecord {
    pub export_id: String,
    pub tenant_id: String,
    pub scope_ref: String,
    pub kind: AuditExportRecordKind,
    pub redaction_profile_ref: String,
    pub event_refs: Vec<String>,
    pub generated_by: String,
    pub contains_secret_material: bool,
    pub export_hash: String,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ComplianceExportBundle {
    pub bundle_id: String,
    pub tenant_id: String,
    pub scope_ref: String,
    pub tenant_policy_record_ref: String,
    pub tenant_policy_hash: String,
    pub production_readiness_ref: Option<String>,
    #[serde(default)]
    pub production_readiness_evidence_hash: Option<String>,
    pub redaction_profile_ref: String,
    pub audit_export_refs: Vec<String>,
    pub p1_execution_bundle_refs: Vec<String>,
    pub event_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub contains_secret_material: bool,
    pub bundle_hash: String,
    pub generated_by: String,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ComplianceExportDeliveryEvidence {
    pub evidence_id: String,
    pub tenant_id: String,
    pub bundle_id: String,
    pub bundle_hash: String,
    pub delivery_ref: String,
    pub storage_provider_ref: String,
    pub adapter_decision_ref: Option<String>,
    pub attestation_ref: String,
    pub receipt_ref: String,
    pub retention_policy_ref: String,
    pub delivered_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ComplianceExportDeliveryDecision {
    pub decision_id: String,
    pub tenant_id: String,
    pub bundle_id: String,
    pub bundle_hash: String,
    pub tenant_policy_hash: String,
    #[serde(default)]
    pub production_readiness_evidence_hash: Option<String>,
    #[serde(default)]
    pub delivery_evidence_ref: String,
    pub delivery_ref: String,
    pub storage_provider_ref: String,
    pub adapter_decision_ref: Option<String>,
    pub decision: ComplianceExportDeliveryDecisionKind,
    pub reasons: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub verified_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProductionHardeningEvidence {
    pub tenant_id: String,
    pub auth_provider_ref: Option<String>,
    pub secret_manager_ref: Option<String>,
    pub cryptographic_verifier_ref: Option<String>,
    pub hardened_sandbox_profile_ref: Option<String>,
    pub secret_injection_profile_ref: Option<String>,
    pub rotation_policy_ref: Option<String>,
    pub compliance_export_profile_ref: Option<String>,
    pub evidence_refs: Vec<String>,
    pub collected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProductionAdapterEvidence {
    pub evidence_id: String,
    pub tenant_id: String,
    pub kind: ProductionAdapterKind,
    pub adapter_ref: String,
    pub adapter_version: String,
    pub provider_ref: String,
    pub attestation_ref: String,
    pub healthcheck_ref: String,
    pub sandbox_profile_ref: Option<String>,
    pub generated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProductionAdapterVerificationDecision {
    pub decision_id: String,
    pub tenant_id: String,
    pub evidence_id: String,
    pub kind: ProductionAdapterKind,
    pub adapter_ref: String,
    pub provider_ref: String,
    pub decision: ProductionAdapterVerificationKind,
    pub reasons: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub verified_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProductionAuthEvidence {
    pub evidence_id: String,
    pub tenant_id: String,
    pub auth_provider_ref: String,
    pub adapter_decision_ref: String,
    pub issuer_ref: String,
    pub jwks_ref: String,
    pub token_policy_ref: String,
    pub audience_ref: String,
    pub session_policy_ref: String,
    pub attestation_ref: String,
    pub checked_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProductionAuthDecision {
    pub decision_id: String,
    pub tenant_id: String,
    pub auth_provider_ref: String,
    pub decision: ProductionAuthDecisionKind,
    pub reasons: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub verified_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExternalSecretManagerEvidence {
    pub evidence_id: String,
    pub tenant_id: String,
    pub credential_id: String,
    pub external_secret_ref: String,
    pub secret_manager_ref: String,
    pub adapter_decision_ref: String,
    pub key_encryption_key_ref: String,
    pub hsm_partition_ref: String,
    pub access_policy_ref: String,
    pub rotation_policy_ref: String,
    pub attestation_ref: String,
    pub checked_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExternalSecretManagerDecision {
    pub decision_id: String,
    pub tenant_id: String,
    pub credential_id: String,
    pub external_secret_ref: String,
    pub secret_manager_ref: String,
    pub decision: ExternalSecretManagerDecisionKind,
    pub reasons: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub verified_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CryptographicVerifierEvidence {
    pub evidence_id: String,
    pub tenant_id: String,
    pub signature_decision_ref: String,
    pub trust_root_record_ref: String,
    pub trust_root_hash: String,
    pub cryptographic_verifier_ref: String,
    pub adapter_decision_ref: String,
    pub verifier_policy_ref: String,
    pub transparency_log_ref: String,
    pub algorithm_suite_ref: String,
    pub attestation_ref: String,
    pub checked_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CryptographicVerifierDecision {
    pub decision_id: String,
    pub tenant_id: String,
    pub signature_decision_ref: String,
    pub trust_root_record_ref: String,
    pub cryptographic_verifier_ref: String,
    pub decision: CryptographicVerifierDecisionKind,
    pub reasons: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub verified_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HardenedSandboxEvidence {
    pub evidence_id: String,
    pub tenant_id: String,
    pub hardened_sandbox_profile_ref: String,
    pub adapter_decision_ref: String,
    pub isolation_policy_ref: String,
    pub filesystem_policy_ref: String,
    pub network_policy_ref: String,
    pub syscall_policy_ref: String,
    pub resource_policy_ref: String,
    pub attestation_ref: String,
    pub checked_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HardenedSandboxDecision {
    pub decision_id: String,
    pub tenant_id: String,
    pub hardened_sandbox_profile_ref: String,
    pub decision: HardenedSandboxDecisionKind,
    pub reasons: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub verified_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProductionReadinessDecision {
    pub decision_id: String,
    pub tenant_id: String,
    pub decision: ProductionReadinessDecisionKind,
    pub missing_gates: Vec<ProductionReadinessGate>,
    pub reasons: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub evaluated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy)]
pub struct ProductionHardeningDecisionSet<'a> {
    pub auth_decision: Option<&'a ProductionAuthDecision>,
    pub external_secret_manager_decisions: &'a [ExternalSecretManagerDecision],
    pub cryptographic_verifier_decisions: &'a [CryptographicVerifierDecision],
    pub hardened_sandbox_decisions: &'a [HardenedSandboxDecision],
    pub rotation_decisions: &'a [RotationEnforcementDecision],
    pub secret_injection_decisions: &'a [SecretInjectionDecision],
    pub compliance_export_delivery_decisions: &'a [ComplianceExportDeliveryDecision],
    pub trust_root_storage_decisions: &'a [TrustRootStorageDecision],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct P1ExecutionReadinessProfile {
    pub profile_id: String,
    pub tenant_id: String,
    pub mode: P1ExecutionMode,
    pub allowed_capabilities: Vec<String>,
    pub allowed_permission_modes: Vec<PermissionMode>,
    pub max_risk_level: RiskLevel,
    pub allow_credential_use: bool,
    pub require_production_readiness_for_high_risk: bool,
    pub evidence_refs: Vec<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct P1ExecutionReadinessProfileRecord {
    pub record_id: String,
    pub tenant_id: String,
    pub profile_id: String,
    pub tenant_policy_pack_ref: String,
    pub tenant_policy_record_ref: String,
    pub tenant_policy_hash: String,
    pub production_readiness_ref: Option<String>,
    #[serde(default)]
    pub production_readiness_evidence_hash: Option<String>,
    pub profile_hash: String,
    pub profile: P1ExecutionReadinessProfile,
    pub evidence_refs: Vec<String>,
    pub sealed_by: String,
    pub sealed_at: DateTime<Utc>,
}

impl P1ExecutionReadinessProfile {
    pub fn local_read_only(tenant_id: impl Into<String>) -> Self {
        let tenant_id = tenant_id.into();
        Self {
            profile_id: format!("p1.local-readonly.{tenant_id}"),
            tenant_id,
            mode: P1ExecutionMode::LocalReadOnly,
            allowed_capabilities: vec!["file.read".into()],
            allowed_permission_modes: vec![PermissionMode::ReadOnly],
            max_risk_level: RiskLevel::Medium,
            allow_credential_use: false,
            require_production_readiness_for_high_risk: true,
            evidence_refs: vec!["p1.local-readonly.profile".into()],
            created_at: Utc::now(),
        }
    }

    pub fn production(tenant_id: impl Into<String>, allowed_capabilities: Vec<String>) -> Self {
        let tenant_id = tenant_id.into();
        Self {
            profile_id: format!("p1.production.{tenant_id}"),
            tenant_id,
            mode: P1ExecutionMode::Production,
            allowed_capabilities,
            allowed_permission_modes: vec![
                PermissionMode::ReadOnly,
                PermissionMode::WorkspaceWrite,
                PermissionMode::Networked,
            ],
            max_risk_level: RiskLevel::High,
            allow_credential_use: true,
            require_production_readiness_for_high_risk: true,
            evidence_refs: vec!["p1.production.profile".into()],
            created_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct P1ExecutionReadinessRequest {
    pub request_id: String,
    pub run_id: String,
    pub tenant_id: String,
    pub actor_id: String,
    pub capability_id: String,
    pub permission_mode: PermissionMode,
    pub risk_level: RiskLevel,
    pub requires_credential: bool,
    pub evidence_refs: Vec<String>,
    pub requested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct P1ExecutionReadinessDecision {
    pub decision_id: String,
    pub request_id: String,
    pub tenant_id: String,
    pub mode: P1ExecutionMode,
    pub decision: P1ExecutionReadinessDecisionKind,
    pub blocked_gates: Vec<P1ExecutionReadinessGate>,
    pub reasons: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub can_enter_p0_execution_chain: bool,
    pub can_issue_ticket_directly: bool,
    pub can_execute_without_p0: bool,
    pub evaluated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct P1ExecutionAuditBundle {
    pub bundle_id: String,
    pub tenant_id: String,
    pub run_id: String,
    pub request_id: String,
    pub profile_record_ref: String,
    pub tenant_policy_pack_ref: String,
    pub tenant_policy_record_ref: String,
    pub tenant_policy_hash: String,
    pub production_readiness_ref: Option<String>,
    #[serde(default)]
    pub production_readiness_evidence_hash: Option<String>,
    pub readiness_decision_ref: String,
    pub audit_export_ref: String,
    #[serde(default)]
    pub audit_export_hash: String,
    pub redaction_profile_ref: String,
    pub evidence_refs: Vec<String>,
    pub can_enter_p0_execution_chain: bool,
    pub can_issue_ticket_directly: bool,
    pub can_execute_without_p0: bool,
    pub contains_secret_material: bool,
    pub bundle_hash: String,
    pub generated_by: String,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct VaultController;

impl VaultController {
    pub fn decide_secret_use(
        credential: &CredentialRef,
        request: &SecretUseRequest,
        approval: Option<&QuorumApproval>,
    ) -> Result<SecretUseDecision, VaultError> {
        validate_credential_ref(credential)?;
        if request.evidence_refs.is_empty() {
            return Err(VaultError::MissingEvidence);
        }
        if credential.tenant_id != request.tenant_id {
            return Err(VaultError::TenantMismatch);
        }
        if credential
            .expires_at
            .is_some_and(|expires_at| expires_at <= Utc::now())
        {
            return Err(VaultError::CredentialExpired);
        }

        let mut reasons = Vec::new();
        let capability_allowed =
            matches_any(&credential.allowed_capabilities, &request.capability_id);
        let resource_allowed =
            matches_any(&credential.allowed_resource_patterns, &request.resource_ref);
        let decision = if !capability_allowed {
            reasons.push("capability is outside credential scope".into());
            SecretUseDecisionKind::Denied
        } else if !resource_allowed {
            reasons.push("resource is outside credential scope".into());
            SecretUseDecisionKind::Denied
        } else if request.risk_level > credential.risk_ceiling {
            reasons.push("requested risk exceeds credential ceiling".into());
            SecretUseDecisionKind::Denied
        } else if approval_required(credential, request.risk_level) {
            match approval {
                Some(grant) => {
                    validate_quorum(grant, &request.request_id, &request.tenant_id)?;
                    reasons.push("quorum approval satisfies secret use policy".into());
                    SecretUseDecisionKind::Allowed
                }
                None => {
                    reasons.push("secret use requires approval".into());
                    SecretUseDecisionKind::RequiresApproval
                }
            }
        } else {
            reasons.push("credential scope and risk policy allow reference use".into());
            SecretUseDecisionKind::Allowed
        };

        let approval_ref = approval.map(|grant| grant.approval_id.clone());
        let mut evidence_refs = request.evidence_refs.clone();
        if let Some(grant) = approval {
            evidence_refs.push(grant.approval_id.clone());
        }
        evidence_refs.sort();
        evidence_refs.dedup();
        let approval_policy =
            if approval_ref.is_some() || decision == SecretUseDecisionKind::RequiresApproval {
                ApprovalPolicy::Quorum
            } else {
                ApprovalPolicy::None
            };

        Ok(SecretUseDecision {
            decision_id: stable_id(
                "secret_use_decision",
                &(
                    request.request_id.as_str(),
                    credential.credential_id.as_str(),
                    &approval_ref,
                ),
            ),
            request_id: request.request_id.clone(),
            credential_id: credential.credential_id.clone(),
            decision,
            approval_policy,
            approval_ref,
            reasons,
            evidence_refs,
            raw_secret_visible_to_model: false,
            raw_secret_visible_to_logs: false,
            raw_secret_persisted: false,
            decided_at: Utc::now(),
            expires_at: credential
                .expires_at
                .unwrap_or_else(|| Utc::now() + chrono::Duration::minutes(15)),
        })
    }

    pub fn verify_executor_signature(
        signature: &ExecutorSignature,
        trust_roots: &[TrustRoot],
        risk_level: RiskLevel,
    ) -> SignatureVerificationDecision {
        let now = Utc::now();
        let root = trust_roots.iter().find(|root| {
            root.tenant_id == signature.tenant_id
                && root.signing_key_ref == signature.signing_key_ref
                && root.valid_from <= signature.signed_at
                && root.valid_until >= signature.signed_at
        });
        let mut reasons = Vec::new();
        let mut evidence_refs = signature.evidence_refs.clone();
        let decision = match root {
            Some(root) if root.revoked => {
                reasons.push("matching trust root is revoked".into());
                SignatureVerificationKind::Rejected
            }
            Some(root)
                if signature.artifact_hash.is_empty() || signature.manifest_hash.is_empty() =>
            {
                reasons.push("executor signature is missing artifact or manifest hash".into());
                evidence_refs.extend(root.evidence_refs.clone());
                SignatureVerificationKind::Rejected
            }
            Some(root) if signature.signature_ref.is_empty() => {
                reasons.push("executor signature reference is empty".into());
                evidence_refs.extend(root.evidence_refs.clone());
                SignatureVerificationKind::Rejected
            }
            Some(root) => {
                reasons.push("executor signature matches tenant trust root".into());
                evidence_refs.extend(root.evidence_refs.clone());
                SignatureVerificationKind::Verified
            }
            None => {
                reasons.push("no matching tenant trust root".into());
                SignatureVerificationKind::Rejected
            }
        };
        evidence_refs.sort();
        evidence_refs.dedup();
        let trust_root_ref = root.map(|root| root.root_id.clone());
        let can_issue_high_risk_ticket =
            decision == SignatureVerificationKind::Verified && risk_level >= RiskLevel::High;

        SignatureVerificationDecision {
            decision_id: stable_id(
                "signature_verification",
                &(signature.signature_id.as_str(), &trust_root_ref, &decision),
            ),
            signature_id: signature.signature_id.clone(),
            tenant_id: signature.tenant_id.clone(),
            executor_ref: signature.executor_ref.clone(),
            decision,
            trust_root_ref,
            can_issue_high_risk_ticket,
            reasons,
            evidence_refs,
            verified_at: now,
        }
    }

    pub fn seal_trust_root(
        trust_root: TrustRoot,
        evidence_refs: Vec<String>,
        sealed_by: impl Into<String>,
    ) -> Result<TrustRootRecord, VaultError> {
        validate_trust_root(&trust_root)?;
        if evidence_refs.is_empty() {
            return Err(VaultError::MissingEvidence);
        }
        let trust_root_hash = stable_id("trust_root_hash", &trust_root);
        let mut combined_evidence = evidence_refs;
        combined_evidence.push(trust_root.root_id.clone());
        combined_evidence.extend(trust_root.evidence_refs.clone());
        combined_evidence.sort();
        combined_evidence.dedup();

        Ok(TrustRootRecord {
            record_id: stable_id(
                "trust_root_record",
                &(
                    trust_root.tenant_id.as_str(),
                    trust_root.root_id.as_str(),
                    trust_root.signing_key_ref.as_str(),
                    trust_root_hash.as_str(),
                    &combined_evidence,
                ),
            ),
            tenant_id: trust_root.tenant_id.clone(),
            root_id: trust_root.root_id.clone(),
            signing_key_ref: trust_root.signing_key_ref.clone(),
            trust_root_hash,
            trust_root,
            evidence_refs: combined_evidence,
            sealed_by: sealed_by.into(),
            sealed_at: Utc::now(),
        })
    }

    pub fn load_trust_root(record: &TrustRootRecord) -> Result<TrustRoot, VaultError> {
        validate_trust_root(&record.trust_root)?;
        if record.evidence_refs.is_empty() {
            return Err(VaultError::MissingEvidence);
        }
        if record.tenant_id != record.trust_root.tenant_id
            || record.root_id != record.trust_root.root_id
            || record.signing_key_ref != record.trust_root.signing_key_ref
        {
            return Err(VaultError::TenantMismatch);
        }
        let expected_hash = stable_id("trust_root_hash", &record.trust_root);
        if record.trust_root_hash != expected_hash {
            return Err(VaultError::MissingEvidence);
        }

        Ok(record.trust_root.clone())
    }

    pub fn verify_trust_root_storage(
        record: &TrustRootRecord,
        evidence: &TrustRootStorageEvidence,
    ) -> TrustRootStorageDecision {
        let mut reasons = Vec::new();
        let mut evidence_refs = record.evidence_refs.clone();
        evidence_refs.extend([
            record.record_id.clone(),
            record.trust_root_hash.clone(),
            evidence.evidence_id.clone(),
            evidence.storage_provider_ref.clone(),
            evidence.storage_location_ref.clone(),
            evidence.attestation_ref.clone(),
            evidence.receipt_ref.clone(),
            evidence.replica_set_ref.clone(),
            evidence.retention_policy_ref.clone(),
        ]);

        if Self::load_trust_root(record).is_err() {
            reasons.push("trust-root record failed local hash validation".into());
        }
        if record.tenant_id != evidence.tenant_id {
            reasons
                .push("trust-root record and storage evidence belong to different tenants".into());
        }
        if record.record_id != evidence.record_id
            || record.trust_root_hash != evidence.trust_root_hash
        {
            reasons.push("storage evidence is not bound to the trust-root record hash".into());
        }
        if evidence.stored_at >= evidence.expires_at || evidence.expires_at <= Utc::now() {
            reasons.push("trust-root storage evidence is expired or invalid".into());
        }
        if [
            evidence.evidence_id.as_str(),
            evidence.storage_provider_ref.as_str(),
            evidence.storage_location_ref.as_str(),
            evidence.attestation_ref.as_str(),
            evidence.receipt_ref.as_str(),
            evidence.replica_set_ref.as_str(),
            evidence.retention_policy_ref.as_str(),
        ]
        .iter()
        .any(|value| is_placeholder_ref(value))
        {
            reasons.push("trust-root storage evidence contains placeholder refs".into());
        }

        evidence_refs.sort();
        evidence_refs.dedup();
        reasons.sort();
        reasons.dedup();

        let decision = if reasons.is_empty() {
            reasons.push("trust-root external storage evidence is verified".into());
            TrustRootStorageDecisionKind::Verified
        } else {
            TrustRootStorageDecisionKind::Rejected
        };

        TrustRootStorageDecision {
            decision_id: stable_id(
                "trust_root_storage",
                &(
                    record.tenant_id.as_str(),
                    record.record_id.as_str(),
                    record.trust_root_hash.as_str(),
                    evidence.evidence_id.as_str(),
                    evidence.storage_provider_ref.as_str(),
                    &decision,
                    &evidence_refs,
                ),
            ),
            tenant_id: record.tenant_id.clone(),
            record_id: record.record_id.clone(),
            root_id: record.root_id.clone(),
            trust_root_hash: record.trust_root_hash.clone(),
            storage_provider_ref: evidence.storage_provider_ref.clone(),
            decision,
            reasons,
            evidence_refs,
            verified_at: Utc::now(),
            expires_at: evidence.expires_at,
        }
    }

    pub fn verify_executor_signature_with_trust_root_records(
        signature: &ExecutorSignature,
        trust_root_records: &[TrustRootRecord],
        risk_level: RiskLevel,
    ) -> Result<SignatureVerificationDecision, VaultError> {
        let trust_roots = trust_root_records
            .iter()
            .map(Self::load_trust_root)
            .collect::<Result<Vec<_>, _>>()?;
        if trust_roots
            .iter()
            .any(|trust_root| trust_root.tenant_id != signature.tenant_id)
        {
            return Err(VaultError::TenantMismatch);
        }

        Ok(Self::verify_executor_signature(
            signature,
            &trust_roots,
            risk_level,
        ))
    }

    pub fn decide_break_glass(
        policy: &TenantPolicyPack,
        request: &BreakGlassRequest,
        approval: Option<&QuorumApproval>,
    ) -> Result<BreakGlassDecision, VaultError> {
        if request.evidence_refs.is_empty() {
            return Err(VaultError::MissingEvidence);
        }
        if policy.tenant_id != request.tenant_id {
            return Err(VaultError::TenantMismatch);
        }

        let mut reasons = Vec::new();
        let has_role = request
            .actor_roles
            .iter()
            .any(|role| policy.break_glass_allowed_roles.contains(role));
        let capability_allowed = request
            .requested_capabilities
            .iter()
            .all(|capability| matches_any(&policy.break_glass_allowed_capabilities, capability));
        let decision = if !policy.break_glass_enabled {
            reasons.push("break-glass mode is disabled by tenant policy".into());
            BreakGlassDecisionKind::Denied
        } else if !has_role {
            reasons.push("actor role is not allowed to request break-glass".into());
            BreakGlassDecisionKind::Denied
        } else if !capability_allowed {
            reasons.push("requested capability is outside break-glass scope".into());
            BreakGlassDecisionKind::Denied
        } else if policy.high_risk_requires_quorum || request.risk_level >= RiskLevel::High {
            match approval {
                Some(grant) => {
                    validate_quorum(grant, &request.request_id, &request.tenant_id)?;
                    reasons.push("quorum approval satisfies break-glass policy".into());
                    BreakGlassDecisionKind::Allowed
                }
                None => {
                    reasons.push("break-glass requires quorum approval".into());
                    BreakGlassDecisionKind::RequiresApproval
                }
            }
        } else {
            reasons.push("tenant policy allows bounded break-glass".into());
            BreakGlassDecisionKind::Allowed
        };

        let approval_ref = approval.map(|grant| grant.approval_id.clone());
        let mut evidence_refs = request.evidence_refs.clone();
        if let Some(grant) = approval {
            evidence_refs.push(grant.approval_id.clone());
        }
        evidence_refs.sort();
        evidence_refs.dedup();

        Ok(BreakGlassDecision {
            decision_id: stable_id(
                "break_glass_decision",
                &(
                    request.request_id.as_str(),
                    policy.pack_id.as_str(),
                    &approval_ref,
                ),
            ),
            request_id: request.request_id.clone(),
            decision,
            approval_ref,
            audit_required: true,
            reasons,
            evidence_refs,
            decided_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::minutes(10),
        })
    }

    pub fn audit_export_record(
        tenant_id: impl Into<String>,
        scope_ref: impl Into<String>,
        kind: AuditExportRecordKind,
        redaction_profile_ref: impl Into<String>,
        event_refs: Vec<String>,
        generated_by: impl Into<String>,
    ) -> Result<AuditExportRecord, VaultError> {
        if event_refs.is_empty() {
            return Err(VaultError::MissingAuditEvents);
        }
        let tenant_id = tenant_id.into();
        let scope_ref = scope_ref.into();
        let redaction_profile_ref = redaction_profile_ref.into();
        let generated_by = generated_by.into();
        let export_hash = stable_id(
            "audit_export_hash",
            &(
                tenant_id.as_str(),
                scope_ref.as_str(),
                &kind,
                redaction_profile_ref.as_str(),
                &event_refs,
            ),
        );

        Ok(AuditExportRecord {
            export_id: stable_id("audit_export", &(scope_ref.as_str(), &event_refs)),
            tenant_id,
            scope_ref,
            kind,
            redaction_profile_ref,
            event_refs,
            generated_by,
            contains_secret_material: false,
            export_hash,
            generated_at: Utc::now(),
        })
    }

    pub fn seal_tenant_policy_pack(
        policy: TenantPolicyPack,
        evidence_refs: Vec<String>,
        sealed_by: impl Into<String>,
    ) -> Result<TenantPolicyPackRecord, VaultError> {
        if policy.credential_scope_refs.is_empty() || evidence_refs.is_empty() {
            return Err(VaultError::MissingEvidence);
        }
        let policy_hash = stable_id("tenant_policy_hash", &policy);
        let mut combined_evidence = evidence_refs;
        combined_evidence.push(policy.pack_id.clone());
        combined_evidence.extend(policy.credential_scope_refs.clone());
        combined_evidence.sort();
        combined_evidence.dedup();

        Ok(TenantPolicyPackRecord {
            record_id: stable_id(
                "tenant_policy_record",
                &(
                    policy.tenant_id.as_str(),
                    policy.pack_id.as_str(),
                    policy.policy_version.as_str(),
                    policy_hash.as_str(),
                    &combined_evidence,
                ),
            ),
            tenant_id: policy.tenant_id.clone(),
            pack_id: policy.pack_id.clone(),
            policy_version: policy.policy_version.clone(),
            policy_hash,
            policy,
            evidence_refs: combined_evidence,
            sealed_by: sealed_by.into(),
            sealed_at: Utc::now(),
        })
    }

    pub fn load_tenant_policy_pack(
        record: &TenantPolicyPackRecord,
    ) -> Result<TenantPolicyPack, VaultError> {
        if record.evidence_refs.is_empty() || record.policy.credential_scope_refs.is_empty() {
            return Err(VaultError::MissingEvidence);
        }
        if record.tenant_id != record.policy.tenant_id
            || record.pack_id != record.policy.pack_id
            || record.policy_version != record.policy.policy_version
        {
            return Err(VaultError::TenantMismatch);
        }
        let expected_hash = stable_id("tenant_policy_hash", &record.policy);
        if record.policy_hash != expected_hash {
            return Err(VaultError::MissingEvidence);
        }

        Ok(record.policy.clone())
    }

    pub fn seal_p1_execution_readiness_profile(
        policy: &TenantPolicyPack,
        profile: P1ExecutionReadinessProfile,
        sealed_by: impl Into<String>,
    ) -> Result<P1ExecutionReadinessProfileRecord, VaultError> {
        let policy_record = Self::seal_tenant_policy_pack(
            policy.clone(),
            policy.credential_scope_refs.clone(),
            "vault.policy.compat",
        )?;
        Self::seal_p1_execution_readiness_profile_with_policy_record(
            &policy_record,
            profile,
            None,
            sealed_by,
        )
    }

    pub fn seal_production_p1_execution_readiness_profile(
        policy: &TenantPolicyPack,
        profile: P1ExecutionReadinessProfile,
        production_readiness: &ProductionReadinessDecision,
        sealed_by: impl Into<String>,
    ) -> Result<P1ExecutionReadinessProfileRecord, VaultError> {
        let policy_record = Self::seal_tenant_policy_pack(
            policy.clone(),
            policy.credential_scope_refs.clone(),
            "vault.policy.compat",
        )?;
        Self::seal_p1_execution_readiness_profile_with_policy_record(
            &policy_record,
            profile,
            Some(production_readiness),
            sealed_by,
        )
    }

    pub fn seal_p1_execution_readiness_profile_with_policy_record(
        policy_record: &TenantPolicyPackRecord,
        profile: P1ExecutionReadinessProfile,
        production_readiness: Option<&ProductionReadinessDecision>,
        sealed_by: impl Into<String>,
    ) -> Result<P1ExecutionReadinessProfileRecord, VaultError> {
        let policy = Self::load_tenant_policy_pack(policy_record)?;
        if profile.evidence_refs.is_empty() || policy.credential_scope_refs.is_empty() {
            return Err(VaultError::MissingEvidence);
        }
        if profile.tenant_id != policy.tenant_id {
            return Err(VaultError::TenantMismatch);
        }
        let production_required = p1_profile_requires_production_readiness(&profile);
        let (production_readiness_ref, production_readiness_evidence_hash_ref) =
            if production_required {
                let production_readiness =
                    production_readiness.ok_or(VaultError::MissingEvidence)?;
                validate_ready_production_readiness(production_readiness, &policy.tenant_id)?;
                (
                    Some(production_readiness.decision_id.clone()),
                    Some(production_readiness_evidence_hash(production_readiness)),
                )
            } else {
                (None, None)
            };
        let profile_hash = stable_id("p1_execution_profile_hash", &profile);
        let mut evidence_refs = profile.evidence_refs.clone();
        evidence_refs.push(policy.pack_id.clone());
        evidence_refs.push(policy_record.record_id.clone());
        evidence_refs.push(policy_record.policy_hash.clone());
        evidence_refs.extend(policy.credential_scope_refs.clone());
        evidence_refs.extend(policy_record.evidence_refs.clone());
        if let Some(production_readiness) = production_readiness {
            validate_production_readiness_ref_for_profile_record(
                production_readiness,
                &policy.tenant_id,
                production_required,
                production_readiness_ref.as_deref(),
                production_readiness_evidence_hash_ref.as_deref(),
            )?;
            evidence_refs.push(production_readiness.decision_id.clone());
            evidence_refs.push(production_readiness_evidence_hash(production_readiness));
        }
        evidence_refs.sort();
        evidence_refs.dedup();
        if evidence_refs.is_empty() {
            return Err(VaultError::MissingEvidence);
        }

        Ok(P1ExecutionReadinessProfileRecord {
            record_id: stable_id(
                "p1_execution_profile_record",
                &(
                    policy.pack_id.as_str(),
                    policy_record.record_id.as_str(),
                    policy_record.policy_hash.as_str(),
                    profile.profile_id.as_str(),
                    profile_hash.as_str(),
                    &production_readiness_ref,
                    &production_readiness_evidence_hash_ref,
                    &evidence_refs,
                ),
            ),
            tenant_id: profile.tenant_id.clone(),
            profile_id: profile.profile_id.clone(),
            tenant_policy_pack_ref: policy.pack_id.clone(),
            tenant_policy_record_ref: policy_record.record_id.clone(),
            tenant_policy_hash: policy_record.policy_hash.clone(),
            production_readiness_ref,
            production_readiness_evidence_hash: production_readiness_evidence_hash_ref,
            profile_hash,
            profile,
            evidence_refs,
            sealed_by: sealed_by.into(),
            sealed_at: Utc::now(),
        })
    }

    pub fn load_p1_execution_readiness_profile(
        record: &P1ExecutionReadinessProfileRecord,
        policy: &TenantPolicyPack,
    ) -> Result<P1ExecutionReadinessProfile, VaultError> {
        let policy_record = Self::seal_tenant_policy_pack(
            policy.clone(),
            policy.credential_scope_refs.clone(),
            "vault.policy.compat",
        )?;
        Self::load_p1_execution_readiness_profile_with_policy_record(record, &policy_record)
    }

    pub fn load_p1_execution_readiness_profile_with_policy_record(
        record: &P1ExecutionReadinessProfileRecord,
        policy_record: &TenantPolicyPackRecord,
    ) -> Result<P1ExecutionReadinessProfile, VaultError> {
        let policy = Self::load_tenant_policy_pack(policy_record)?;
        if record.evidence_refs.is_empty() {
            return Err(VaultError::MissingEvidence);
        }
        if record.tenant_id != policy.tenant_id
            || record.profile.tenant_id != policy.tenant_id
            || record.tenant_policy_pack_ref != policy.pack_id
            || record.tenant_policy_record_ref != policy_record.record_id
        {
            return Err(VaultError::TenantMismatch);
        }
        if record.tenant_policy_hash != policy_record.policy_hash {
            return Err(VaultError::MissingEvidence);
        }
        if !refs_contain_all(&record.evidence_refs, &record.profile.evidence_refs)
            || !refs_contain_all(&record.evidence_refs, &policy.credential_scope_refs)
            || !refs_contain_all(&record.evidence_refs, &policy_record.evidence_refs)
            || !record.evidence_refs.contains(&policy.pack_id)
            || !record.evidence_refs.contains(&policy_record.record_id)
            || !record.evidence_refs.contains(&policy_record.policy_hash)
        {
            return Err(VaultError::MissingEvidence);
        }
        let expected_hash = stable_id("p1_execution_profile_hash", &record.profile);
        if record.profile_hash != expected_hash || record.profile_id != record.profile.profile_id {
            return Err(VaultError::MissingEvidence);
        }
        let production_required = p1_profile_requires_production_readiness(&record.profile);
        if production_required && record.production_readiness_ref.is_none() {
            return Err(VaultError::MissingEvidence);
        }
        if production_required && record.production_readiness_evidence_hash.is_none() {
            return Err(VaultError::MissingEvidence);
        }
        if production_required
            && (record
                .production_readiness_ref
                .as_ref()
                .is_some_and(|readiness_ref| !record.evidence_refs.contains(readiness_ref))
                || record
                    .production_readiness_evidence_hash
                    .as_ref()
                    .is_some_and(|readiness_hash| !record.evidence_refs.contains(readiness_hash)))
        {
            return Err(VaultError::MissingEvidence);
        }
        if !production_required
            && (record.production_readiness_ref.is_some()
                || record.production_readiness_evidence_hash.is_some())
        {
            return Err(VaultError::MissingEvidence);
        }

        Ok(record.profile.clone())
    }

    pub fn load_p1_execution_readiness_profile_with_production_readiness(
        record: &P1ExecutionReadinessProfileRecord,
        policy_record: &TenantPolicyPackRecord,
        production_readiness: Option<&ProductionReadinessDecision>,
    ) -> Result<P1ExecutionReadinessProfile, VaultError> {
        let profile =
            Self::load_p1_execution_readiness_profile_with_policy_record(record, policy_record)?;
        validate_production_readiness_for_loaded_profile_record(record, production_readiness)?;
        Ok(profile)
    }

    pub fn audit_p1_execution_readiness(
        decision: &P1ExecutionReadinessDecision,
        profile_record: &P1ExecutionReadinessProfileRecord,
        redaction_profile_ref: impl Into<String>,
        generated_by: impl Into<String>,
    ) -> Result<AuditExportRecord, VaultError> {
        if decision.tenant_id != profile_record.tenant_id {
            return Err(VaultError::TenantMismatch);
        }
        validate_p1_execution_readiness_decision_for_record(decision, profile_record, None)?;
        Self::audit_export_record(
            decision.tenant_id.clone(),
            decision.request_id.clone(),
            AuditExportRecordKind::P1ExecutionReadiness,
            redaction_profile_ref,
            vec![
                profile_record.record_id.clone(),
                decision.decision_id.clone(),
                decision.request_id.clone(),
            ],
            generated_by,
        )
    }

    pub fn p1_execution_audit_bundle(
        request: &P1ExecutionReadinessRequest,
        decision: &P1ExecutionReadinessDecision,
        profile_record: &P1ExecutionReadinessProfileRecord,
        audit_export: &AuditExportRecord,
        production_readiness: Option<&ProductionReadinessDecision>,
    ) -> Result<P1ExecutionAuditBundle, VaultError> {
        if request.tenant_id != decision.tenant_id
            || request.tenant_id != profile_record.tenant_id
            || request.tenant_id != audit_export.tenant_id
            || production_readiness
                .is_some_and(|readiness| readiness.tenant_id != request.tenant_id)
        {
            return Err(VaultError::TenantMismatch);
        }
        if request.evidence_refs.is_empty()
            || decision.evidence_refs.is_empty()
            || profile_record.evidence_refs.is_empty()
            || audit_export.event_refs.is_empty()
        {
            return Err(VaultError::MissingEvidence);
        }
        validate_audit_export_record(audit_export)?;
        validate_p1_execution_readiness_decision_for_record(
            decision,
            profile_record,
            Some(request),
        )?;
        if decision.request_id != request.request_id
            || audit_export.kind != AuditExportRecordKind::P1ExecutionReadiness
            || !audit_export.event_refs.contains(&profile_record.record_id)
            || !audit_export.event_refs.contains(&decision.decision_id)
            || !audit_export.event_refs.contains(&request.request_id)
        {
            return Err(VaultError::MissingEvidence);
        }

        validate_production_readiness_for_loaded_profile_record(
            profile_record,
            production_readiness,
        )?;

        let mut evidence_refs = request.evidence_refs.clone();
        evidence_refs.extend(decision.evidence_refs.clone());
        evidence_refs.extend(profile_record.evidence_refs.clone());
        evidence_refs.extend(audit_export.event_refs.clone());
        evidence_refs.push(profile_record.record_id.clone());
        evidence_refs.push(profile_record.tenant_policy_pack_ref.clone());
        evidence_refs.push(profile_record.tenant_policy_record_ref.clone());
        evidence_refs.push(profile_record.tenant_policy_hash.clone());
        evidence_refs.push(decision.decision_id.clone());
        evidence_refs.push(audit_export.export_id.clone());
        evidence_refs.push(audit_export.export_hash.clone());
        if let Some(readiness) = production_readiness {
            evidence_refs.push(readiness.decision_id.clone());
            evidence_refs.push(production_readiness_evidence_hash(readiness));
            evidence_refs.extend(readiness.evidence_refs.clone());
        }
        evidence_refs.sort();
        evidence_refs.dedup();
        if evidence_refs.is_empty() {
            return Err(VaultError::MissingEvidence);
        }

        let bundle_hash = stable_id(
            "p1_execution_audit_bundle_hash",
            &(
                request.request_id.as_str(),
                profile_record.record_id.as_str(),
                decision.decision_id.as_str(),
                audit_export.export_hash.as_str(),
                &profile_record.production_readiness_ref,
                &profile_record.production_readiness_evidence_hash,
                &evidence_refs,
            ),
        );

        Ok(P1ExecutionAuditBundle {
            bundle_id: stable_id(
                "p1_execution_audit_bundle",
                &(
                    request.request_id.as_str(),
                    profile_record.record_id.as_str(),
                    decision.decision_id.as_str(),
                    audit_export.export_id.as_str(),
                    bundle_hash.as_str(),
                ),
            ),
            tenant_id: request.tenant_id.clone(),
            run_id: request.run_id.clone(),
            request_id: request.request_id.clone(),
            profile_record_ref: profile_record.record_id.clone(),
            tenant_policy_pack_ref: profile_record.tenant_policy_pack_ref.clone(),
            tenant_policy_record_ref: profile_record.tenant_policy_record_ref.clone(),
            tenant_policy_hash: profile_record.tenant_policy_hash.clone(),
            production_readiness_ref: profile_record.production_readiness_ref.clone(),
            production_readiness_evidence_hash: profile_record
                .production_readiness_evidence_hash
                .clone(),
            readiness_decision_ref: decision.decision_id.clone(),
            audit_export_ref: audit_export.export_id.clone(),
            audit_export_hash: audit_export.export_hash.clone(),
            redaction_profile_ref: audit_export.redaction_profile_ref.clone(),
            evidence_refs,
            can_enter_p0_execution_chain: decision.can_enter_p0_execution_chain,
            can_issue_ticket_directly: false,
            can_execute_without_p0: false,
            contains_secret_material: false,
            bundle_hash,
            generated_by: audit_export.generated_by.clone(),
            generated_at: Utc::now(),
        })
    }

    pub fn compliance_export_bundle(
        scope_ref: impl Into<String>,
        policy_record: &TenantPolicyPackRecord,
        audit_exports: &[AuditExportRecord],
        p1_execution_bundles: &[P1ExecutionAuditBundle],
        production_readiness: Option<&ProductionReadinessDecision>,
        generated_by: impl Into<String>,
    ) -> Result<ComplianceExportBundle, VaultError> {
        let policy = Self::load_tenant_policy_pack(policy_record)?;
        if audit_exports.is_empty() && p1_execution_bundles.is_empty() {
            return Err(VaultError::MissingAuditEvents);
        }
        if !policy.audit_export_required {
            return Err(VaultError::MissingEvidence);
        }
        if audit_exports
            .iter()
            .any(|export| export.tenant_id != policy.tenant_id)
            || p1_execution_bundles
                .iter()
                .any(|bundle| bundle.tenant_id != policy.tenant_id)
            || production_readiness.is_some_and(|decision| decision.tenant_id != policy.tenant_id)
        {
            return Err(VaultError::TenantMismatch);
        }
        for export in audit_exports {
            validate_audit_export_record(export)?;
        }
        for bundle in p1_execution_bundles {
            validate_p1_execution_audit_bundle_record(bundle)?;
        }
        if audit_exports
            .iter()
            .any(|export| export.event_refs.is_empty() || export.contains_secret_material)
            || p1_execution_bundles
                .iter()
                .any(|bundle| bundle.evidence_refs.is_empty() || bundle.contains_secret_material)
        {
            return Err(VaultError::MissingEvidence);
        }
        if let Some(production_readiness) = production_readiness {
            validate_ready_production_readiness(production_readiness, &policy.tenant_id)?;
        }
        let expected_production_readiness_ref =
            production_readiness.map(|decision| decision.decision_id.clone());
        let expected_production_readiness_evidence_hash =
            production_readiness.map(production_readiness_evidence_hash);
        for bundle in p1_execution_bundles {
            if bundle.production_readiness_ref != expected_production_readiness_ref
                || bundle.production_readiness_evidence_hash
                    != expected_production_readiness_evidence_hash
            {
                return Err(VaultError::MissingEvidence);
            }
        }

        let mut redaction_profiles = audit_exports
            .iter()
            .map(|export| export.redaction_profile_ref.clone())
            .chain(
                p1_execution_bundles
                    .iter()
                    .map(|bundle| bundle.redaction_profile_ref.clone()),
            )
            .collect::<Vec<_>>();
        redaction_profiles.sort();
        redaction_profiles.dedup();
        if redaction_profiles.len() != 1 {
            return Err(VaultError::MissingEvidence);
        }
        let redaction_profile_ref = redaction_profiles.remove(0);

        let mut audit_export_refs = audit_exports
            .iter()
            .map(|export| export.export_id.clone())
            .collect::<Vec<_>>();
        audit_export_refs.sort();
        audit_export_refs.dedup();

        let mut p1_execution_bundle_refs = p1_execution_bundles
            .iter()
            .map(|bundle| bundle.bundle_id.clone())
            .collect::<Vec<_>>();
        p1_execution_bundle_refs.sort();
        p1_execution_bundle_refs.dedup();

        let mut event_refs = audit_exports
            .iter()
            .flat_map(|export| {
                export
                    .event_refs
                    .iter()
                    .cloned()
                    .chain(std::iter::once(export.export_hash.clone()))
            })
            .chain(
                p1_execution_bundles
                    .iter()
                    .flat_map(|bundle| bundle.evidence_refs.iter().cloned()),
            )
            .collect::<Vec<_>>();
        event_refs.sort();
        event_refs.dedup();
        if event_refs.is_empty() {
            return Err(VaultError::MissingAuditEvents);
        }

        let mut evidence_refs = policy_record.evidence_refs.clone();
        evidence_refs.push(policy_record.record_id.clone());
        evidence_refs.push(policy_record.policy_hash.clone());
        evidence_refs.extend(audit_export_refs.clone());
        evidence_refs.extend(p1_execution_bundle_refs.clone());
        evidence_refs.extend(event_refs.clone());
        if let Some(production_readiness) = production_readiness {
            evidence_refs.push(production_readiness.decision_id.clone());
            evidence_refs.push(production_readiness_evidence_hash(production_readiness));
            evidence_refs.extend(production_readiness.evidence_refs.clone());
        }
        evidence_refs.sort();
        evidence_refs.dedup();
        if evidence_refs.is_empty() {
            return Err(VaultError::MissingEvidence);
        }

        let scope_ref = scope_ref.into();
        let generated_by = generated_by.into();
        let bundle_hash = stable_id(
            "compliance_export_bundle_hash",
            &(
                policy_record.record_id.as_str(),
                policy_record.policy_hash.as_str(),
                scope_ref.as_str(),
                redaction_profile_ref.as_str(),
                &audit_export_refs,
                &p1_execution_bundle_refs,
                &expected_production_readiness_ref,
                &expected_production_readiness_evidence_hash,
                &evidence_refs,
            ),
        );

        Ok(ComplianceExportBundle {
            bundle_id: stable_id(
                "compliance_export_bundle",
                &(
                    policy.tenant_id.as_str(),
                    scope_ref.as_str(),
                    bundle_hash.as_str(),
                ),
            ),
            tenant_id: policy.tenant_id,
            scope_ref,
            tenant_policy_record_ref: policy_record.record_id.clone(),
            tenant_policy_hash: policy_record.policy_hash.clone(),
            production_readiness_ref: expected_production_readiness_ref,
            production_readiness_evidence_hash: expected_production_readiness_evidence_hash,
            redaction_profile_ref,
            audit_export_refs,
            p1_execution_bundle_refs,
            event_refs,
            evidence_refs,
            contains_secret_material: false,
            bundle_hash,
            generated_by,
            generated_at: Utc::now(),
        })
    }

    pub fn verify_compliance_export_delivery(
        bundle: &ComplianceExportBundle,
        evidence: &ComplianceExportDeliveryEvidence,
    ) -> ComplianceExportDeliveryDecision {
        Self::verify_compliance_export_delivery_inner(bundle, evidence, None)
    }

    pub fn verify_compliance_export_delivery_with_adapter_decision(
        bundle: &ComplianceExportBundle,
        evidence: &ComplianceExportDeliveryEvidence,
        adapter_decision: &ProductionAdapterVerificationDecision,
    ) -> ComplianceExportDeliveryDecision {
        Self::verify_compliance_export_delivery_inner(bundle, evidence, Some(adapter_decision))
    }

    fn verify_compliance_export_delivery_inner(
        bundle: &ComplianceExportBundle,
        evidence: &ComplianceExportDeliveryEvidence,
        adapter_decision: Option<&ProductionAdapterVerificationDecision>,
    ) -> ComplianceExportDeliveryDecision {
        let mut reasons = Vec::new();
        if validate_compliance_export_bundle_record(bundle).is_err() {
            reasons
                .push("compliance export bundle record failed hash or evidence validation".into());
        }
        let mut evidence_refs = vec![
            bundle.bundle_id.clone(),
            bundle.bundle_hash.clone(),
            bundle.tenant_policy_record_ref.clone(),
            bundle.tenant_policy_hash.clone(),
            evidence.evidence_id.clone(),
            evidence.delivery_ref.clone(),
            evidence.storage_provider_ref.clone(),
            evidence.attestation_ref.clone(),
            evidence.receipt_ref.clone(),
            evidence.retention_policy_ref.clone(),
        ];
        if let Some(adapter_decision_ref) = &evidence.adapter_decision_ref {
            evidence_refs.push(adapter_decision_ref.clone());
        }
        if let Some(production_readiness_ref) = &bundle.production_readiness_ref {
            evidence_refs.push(production_readiness_ref.clone());
        }
        if let Some(production_readiness_evidence_hash) = &bundle.production_readiness_evidence_hash
        {
            evidence_refs.push(production_readiness_evidence_hash.clone());
        }

        if bundle.tenant_id != evidence.tenant_id {
            reasons
                .push("compliance bundle and delivery evidence belong to different tenants".into());
        }
        if bundle.bundle_id != evidence.bundle_id || bundle.bundle_hash != evidence.bundle_hash {
            reasons.push("delivery evidence is not bound to the compliance bundle hash".into());
        }
        if bundle.contains_secret_material {
            reasons.push("compliance export bundle contains secret material".into());
        }
        match (
            &bundle.production_readiness_ref,
            &bundle.production_readiness_evidence_hash,
        ) {
            (Some(readiness_ref), Some(readiness_hash)) => {
                if !bundle.evidence_refs.contains(readiness_ref)
                    || !bundle.evidence_refs.contains(readiness_hash)
                {
                    reasons.push(
                        "compliance bundle readiness refs are not bound to bundle evidence".into(),
                    );
                }
            }
            (None, None) => {}
            _ => reasons.push(
                "compliance bundle readiness ref and evidence hash must both be present or absent"
                    .into(),
            ),
        }
        if let Some(adapter_decision) = adapter_decision {
            if adapter_decision.tenant_id != bundle.tenant_id {
                reasons.push(
                    "compliance bundle and export adapter decision belong to different tenants"
                        .into(),
                );
            }
            if adapter_decision.decision != ProductionAdapterVerificationKind::Verified {
                reasons.push("compliance export adapter decision must be verified".into());
            }
            if adapter_decision.kind != ProductionAdapterKind::ComplianceAuditExport {
                reasons.push("adapter decision must be for compliance audit export".into());
            }
            if adapter_decision.provider_ref != evidence.storage_provider_ref {
                reasons.push("compliance export adapter provider does not match evidence".into());
            }
            if evidence.adapter_decision_ref.as_deref()
                != Some(adapter_decision.decision_id.as_str())
            {
                reasons.push("delivery evidence is not bound to the adapter decision".into());
            }
            evidence_refs.push(adapter_decision.decision_id.clone());
            evidence_refs.extend(adapter_decision.evidence_refs.clone());
        }
        if evidence.delivered_at >= evidence.expires_at || evidence.expires_at <= Utc::now() {
            reasons.push("compliance export delivery evidence is expired or invalid".into());
        }
        if [
            evidence.evidence_id.as_str(),
            evidence.delivery_ref.as_str(),
            evidence.storage_provider_ref.as_str(),
            evidence.attestation_ref.as_str(),
            evidence.receipt_ref.as_str(),
            evidence.retention_policy_ref.as_str(),
        ]
        .iter()
        .any(|value| is_placeholder_ref(value))
            || evidence
                .adapter_decision_ref
                .as_deref()
                .is_some_and(is_placeholder_ref)
        {
            reasons.push("compliance export delivery evidence contains placeholder refs".into());
        }

        evidence_refs.sort();
        evidence_refs.dedup();
        reasons.sort();
        reasons.dedup();

        let decision = if reasons.is_empty() {
            reasons.push("compliance export delivery evidence is verified".into());
            ComplianceExportDeliveryDecisionKind::Verified
        } else {
            ComplianceExportDeliveryDecisionKind::Rejected
        };

        ComplianceExportDeliveryDecision {
            decision_id: stable_id(
                "compliance_export_delivery",
                &(
                    bundle.tenant_id.as_str(),
                    bundle.bundle_id.as_str(),
                    bundle.bundle_hash.as_str(),
                    bundle.tenant_policy_hash.as_str(),
                    &bundle.production_readiness_evidence_hash,
                    evidence.evidence_id.as_str(),
                    evidence.delivery_ref.as_str(),
                    &evidence.adapter_decision_ref,
                    &decision,
                    &evidence_refs,
                ),
            ),
            tenant_id: bundle.tenant_id.clone(),
            bundle_id: bundle.bundle_id.clone(),
            bundle_hash: bundle.bundle_hash.clone(),
            tenant_policy_hash: bundle.tenant_policy_hash.clone(),
            production_readiness_evidence_hash: bundle.production_readiness_evidence_hash.clone(),
            delivery_evidence_ref: evidence.evidence_id.clone(),
            delivery_ref: evidence.delivery_ref.clone(),
            storage_provider_ref: evidence.storage_provider_ref.clone(),
            adapter_decision_ref: evidence.adapter_decision_ref.clone(),
            decision,
            reasons,
            evidence_refs,
            verified_at: Utc::now(),
            expires_at: evidence.expires_at,
        }
    }

    pub fn verify_production_adapter_evidence(
        evidence: &ProductionAdapterEvidence,
    ) -> ProductionAdapterVerificationDecision {
        let mut reasons = Vec::new();
        let validation = validate_adapter_evidence(evidence);
        if let Err(error) = &validation {
            reasons.push(format!("adapter evidence failed validation: {error}"));
        }
        if evidence.generated_at >= evidence.expires_at {
            reasons.push("adapter evidence expiry must be after generation time".into());
        }
        if evidence.adapter_version.trim().is_empty() {
            reasons.push("adapter version is empty".into());
        }
        reasons.sort();
        reasons.dedup();

        let decision = if reasons.is_empty() {
            reasons.push("production adapter evidence is verified".into());
            ProductionAdapterVerificationKind::Verified
        } else {
            ProductionAdapterVerificationKind::Rejected
        };
        let mut evidence_refs = vec![
            evidence.evidence_id.clone(),
            evidence.attestation_ref.clone(),
            evidence.healthcheck_ref.clone(),
        ];
        if let Some(sandbox_profile_ref) = &evidence.sandbox_profile_ref {
            evidence_refs.push(sandbox_profile_ref.clone());
        }
        evidence_refs.sort();
        evidence_refs.dedup();

        ProductionAdapterVerificationDecision {
            decision_id: stable_id(
                "production_adapter_verification",
                &(
                    evidence.evidence_id.as_str(),
                    &evidence.kind,
                    evidence.adapter_ref.as_str(),
                    evidence.provider_ref.as_str(),
                    &decision,
                    &evidence_refs,
                ),
            ),
            tenant_id: evidence.tenant_id.clone(),
            evidence_id: evidence.evidence_id.clone(),
            kind: evidence.kind,
            adapter_ref: evidence.adapter_ref.clone(),
            provider_ref: evidence.provider_ref.clone(),
            decision,
            reasons,
            evidence_refs,
            verified_at: Utc::now(),
            expires_at: evidence.expires_at,
        }
    }

    pub fn verify_production_auth(
        hardening: &ProductionHardeningEvidence,
        adapter_decision: &ProductionAdapterVerificationDecision,
        evidence: &ProductionAuthEvidence,
    ) -> ProductionAuthDecision {
        let mut reasons = Vec::new();
        let mut evidence_refs = vec![
            adapter_decision.decision_id.clone(),
            evidence.evidence_id.clone(),
            evidence.auth_provider_ref.clone(),
            evidence.adapter_decision_ref.clone(),
            evidence.issuer_ref.clone(),
            evidence.jwks_ref.clone(),
            evidence.token_policy_ref.clone(),
            evidence.audience_ref.clone(),
            evidence.session_policy_ref.clone(),
            evidence.attestation_ref.clone(),
        ];
        evidence_refs.extend(hardening.evidence_refs.clone());
        evidence_refs.extend(adapter_decision.evidence_refs.clone());

        if hardening.tenant_id != evidence.tenant_id
            || hardening.tenant_id != adapter_decision.tenant_id
        {
            reasons.push(
                "production hardening, auth adapter decision, and auth evidence must share a tenant"
                    .into(),
            );
        }

        let hardening_auth_ref = hardening.auth_provider_ref.as_deref();
        if hardening_auth_ref.is_none_or(is_placeholder_ref) {
            reasons.push("production authentication provider is not configured".into());
        }
        if hardening_auth_ref != Some(evidence.auth_provider_ref.as_str()) {
            reasons.push("auth evidence does not match the hardening auth provider".into());
        }
        if adapter_decision.decision != ProductionAdapterVerificationKind::Verified {
            reasons.push("auth provider adapter decision must be verified".into());
        }
        if adapter_decision.kind != ProductionAdapterKind::AuthProvider {
            reasons.push("adapter decision must be for the production auth provider".into());
        }
        if adapter_decision.provider_ref != evidence.auth_provider_ref {
            reasons.push("auth adapter provider does not match auth evidence".into());
        }
        if evidence.adapter_decision_ref != adapter_decision.decision_id {
            reasons.push("auth evidence is not bound to the adapter decision".into());
        }
        if evidence.checked_at >= evidence.expires_at || evidence.expires_at <= Utc::now() {
            reasons.push("production auth evidence is expired or invalid".into());
        }
        if [
            evidence.evidence_id.as_str(),
            evidence.auth_provider_ref.as_str(),
            evidence.adapter_decision_ref.as_str(),
            evidence.issuer_ref.as_str(),
            evidence.jwks_ref.as_str(),
            evidence.token_policy_ref.as_str(),
            evidence.audience_ref.as_str(),
            evidence.session_policy_ref.as_str(),
            evidence.attestation_ref.as_str(),
        ]
        .iter()
        .any(|value| is_placeholder_ref(value))
        {
            reasons.push("production auth evidence contains placeholder refs".into());
        }

        evidence_refs.sort();
        evidence_refs.dedup();
        reasons.sort();
        reasons.dedup();

        let decision = if reasons.is_empty() {
            reasons.push("production auth evidence is verified".into());
            ProductionAuthDecisionKind::Verified
        } else {
            ProductionAuthDecisionKind::Rejected
        };

        ProductionAuthDecision {
            decision_id: stable_id(
                "production_auth",
                &(
                    hardening.tenant_id.as_str(),
                    evidence.auth_provider_ref.as_str(),
                    evidence.evidence_id.as_str(),
                    &decision,
                    &evidence_refs,
                ),
            ),
            tenant_id: hardening.tenant_id.clone(),
            auth_provider_ref: evidence.auth_provider_ref.clone(),
            decision,
            reasons,
            evidence_refs,
            verified_at: Utc::now(),
            expires_at: evidence.expires_at,
        }
    }

    pub fn verify_external_secret_manager(
        credential: &CredentialRef,
        hardening: &ProductionHardeningEvidence,
        adapter_decision: &ProductionAdapterVerificationDecision,
        evidence: &ExternalSecretManagerEvidence,
    ) -> ExternalSecretManagerDecision {
        let mut reasons = Vec::new();
        let mut evidence_refs = vec![
            credential.credential_id.clone(),
            credential.external_secret_ref.clone(),
            adapter_decision.decision_id.clone(),
            evidence.evidence_id.clone(),
            evidence.external_secret_ref.clone(),
            evidence.secret_manager_ref.clone(),
            evidence.adapter_decision_ref.clone(),
            evidence.key_encryption_key_ref.clone(),
            evidence.hsm_partition_ref.clone(),
            evidence.access_policy_ref.clone(),
            evidence.rotation_policy_ref.clone(),
            evidence.attestation_ref.clone(),
        ];
        evidence_refs.extend(hardening.evidence_refs.clone());
        evidence_refs.extend(adapter_decision.evidence_refs.clone());

        if credential.tenant_id != hardening.tenant_id
            || credential.tenant_id != evidence.tenant_id
            || credential.tenant_id != adapter_decision.tenant_id
        {
            reasons.push(
                "credential, hardening, secret-manager adapter decision, and evidence must share a tenant"
                    .into(),
            );
        }
        if evidence.credential_id != credential.credential_id
            || evidence.external_secret_ref != credential.external_secret_ref
        {
            reasons.push("secret-manager evidence is not bound to the credential reference".into());
        }
        let hardening_secret_manager_ref = hardening.secret_manager_ref.as_deref();
        if hardening_secret_manager_ref.is_none_or(is_placeholder_ref) {
            reasons.push("production secret manager is not configured".into());
        }
        if hardening_secret_manager_ref != Some(evidence.secret_manager_ref.as_str()) {
            reasons.push("secret-manager evidence does not match the hardening provider".into());
        }
        if credential.material_policy != SecretMaterialPolicy::ExecutorInjected {
            reasons.push("credential material policy must require executor injection".into());
        }
        if credential
            .rotation_ref
            .as_deref()
            .is_none_or(is_placeholder_ref)
        {
            reasons
                .push("credential rotation ref must be configured for production secrets".into());
        }
        let evidence_rotation_ref = evidence.rotation_policy_ref.as_str();
        let credential_rotation_matches = credential
            .rotation_ref
            .as_deref()
            .is_some_and(|rotation_ref| rotation_ref == evidence_rotation_ref);
        let hardening_rotation_matches = hardening
            .rotation_policy_ref
            .as_deref()
            .is_some_and(|rotation_ref| rotation_ref == evidence_rotation_ref);
        if !credential_rotation_matches && !hardening_rotation_matches {
            reasons
                .push("secret-manager evidence is not bound to configured rotation policy".into());
        }
        if adapter_decision.decision != ProductionAdapterVerificationKind::Verified {
            reasons.push("external secret-manager adapter decision must be verified".into());
        }
        if adapter_decision.kind != ProductionAdapterKind::ExternalSecretManager {
            reasons.push("adapter decision must be for the external secret manager".into());
        }
        if adapter_decision.provider_ref != evidence.secret_manager_ref {
            reasons.push("secret-manager adapter provider does not match evidence".into());
        }
        if evidence.adapter_decision_ref != adapter_decision.decision_id {
            reasons.push("secret-manager evidence is not bound to the adapter decision".into());
        }
        if evidence.checked_at >= evidence.expires_at || evidence.expires_at <= Utc::now() {
            reasons.push("external secret-manager evidence is expired or invalid".into());
        }
        if [
            evidence.evidence_id.as_str(),
            evidence.external_secret_ref.as_str(),
            evidence.secret_manager_ref.as_str(),
            evidence.adapter_decision_ref.as_str(),
            evidence.key_encryption_key_ref.as_str(),
            evidence.hsm_partition_ref.as_str(),
            evidence.access_policy_ref.as_str(),
            evidence.rotation_policy_ref.as_str(),
            evidence.attestation_ref.as_str(),
        ]
        .iter()
        .any(|value| is_placeholder_ref(value) || looks_like_raw_secret(value))
        {
            reasons.push(
                "external secret-manager evidence contains placeholder or raw-secret refs".into(),
            );
        }

        evidence_refs.sort();
        evidence_refs.dedup();
        reasons.sort();
        reasons.dedup();

        let decision = if reasons.is_empty() {
            reasons.push("external secret-manager evidence is verified".into());
            ExternalSecretManagerDecisionKind::Verified
        } else {
            ExternalSecretManagerDecisionKind::Rejected
        };

        ExternalSecretManagerDecision {
            decision_id: stable_id(
                "external_secret_manager",
                &(
                    credential.tenant_id.as_str(),
                    credential.credential_id.as_str(),
                    credential.external_secret_ref.as_str(),
                    evidence.secret_manager_ref.as_str(),
                    &decision,
                    &evidence_refs,
                ),
            ),
            tenant_id: credential.tenant_id.clone(),
            credential_id: credential.credential_id.clone(),
            external_secret_ref: credential.external_secret_ref.clone(),
            secret_manager_ref: evidence.secret_manager_ref.clone(),
            decision,
            reasons,
            evidence_refs,
            verified_at: Utc::now(),
            expires_at: evidence.expires_at,
        }
    }

    pub fn verify_cryptographic_verifier(
        hardening: &ProductionHardeningEvidence,
        signature_decision: &SignatureVerificationDecision,
        trust_root_record: &TrustRootRecord,
        adapter_decision: &ProductionAdapterVerificationDecision,
        evidence: &CryptographicVerifierEvidence,
    ) -> CryptographicVerifierDecision {
        let mut reasons = Vec::new();
        let mut evidence_refs = vec![
            signature_decision.decision_id.clone(),
            trust_root_record.record_id.clone(),
            trust_root_record.trust_root_hash.clone(),
            adapter_decision.decision_id.clone(),
            evidence.evidence_id.clone(),
            evidence.signature_decision_ref.clone(),
            evidence.trust_root_record_ref.clone(),
            evidence.trust_root_hash.clone(),
            evidence.cryptographic_verifier_ref.clone(),
            evidence.adapter_decision_ref.clone(),
            evidence.verifier_policy_ref.clone(),
            evidence.transparency_log_ref.clone(),
            evidence.algorithm_suite_ref.clone(),
            evidence.attestation_ref.clone(),
        ];
        evidence_refs.extend(hardening.evidence_refs.clone());
        evidence_refs.extend(signature_decision.evidence_refs.clone());
        evidence_refs.extend(trust_root_record.evidence_refs.clone());
        evidence_refs.extend(adapter_decision.evidence_refs.clone());

        if hardening.tenant_id != evidence.tenant_id
            || hardening.tenant_id != signature_decision.tenant_id
            || hardening.tenant_id != trust_root_record.tenant_id
            || hardening.tenant_id != adapter_decision.tenant_id
        {
            reasons.push(
                "hardening, signature decision, trust-root record, adapter decision, and crypto evidence must share a tenant"
                    .into(),
            );
        }
        if Self::load_trust_root(trust_root_record).is_err() {
            reasons.push("trust-root record failed local hash validation".into());
        }
        if evidence.signature_decision_ref != signature_decision.decision_id {
            reasons.push("crypto verifier evidence is not bound to the signature decision".into());
        }
        if evidence.trust_root_record_ref != trust_root_record.record_id
            || evidence.trust_root_hash != trust_root_record.trust_root_hash
        {
            reasons.push("crypto verifier evidence is not bound to the trust-root record".into());
        }
        if signature_decision.decision != SignatureVerificationKind::Verified
            || !signature_decision.can_issue_high_risk_ticket
        {
            reasons
                .push("signature decision must be verified for high-risk ticket issuance".into());
        }
        if signature_decision.trust_root_ref.as_deref() != Some(trust_root_record.root_id.as_str())
        {
            reasons.push("signature decision does not reference the trust-root record root".into());
        }

        let hardening_verifier_ref = hardening.cryptographic_verifier_ref.as_deref();
        if hardening_verifier_ref.is_none_or(is_placeholder_ref) {
            reasons.push("production cryptographic verifier is not configured".into());
        }
        if hardening_verifier_ref != Some(evidence.cryptographic_verifier_ref.as_str()) {
            reasons.push("crypto verifier evidence does not match the hardening verifier".into());
        }
        if adapter_decision.decision != ProductionAdapterVerificationKind::Verified {
            reasons.push("cryptographic verifier adapter decision must be verified".into());
        }
        if adapter_decision.kind != ProductionAdapterKind::CryptographicVerifier {
            reasons.push("adapter decision must be for the cryptographic verifier".into());
        }
        if adapter_decision.provider_ref != evidence.cryptographic_verifier_ref {
            reasons.push("cryptographic verifier adapter provider does not match evidence".into());
        }
        if evidence.adapter_decision_ref != adapter_decision.decision_id {
            reasons.push("crypto verifier evidence is not bound to the adapter decision".into());
        }
        if evidence.checked_at >= evidence.expires_at || evidence.expires_at <= Utc::now() {
            reasons.push("cryptographic verifier evidence is expired or invalid".into());
        }
        if [
            evidence.evidence_id.as_str(),
            evidence.signature_decision_ref.as_str(),
            evidence.trust_root_record_ref.as_str(),
            evidence.trust_root_hash.as_str(),
            evidence.cryptographic_verifier_ref.as_str(),
            evidence.adapter_decision_ref.as_str(),
            evidence.verifier_policy_ref.as_str(),
            evidence.transparency_log_ref.as_str(),
            evidence.algorithm_suite_ref.as_str(),
            evidence.attestation_ref.as_str(),
        ]
        .iter()
        .any(|value| is_placeholder_ref(value))
        {
            reasons.push("cryptographic verifier evidence contains placeholder refs".into());
        }

        evidence_refs.sort();
        evidence_refs.dedup();
        reasons.sort();
        reasons.dedup();

        let decision = if reasons.is_empty() {
            reasons.push("cryptographic verifier evidence is verified".into());
            CryptographicVerifierDecisionKind::Verified
        } else {
            CryptographicVerifierDecisionKind::Rejected
        };

        CryptographicVerifierDecision {
            decision_id: stable_id(
                "cryptographic_verifier",
                &(
                    hardening.tenant_id.as_str(),
                    signature_decision.decision_id.as_str(),
                    trust_root_record.record_id.as_str(),
                    evidence.cryptographic_verifier_ref.as_str(),
                    &decision,
                    &evidence_refs,
                ),
            ),
            tenant_id: hardening.tenant_id.clone(),
            signature_decision_ref: signature_decision.decision_id.clone(),
            trust_root_record_ref: trust_root_record.record_id.clone(),
            cryptographic_verifier_ref: evidence.cryptographic_verifier_ref.clone(),
            decision,
            reasons,
            evidence_refs,
            verified_at: Utc::now(),
            expires_at: evidence.expires_at,
        }
    }

    pub fn verify_hardened_sandbox(
        hardening: &ProductionHardeningEvidence,
        adapter_decision: &ProductionAdapterVerificationDecision,
        evidence: &HardenedSandboxEvidence,
    ) -> HardenedSandboxDecision {
        let mut reasons = Vec::new();
        let mut evidence_refs = vec![
            adapter_decision.decision_id.clone(),
            evidence.evidence_id.clone(),
            evidence.hardened_sandbox_profile_ref.clone(),
            evidence.adapter_decision_ref.clone(),
            evidence.isolation_policy_ref.clone(),
            evidence.filesystem_policy_ref.clone(),
            evidence.network_policy_ref.clone(),
            evidence.syscall_policy_ref.clone(),
            evidence.resource_policy_ref.clone(),
            evidence.attestation_ref.clone(),
        ];
        evidence_refs.extend(hardening.evidence_refs.clone());
        evidence_refs.extend(adapter_decision.evidence_refs.clone());

        if hardening.tenant_id != evidence.tenant_id
            || hardening.tenant_id != adapter_decision.tenant_id
        {
            reasons.push(
                "production hardening, sandbox adapter decision, and sandbox evidence must share a tenant"
                    .into(),
            );
        }

        let hardening_sandbox_ref = hardening.hardened_sandbox_profile_ref.as_deref();
        if hardening_sandbox_ref.is_none_or(is_placeholder_ref) {
            reasons.push("production OS/container sandbox profile is not configured".into());
        }
        if hardening_sandbox_ref != Some(evidence.hardened_sandbox_profile_ref.as_str()) {
            reasons.push("sandbox evidence does not match the hardening sandbox profile".into());
        }
        if adapter_decision.decision != ProductionAdapterVerificationKind::Verified {
            reasons.push("hardened sandbox adapter decision must be verified".into());
        }
        if adapter_decision.kind != ProductionAdapterKind::HardenedSandbox {
            reasons.push("adapter decision must be for the hardened sandbox".into());
        }
        if adapter_decision.provider_ref != evidence.hardened_sandbox_profile_ref {
            reasons.push("hardened sandbox adapter provider does not match evidence".into());
        }
        if !(adapter_decision
            .evidence_refs
            .iter()
            .any(|reference| reference == &evidence.hardened_sandbox_profile_ref)
            || adapter_decision.provider_ref == evidence.hardened_sandbox_profile_ref)
        {
            reasons.push("hardened sandbox adapter decision is not profile-bound".into());
        }
        if evidence.adapter_decision_ref != adapter_decision.decision_id {
            reasons.push("sandbox evidence is not bound to the adapter decision".into());
        }
        if evidence.checked_at >= evidence.expires_at || evidence.expires_at <= Utc::now() {
            reasons.push("hardened sandbox evidence is expired or invalid".into());
        }
        if [
            evidence.evidence_id.as_str(),
            evidence.hardened_sandbox_profile_ref.as_str(),
            evidence.adapter_decision_ref.as_str(),
            evidence.isolation_policy_ref.as_str(),
            evidence.filesystem_policy_ref.as_str(),
            evidence.network_policy_ref.as_str(),
            evidence.syscall_policy_ref.as_str(),
            evidence.resource_policy_ref.as_str(),
            evidence.attestation_ref.as_str(),
        ]
        .iter()
        .any(|value| is_placeholder_ref(value))
        {
            reasons.push("hardened sandbox evidence contains placeholder refs".into());
        }

        evidence_refs.sort();
        evidence_refs.dedup();
        reasons.sort();
        reasons.dedup();

        let decision = if reasons.is_empty() {
            reasons.push("hardened sandbox evidence is verified".into());
            HardenedSandboxDecisionKind::Verified
        } else {
            HardenedSandboxDecisionKind::Rejected
        };

        HardenedSandboxDecision {
            decision_id: stable_id(
                "hardened_sandbox",
                &(
                    hardening.tenant_id.as_str(),
                    evidence.hardened_sandbox_profile_ref.as_str(),
                    evidence.evidence_id.as_str(),
                    &decision,
                    &evidence_refs,
                ),
            ),
            tenant_id: hardening.tenant_id.clone(),
            hardened_sandbox_profile_ref: evidence.hardened_sandbox_profile_ref.clone(),
            decision,
            reasons,
            evidence_refs,
            verified_at: Utc::now(),
            expires_at: evidence.expires_at,
        }
    }

    pub fn verify_rotation_enforcement(
        credential: &CredentialRef,
        hardening: &ProductionHardeningEvidence,
    ) -> RotationEnforcementDecision {
        Self::verify_rotation_enforcement_inner(credential, hardening, None)
    }

    pub fn verify_rotation_enforcement_with_adapter_decision(
        credential: &CredentialRef,
        hardening: &ProductionHardeningEvidence,
        adapter_decision: &ProductionAdapterVerificationDecision,
    ) -> RotationEnforcementDecision {
        Self::verify_rotation_enforcement_inner(credential, hardening, Some(adapter_decision))
    }

    fn verify_rotation_enforcement_inner(
        credential: &CredentialRef,
        hardening: &ProductionHardeningEvidence,
        adapter_decision: Option<&ProductionAdapterVerificationDecision>,
    ) -> RotationEnforcementDecision {
        let mut reasons = Vec::new();
        let mut evidence_refs = vec![credential.credential_id.clone()];

        let tenant_mismatch = credential.tenant_id != hardening.tenant_id;
        if tenant_mismatch {
            reasons.push(
                "credential and production hardening evidence belong to different tenants".into(),
            );
        }
        if credential
            .rotation_ref
            .as_deref()
            .is_none_or(is_placeholder_ref)
        {
            reasons.push(format!(
                "credential {} is missing enforceable rotation metadata",
                credential.credential_id
            ));
        }
        if hardening
            .rotation_policy_ref
            .as_deref()
            .is_none_or(is_placeholder_ref)
        {
            reasons.push("production rotation enforcement policy is not configured".into());
        }
        if hardening.evidence_refs.is_empty() {
            reasons.push("production hardening evidence refs are missing".into());
        }
        if let Some(adapter_decision) = adapter_decision {
            if adapter_decision.tenant_id != credential.tenant_id {
                reasons.push(
                    "credential and rotation adapter decision belong to different tenants".into(),
                );
            }
            if adapter_decision.decision != ProductionAdapterVerificationKind::Verified {
                reasons.push("rotation enforcement adapter decision must be verified".into());
            }
            if adapter_decision.kind != ProductionAdapterKind::RotationEnforcement {
                reasons.push("adapter decision must be for rotation enforcement".into());
            }
            if hardening.rotation_policy_ref.as_deref()
                != Some(adapter_decision.provider_ref.as_str())
            {
                reasons.push(
                    "rotation enforcement adapter provider does not match the hardening policy"
                        .into(),
                );
            }
            evidence_refs.push(adapter_decision.decision_id.clone());
            evidence_refs.extend(adapter_decision.evidence_refs.clone());
        }
        evidence_refs.extend(hardening.evidence_refs.clone());
        if let Some(rotation_ref) = &credential.rotation_ref {
            evidence_refs.push(rotation_ref.clone());
        }
        if let Some(rotation_policy_ref) = &hardening.rotation_policy_ref {
            evidence_refs.push(rotation_policy_ref.clone());
        }
        evidence_refs.sort();
        evidence_refs.dedup();
        reasons.sort();
        reasons.dedup();

        let decision = if reasons.is_empty() {
            reasons.push("credential rotation enforcement is verified".into());
            RotationEnforcementDecisionKind::Verified
        } else {
            RotationEnforcementDecisionKind::Rejected
        };

        RotationEnforcementDecision {
            decision_id: stable_id(
                "rotation_enforcement",
                &(
                    credential.tenant_id.as_str(),
                    credential.credential_id.as_str(),
                    &credential.rotation_ref,
                    &hardening.rotation_policy_ref,
                    &adapter_decision.map(|decision| decision.decision_id.as_str()),
                    &decision,
                    &evidence_refs,
                ),
            ),
            tenant_id: credential.tenant_id.clone(),
            credential_id: credential.credential_id.clone(),
            rotation_ref: credential.rotation_ref.clone(),
            rotation_policy_ref: hardening.rotation_policy_ref.clone(),
            adapter_decision_ref: adapter_decision.map(|decision| decision.decision_id.clone()),
            decision,
            reasons,
            evidence_refs,
            verified_at: Utc::now(),
            expires_at: credential
                .expires_at
                .unwrap_or_else(|| Utc::now() + chrono::Duration::hours(1)),
        }
    }

    pub fn verify_secret_injection(
        credential: &CredentialRef,
        secret_use: &SecretUseDecision,
        hardening: &ProductionHardeningEvidence,
        adapter_decision: &ProductionAdapterVerificationDecision,
        evidence: &SecretInjectionEvidence,
    ) -> SecretInjectionDecision {
        let mut reasons = Vec::new();
        let mut evidence_refs = vec![
            credential.credential_id.clone(),
            secret_use.decision_id.clone(),
            adapter_decision.decision_id.clone(),
            evidence.evidence_id.clone(),
            evidence.injection_receipt_ref.clone(),
            evidence.executor_ref.clone(),
            evidence.run_id.clone(),
            evidence.attestation_ref.clone(),
        ];
        evidence_refs.extend(secret_use.evidence_refs.clone());
        evidence_refs.extend(hardening.evidence_refs.clone());
        evidence_refs.extend(adapter_decision.evidence_refs.clone());

        if credential.tenant_id != evidence.tenant_id
            || credential.tenant_id != hardening.tenant_id
            || credential.tenant_id != adapter_decision.tenant_id
        {
            reasons.push(
                "credential, hardening, adapter decision, and injection evidence must share a tenant"
                    .into(),
            );
        }
        if secret_use.credential_id != credential.credential_id
            || evidence.credential_id != credential.credential_id
        {
            reasons.push("secret injection evidence is not bound to the credential".into());
        }
        if evidence.secret_use_decision_id != secret_use.decision_id {
            reasons
                .push("secret injection evidence is not bound to the secret-use decision".into());
        }
        if secret_use.decision != SecretUseDecisionKind::Allowed {
            reasons.push("secret-use decision must be allowed before injection".into());
        }
        if secret_use.raw_secret_visible_to_model
            || secret_use.raw_secret_visible_to_logs
            || secret_use.raw_secret_persisted
        {
            reasons.push("secret-use decision exposes or persists raw secret material".into());
        }
        if credential.material_policy != SecretMaterialPolicy::ExecutorInjected {
            reasons.push("credential material policy must require executor injection".into());
        }

        let hardening_injection_ref = hardening.secret_injection_profile_ref.as_deref();
        let hardening_sandbox_ref = hardening.hardened_sandbox_profile_ref.as_deref();
        if hardening_injection_ref.is_none_or(is_placeholder_ref) {
            reasons.push("production secret injection profile is not configured".into());
        }
        if hardening_sandbox_ref.is_none_or(is_placeholder_ref) {
            reasons.push("production hardened sandbox profile is not configured".into());
        }
        if hardening_injection_ref != Some(evidence.secret_injection_profile_ref.as_str()) {
            reasons
                .push("injection evidence does not match the hardening injection profile".into());
        }
        if hardening_sandbox_ref != Some(evidence.hardened_sandbox_profile_ref.as_str()) {
            reasons.push("injection evidence does not match the hardening sandbox profile".into());
        }

        if adapter_decision.decision != ProductionAdapterVerificationKind::Verified {
            reasons.push("secret injection adapter decision must be verified".into());
        }
        if adapter_decision.kind != ProductionAdapterKind::SecretInjection {
            reasons.push("adapter decision must be for the secret injection adapter".into());
        }
        if adapter_decision.provider_ref != evidence.secret_injection_profile_ref {
            reasons.push("adapter decision provider does not match injection profile".into());
        }
        if evidence.adapter_decision_ref != adapter_decision.decision_id {
            reasons.push("injection evidence is not bound to the adapter decision".into());
        }
        if evidence.delivered_at >= evidence.expires_at || evidence.expires_at <= Utc::now() {
            reasons.push("secret injection evidence is expired or invalid".into());
        }
        if [
            evidence.evidence_id.as_str(),
            evidence.secret_injection_profile_ref.as_str(),
            evidence.hardened_sandbox_profile_ref.as_str(),
            evidence.adapter_decision_ref.as_str(),
            evidence.injection_receipt_ref.as_str(),
            evidence.executor_ref.as_str(),
            evidence.run_id.as_str(),
            evidence.attestation_ref.as_str(),
        ]
        .iter()
        .any(|value| is_placeholder_ref(value))
        {
            reasons.push("secret injection evidence contains placeholder refs".into());
        }

        evidence_refs.push(evidence.secret_injection_profile_ref.clone());
        evidence_refs.push(evidence.hardened_sandbox_profile_ref.clone());
        evidence_refs.push(evidence.adapter_decision_ref.clone());
        evidence_refs.sort();
        evidence_refs.dedup();
        reasons.sort();
        reasons.dedup();

        let decision = if reasons.is_empty() {
            reasons.push("secret injection evidence is verified".into());
            SecretInjectionDecisionKind::Verified
        } else {
            SecretInjectionDecisionKind::Rejected
        };

        SecretInjectionDecision {
            decision_id: stable_id(
                "secret_injection",
                &(
                    credential.tenant_id.as_str(),
                    credential.credential_id.as_str(),
                    secret_use.decision_id.as_str(),
                    evidence.evidence_id.as_str(),
                    evidence.injection_receipt_ref.as_str(),
                    &decision,
                    &evidence_refs,
                ),
            ),
            tenant_id: credential.tenant_id.clone(),
            credential_id: credential.credential_id.clone(),
            secret_use_decision_id: secret_use.decision_id.clone(),
            secret_injection_profile_ref: evidence.secret_injection_profile_ref.clone(),
            hardened_sandbox_profile_ref: evidence.hardened_sandbox_profile_ref.clone(),
            decision,
            reasons,
            evidence_refs,
            verified_at: Utc::now(),
            expires_at: evidence.expires_at,
        }
    }

    pub fn evaluate_production_readiness(
        policy: &TenantPolicyPack,
        credentials: &[CredentialRef],
        signature_decisions: &[SignatureVerificationDecision],
        hardening: &ProductionHardeningEvidence,
        adapter_evidence: &[ProductionAdapterEvidence],
    ) -> Result<ProductionReadinessDecision, VaultError> {
        let adapter_decisions = adapter_evidence
            .iter()
            .map(Self::verify_production_adapter_evidence)
            .collect::<Vec<_>>();
        let rotation_decisions = credentials
            .iter()
            .map(|credential| Self::verify_rotation_enforcement(credential, hardening))
            .collect::<Vec<_>>();
        Self::evaluate_production_readiness_with_decisions(
            policy,
            credentials,
            signature_decisions,
            hardening,
            adapter_evidence,
            &adapter_decisions,
            &rotation_decisions,
        )
    }

    pub fn evaluate_production_readiness_with_adapter_decisions(
        policy: &TenantPolicyPack,
        credentials: &[CredentialRef],
        signature_decisions: &[SignatureVerificationDecision],
        hardening: &ProductionHardeningEvidence,
        adapter_evidence: &[ProductionAdapterEvidence],
        adapter_decisions: &[ProductionAdapterVerificationDecision],
    ) -> Result<ProductionReadinessDecision, VaultError> {
        let rotation_decisions = credentials
            .iter()
            .map(|credential| Self::verify_rotation_enforcement(credential, hardening))
            .collect::<Vec<_>>();
        Self::evaluate_production_readiness_with_decisions(
            policy,
            credentials,
            signature_decisions,
            hardening,
            adapter_evidence,
            adapter_decisions,
            &rotation_decisions,
        )
    }

    pub fn evaluate_production_readiness_with_decisions(
        policy: &TenantPolicyPack,
        credentials: &[CredentialRef],
        signature_decisions: &[SignatureVerificationDecision],
        hardening: &ProductionHardeningEvidence,
        adapter_evidence: &[ProductionAdapterEvidence],
        adapter_decisions: &[ProductionAdapterVerificationDecision],
        rotation_decisions: &[RotationEnforcementDecision],
    ) -> Result<ProductionReadinessDecision, VaultError> {
        Self::evaluate_production_readiness_inner(
            policy,
            credentials,
            signature_decisions,
            hardening,
            adapter_evidence,
            adapter_decisions,
            rotation_decisions,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_production_readiness_with_hardened_sandbox_decisions(
        policy: &TenantPolicyPack,
        credentials: &[CredentialRef],
        signature_decisions: &[SignatureVerificationDecision],
        hardening: &ProductionHardeningEvidence,
        adapter_evidence: &[ProductionAdapterEvidence],
        adapter_decisions: &[ProductionAdapterVerificationDecision],
        rotation_decisions: &[RotationEnforcementDecision],
        sandbox_decisions: &[HardenedSandboxDecision],
    ) -> Result<ProductionReadinessDecision, VaultError> {
        Self::evaluate_production_readiness_inner(
            policy,
            credentials,
            signature_decisions,
            hardening,
            adapter_evidence,
            adapter_decisions,
            rotation_decisions,
            Some(sandbox_decisions),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_production_readiness_with_hardening_decision_set(
        policy: &TenantPolicyPack,
        credentials: &[CredentialRef],
        signature_decisions: &[SignatureVerificationDecision],
        hardening: &ProductionHardeningEvidence,
        adapter_evidence: &[ProductionAdapterEvidence],
        adapter_decisions: &[ProductionAdapterVerificationDecision],
        decision_set: ProductionHardeningDecisionSet<'_>,
    ) -> Result<ProductionReadinessDecision, VaultError> {
        Self::validate_production_hardening_decision_set(
            policy,
            credentials,
            signature_decisions,
            hardening,
            adapter_decisions,
            &decision_set,
        )?;

        let mut readiness = Self::evaluate_production_readiness_inner(
            policy,
            credentials,
            signature_decisions,
            hardening,
            adapter_evidence,
            adapter_decisions,
            decision_set.rotation_decisions,
            Some(decision_set.hardened_sandbox_decisions),
        )?;

        extend_readiness_evidence_refs_from_decision_set(
            &mut readiness.evidence_refs,
            &decision_set,
        );
        readiness.decision_id = stable_id(
            "production_readiness",
            &(
                policy.pack_id.as_str(),
                &readiness.decision,
                &readiness.missing_gates,
                &readiness.evidence_refs,
            ),
        );

        Ok(readiness)
    }

    fn validate_production_hardening_decision_set(
        policy: &TenantPolicyPack,
        credentials: &[CredentialRef],
        signature_decisions: &[SignatureVerificationDecision],
        hardening: &ProductionHardeningEvidence,
        adapter_decisions: &[ProductionAdapterVerificationDecision],
        decision_set: &ProductionHardeningDecisionSet<'_>,
    ) -> Result<(), VaultError> {
        require_tenant_match_for_hardening_decision_set(policy, decision_set)?;
        require_verified_production_auth_decision(hardening, decision_set.auth_decision)?;
        require_verified_external_secret_manager_decisions(
            credentials,
            hardening,
            adapter_decisions,
            decision_set.external_secret_manager_decisions,
        )?;
        require_verified_cryptographic_verifier_decisions(
            signature_decisions,
            hardening,
            adapter_decisions,
            decision_set.cryptographic_verifier_decisions,
        )?;
        require_verified_hardened_sandbox_decision(
            hardening,
            decision_set.hardened_sandbox_decisions,
        )?;
        for decision in decision_set.rotation_decisions {
            validate_rotation_decision(decision, adapter_decisions)?;
        }
        require_verified_rotation_decisions(
            credentials,
            hardening,
            decision_set.rotation_decisions,
        )?;
        require_verified_secret_injection_decisions(
            credentials,
            hardening,
            adapter_decisions,
            decision_set.secret_injection_decisions,
        )?;
        require_verified_compliance_export_delivery_decisions(
            hardening,
            adapter_decisions,
            decision_set.compliance_export_delivery_decisions,
        )?;
        require_verified_trust_root_storage_decisions(
            signature_decisions,
            decision_set.trust_root_storage_decisions,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn evaluate_production_readiness_inner(
        policy: &TenantPolicyPack,
        credentials: &[CredentialRef],
        signature_decisions: &[SignatureVerificationDecision],
        hardening: &ProductionHardeningEvidence,
        adapter_evidence: &[ProductionAdapterEvidence],
        adapter_decisions: &[ProductionAdapterVerificationDecision],
        rotation_decisions: &[RotationEnforcementDecision],
        sandbox_decisions: Option<&[HardenedSandboxDecision]>,
    ) -> Result<ProductionReadinessDecision, VaultError> {
        if hardening.evidence_refs.is_empty() {
            return Err(VaultError::MissingEvidence);
        }
        if policy.tenant_id != hardening.tenant_id
            || credentials
                .iter()
                .any(|credential| credential.tenant_id != policy.tenant_id)
            || signature_decisions
                .iter()
                .any(|decision| decision.tenant_id != policy.tenant_id)
            || adapter_evidence
                .iter()
                .any(|evidence| evidence.tenant_id != policy.tenant_id)
            || adapter_decisions
                .iter()
                .any(|decision| decision.tenant_id != policy.tenant_id)
            || rotation_decisions
                .iter()
                .any(|decision| decision.tenant_id != policy.tenant_id)
            || sandbox_decisions.is_some_and(|decisions| {
                decisions
                    .iter()
                    .any(|decision| decision.tenant_id != policy.tenant_id)
            })
        {
            return Err(VaultError::TenantMismatch);
        }

        for credential in credentials {
            validate_credential_ref(credential)?;
        }
        for evidence in adapter_evidence {
            validate_adapter_evidence(evidence)?;
        }
        for decision in adapter_decisions {
            validate_adapter_decision(decision)?;
        }
        require_verified_adapter_decisions(adapter_evidence, adapter_decisions)?;
        let mut missing_gates = Vec::new();
        let mut reasons = Vec::new();

        require_production_ref_and_adapter(
            &hardening.auth_provider_ref,
            adapter_evidence,
            ProductionAdapterKind::AuthProvider,
            ProductionReadinessGate::ProductionAuth,
            "production authentication provider is not configured",
            &mut missing_gates,
            &mut reasons,
        );
        require_production_ref_and_adapter(
            &hardening.secret_manager_ref,
            adapter_evidence,
            ProductionAdapterKind::ExternalSecretManager,
            ProductionReadinessGate::ExternalSecretManager,
            "real KMS/HSM/secret-manager reference is not configured",
            &mut missing_gates,
            &mut reasons,
        );
        require_production_ref_and_adapter(
            &hardening.cryptographic_verifier_ref,
            adapter_evidence,
            ProductionAdapterKind::CryptographicVerifier,
            ProductionReadinessGate::CryptographicVerifier,
            "production cryptographic verifier is not configured",
            &mut missing_gates,
            &mut reasons,
        );
        require_production_ref_and_adapter(
            &hardening.hardened_sandbox_profile_ref,
            adapter_evidence,
            ProductionAdapterKind::HardenedSandbox,
            ProductionReadinessGate::HardenedSandbox,
            "production OS/container sandbox profile is not configured",
            &mut missing_gates,
            &mut reasons,
        );
        require_production_ref_and_adapter(
            &hardening.secret_injection_profile_ref,
            adapter_evidence,
            ProductionAdapterKind::SecretInjection,
            ProductionReadinessGate::SecretInjection,
            "secret injection profile for hardened sandbox execution is not configured",
            &mut missing_gates,
            &mut reasons,
        );
        require_production_ref_and_adapter(
            &hardening.rotation_policy_ref,
            adapter_evidence,
            ProductionAdapterKind::RotationEnforcement,
            ProductionReadinessGate::RotationEnforcement,
            "credential rotation enforcement policy is not configured",
            &mut missing_gates,
            &mut reasons,
        );
        require_production_ref_and_adapter(
            &hardening.compliance_export_profile_ref,
            adapter_evidence,
            ProductionAdapterKind::ComplianceAuditExport,
            ProductionReadinessGate::ComplianceAuditExport,
            "compliance audit export bundle profile is not configured",
            &mut missing_gates,
            &mut reasons,
        );

        if !policy.high_risk_requires_quorum || policy.quorum_approvers < 2 {
            missing_gates.push(ProductionReadinessGate::TenantPolicy);
            reasons
                .push("tenant policy must require quorum for high-risk production actions".into());
        }
        if !policy.audit_export_required {
            missing_gates.push(ProductionReadinessGate::ComplianceAuditExport);
            reasons.push("tenant policy must require audit export for production actions".into());
        }
        if credentials.is_empty() {
            missing_gates.push(ProductionReadinessGate::ExternalSecretManager);
            reasons.push("no credential references were supplied for production readiness".into());
        }

        let now = Utc::now();
        for credential in credentials {
            if credential
                .expires_at
                .is_some_and(|expires_at| expires_at <= now)
            {
                missing_gates.push(ProductionReadinessGate::ExternalSecretManager);
                reasons.push(format!(
                    "credential {} is expired",
                    credential.credential_id
                ));
            }
            if credential
                .rotation_ref
                .as_deref()
                .is_none_or(is_placeholder_ref)
            {
                missing_gates.push(ProductionReadinessGate::RotationEnforcement);
                reasons.push(format!(
                    "credential {} is missing enforceable rotation metadata",
                    credential.credential_id
                ));
            }
            if credential.material_policy != SecretMaterialPolicy::ExecutorInjected {
                missing_gates.push(ProductionReadinessGate::SecretInjection);
                reasons.push(format!(
                    "credential {} is not restricted to executor injection",
                    credential.credential_id
                ));
            }
        }
        let rotation_refs_configured = hardening
            .rotation_policy_ref
            .as_deref()
            .is_some_and(|value| !is_placeholder_ref(value))
            && credentials.iter().all(|credential| {
                credential
                    .rotation_ref
                    .as_deref()
                    .is_some_and(|value| !is_placeholder_ref(value))
            });
        if rotation_refs_configured {
            for decision in rotation_decisions {
                validate_rotation_decision(decision, adapter_decisions)?;
            }
            require_verified_rotation_decisions(credentials, hardening, rotation_decisions)?;
        }
        let hardened_sandbox_configured = hardening
            .hardened_sandbox_profile_ref
            .as_deref()
            .is_some_and(|value| !is_placeholder_ref(value));
        if hardened_sandbox_configured {
            if let Some(sandbox_decisions) = sandbox_decisions {
                for decision in sandbox_decisions {
                    validate_hardened_sandbox_decision(decision)?;
                }
                require_verified_hardened_sandbox_decision(hardening, sandbox_decisions)?;
            }
        } else if let Some(sandbox_decisions) = sandbox_decisions {
            for decision in sandbox_decisions {
                validate_hardened_sandbox_decision(decision)?;
            }
        }

        if signature_decisions.is_empty()
            || signature_decisions
                .iter()
                .any(|decision| decision.decision != SignatureVerificationKind::Verified)
        {
            missing_gates.push(ProductionReadinessGate::ExecutorTrustRoots);
            reasons
                .push("executor trust roots have not produced verified signature decisions".into());
        }
        if !signature_decisions
            .iter()
            .any(|decision| decision.can_issue_high_risk_ticket)
        {
            missing_gates.push(ProductionReadinessGate::CryptographicVerifier);
            reasons.push("no verified executor signature can issue high-risk tickets".into());
        }

        missing_gates.sort();
        missing_gates.dedup();
        reasons.sort();
        reasons.dedup();

        let decision = if missing_gates.is_empty() {
            reasons.push("all production P0 hardening gates are satisfied".into());
            ProductionReadinessDecisionKind::Ready
        } else {
            ProductionReadinessDecisionKind::Blocked
        };

        let mut evidence_refs = hardening.evidence_refs.clone();
        evidence_refs.extend(
            credentials
                .iter()
                .map(|credential| credential.credential_id.clone()),
        );
        evidence_refs.extend(
            signature_decisions
                .iter()
                .map(|decision| decision.decision_id.clone()),
        );
        evidence_refs.extend(
            adapter_evidence
                .iter()
                .map(|evidence| evidence.evidence_id.clone()),
        );
        evidence_refs.extend(
            adapter_decisions
                .iter()
                .map(|decision| decision.decision_id.clone()),
        );
        evidence_refs.extend(
            rotation_decisions
                .iter()
                .map(|decision| decision.decision_id.clone()),
        );
        if let Some(sandbox_decisions) = sandbox_decisions {
            evidence_refs.extend(
                sandbox_decisions
                    .iter()
                    .map(|decision| decision.decision_id.clone()),
            );
        }
        evidence_refs.sort();
        evidence_refs.dedup();

        Ok(ProductionReadinessDecision {
            decision_id: stable_id(
                "production_readiness",
                &(
                    policy.pack_id.as_str(),
                    &decision,
                    &missing_gates,
                    &evidence_refs,
                ),
            ),
            tenant_id: policy.tenant_id.clone(),
            decision,
            missing_gates,
            reasons,
            evidence_refs,
            evaluated_at: now,
        })
    }

    pub fn evaluate_p1_execution_readiness(
        profile: &P1ExecutionReadinessProfile,
        request: &P1ExecutionReadinessRequest,
        production_readiness: Option<&ProductionReadinessDecision>,
    ) -> Result<P1ExecutionReadinessDecision, VaultError> {
        if profile.evidence_refs.is_empty() || request.evidence_refs.is_empty() {
            return Err(VaultError::MissingEvidence);
        }
        if profile.tenant_id != request.tenant_id
            || production_readiness.is_some_and(|decision| decision.tenant_id != request.tenant_id)
        {
            return Err(VaultError::TenantMismatch);
        }

        let mut blocked_gates = Vec::new();
        let mut reasons = Vec::new();
        let capability_allowed = matches_any(&profile.allowed_capabilities, &request.capability_id);
        if !capability_allowed {
            blocked_gates.push(P1ExecutionReadinessGate::CapabilityScope);
            reasons.push(format!(
                "capability {} is outside the P1 execution readiness profile",
                request.capability_id
            ));
        }
        if !profile
            .allowed_permission_modes
            .contains(&request.permission_mode)
        {
            blocked_gates.push(P1ExecutionReadinessGate::PermissionMode);
            reasons.push(format!(
                "permission mode {:?} is outside the P1 execution readiness profile",
                request.permission_mode
            ));
        }
        if request.risk_level > profile.max_risk_level {
            blocked_gates.push(P1ExecutionReadinessGate::RiskCeiling);
            reasons.push(format!(
                "risk level {:?} exceeds P1 execution ceiling {:?}",
                request.risk_level, profile.max_risk_level
            ));
        }
        if request.requires_credential && !profile.allow_credential_use {
            blocked_gates.push(P1ExecutionReadinessGate::CredentialUse);
            reasons.push("P1 execution profile does not allow credential use".into());
        }

        let production_ready = production_readiness
            .is_some_and(|decision| decision.decision == ProductionReadinessDecisionKind::Ready);
        let needs_production_readiness = profile.mode == P1ExecutionMode::Production
            || (profile.require_production_readiness_for_high_risk
                && request.risk_level >= RiskLevel::High)
            || request.requires_credential;
        if needs_production_readiness && !production_ready {
            blocked_gates.push(P1ExecutionReadinessGate::ProductionReadiness);
            reasons.push(
                "P1 execution requires ready P0 production hardening evidence for this request"
                    .into(),
            );
        }

        blocked_gates.sort();
        blocked_gates.dedup();
        reasons.sort();
        reasons.dedup();

        let decision = if blocked_gates.is_empty() {
            reasons.push("P1 request may enter the P0 execution chain".into());
            P1ExecutionReadinessDecisionKind::Ready
        } else {
            P1ExecutionReadinessDecisionKind::Blocked
        };
        let mut evidence_refs = profile.evidence_refs.clone();
        evidence_refs.extend(request.evidence_refs.clone());
        if let Some(production_readiness) = production_readiness {
            evidence_refs.push(production_readiness.decision_id.clone());
        }
        evidence_refs.sort();
        evidence_refs.dedup();

        Ok(P1ExecutionReadinessDecision {
            decision_id: stable_id(
                "p1_execution_readiness",
                &(
                    profile.profile_id.as_str(),
                    request.request_id.as_str(),
                    &decision,
                    &blocked_gates,
                    &evidence_refs,
                ),
            ),
            request_id: request.request_id.clone(),
            tenant_id: request.tenant_id.clone(),
            mode: profile.mode,
            decision,
            blocked_gates,
            reasons,
            evidence_refs,
            can_enter_p0_execution_chain: decision == P1ExecutionReadinessDecisionKind::Ready,
            can_issue_ticket_directly: false,
            can_execute_without_p0: false,
            evaluated_at: Utc::now(),
        })
    }
}

fn validate_credential_ref(credential: &CredentialRef) -> Result<(), VaultError> {
    let refs = [
        credential.external_secret_ref.as_str(),
        credential.vault_provider_ref.as_str(),
        credential.fingerprint.as_str(),
    ];
    if refs.iter().any(|value| looks_like_raw_secret(value)) {
        return Err(VaultError::RawSecretMaterial);
    }
    Ok(())
}

fn p1_profile_requires_production_readiness(profile: &P1ExecutionReadinessProfile) -> bool {
    profile.mode == P1ExecutionMode::Production || profile.allow_credential_use
}

fn production_readiness_evidence_hash(decision: &ProductionReadinessDecision) -> String {
    stable_id(
        "production_readiness_evidence_hash",
        &(
            decision.decision_id.as_str(),
            &decision.decision,
            &decision.missing_gates,
            &decision.evidence_refs,
        ),
    )
}

fn validate_ready_production_readiness(
    decision: &ProductionReadinessDecision,
    tenant_id: &str,
) -> Result<(), VaultError> {
    if decision.tenant_id != tenant_id {
        return Err(VaultError::TenantMismatch);
    }
    if decision.decision != ProductionReadinessDecisionKind::Ready
        || !decision.missing_gates.is_empty()
        || decision.evidence_refs.is_empty()
    {
        return Err(VaultError::MissingEvidence);
    }

    Ok(())
}

fn validate_production_readiness_ref_for_profile_record(
    decision: &ProductionReadinessDecision,
    tenant_id: &str,
    production_required: bool,
    expected_ref: Option<&str>,
    expected_evidence_hash: Option<&str>,
) -> Result<(), VaultError> {
    if !production_required {
        return Err(VaultError::MissingEvidence);
    }
    validate_ready_production_readiness(decision, tenant_id)?;
    if expected_ref != Some(decision.decision_id.as_str())
        || expected_evidence_hash != Some(production_readiness_evidence_hash(decision).as_str())
    {
        return Err(VaultError::MissingEvidence);
    }

    Ok(())
}

fn validate_production_readiness_for_loaded_profile_record(
    record: &P1ExecutionReadinessProfileRecord,
    production_readiness: Option<&ProductionReadinessDecision>,
) -> Result<(), VaultError> {
    let production_required = p1_profile_requires_production_readiness(&record.profile);
    if !production_required {
        if production_readiness.is_some() {
            return Err(VaultError::MissingEvidence);
        }
        return Ok(());
    }
    let production_readiness = production_readiness.ok_or(VaultError::MissingEvidence)?;
    validate_production_readiness_ref_for_profile_record(
        production_readiness,
        &record.tenant_id,
        true,
        record.production_readiness_ref.as_deref(),
        record.production_readiness_evidence_hash.as_deref(),
    )
}

fn refs_contain_all(refs: &[String], required_refs: &[String]) -> bool {
    required_refs
        .iter()
        .all(|required_ref| refs.contains(required_ref))
}

fn validate_audit_export_record(record: &AuditExportRecord) -> Result<(), VaultError> {
    if record.event_refs.is_empty() || record.contains_secret_material {
        return Err(VaultError::MissingEvidence);
    }
    let expected_export_hash = stable_id(
        "audit_export_hash",
        &(
            record.tenant_id.as_str(),
            record.scope_ref.as_str(),
            &record.kind,
            record.redaction_profile_ref.as_str(),
            &record.event_refs,
        ),
    );
    let expected_export_id = stable_id(
        "audit_export",
        &(record.scope_ref.as_str(), &record.event_refs),
    );
    if record.export_hash != expected_export_hash || record.export_id != expected_export_id {
        return Err(VaultError::MissingEvidence);
    }

    Ok(())
}

fn validate_p1_execution_audit_bundle_record(
    bundle: &P1ExecutionAuditBundle,
) -> Result<(), VaultError> {
    if bundle.evidence_refs.is_empty()
        || bundle.contains_secret_material
        || bundle.can_issue_ticket_directly
        || bundle.can_execute_without_p0
        || bundle.audit_export_hash.is_empty()
        || !bundle.evidence_refs.contains(&bundle.audit_export_hash)
        || !bundle.evidence_refs.contains(&bundle.audit_export_ref)
        || !bundle
            .evidence_refs
            .contains(&bundle.readiness_decision_ref)
        || !bundle.evidence_refs.contains(&bundle.profile_record_ref)
        || !bundle.evidence_refs.contains(&bundle.tenant_policy_hash)
        || bundle
            .production_readiness_ref
            .as_ref()
            .is_some_and(|readiness_ref| !bundle.evidence_refs.contains(readiness_ref))
        || bundle
            .production_readiness_evidence_hash
            .as_ref()
            .is_some_and(|readiness_hash| !bundle.evidence_refs.contains(readiness_hash))
    {
        return Err(VaultError::MissingEvidence);
    }
    let expected_bundle_hash = stable_id(
        "p1_execution_audit_bundle_hash",
        &(
            bundle.request_id.as_str(),
            bundle.profile_record_ref.as_str(),
            bundle.readiness_decision_ref.as_str(),
            bundle.audit_export_hash.as_str(),
            &bundle.production_readiness_ref,
            &bundle.production_readiness_evidence_hash,
            &bundle.evidence_refs,
        ),
    );
    let expected_bundle_id = stable_id(
        "p1_execution_audit_bundle",
        &(
            bundle.request_id.as_str(),
            bundle.profile_record_ref.as_str(),
            bundle.readiness_decision_ref.as_str(),
            bundle.audit_export_ref.as_str(),
            expected_bundle_hash.as_str(),
        ),
    );
    if bundle.bundle_hash != expected_bundle_hash || bundle.bundle_id != expected_bundle_id {
        return Err(VaultError::MissingEvidence);
    }

    Ok(())
}

fn validate_compliance_export_bundle_record(
    bundle: &ComplianceExportBundle,
) -> Result<(), VaultError> {
    if bundle.audit_export_refs.is_empty() && bundle.p1_execution_bundle_refs.is_empty() {
        return Err(VaultError::MissingAuditEvents);
    }
    if bundle.event_refs.is_empty()
        || bundle.evidence_refs.is_empty()
        || bundle.contains_secret_material
        || bundle.redaction_profile_ref.trim().is_empty()
        || bundle.tenant_policy_record_ref.trim().is_empty()
        || bundle.tenant_policy_hash.trim().is_empty()
        || !bundle
            .evidence_refs
            .contains(&bundle.tenant_policy_record_ref)
        || !bundle.evidence_refs.contains(&bundle.tenant_policy_hash)
        || !refs_contain_all(&bundle.evidence_refs, &bundle.audit_export_refs)
        || !refs_contain_all(&bundle.evidence_refs, &bundle.p1_execution_bundle_refs)
        || !refs_contain_all(&bundle.evidence_refs, &bundle.event_refs)
        || bundle
            .production_readiness_ref
            .as_ref()
            .is_some_and(|readiness_ref| !bundle.evidence_refs.contains(readiness_ref))
        || bundle
            .production_readiness_evidence_hash
            .as_ref()
            .is_some_and(|readiness_hash| !bundle.evidence_refs.contains(readiness_hash))
    {
        return Err(VaultError::MissingEvidence);
    }
    if bundle.production_readiness_ref.is_some()
        != bundle.production_readiness_evidence_hash.is_some()
    {
        return Err(VaultError::MissingEvidence);
    }

    let expected_bundle_hash = stable_id(
        "compliance_export_bundle_hash",
        &(
            bundle.tenant_policy_record_ref.as_str(),
            bundle.tenant_policy_hash.as_str(),
            bundle.scope_ref.as_str(),
            bundle.redaction_profile_ref.as_str(),
            &bundle.audit_export_refs,
            &bundle.p1_execution_bundle_refs,
            &bundle.production_readiness_ref,
            &bundle.production_readiness_evidence_hash,
            &bundle.evidence_refs,
        ),
    );
    let expected_bundle_id = stable_id(
        "compliance_export_bundle",
        &(
            bundle.tenant_id.as_str(),
            bundle.scope_ref.as_str(),
            expected_bundle_hash.as_str(),
        ),
    );
    if bundle.bundle_hash != expected_bundle_hash || bundle.bundle_id != expected_bundle_id {
        return Err(VaultError::MissingEvidence);
    }

    Ok(())
}

fn validate_p1_execution_readiness_decision_for_record(
    decision: &P1ExecutionReadinessDecision,
    profile_record: &P1ExecutionReadinessProfileRecord,
    request: Option<&P1ExecutionReadinessRequest>,
) -> Result<(), VaultError> {
    if decision.tenant_id != profile_record.tenant_id
        || request.is_some_and(|request| request.tenant_id != decision.tenant_id)
    {
        return Err(VaultError::TenantMismatch);
    }
    if decision.evidence_refs.is_empty()
        || !refs_contain_all(
            &decision.evidence_refs,
            &profile_record.profile.evidence_refs,
        )
        || decision.can_issue_ticket_directly
        || decision.can_execute_without_p0
        || decision.can_enter_p0_execution_chain
            != (decision.decision == P1ExecutionReadinessDecisionKind::Ready)
        || (decision.decision == P1ExecutionReadinessDecisionKind::Ready
            && !decision.blocked_gates.is_empty())
        || (decision.decision == P1ExecutionReadinessDecisionKind::Blocked
            && decision.blocked_gates.is_empty())
    {
        return Err(VaultError::MissingEvidence);
    }
    if let Some(request) = request {
        if decision.request_id != request.request_id
            || !refs_contain_all(&decision.evidence_refs, &request.evidence_refs)
        {
            return Err(VaultError::MissingEvidence);
        }
    }

    Ok(())
}

fn looks_like_raw_secret(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("-----begin")
        || lower.contains("password=")
        || lower.contains("secret=")
        || lower.starts_with("sk-")
        || lower.starts_with("xoxb-")
}

fn validate_trust_root(trust_root: &TrustRoot) -> Result<(), VaultError> {
    if trust_root.evidence_refs.is_empty()
        || trust_root.valid_from >= trust_root.valid_until
        || [
            trust_root.root_id.as_str(),
            trust_root.issuer.as_str(),
            trust_root.algorithm.as_str(),
            trust_root.signing_key_ref.as_str(),
            trust_root.fingerprint.as_str(),
        ]
        .iter()
        .any(|value| is_placeholder_ref(value))
    {
        return Err(VaultError::MissingEvidence);
    }

    Ok(())
}

fn require_production_ref_and_adapter(
    value: &Option<String>,
    adapter_evidence: &[ProductionAdapterEvidence],
    adapter_kind: ProductionAdapterKind,
    gate: ProductionReadinessGate,
    reason: &str,
    missing_gates: &mut Vec<ProductionReadinessGate>,
    reasons: &mut Vec<String>,
) {
    let configured_ref = value.as_deref().filter(|value| !is_placeholder_ref(value));
    let matching_adapter = configured_ref.and_then(|configured_ref| {
        adapter_evidence.iter().find(|evidence| {
            evidence.kind == adapter_kind && evidence.provider_ref == configured_ref
        })
    });

    if configured_ref.is_none() {
        missing_gates.push(gate);
        reasons.push(reason.into());
    } else if matching_adapter.is_none() {
        missing_gates.push(gate);
        reasons.push(format!(
            "{adapter_kind:?} is configured but has no matching production adapter evidence"
        ));
    }
}

fn is_placeholder_ref(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.trim().is_empty()
        || lower.contains("local")
        || lower.contains("mock")
        || lower.starts_with("test:")
        || lower.contains("://test")
        || lower.contains("/test")
        || lower.contains("-test")
        || lower.contains(".test")
        || lower.contains("stub")
        || lower.contains("example")
}

fn validate_adapter_evidence(evidence: &ProductionAdapterEvidence) -> Result<(), VaultError> {
    let required_refs = [
        evidence.adapter_ref.as_str(),
        evidence.adapter_version.as_str(),
        evidence.provider_ref.as_str(),
        evidence.attestation_ref.as_str(),
        evidence.healthcheck_ref.as_str(),
    ];
    if required_refs.iter().any(|value| is_placeholder_ref(value)) {
        return Err(VaultError::MissingEvidence);
    }
    if evidence.expires_at <= Utc::now() {
        return Err(VaultError::MissingEvidence);
    }
    if matches!(
        evidence.kind,
        ProductionAdapterKind::HardenedSandbox | ProductionAdapterKind::SecretInjection
    ) && evidence
        .sandbox_profile_ref
        .as_deref()
        .is_none_or(is_placeholder_ref)
    {
        return Err(VaultError::MissingEvidence);
    }
    Ok(())
}

fn validate_adapter_decision(
    decision: &ProductionAdapterVerificationDecision,
) -> Result<(), VaultError> {
    if decision.decision != ProductionAdapterVerificationKind::Verified
        || decision.evidence_refs.is_empty()
        || decision.expires_at <= Utc::now()
    {
        return Err(VaultError::MissingEvidence);
    }
    if decision
        .evidence_refs
        .iter()
        .any(|value| is_placeholder_ref(value))
        || is_placeholder_ref(&decision.adapter_ref)
        || is_placeholder_ref(&decision.provider_ref)
    {
        return Err(VaultError::MissingEvidence);
    }
    Ok(())
}

fn validate_rotation_decision(
    decision: &RotationEnforcementDecision,
    adapter_decisions: &[ProductionAdapterVerificationDecision],
) -> Result<(), VaultError> {
    if decision.decision != RotationEnforcementDecisionKind::Verified
        || decision.evidence_refs.is_empty()
        || decision.expires_at <= Utc::now()
        || decision
            .rotation_ref
            .as_deref()
            .is_none_or(is_placeholder_ref)
        || decision
            .rotation_policy_ref
            .as_deref()
            .is_none_or(is_placeholder_ref)
    {
        return Err(VaultError::MissingEvidence);
    }
    if let Some(adapter_decision_ref) = &decision.adapter_decision_ref {
        let Some(adapter_decision) = adapter_decisions
            .iter()
            .find(|candidate| candidate.decision_id == *adapter_decision_ref)
        else {
            return Err(VaultError::MissingEvidence);
        };
        let Some(rotation_policy_ref) = decision.rotation_policy_ref.as_ref() else {
            return Err(VaultError::MissingEvidence);
        };
        if adapter_decision.kind != ProductionAdapterKind::RotationEnforcement
            || adapter_decision.decision != ProductionAdapterVerificationKind::Verified
            || &adapter_decision.provider_ref != rotation_policy_ref
            || !decision.evidence_refs.contains(adapter_decision_ref)
        {
            return Err(VaultError::MissingEvidence);
        }
    }
    if decision
        .evidence_refs
        .iter()
        .any(|value| is_placeholder_ref(value))
    {
        return Err(VaultError::MissingEvidence);
    }
    Ok(())
}

fn validate_hardened_sandbox_decision(
    decision: &HardenedSandboxDecision,
) -> Result<(), VaultError> {
    if decision.decision != HardenedSandboxDecisionKind::Verified
        || decision.evidence_refs.is_empty()
        || decision.expires_at <= Utc::now()
        || is_placeholder_ref(&decision.hardened_sandbox_profile_ref)
    {
        return Err(VaultError::MissingEvidence);
    }
    if decision
        .evidence_refs
        .iter()
        .any(|value| is_placeholder_ref(value))
    {
        return Err(VaultError::MissingEvidence);
    }
    Ok(())
}

fn require_tenant_match_for_hardening_decision_set(
    policy: &TenantPolicyPack,
    decision_set: &ProductionHardeningDecisionSet<'_>,
) -> Result<(), VaultError> {
    let tenant_id = policy.tenant_id.as_str();
    if decision_set
        .auth_decision
        .is_some_and(|decision| decision.tenant_id != tenant_id)
        || decision_set
            .external_secret_manager_decisions
            .iter()
            .any(|decision| decision.tenant_id != tenant_id)
        || decision_set
            .cryptographic_verifier_decisions
            .iter()
            .any(|decision| decision.tenant_id != tenant_id)
        || decision_set
            .hardened_sandbox_decisions
            .iter()
            .any(|decision| decision.tenant_id != tenant_id)
        || decision_set
            .rotation_decisions
            .iter()
            .any(|decision| decision.tenant_id != tenant_id)
        || decision_set
            .secret_injection_decisions
            .iter()
            .any(|decision| decision.tenant_id != tenant_id)
        || decision_set
            .compliance_export_delivery_decisions
            .iter()
            .any(|decision| decision.tenant_id != tenant_id)
        || decision_set
            .trust_root_storage_decisions
            .iter()
            .any(|decision| decision.tenant_id != tenant_id)
    {
        return Err(VaultError::TenantMismatch);
    }

    Ok(())
}

fn require_verified_production_auth_decision(
    hardening: &ProductionHardeningEvidence,
    decision: Option<&ProductionAuthDecision>,
) -> Result<(), VaultError> {
    let Some(decision) = decision else {
        return Err(VaultError::MissingEvidence);
    };
    if decision.decision != ProductionAuthDecisionKind::Verified
        || decision.evidence_refs.is_empty()
        || decision.expires_at <= Utc::now()
        || hardening.auth_provider_ref.as_ref() != Some(&decision.auth_provider_ref)
        || !decision.evidence_refs.contains(&decision.auth_provider_ref)
        || decision
            .evidence_refs
            .iter()
            .any(|value| is_placeholder_ref(value))
    {
        return Err(VaultError::MissingEvidence);
    }

    Ok(())
}

fn require_verified_external_secret_manager_decisions(
    credentials: &[CredentialRef],
    hardening: &ProductionHardeningEvidence,
    adapter_decisions: &[ProductionAdapterVerificationDecision],
    decisions: &[ExternalSecretManagerDecision],
) -> Result<(), VaultError> {
    if credentials.len() != decisions.len() {
        return Err(VaultError::MissingEvidence);
    }
    let decisions_by_credential = decisions
        .iter()
        .map(|decision| (decision.credential_id.as_str(), decision))
        .collect::<BTreeMap<_, _>>();
    if decisions_by_credential.len() != decisions.len() {
        return Err(VaultError::MissingEvidence);
    }

    for credential in credentials {
        let Some(decision) = decisions_by_credential.get(credential.credential_id.as_str()) else {
            return Err(VaultError::MissingEvidence);
        };
        if decision.decision != ExternalSecretManagerDecisionKind::Verified
            || decision.evidence_refs.is_empty()
            || decision.expires_at <= Utc::now()
            || decision.external_secret_ref != credential.external_secret_ref
            || hardening.secret_manager_ref.as_ref() != Some(&decision.secret_manager_ref)
            || !decision.evidence_refs.contains(&credential.credential_id)
            || !decision
                .evidence_refs
                .contains(&credential.external_secret_ref)
            || !decision_refs_verified_adapter_kind(
                &decision.evidence_refs,
                adapter_decisions,
                ProductionAdapterKind::ExternalSecretManager,
                &decision.secret_manager_ref,
            )?
            || decision
                .evidence_refs
                .iter()
                .any(|value| is_placeholder_ref(value) || looks_like_raw_secret(value))
        {
            return Err(VaultError::MissingEvidence);
        }
    }

    Ok(())
}

fn require_verified_cryptographic_verifier_decisions(
    signature_decisions: &[SignatureVerificationDecision],
    hardening: &ProductionHardeningEvidence,
    adapter_decisions: &[ProductionAdapterVerificationDecision],
    decisions: &[CryptographicVerifierDecision],
) -> Result<(), VaultError> {
    let high_risk_signature_refs = signature_decisions
        .iter()
        .filter(|decision| {
            decision.decision == SignatureVerificationKind::Verified
                && decision.can_issue_high_risk_ticket
        })
        .map(|decision| decision.decision_id.as_str())
        .collect::<BTreeSet<_>>();
    if high_risk_signature_refs.is_empty() || decisions.len() != high_risk_signature_refs.len() {
        return Err(VaultError::MissingEvidence);
    }

    let mut seen = BTreeSet::new();
    for decision in decisions {
        if decision.decision != CryptographicVerifierDecisionKind::Verified
            || decision.evidence_refs.is_empty()
            || decision.expires_at <= Utc::now()
            || hardening.cryptographic_verifier_ref.as_ref()
                != Some(&decision.cryptographic_verifier_ref)
            || !high_risk_signature_refs.contains(decision.signature_decision_ref.as_str())
            || !seen.insert(decision.signature_decision_ref.as_str())
            || !decision
                .evidence_refs
                .contains(&decision.signature_decision_ref)
            || !decision
                .evidence_refs
                .contains(&decision.trust_root_record_ref)
            || !decision_refs_verified_adapter_kind(
                &decision.evidence_refs,
                adapter_decisions,
                ProductionAdapterKind::CryptographicVerifier,
                &decision.cryptographic_verifier_ref,
            )?
            || decision
                .evidence_refs
                .iter()
                .any(|value| is_placeholder_ref(value))
        {
            return Err(VaultError::MissingEvidence);
        }
    }

    Ok(())
}

fn require_verified_secret_injection_decisions(
    credentials: &[CredentialRef],
    hardening: &ProductionHardeningEvidence,
    adapter_decisions: &[ProductionAdapterVerificationDecision],
    decisions: &[SecretInjectionDecision],
) -> Result<(), VaultError> {
    if credentials.len() != decisions.len() {
        return Err(VaultError::MissingEvidence);
    }
    let decisions_by_credential = decisions
        .iter()
        .map(|decision| (decision.credential_id.as_str(), decision))
        .collect::<BTreeMap<_, _>>();
    if decisions_by_credential.len() != decisions.len() {
        return Err(VaultError::MissingEvidence);
    }

    for credential in credentials {
        let Some(decision) = decisions_by_credential.get(credential.credential_id.as_str()) else {
            return Err(VaultError::MissingEvidence);
        };
        if decision.decision != SecretInjectionDecisionKind::Verified
            || decision.evidence_refs.is_empty()
            || decision.expires_at <= Utc::now()
            || hardening.secret_injection_profile_ref.as_ref()
                != Some(&decision.secret_injection_profile_ref)
            || hardening.hardened_sandbox_profile_ref.as_ref()
                != Some(&decision.hardened_sandbox_profile_ref)
            || !decision.evidence_refs.contains(&credential.credential_id)
            || !decision
                .evidence_refs
                .contains(&decision.secret_use_decision_id)
            || !decision_refs_verified_adapter_kind(
                &decision.evidence_refs,
                adapter_decisions,
                ProductionAdapterKind::SecretInjection,
                &decision.secret_injection_profile_ref,
            )?
            || decision
                .evidence_refs
                .iter()
                .any(|value| is_placeholder_ref(value))
        {
            return Err(VaultError::MissingEvidence);
        }
    }

    Ok(())
}

fn require_verified_compliance_export_delivery_decisions(
    hardening: &ProductionHardeningEvidence,
    adapter_decisions: &[ProductionAdapterVerificationDecision],
    decisions: &[ComplianceExportDeliveryDecision],
) -> Result<(), VaultError> {
    if decisions.is_empty() {
        return Err(VaultError::MissingEvidence);
    }

    for decision in decisions {
        if validate_compliance_export_delivery_decision_record(decision).is_err()
            || decision.decision != ComplianceExportDeliveryDecisionKind::Verified
            || decision.evidence_refs.is_empty()
            || decision.expires_at <= Utc::now()
            || !decision.evidence_refs.contains(&decision.bundle_id)
            || !decision.evidence_refs.contains(&decision.bundle_hash)
            || !decision
                .evidence_refs
                .contains(&decision.tenant_policy_hash)
            || decision
                .production_readiness_evidence_hash
                .as_ref()
                .is_some_and(|readiness_hash| !decision.evidence_refs.contains(readiness_hash))
            || decision
                .adapter_decision_ref
                .as_ref()
                .is_none_or(|adapter_decision_ref| {
                    !decision.evidence_refs.contains(adapter_decision_ref)
                })
            || hardening.compliance_export_profile_ref.as_ref()
                != Some(&decision.storage_provider_ref)
            || !decision_refs_verified_adapter_kind(
                &decision.evidence_refs,
                adapter_decisions,
                ProductionAdapterKind::ComplianceAuditExport,
                &decision.storage_provider_ref,
            )?
            || decision
                .evidence_refs
                .iter()
                .any(|value| is_placeholder_ref(value))
        {
            return Err(VaultError::MissingEvidence);
        }
    }

    Ok(())
}

fn validate_compliance_export_delivery_decision_record(
    decision: &ComplianceExportDeliveryDecision,
) -> Result<(), VaultError> {
    if decision.evidence_refs.is_empty()
        || decision.tenant_id.trim().is_empty()
        || decision.bundle_id.trim().is_empty()
        || decision.bundle_hash.trim().is_empty()
        || decision.tenant_policy_hash.trim().is_empty()
        || decision.delivery_evidence_ref.trim().is_empty()
        || decision.delivery_ref.trim().is_empty()
        || decision.storage_provider_ref.trim().is_empty()
        || decision.verified_at >= decision.expires_at
        || !decision.evidence_refs.contains(&decision.bundle_id)
        || !decision.evidence_refs.contains(&decision.bundle_hash)
        || !decision
            .evidence_refs
            .contains(&decision.tenant_policy_hash)
        || !decision
            .evidence_refs
            .contains(&decision.delivery_evidence_ref)
        || !decision.evidence_refs.contains(&decision.delivery_ref)
        || !decision
            .evidence_refs
            .contains(&decision.storage_provider_ref)
        || decision
            .production_readiness_evidence_hash
            .as_ref()
            .is_some_and(|readiness_hash| !decision.evidence_refs.contains(readiness_hash))
        || decision
            .adapter_decision_ref
            .as_ref()
            .is_none_or(|adapter_decision_ref| {
                !decision.evidence_refs.contains(adapter_decision_ref)
            })
        || decision
            .evidence_refs
            .iter()
            .any(|value| is_placeholder_ref(value))
    {
        return Err(VaultError::MissingEvidence);
    }

    let expected_decision_id = stable_id(
        "compliance_export_delivery",
        &(
            decision.tenant_id.as_str(),
            decision.bundle_id.as_str(),
            decision.bundle_hash.as_str(),
            decision.tenant_policy_hash.as_str(),
            &decision.production_readiness_evidence_hash,
            decision.delivery_evidence_ref.as_str(),
            decision.delivery_ref.as_str(),
            &decision.adapter_decision_ref,
            &decision.decision,
            &decision.evidence_refs,
        ),
    );
    if decision.decision_id != expected_decision_id {
        return Err(VaultError::MissingEvidence);
    }

    Ok(())
}

fn require_verified_trust_root_storage_decisions(
    signature_decisions: &[SignatureVerificationDecision],
    decisions: &[TrustRootStorageDecision],
) -> Result<(), VaultError> {
    let required_roots = signature_decisions
        .iter()
        .filter(|decision| {
            decision.decision == SignatureVerificationKind::Verified
                && decision.can_issue_high_risk_ticket
        })
        .filter_map(|decision| decision.trust_root_ref.as_deref())
        .collect::<BTreeSet<_>>();
    if required_roots.is_empty() || decisions.len() != required_roots.len() {
        return Err(VaultError::MissingEvidence);
    }

    let mut seen = BTreeSet::new();
    for decision in decisions {
        if decision.decision != TrustRootStorageDecisionKind::Verified
            || decision.evidence_refs.is_empty()
            || decision.expires_at <= Utc::now()
            || !required_roots.contains(decision.root_id.as_str())
            || !seen.insert(decision.root_id.as_str())
            || !decision.evidence_refs.contains(&decision.record_id)
            || !decision.evidence_refs.contains(&decision.trust_root_hash)
            || !decision
                .evidence_refs
                .contains(&decision.storage_provider_ref)
            || decision
                .evidence_refs
                .iter()
                .any(|value| is_placeholder_ref(value))
        {
            return Err(VaultError::MissingEvidence);
        }
    }

    Ok(())
}

fn decision_refs_verified_adapter_kind(
    evidence_refs: &[String],
    adapter_decisions: &[ProductionAdapterVerificationDecision],
    expected_kind: ProductionAdapterKind,
    expected_provider_ref: &str,
) -> Result<bool, VaultError> {
    let matching_decisions = adapter_decisions
        .iter()
        .filter(|decision| evidence_refs.contains(&decision.decision_id))
        .collect::<Vec<_>>();
    if matching_decisions.len() > 1 {
        return Err(VaultError::MissingEvidence);
    }
    Ok(matching_decisions.first().is_some_and(|decision| {
        decision.decision == ProductionAdapterVerificationKind::Verified
            && decision.kind == expected_kind
            && decision.provider_ref == expected_provider_ref
    }))
}

fn extend_readiness_evidence_refs_from_decision_set(
    evidence_refs: &mut Vec<String>,
    decision_set: &ProductionHardeningDecisionSet<'_>,
) {
    if let Some(decision) = decision_set.auth_decision {
        evidence_refs.push(decision.decision_id.clone());
    }
    evidence_refs.extend(
        decision_set
            .external_secret_manager_decisions
            .iter()
            .map(|decision| decision.decision_id.clone()),
    );
    evidence_refs.extend(
        decision_set
            .cryptographic_verifier_decisions
            .iter()
            .map(|decision| decision.decision_id.clone()),
    );
    evidence_refs.extend(
        decision_set
            .hardened_sandbox_decisions
            .iter()
            .map(|decision| decision.decision_id.clone()),
    );
    evidence_refs.extend(
        decision_set
            .secret_injection_decisions
            .iter()
            .map(|decision| decision.decision_id.clone()),
    );
    evidence_refs.extend(
        decision_set
            .compliance_export_delivery_decisions
            .iter()
            .map(|decision| decision.decision_id.clone()),
    );
    evidence_refs.extend(
        decision_set
            .trust_root_storage_decisions
            .iter()
            .map(|decision| decision.decision_id.clone()),
    );
    evidence_refs.sort();
    evidence_refs.dedup();
}

fn require_verified_adapter_decisions(
    adapter_evidence: &[ProductionAdapterEvidence],
    adapter_decisions: &[ProductionAdapterVerificationDecision],
) -> Result<(), VaultError> {
    if adapter_evidence.len() != adapter_decisions.len() {
        return Err(VaultError::MissingEvidence);
    }

    let decisions_by_evidence = adapter_decisions
        .iter()
        .map(|decision| (decision.evidence_id.as_str(), decision))
        .collect::<BTreeMap<_, _>>();
    if decisions_by_evidence.len() != adapter_decisions.len() {
        return Err(VaultError::MissingEvidence);
    }

    for evidence in adapter_evidence {
        let Some(decision) = decisions_by_evidence.get(evidence.evidence_id.as_str()) else {
            return Err(VaultError::MissingEvidence);
        };
        if decision.kind != evidence.kind
            || decision.adapter_ref != evidence.adapter_ref
            || decision.provider_ref != evidence.provider_ref
            || decision.expires_at != evidence.expires_at
            || !decision.evidence_refs.contains(&evidence.evidence_id)
        {
            return Err(VaultError::MissingEvidence);
        }
    }

    Ok(())
}

fn require_verified_hardened_sandbox_decision(
    hardening: &ProductionHardeningEvidence,
    sandbox_decisions: &[HardenedSandboxDecision],
) -> Result<(), VaultError> {
    if sandbox_decisions.len() != 1 {
        return Err(VaultError::MissingEvidence);
    }

    let Some(profile_ref) = hardening.hardened_sandbox_profile_ref.as_deref() else {
        return Err(VaultError::MissingEvidence);
    };
    let decision = &sandbox_decisions[0];
    if decision.hardened_sandbox_profile_ref != profile_ref
        || !decision.evidence_refs.contains(&profile_ref.to_string())
    {
        return Err(VaultError::MissingEvidence);
    }

    Ok(())
}

fn require_verified_rotation_decisions(
    credentials: &[CredentialRef],
    hardening: &ProductionHardeningEvidence,
    rotation_decisions: &[RotationEnforcementDecision],
) -> Result<(), VaultError> {
    if credentials.len() != rotation_decisions.len() {
        return Err(VaultError::MissingEvidence);
    }

    let decisions_by_credential = rotation_decisions
        .iter()
        .map(|decision| (decision.credential_id.as_str(), decision))
        .collect::<BTreeMap<_, _>>();
    if decisions_by_credential.len() != rotation_decisions.len() {
        return Err(VaultError::MissingEvidence);
    }

    for credential in credentials {
        let Some(decision) = decisions_by_credential.get(credential.credential_id.as_str()) else {
            return Err(VaultError::MissingEvidence);
        };
        if decision.rotation_ref != credential.rotation_ref
            || decision.rotation_policy_ref != hardening.rotation_policy_ref
            || !decision.evidence_refs.contains(&credential.credential_id)
        {
            return Err(VaultError::MissingEvidence);
        }
    }

    Ok(())
}

fn approval_required(credential: &CredentialRef, risk_level: RiskLevel) -> bool {
    credential
        .approval_required_at_or_above
        .is_some_and(|threshold| risk_level >= threshold)
}

fn validate_quorum(
    approval: &QuorumApproval,
    request_ref: &str,
    tenant_id: &str,
) -> Result<(), VaultError> {
    let mut approvers = approval.approver_ids.clone();
    approvers.sort();
    approvers.dedup();
    if approval.request_ref != request_ref
        || approval.tenant_id != tenant_id
        || approvers.len() < usize::from(approval.required_approvers)
        || approval.expires_at <= Utc::now()
    {
        return Err(VaultError::InvalidApproval);
    }
    Ok(())
}

fn matches_any(patterns: &[String], value: &str) -> bool {
    patterns.iter().any(|pattern| {
        pattern == "*"
            || pattern == value
            || pattern
                .strip_suffix('*')
                .is_some_and(|prefix| value.starts_with(prefix))
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
    use chrono::Duration;

    fn credential() -> CredentialRef {
        CredentialRef {
            credential_id: "cred.github".into(),
            tenant_id: "tenant.a".into(),
            vault_provider_ref: "vault.local".into(),
            external_secret_ref: "vault://tenant.a/github/token".into(),
            purpose: "github api token".into(),
            allowed_capabilities: vec!["github.*".into()],
            allowed_resource_patterns: vec!["repo:moxi/*".into()],
            risk_ceiling: RiskLevel::High,
            approval_required_at_or_above: Some(RiskLevel::High),
            material_policy: SecretMaterialPolicy::ExecutorInjected,
            fingerprint: "sha256:credential-handle".into(),
            rotation_ref: Some("rotation.30d".into()),
            expires_at: Some(Utc::now() + Duration::hours(1)),
            created_at: Utc::now(),
        }
    }

    fn secret_request(risk_level: RiskLevel) -> SecretUseRequest {
        SecretUseRequest {
            request_id: "secret.req.1".into(),
            run_id: "run.1".into(),
            tenant_id: "tenant.a".into(),
            actor_id: "user.1".into(),
            capability_id: "github.pull_request".into(),
            resource_ref: "repo:moxi/core".into(),
            credential_id: "cred.github".into(),
            purpose: "open pull request".into(),
            risk_level,
            evidence_refs: vec!["policy.decision.1".into(), "ticket.1".into()],
            requested_at: Utc::now(),
        }
    }

    fn approval(request_ref: &str) -> QuorumApproval {
        QuorumApproval {
            approval_id: "approval.1".into(),
            request_ref: request_ref.into(),
            tenant_id: "tenant.a".into(),
            approver_ids: vec!["owner.1".into(), "security.1".into()],
            required_approvers: 2,
            reason: "bounded high-risk secret use".into(),
            granted_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5),
        }
    }

    fn trust_root() -> TrustRoot {
        TrustRoot {
            root_id: "root.1".into(),
            tenant_id: "tenant.a".into(),
            issuer: "MOXI internal CA".into(),
            algorithm: "ed25519".into(),
            signing_key_ref: "key.executor.root".into(),
            fingerprint: "sha256:root".into(),
            valid_from: Utc::now() - Duration::days(1),
            valid_until: Utc::now() + Duration::days(1),
            revoked: false,
            evidence_refs: vec!["trust.root.import".into()],
        }
    }

    fn signature() -> ExecutorSignature {
        ExecutorSignature {
            signature_id: "sig.1".into(),
            tenant_id: "tenant.a".into(),
            executor_ref: "executor.github".into(),
            executor_version: "0.1.0".into(),
            artifact_hash: "sha256:artifact".into(),
            manifest_hash: "sha256:manifest".into(),
            signing_key_ref: "key.executor.root".into(),
            signature_ref: "sigstore://sig.1".into(),
            signed_at: Utc::now(),
            evidence_refs: vec!["executor.manifest".into()],
        }
    }

    fn tenant_policy() -> TenantPolicyPack {
        TenantPolicyPack {
            pack_id: "tenant.policy.1".into(),
            tenant_id: "tenant.a".into(),
            policy_version: "2026.05".into(),
            credential_scope_refs: vec!["cred.github".into()],
            high_risk_requires_quorum: true,
            quorum_approvers: 2,
            break_glass_enabled: true,
            break_glass_allowed_roles: vec!["owner".into()],
            break_glass_allowed_capabilities: vec!["github.*".into()],
            audit_export_required: true,
            created_at: Utc::now(),
        }
    }

    fn hardening_evidence() -> ProductionHardeningEvidence {
        ProductionHardeningEvidence {
            tenant_id: "tenant.a".into(),
            auth_provider_ref: Some("oidc://prod/tenant.a".into()),
            secret_manager_ref: Some("kms://tenant.a/prod".into()),
            cryptographic_verifier_ref: Some("sigstore://tenant.a/verifier".into()),
            hardened_sandbox_profile_ref: Some("container://tenant.a/hardened-v1".into()),
            secret_injection_profile_ref: Some("injector://tenant.a/prod".into()),
            rotation_policy_ref: Some("rotation://tenant.a/30d-enforced".into()),
            compliance_export_profile_ref: Some("audit://tenant.a/soc2-bundle".into()),
            evidence_refs: vec!["hardening.review.1".into()],
            collected_at: Utc::now(),
        }
    }

    fn adapter_evidence(
        kind: ProductionAdapterKind,
        provider_ref: &str,
    ) -> ProductionAdapterEvidence {
        ProductionAdapterEvidence {
            evidence_id: format!("adapter.evidence.{kind:?}"),
            tenant_id: "tenant.a".into(),
            kind,
            adapter_ref: format!("adapter://tenant.a/{kind:?}"),
            adapter_version: "2026.05.prod".into(),
            provider_ref: provider_ref.into(),
            attestation_ref: format!("attestation://tenant.a/{kind:?}"),
            healthcheck_ref: format!("health://tenant.a/{kind:?}"),
            sandbox_profile_ref: if matches!(
                kind,
                ProductionAdapterKind::HardenedSandbox | ProductionAdapterKind::SecretInjection
            ) {
                Some("container://tenant.a/hardened-v1".into())
            } else {
                None
            },
            generated_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
        }
    }

    fn all_adapter_evidence() -> Vec<ProductionAdapterEvidence> {
        vec![
            adapter_evidence(ProductionAdapterKind::AuthProvider, "oidc://prod/tenant.a"),
            adapter_evidence(
                ProductionAdapterKind::ExternalSecretManager,
                "kms://tenant.a/prod",
            ),
            adapter_evidence(
                ProductionAdapterKind::CryptographicVerifier,
                "sigstore://tenant.a/verifier",
            ),
            adapter_evidence(
                ProductionAdapterKind::HardenedSandbox,
                "container://tenant.a/hardened-v1",
            ),
            adapter_evidence(
                ProductionAdapterKind::SecretInjection,
                "injector://tenant.a/prod",
            ),
            adapter_evidence(
                ProductionAdapterKind::RotationEnforcement,
                "rotation://tenant.a/30d-enforced",
            ),
            adapter_evidence(
                ProductionAdapterKind::ComplianceAuditExport,
                "audit://tenant.a/soc2-bundle",
            ),
        ]
    }

    fn all_adapter_decisions(
        adapter_evidence: &[ProductionAdapterEvidence],
    ) -> Vec<ProductionAdapterVerificationDecision> {
        adapter_evidence
            .iter()
            .map(VaultController::verify_production_adapter_evidence)
            .collect()
    }

    fn production_auth_evidence(
        adapter_decision: &ProductionAdapterVerificationDecision,
    ) -> ProductionAuthEvidence {
        ProductionAuthEvidence {
            evidence_id: "production.auth.evidence.1".into(),
            tenant_id: "tenant.a".into(),
            auth_provider_ref: "oidc://prod/tenant.a".into(),
            adapter_decision_ref: adapter_decision.decision_id.clone(),
            issuer_ref: "issuer://tenant.a/prod-oidc".into(),
            jwks_ref: "jwks://tenant.a/prod-oidc/current".into(),
            token_policy_ref: "token-policy://tenant.a/prod".into(),
            audience_ref: "audience://tenant.a/moxi-core".into(),
            session_policy_ref: "session-policy://tenant.a/prod".into(),
            attestation_ref: "attestation://tenant.a/production-auth/2026-05".into(),
            checked_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
        }
    }

    fn external_secret_manager_evidence(
        credential: &CredentialRef,
        adapter_decision: &ProductionAdapterVerificationDecision,
    ) -> ExternalSecretManagerEvidence {
        ExternalSecretManagerEvidence {
            evidence_id: "external.secret.manager.evidence.1".into(),
            tenant_id: credential.tenant_id.clone(),
            credential_id: credential.credential_id.clone(),
            external_secret_ref: credential.external_secret_ref.clone(),
            secret_manager_ref: "kms://tenant.a/prod".into(),
            adapter_decision_ref: adapter_decision.decision_id.clone(),
            key_encryption_key_ref: "kek://tenant.a/prod-primary".into(),
            hsm_partition_ref: "hsm://tenant.a/prod-partition".into(),
            access_policy_ref: "access-policy://tenant.a/prod-secrets".into(),
            rotation_policy_ref: "rotation://tenant.a/30d-enforced".into(),
            attestation_ref: "attestation://tenant.a/external-secret-manager/2026-05".into(),
            checked_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
        }
    }

    fn cryptographic_verifier_evidence(
        signature_decision: &SignatureVerificationDecision,
        trust_root_record: &TrustRootRecord,
        adapter_decision: &ProductionAdapterVerificationDecision,
    ) -> CryptographicVerifierEvidence {
        CryptographicVerifierEvidence {
            evidence_id: "crypto.verifier.evidence.1".into(),
            tenant_id: signature_decision.tenant_id.clone(),
            signature_decision_ref: signature_decision.decision_id.clone(),
            trust_root_record_ref: trust_root_record.record_id.clone(),
            trust_root_hash: trust_root_record.trust_root_hash.clone(),
            cryptographic_verifier_ref: "sigstore://tenant.a/verifier".into(),
            adapter_decision_ref: adapter_decision.decision_id.clone(),
            verifier_policy_ref: "verifier-policy://tenant.a/prod".into(),
            transparency_log_ref: "rekor://tenant.a/prod-log".into(),
            algorithm_suite_ref: "algorithm-suite://tenant.a/ed25519-sha256".into(),
            attestation_ref: "attestation://tenant.a/crypto-verifier/2026-05".into(),
            checked_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
        }
    }

    fn hardened_sandbox_evidence(
        adapter_decision: &ProductionAdapterVerificationDecision,
    ) -> HardenedSandboxEvidence {
        HardenedSandboxEvidence {
            evidence_id: "hardened.sandbox.evidence.1".into(),
            tenant_id: "tenant.a".into(),
            hardened_sandbox_profile_ref: "container://tenant.a/hardened-v1".into(),
            adapter_decision_ref: adapter_decision.decision_id.clone(),
            isolation_policy_ref: "isolation-policy://tenant.a/prod-container".into(),
            filesystem_policy_ref: "fs-policy://tenant.a/read-write-scratch".into(),
            network_policy_ref: "network-policy://tenant.a/egress-deny-default".into(),
            syscall_policy_ref: "syscall-policy://tenant.a/seccomp-prod".into(),
            resource_policy_ref: "resource-policy://tenant.a/cpu-mem-prod".into(),
            attestation_ref: "attestation://tenant.a/hardened-sandbox/2026-05".into(),
            checked_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
        }
    }

    fn secret_injection_evidence(
        credential: &CredentialRef,
        secret_use: &SecretUseDecision,
        adapter_decision: &ProductionAdapterVerificationDecision,
    ) -> SecretInjectionEvidence {
        SecretInjectionEvidence {
            evidence_id: "secret.injection.evidence.1".into(),
            tenant_id: credential.tenant_id.clone(),
            credential_id: credential.credential_id.clone(),
            secret_use_decision_id: secret_use.decision_id.clone(),
            secret_injection_profile_ref: "injector://tenant.a/prod".into(),
            hardened_sandbox_profile_ref: "container://tenant.a/hardened-v1".into(),
            adapter_decision_ref: adapter_decision.decision_id.clone(),
            injection_receipt_ref: "receipt://tenant.a/secret-injection/run.1".into(),
            executor_ref: "executor://tenant.a/hardened-runner".into(),
            run_id: "run.1".into(),
            attestation_ref: "attestation://tenant.a/secret-injection/2026-05".into(),
            delivered_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
        }
    }

    fn compliance_delivery_evidence(
        bundle: &ComplianceExportBundle,
    ) -> ComplianceExportDeliveryEvidence {
        ComplianceExportDeliveryEvidence {
            evidence_id: "compliance.delivery.evidence.1".into(),
            tenant_id: bundle.tenant_id.clone(),
            bundle_id: bundle.bundle_id.clone(),
            bundle_hash: bundle.bundle_hash.clone(),
            delivery_ref: "compliance-delivery://tenant.a/export/run.compliance".into(),
            storage_provider_ref: "compliance-store://tenant.a/prod-archive".into(),
            adapter_decision_ref: None,
            attestation_ref: "attestation://tenant.a/compliance-delivery/2026-05".into(),
            receipt_ref: "receipt://tenant.a/compliance-delivery/run.compliance".into(),
            retention_policy_ref: "retention://tenant.a/seven-years".into(),
            delivered_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
        }
    }

    fn trust_root_storage_evidence(record: &TrustRootRecord) -> TrustRootStorageEvidence {
        TrustRootStorageEvidence {
            evidence_id: "trust-root.storage.evidence.1".into(),
            tenant_id: record.tenant_id.clone(),
            record_id: record.record_id.clone(),
            trust_root_hash: record.trust_root_hash.clone(),
            storage_provider_ref: "trust-store://tenant.a/prod-roots".into(),
            storage_location_ref: "trust-store://tenant.a/prod-roots/root.github".into(),
            attestation_ref: "attestation://tenant.a/trust-store/2026-05".into(),
            receipt_ref: "receipt://tenant.a/trust-store/root.github".into(),
            replica_set_ref: "replica-set://tenant.a/trust-store/quorum-a".into(),
            retention_policy_ref: "retention://tenant.a/trust-root/seven-years".into(),
            stored_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
        }
    }

    struct ProductionHardeningDecisionFixtures {
        credential: CredentialRef,
        signature_decision: SignatureVerificationDecision,
        hardening: ProductionHardeningEvidence,
        adapters: Vec<ProductionAdapterEvidence>,
        adapter_decisions: Vec<ProductionAdapterVerificationDecision>,
        auth_decision: ProductionAuthDecision,
        external_secret_manager_decisions: Vec<ExternalSecretManagerDecision>,
        cryptographic_verifier_decisions: Vec<CryptographicVerifierDecision>,
        hardened_sandbox_decisions: Vec<HardenedSandboxDecision>,
        rotation_decisions: Vec<RotationEnforcementDecision>,
        secret_injection_decisions: Vec<SecretInjectionDecision>,
        compliance_export_delivery_decisions: Vec<ComplianceExportDeliveryDecision>,
        trust_root_storage_decisions: Vec<TrustRootStorageDecision>,
    }

    impl ProductionHardeningDecisionFixtures {
        fn decision_set(&self) -> ProductionHardeningDecisionSet<'_> {
            ProductionHardeningDecisionSet {
                auth_decision: Some(&self.auth_decision),
                external_secret_manager_decisions: &self.external_secret_manager_decisions,
                cryptographic_verifier_decisions: &self.cryptographic_verifier_decisions,
                hardened_sandbox_decisions: &self.hardened_sandbox_decisions,
                rotation_decisions: &self.rotation_decisions,
                secret_injection_decisions: &self.secret_injection_decisions,
                compliance_export_delivery_decisions: &self.compliance_export_delivery_decisions,
                trust_root_storage_decisions: &self.trust_root_storage_decisions,
            }
        }
    }

    fn production_hardening_decision_fixtures() -> ProductionHardeningDecisionFixtures {
        let credential = credential();
        let hardening = hardening_evidence();
        let adapters = all_adapter_evidence();
        let adapter_decisions = all_adapter_decisions(&adapters);
        let adapter_decision = |kind: ProductionAdapterKind| {
            adapter_decisions
                .iter()
                .find(|decision| decision.kind == kind)
                .unwrap()
                .clone()
        };
        let auth_adapter_decision = adapter_decision(ProductionAdapterKind::AuthProvider);
        let secret_manager_adapter_decision =
            adapter_decision(ProductionAdapterKind::ExternalSecretManager);
        let crypto_adapter_decision =
            adapter_decision(ProductionAdapterKind::CryptographicVerifier);
        let sandbox_adapter_decision = adapter_decision(ProductionAdapterKind::HardenedSandbox);
        let injection_adapter_decision = adapter_decision(ProductionAdapterKind::SecretInjection);
        let rotation_adapter_decision =
            adapter_decision(ProductionAdapterKind::RotationEnforcement);
        let compliance_adapter_decision =
            adapter_decision(ProductionAdapterKind::ComplianceAuditExport);

        let trust_root_record = VaultController::seal_trust_root(
            trust_root(),
            vec!["security.import.review".into()],
            "vault.controller",
        )
        .unwrap();
        let trust_root_storage_decision = VaultController::verify_trust_root_storage(
            &trust_root_record,
            &trust_root_storage_evidence(&trust_root_record),
        );
        let signature_decision =
            VaultController::verify_executor_signature_with_trust_root_records(
                &signature(),
                std::slice::from_ref(&trust_root_record),
                RiskLevel::High,
            )
            .unwrap();
        let auth_decision = VaultController::verify_production_auth(
            &hardening,
            &auth_adapter_decision,
            &production_auth_evidence(&auth_adapter_decision),
        );
        let secret_manager_decision = VaultController::verify_external_secret_manager(
            &credential,
            &hardening,
            &secret_manager_adapter_decision,
            &external_secret_manager_evidence(&credential, &secret_manager_adapter_decision),
        );
        let crypto_decision = VaultController::verify_cryptographic_verifier(
            &hardening,
            &signature_decision,
            &trust_root_record,
            &crypto_adapter_decision,
            &cryptographic_verifier_evidence(
                &signature_decision,
                &trust_root_record,
                &crypto_adapter_decision,
            ),
        );
        let sandbox_decision = VaultController::verify_hardened_sandbox(
            &hardening,
            &sandbox_adapter_decision,
            &hardened_sandbox_evidence(&sandbox_adapter_decision),
        );
        let rotation_decision = VaultController::verify_rotation_enforcement_with_adapter_decision(
            &credential,
            &hardening,
            &rotation_adapter_decision,
        );
        let secret_use = VaultController::decide_secret_use(
            &credential,
            &secret_request(RiskLevel::High),
            Some(&approval("secret.req.1")),
        )
        .unwrap();
        let injection_decision = VaultController::verify_secret_injection(
            &credential,
            &secret_use,
            &hardening,
            &injection_adapter_decision,
            &secret_injection_evidence(&credential, &secret_use, &injection_adapter_decision),
        );
        let policy_record = VaultController::seal_tenant_policy_pack(
            tenant_policy(),
            vec!["policy.approved.1".into()],
            "vault.controller",
        )
        .unwrap();
        let export = VaultController::audit_export_record(
            "tenant.a",
            "production.hardening.decision-set",
            AuditExportRecordKind::Run,
            "redaction.compliance.v1",
            vec!["ledger.decision-set".into(), "proof.decision-set".into()],
            "auditor.1",
        )
        .unwrap();
        let bundle = VaultController::compliance_export_bundle(
            "production.hardening.decision-set",
            &policy_record,
            std::slice::from_ref(&export),
            &[],
            None,
            "auditor.1",
        )
        .unwrap();
        let mut delivery_evidence = compliance_delivery_evidence(&bundle);
        delivery_evidence.storage_provider_ref = "audit://tenant.a/soc2-bundle".into();
        delivery_evidence.adapter_decision_ref =
            Some(compliance_adapter_decision.decision_id.clone());
        let compliance_delivery_decision =
            VaultController::verify_compliance_export_delivery_with_adapter_decision(
                &bundle,
                &delivery_evidence,
                &compliance_adapter_decision,
            );

        ProductionHardeningDecisionFixtures {
            credential,
            signature_decision,
            hardening,
            adapters,
            adapter_decisions,
            auth_decision,
            external_secret_manager_decisions: vec![secret_manager_decision],
            cryptographic_verifier_decisions: vec![crypto_decision],
            hardened_sandbox_decisions: vec![sandbox_decision],
            rotation_decisions: vec![rotation_decision],
            secret_injection_decisions: vec![injection_decision],
            compliance_export_delivery_decisions: vec![compliance_delivery_decision],
            trust_root_storage_decisions: vec![trust_root_storage_decision],
        }
    }

    #[test]
    fn low_risk_secret_use_is_reference_only_and_never_exposes_raw_secret() {
        let decision = VaultController::decide_secret_use(
            &credential(),
            &secret_request(RiskLevel::Low),
            None,
        )
        .unwrap();

        assert_eq!(decision.decision, SecretUseDecisionKind::Allowed);
        assert!(!decision.raw_secret_visible_to_model);
        assert!(!decision.raw_secret_visible_to_logs);
        assert!(!decision.raw_secret_persisted);
    }

    #[test]
    fn high_risk_secret_use_requires_quorum_then_allows() {
        let request = secret_request(RiskLevel::High);
        let pending = VaultController::decide_secret_use(&credential(), &request, None).unwrap();
        let approved = VaultController::decide_secret_use(
            &credential(),
            &request,
            Some(&approval(&request.request_id)),
        )
        .unwrap();

        assert_eq!(pending.decision, SecretUseDecisionKind::RequiresApproval);
        assert_eq!(approved.decision, SecretUseDecisionKind::Allowed);
        assert_eq!(approved.approval_policy, ApprovalPolicy::Quorum);
        assert!(approved.approval_ref.is_some());
    }

    #[test]
    fn risk_above_credential_ceiling_is_denied_even_with_quorum() {
        let request = secret_request(RiskLevel::Critical);
        let decision = VaultController::decide_secret_use(
            &credential(),
            &request,
            Some(&approval(&request.request_id)),
        )
        .unwrap();

        assert_eq!(decision.decision, SecretUseDecisionKind::Denied);
    }

    #[test]
    fn raw_secret_like_reference_is_rejected_before_decision() {
        let mut credential = credential();
        credential.external_secret_ref = "sk-live-should-not-be-here".into();
        let error =
            VaultController::decide_secret_use(&credential, &secret_request(RiskLevel::Low), None)
                .unwrap_err();

        assert_eq!(error, VaultError::RawSecretMaterial);
    }

    #[test]
    fn high_risk_executor_signature_must_match_tenant_trust_root() {
        let decision = VaultController::verify_executor_signature(
            &signature(),
            &[trust_root()],
            RiskLevel::High,
        );

        assert_eq!(decision.decision, SignatureVerificationKind::Verified);
        assert!(decision.can_issue_high_risk_ticket);
        assert_eq!(decision.trust_root_ref, Some("root.1".into()));
    }

    #[test]
    fn revoked_trust_root_rejects_executor_signature() {
        let mut root = trust_root();
        root.revoked = true;
        let decision =
            VaultController::verify_executor_signature(&signature(), &[root], RiskLevel::High);

        assert_eq!(decision.decision, SignatureVerificationKind::Rejected);
        assert!(!decision.can_issue_high_risk_ticket);
    }

    #[test]
    fn trust_root_record_roundtrips_and_verifies_executor_signature() {
        let root = trust_root();
        let record = VaultController::seal_trust_root(
            root.clone(),
            vec!["security.import.review".into()],
            "vault.controller",
        )
        .unwrap();

        let loaded = VaultController::load_trust_root(&record).unwrap();
        let decision = VaultController::verify_executor_signature_with_trust_root_records(
            &signature(),
            std::slice::from_ref(&record),
            RiskLevel::High,
        )
        .unwrap();

        assert_eq!(loaded, root);
        assert_eq!(record.tenant_id, "tenant.a");
        assert_eq!(record.root_id, "root.1");
        assert!(record.trust_root_hash.starts_with("trust_root_hash."));
        assert!(record.evidence_refs.contains(&"trust.root.import".into()));
        assert!(record
            .evidence_refs
            .contains(&"security.import.review".into()));
        assert_eq!(decision.decision, SignatureVerificationKind::Verified);
        assert_eq!(decision.trust_root_ref, Some("root.1".into()));
        assert!(decision.evidence_refs.contains(&"trust.root.import".into()));
    }

    #[test]
    fn trust_root_record_rejects_tamper_missing_evidence_and_cross_tenant_records() {
        let missing_error =
            VaultController::seal_trust_root(trust_root(), vec![], "vault.controller").unwrap_err();
        assert_eq!(missing_error, VaultError::MissingEvidence);

        let mut record = VaultController::seal_trust_root(
            trust_root(),
            vec!["security.import.review".into()],
            "vault.controller",
        )
        .unwrap();
        record.trust_root.fingerprint = "sha256:tampered".into();
        let tamper_error = VaultController::load_trust_root(&record).unwrap_err();
        assert_eq!(tamper_error, VaultError::MissingEvidence);

        let mut other_tenant_root = trust_root();
        other_tenant_root.tenant_id = "tenant.b".into();
        let other_tenant_record = VaultController::seal_trust_root(
            other_tenant_root,
            vec!["security.import.review".into()],
            "vault.controller",
        )
        .unwrap();
        let tenant_error = VaultController::verify_executor_signature_with_trust_root_records(
            &signature(),
            &[other_tenant_record],
            RiskLevel::High,
        )
        .unwrap_err();
        assert_eq!(tenant_error, VaultError::TenantMismatch);
    }

    #[test]
    fn trust_root_storage_decision_is_record_hash_bound_and_fail_closed() {
        let record = VaultController::seal_trust_root(
            trust_root(),
            vec!["security.import.review".into()],
            "vault.controller",
        )
        .unwrap();
        let evidence = trust_root_storage_evidence(&record);
        let decision = VaultController::verify_trust_root_storage(&record, &evidence);

        assert_eq!(decision.decision, TrustRootStorageDecisionKind::Verified);
        assert_eq!(decision.tenant_id, record.tenant_id);
        assert_eq!(decision.record_id, record.record_id);
        assert_eq!(decision.root_id, record.root_id);
        assert_eq!(decision.trust_root_hash, record.trust_root_hash);
        assert!(decision.evidence_refs.contains(&record.trust_root_hash));
        assert!(decision.evidence_refs.contains(&evidence.receipt_ref));

        let mut hash_mismatch = evidence.clone();
        hash_mismatch.trust_root_hash = "trust_root_hash.tampered".into();
        let rejected_hash = VaultController::verify_trust_root_storage(&record, &hash_mismatch);
        assert_eq!(
            rejected_hash.decision,
            TrustRootStorageDecisionKind::Rejected
        );
        assert!(!rejected_hash.reasons.is_empty());

        let mut placeholder_receipt = evidence.clone();
        placeholder_receipt.receipt_ref = "mock-receipt".into();
        let rejected_placeholder =
            VaultController::verify_trust_root_storage(&record, &placeholder_receipt);
        assert_eq!(
            rejected_placeholder.decision,
            TrustRootStorageDecisionKind::Rejected
        );
        assert!(!rejected_placeholder.reasons.is_empty());

        let mut cross_tenant = evidence;
        cross_tenant.tenant_id = "tenant.b".into();
        let rejected_tenant = VaultController::verify_trust_root_storage(&record, &cross_tenant);
        assert_eq!(
            rejected_tenant.decision,
            TrustRootStorageDecisionKind::Rejected
        );
        assert!(!rejected_tenant.reasons.is_empty());
    }

    #[test]
    fn break_glass_requires_quorum_and_always_requires_audit() {
        let policy = tenant_policy();
        let request = BreakGlassRequest {
            request_id: "break.req.1".into(),
            tenant_id: "tenant.a".into(),
            actor_id: "owner.1".into(),
            actor_roles: vec!["owner".into()],
            run_id: "run.1".into(),
            reason: "production incident".into(),
            requested_capabilities: vec!["github.rollback".into()],
            risk_level: RiskLevel::Critical,
            evidence_refs: vec!["incident.1".into()],
            requested_at: Utc::now(),
        };

        let pending = VaultController::decide_break_glass(&policy, &request, None).unwrap();
        let approved = VaultController::decide_break_glass(
            &policy,
            &request,
            Some(&approval(&request.request_id)),
        )
        .unwrap();

        assert_eq!(pending.decision, BreakGlassDecisionKind::RequiresApproval);
        assert_eq!(approved.decision, BreakGlassDecisionKind::Allowed);
        assert!(approved.audit_required);
    }

    #[test]
    fn audit_export_records_are_redacted_and_event_bound() {
        let record = VaultController::audit_export_record(
            "tenant.a",
            "run.1",
            AuditExportRecordKind::CredentialUse,
            "redaction.compliance.v1",
            vec!["secret.decision.1".into(), "ledger.1".into()],
            "auditor.1",
        )
        .unwrap();

        assert!(!record.contains_secret_material);
        assert!(record.export_hash.starts_with("audit_export_hash."));
        assert!(VaultController::audit_export_record(
            "tenant.a",
            "run.1",
            AuditExportRecordKind::Run,
            "redaction.compliance.v1",
            vec![],
            "auditor.1",
        )
        .is_err());
    }

    #[test]
    fn tenant_policy_pack_record_roundtrips_with_hash_binding() {
        let policy = tenant_policy();
        let record = VaultController::seal_tenant_policy_pack(
            policy.clone(),
            vec!["policy.approved.1".into()],
            "vault.controller",
        )
        .unwrap();

        let loaded = VaultController::load_tenant_policy_pack(&record).unwrap();

        assert_eq!(loaded, policy);
        assert_eq!(record.tenant_id, "tenant.a");
        assert_eq!(record.pack_id, "tenant.policy.1");
        assert!(record.policy_hash.starts_with("tenant_policy_hash."));
        assert!(record.evidence_refs.contains(&"policy.approved.1".into()));
        assert!(record.evidence_refs.contains(&"cred.github".into()));
    }

    #[test]
    fn tenant_policy_pack_record_rejects_tamper_and_missing_evidence() {
        let policy = tenant_policy();
        let missing_error =
            VaultController::seal_tenant_policy_pack(policy.clone(), vec![], "vault.controller")
                .unwrap_err();
        assert_eq!(missing_error, VaultError::MissingEvidence);

        let mut record = VaultController::seal_tenant_policy_pack(
            policy,
            vec!["policy.approved.1".into()],
            "vault.controller",
        )
        .unwrap();
        record.policy.quorum_approvers = 1;

        let tamper_error = VaultController::load_tenant_policy_pack(&record).unwrap_err();
        assert_eq!(tamper_error, VaultError::MissingEvidence);
    }

    #[test]
    fn p1_execution_profile_record_roundtrips_with_policy_binding() {
        let policy = tenant_policy();
        let policy_record = VaultController::seal_tenant_policy_pack(
            policy.clone(),
            vec!["policy.approved.1".into()],
            "vault.controller",
        )
        .unwrap();
        let profile = P1ExecutionReadinessProfile::local_read_only("tenant.a");
        let record = VaultController::seal_p1_execution_readiness_profile_with_policy_record(
            &policy_record,
            profile.clone(),
            None,
            "vault.controller",
        )
        .unwrap();

        let loaded = VaultController::load_p1_execution_readiness_profile_with_policy_record(
            &record,
            &policy_record,
        )
        .unwrap();

        assert_eq!(loaded, profile);
        assert_eq!(record.tenant_policy_pack_ref, policy.pack_id);
        assert_eq!(record.tenant_policy_record_ref, policy_record.record_id);
        assert_eq!(record.tenant_policy_hash, policy_record.policy_hash);
        assert!(record.evidence_refs.contains(&"cred.github".into()));
        assert!(record.evidence_refs.contains(&"policy.approved.1".into()));
        assert!(record
            .profile_hash
            .starts_with("p1_execution_profile_hash."));
    }

    #[test]
    fn p1_execution_profile_record_rejects_tamper_and_cross_tenant_policy() {
        let policy = tenant_policy();
        let policy_record = VaultController::seal_tenant_policy_pack(
            policy.clone(),
            vec!["policy.approved.1".into()],
            "vault.controller",
        )
        .unwrap();
        let profile = P1ExecutionReadinessProfile::local_read_only("tenant.a");
        let record = VaultController::seal_p1_execution_readiness_profile_with_policy_record(
            &policy_record,
            profile,
            None,
            "vault.controller",
        )
        .unwrap();
        let mut tampered_record = record.clone();
        tampered_record
            .profile
            .allowed_capabilities
            .push("network.http".into());

        let tamper_error = VaultController::load_p1_execution_readiness_profile_with_policy_record(
            &tampered_record,
            &policy_record,
        )
        .unwrap_err();
        assert_eq!(tamper_error, VaultError::MissingEvidence);

        let other_policy = TenantPolicyPack {
            tenant_id: "tenant.b".into(),
            ..tenant_policy()
        };
        let other_policy_record = VaultController::seal_tenant_policy_pack(
            other_policy,
            vec!["policy.approved.other".into()],
            "vault.controller",
        )
        .unwrap();
        let tenant_error = VaultController::load_p1_execution_readiness_profile_with_policy_record(
            &record,
            &other_policy_record,
        )
        .unwrap_err();
        assert_eq!(tenant_error, VaultError::TenantMismatch);

        let mut missing_policy_hash_ref = record.clone();
        missing_policy_hash_ref
            .evidence_refs
            .retain(|evidence_ref| evidence_ref != &policy_record.policy_hash);
        let missing_policy_hash_error =
            VaultController::load_p1_execution_readiness_profile_with_policy_record(
                &missing_policy_hash_ref,
                &policy_record,
            )
            .unwrap_err();
        assert_eq!(missing_policy_hash_error, VaultError::MissingEvidence);

        let mut missing_profile_evidence_ref = record;
        missing_profile_evidence_ref
            .evidence_refs
            .retain(|evidence_ref| evidence_ref != "p1.local-readonly.profile");
        let missing_profile_evidence_error =
            VaultController::load_p1_execution_readiness_profile_with_policy_record(
                &missing_profile_evidence_ref,
                &policy_record,
            )
            .unwrap_err();
        assert_eq!(missing_profile_evidence_error, VaultError::MissingEvidence);
    }

    #[test]
    fn p1_production_profile_record_requires_ready_production_readiness() {
        let policy = tenant_policy();
        let production_profile =
            P1ExecutionReadinessProfile::production("tenant.a", vec!["file.read".into()]);
        let missing_error = VaultController::seal_p1_execution_readiness_profile(
            &policy,
            production_profile.clone(),
            "vault.controller",
        )
        .unwrap_err();
        assert_eq!(missing_error, VaultError::MissingEvidence);

        let signature_decision = VaultController::verify_executor_signature(
            &signature(),
            &[trust_root()],
            RiskLevel::High,
        );
        let blocked = VaultController::evaluate_production_readiness(
            &policy,
            &[credential()],
            &[signature_decision],
            &ProductionHardeningEvidence {
                auth_provider_ref: None,
                ..hardening_evidence()
            },
            &all_adapter_evidence(),
        )
        .unwrap();
        assert_eq!(blocked.decision, ProductionReadinessDecisionKind::Blocked);
        let blocked_error = VaultController::seal_production_p1_execution_readiness_profile(
            &policy,
            production_profile.clone(),
            &blocked,
            "vault.controller",
        )
        .unwrap_err();
        assert_eq!(blocked_error, VaultError::MissingEvidence);

        let ready_signature = VaultController::verify_executor_signature(
            &signature(),
            &[trust_root()],
            RiskLevel::High,
        );
        let ready = VaultController::evaluate_production_readiness(
            &policy,
            &[credential()],
            &[ready_signature],
            &hardening_evidence(),
            &all_adapter_evidence(),
        )
        .unwrap();
        let record = VaultController::seal_production_p1_execution_readiness_profile(
            &policy,
            production_profile.clone(),
            &ready,
            "vault.controller",
        )
        .unwrap();

        assert_eq!(
            record.production_readiness_ref,
            Some(ready.decision_id.clone())
        );
        assert_eq!(
            record.production_readiness_evidence_hash,
            Some(production_readiness_evidence_hash(&ready))
        );
        assert!(record
            .evidence_refs
            .contains(record.production_readiness_ref.as_ref().unwrap()));
        assert!(record
            .evidence_refs
            .contains(record.production_readiness_evidence_hash.as_ref().unwrap()));
        assert_eq!(
            VaultController::load_p1_execution_readiness_profile(&record, &policy).unwrap(),
            production_profile
        );
    }

    #[test]
    fn p1_production_profile_record_can_validate_readiness_evidence_hash_on_load() {
        let policy = tenant_policy();
        let policy_record = VaultController::seal_tenant_policy_pack(
            policy,
            vec!["policy.approved.1".into()],
            "vault.controller",
        )
        .unwrap();
        let production_profile =
            P1ExecutionReadinessProfile::production("tenant.a", vec!["file.read".into()]);
        let signature_decision = VaultController::verify_executor_signature(
            &signature(),
            &[trust_root()],
            RiskLevel::High,
        );
        let ready = VaultController::evaluate_production_readiness(
            &tenant_policy(),
            &[credential()],
            &[signature_decision],
            &hardening_evidence(),
            &all_adapter_evidence(),
        )
        .unwrap();
        let record = VaultController::seal_p1_execution_readiness_profile_with_policy_record(
            &policy_record,
            production_profile.clone(),
            Some(&ready),
            "vault.controller",
        )
        .unwrap();

        let loaded =
            VaultController::load_p1_execution_readiness_profile_with_production_readiness(
                &record,
                &policy_record,
                Some(&ready),
            )
            .unwrap();
        assert_eq!(loaded, production_profile);

        let missing_readiness_error =
            VaultController::load_p1_execution_readiness_profile_with_production_readiness(
                &record,
                &policy_record,
                None,
            )
            .unwrap_err();
        assert_eq!(missing_readiness_error, VaultError::MissingEvidence);

        let mut tampered_readiness = ready.clone();
        tampered_readiness
            .evidence_refs
            .push("unreviewed.evidence".into());
        let tampered_readiness_error =
            VaultController::load_p1_execution_readiness_profile_with_production_readiness(
                &record,
                &policy_record,
                Some(&tampered_readiness),
            )
            .unwrap_err();
        assert_eq!(tampered_readiness_error, VaultError::MissingEvidence);

        let mut tampered_record = record;
        tampered_record.production_readiness_evidence_hash =
            Some("production_readiness_evidence_hash.tampered".into());
        let tampered_record_error =
            VaultController::load_p1_execution_readiness_profile_with_production_readiness(
                &tampered_record,
                &policy_record,
                Some(&ready),
            )
            .unwrap_err();
        assert_eq!(tampered_record_error, VaultError::MissingEvidence);
    }

    #[test]
    fn p1_production_profile_record_rejects_missing_production_ref_on_load() {
        let policy = tenant_policy();
        let production_profile =
            P1ExecutionReadinessProfile::production("tenant.a", vec!["file.read".into()]);
        let signature_decision = VaultController::verify_executor_signature(
            &signature(),
            &[trust_root()],
            RiskLevel::High,
        );
        let ready = VaultController::evaluate_production_readiness(
            &policy,
            &[credential()],
            &[signature_decision],
            &hardening_evidence(),
            &all_adapter_evidence(),
        )
        .unwrap();
        let mut record = VaultController::seal_production_p1_execution_readiness_profile(
            &policy,
            production_profile.clone(),
            &ready,
            "vault.controller",
        )
        .unwrap();
        record.production_readiness_ref = None;

        let error =
            VaultController::load_p1_execution_readiness_profile(&record, &policy).unwrap_err();

        assert_eq!(error, VaultError::MissingEvidence);

        let mut record = VaultController::seal_production_p1_execution_readiness_profile(
            &policy,
            production_profile,
            &ready,
            "vault.controller",
        )
        .unwrap();
        record.production_readiness_evidence_hash = None;

        let error =
            VaultController::load_p1_execution_readiness_profile(&record, &policy).unwrap_err();

        assert_eq!(error, VaultError::MissingEvidence);

        let mut record = VaultController::seal_production_p1_execution_readiness_profile(
            &policy,
            P1ExecutionReadinessProfile::production("tenant.a", vec!["file.read".into()]),
            &ready,
            "vault.controller",
        )
        .unwrap();
        let readiness_hash = record.production_readiness_evidence_hash.clone().unwrap();
        record
            .evidence_refs
            .retain(|evidence_ref| evidence_ref != &readiness_hash);

        let error =
            VaultController::load_p1_execution_readiness_profile(&record, &policy).unwrap_err();

        assert_eq!(error, VaultError::MissingEvidence);
    }

    #[test]
    fn p1_execution_readiness_audit_export_is_redacted_and_event_bound() {
        let policy = tenant_policy();
        let profile = P1ExecutionReadinessProfile::local_read_only("tenant.a");
        let record = VaultController::seal_p1_execution_readiness_profile(
            &policy,
            profile.clone(),
            "vault.controller",
        )
        .unwrap();
        let request = P1ExecutionReadinessRequest {
            request_id: "p1.req.audit".into(),
            run_id: "run.audit".into(),
            tenant_id: "tenant.a".into(),
            actor_id: "moxi-runtime".into(),
            capability_id: "file.read".into(),
            permission_mode: PermissionMode::ReadOnly,
            risk_level: RiskLevel::Low,
            requires_credential: false,
            evidence_refs: vec!["policy.decision.audit".into()],
            requested_at: Utc::now(),
        };
        let loaded =
            VaultController::load_p1_execution_readiness_profile(&record, &policy).unwrap();
        let decision =
            VaultController::evaluate_p1_execution_readiness(&loaded, &request, None).unwrap();

        let audit = VaultController::audit_p1_execution_readiness(
            &decision,
            &record,
            "redaction.compliance.v1",
            "auditor.1",
        )
        .unwrap();

        assert_eq!(audit.kind, AuditExportRecordKind::P1ExecutionReadiness);
        assert!(!audit.contains_secret_material);
        assert!(audit.event_refs.contains(&record.record_id));
        assert!(audit.event_refs.contains(&decision.decision_id));

        let mut direct_ticket_decision = decision.clone();
        direct_ticket_decision.can_issue_ticket_directly = true;
        let direct_ticket_error = VaultController::audit_p1_execution_readiness(
            &direct_ticket_decision,
            &record,
            "redaction.compliance.v1",
            "auditor.1",
        )
        .unwrap_err();
        assert_eq!(direct_ticket_error, VaultError::MissingEvidence);

        let mut missing_profile_evidence_decision = decision;
        missing_profile_evidence_decision
            .evidence_refs
            .retain(|evidence_ref| evidence_ref != "p1.local-readonly.profile");
        let missing_profile_evidence_error = VaultController::audit_p1_execution_readiness(
            &missing_profile_evidence_decision,
            &record,
            "redaction.compliance.v1",
            "auditor.1",
        )
        .unwrap_err();
        assert_eq!(missing_profile_evidence_error, VaultError::MissingEvidence);
    }

    #[test]
    fn p1_execution_audit_bundle_is_redacted_and_chain_bound() {
        let policy = tenant_policy();
        let profile = P1ExecutionReadinessProfile::local_read_only("tenant.a");
        let record = VaultController::seal_p1_execution_readiness_profile(
            &policy,
            profile.clone(),
            "vault.controller",
        )
        .unwrap();
        let request = P1ExecutionReadinessRequest {
            request_id: "p1.req.bundle".into(),
            run_id: "run.bundle".into(),
            tenant_id: "tenant.a".into(),
            actor_id: "moxi-runtime".into(),
            capability_id: "file.read".into(),
            permission_mode: PermissionMode::ReadOnly,
            risk_level: RiskLevel::Low,
            requires_credential: false,
            evidence_refs: vec!["policy.decision.bundle".into(), "runtime.task.1".into()],
            requested_at: Utc::now(),
        };
        let loaded =
            VaultController::load_p1_execution_readiness_profile(&record, &policy).unwrap();
        let decision =
            VaultController::evaluate_p1_execution_readiness(&loaded, &request, None).unwrap();
        let audit = VaultController::audit_p1_execution_readiness(
            &decision,
            &record,
            "redaction.compliance.v1",
            "auditor.1",
        )
        .unwrap();

        let bundle =
            VaultController::p1_execution_audit_bundle(&request, &decision, &record, &audit, None)
                .unwrap();

        assert_eq!(bundle.tenant_id, "tenant.a");
        assert_eq!(bundle.run_id, request.run_id);
        assert_eq!(bundle.profile_record_ref, record.record_id);
        assert_eq!(bundle.tenant_policy_pack_ref, policy.pack_id);
        assert_eq!(
            bundle.tenant_policy_record_ref,
            record.tenant_policy_record_ref
        );
        assert_eq!(bundle.tenant_policy_hash, record.tenant_policy_hash);
        assert_eq!(bundle.readiness_decision_ref, decision.decision_id);
        assert_eq!(bundle.audit_export_ref, audit.export_id);
        assert_eq!(bundle.audit_export_hash, audit.export_hash);
        assert_eq!(bundle.redaction_profile_ref, "redaction.compliance.v1");
        assert!(bundle.production_readiness_ref.is_none());
        assert!(bundle.can_enter_p0_execution_chain);
        assert!(!bundle.can_issue_ticket_directly);
        assert!(!bundle.can_execute_without_p0);
        assert!(!bundle.contains_secret_material);
        assert!(bundle
            .bundle_hash
            .starts_with("p1_execution_audit_bundle_hash."));
        assert!(bundle.evidence_refs.contains(&"runtime.task.1".into()));
        assert!(bundle.evidence_refs.contains(&record.tenant_policy_hash));
        assert!(bundle.evidence_refs.contains(&audit.export_hash));

        let mut missing_request_evidence_decision = decision.clone();
        missing_request_evidence_decision
            .evidence_refs
            .retain(|evidence_ref| evidence_ref != "runtime.task.1");
        let missing_request_evidence_error = VaultController::p1_execution_audit_bundle(
            &request,
            &missing_request_evidence_decision,
            &record,
            &audit,
            None,
        )
        .unwrap_err();
        assert_eq!(missing_request_evidence_error, VaultError::MissingEvidence);

        let mut bypass_p0_decision = decision;
        bypass_p0_decision.can_execute_without_p0 = true;
        let bypass_p0_error = VaultController::p1_execution_audit_bundle(
            &request,
            &bypass_p0_decision,
            &record,
            &audit,
            None,
        )
        .unwrap_err();
        assert_eq!(bypass_p0_error, VaultError::MissingEvidence);
    }

    #[test]
    fn compliance_export_bundle_rejects_tampered_p1_execution_bundle_hash() {
        let policy = tenant_policy();
        let policy_record = VaultController::seal_tenant_policy_pack(
            policy.clone(),
            vec!["policy.approved.1".into()],
            "vault.controller",
        )
        .unwrap();
        let profile = P1ExecutionReadinessProfile::local_read_only("tenant.a");
        let profile_record =
            VaultController::seal_p1_execution_readiness_profile_with_policy_record(
                &policy_record,
                profile.clone(),
                None,
                "vault.controller",
            )
            .unwrap();
        let request = P1ExecutionReadinessRequest {
            request_id: "p1.req.tamper.bundle".into(),
            run_id: "run.tamper.bundle".into(),
            tenant_id: "tenant.a".into(),
            actor_id: "moxi-runtime".into(),
            capability_id: "file.read".into(),
            permission_mode: PermissionMode::ReadOnly,
            risk_level: RiskLevel::Low,
            requires_credential: false,
            evidence_refs: vec!["policy.decision.tamper.bundle".into()],
            requested_at: Utc::now(),
        };
        let decision =
            VaultController::evaluate_p1_execution_readiness(&profile, &request, None).unwrap();
        let audit = VaultController::audit_p1_execution_readiness(
            &decision,
            &profile_record,
            "redaction.compliance.v1",
            "auditor.1",
        )
        .unwrap();
        let bundle = VaultController::p1_execution_audit_bundle(
            &request,
            &decision,
            &profile_record,
            &audit,
            None,
        )
        .unwrap();

        let mut tampered_hash = bundle.clone();
        tampered_hash.bundle_hash = "p1_execution_audit_bundle_hash.tampered".into();
        let hash_error = VaultController::compliance_export_bundle(
            "run.tamper.bundle",
            &policy_record,
            std::slice::from_ref(&audit),
            &[tampered_hash],
            None,
            "auditor.1",
        )
        .unwrap_err();
        assert_eq!(hash_error, VaultError::MissingEvidence);

        let mut tampered_export_hash = bundle;
        tampered_export_hash.audit_export_hash = "audit_export_hash.tampered".into();
        let export_hash_error = VaultController::compliance_export_bundle(
            "run.tamper.bundle",
            &policy_record,
            std::slice::from_ref(&audit),
            &[tampered_export_hash],
            None,
            "auditor.1",
        )
        .unwrap_err();
        assert_eq!(export_hash_error, VaultError::MissingEvidence);
    }

    #[test]
    fn p1_execution_audit_bundle_preserves_production_readiness_ref() {
        let policy = tenant_policy();
        let signature_decision = VaultController::verify_executor_signature(
            &signature(),
            &[trust_root()],
            RiskLevel::High,
        );
        let production_readiness = VaultController::evaluate_production_readiness(
            &policy,
            &[credential()],
            &[signature_decision],
            &hardening_evidence(),
            &all_adapter_evidence(),
        )
        .unwrap();
        let production_profile =
            P1ExecutionReadinessProfile::production("tenant.a", vec!["file.read".into()]);
        let record = VaultController::seal_production_p1_execution_readiness_profile(
            &policy,
            production_profile.clone(),
            &production_readiness,
            "vault.controller",
        )
        .unwrap();
        let request = P1ExecutionReadinessRequest {
            request_id: "p1.req.prod.bundle".into(),
            run_id: "run.prod.bundle".into(),
            tenant_id: "tenant.a".into(),
            actor_id: "moxi-runtime".into(),
            capability_id: "file.read".into(),
            permission_mode: PermissionMode::ReadOnly,
            risk_level: RiskLevel::High,
            requires_credential: true,
            evidence_refs: vec!["policy.decision.prod.bundle".into()],
            requested_at: Utc::now(),
        };
        let decision = VaultController::evaluate_p1_execution_readiness(
            &production_profile,
            &request,
            Some(&production_readiness),
        )
        .unwrap();
        let audit = VaultController::audit_p1_execution_readiness(
            &decision,
            &record,
            "redaction.compliance.v1",
            "auditor.1",
        )
        .unwrap();

        let bundle = VaultController::p1_execution_audit_bundle(
            &request,
            &decision,
            &record,
            &audit,
            Some(&production_readiness),
        )
        .unwrap();

        assert_eq!(
            bundle.production_readiness_ref,
            Some(production_readiness.decision_id.clone())
        );
        assert_eq!(
            bundle.production_readiness_evidence_hash,
            Some(production_readiness_evidence_hash(&production_readiness))
        );
        assert!(bundle
            .evidence_refs
            .contains(&production_readiness.decision_id));
        assert!(bundle
            .evidence_refs
            .contains(bundle.production_readiness_evidence_hash.as_ref().unwrap()));
        assert!(bundle.can_enter_p0_execution_chain);
        assert!(!bundle.can_issue_ticket_directly);
        assert!(!bundle.can_execute_without_p0);

        let mut tampered_record = record;
        tampered_record.production_readiness_evidence_hash =
            Some("production_readiness_evidence_hash.tampered".into());
        let tampered_error = VaultController::p1_execution_audit_bundle(
            &request,
            &decision,
            &tampered_record,
            &audit,
            Some(&production_readiness),
        )
        .unwrap_err();
        assert_eq!(tampered_error, VaultError::MissingEvidence);
    }

    #[test]
    fn p1_execution_audit_bundle_rejects_unbound_or_cross_tenant_inputs() {
        let policy = tenant_policy();
        let profile = P1ExecutionReadinessProfile::local_read_only("tenant.a");
        let record = VaultController::seal_p1_execution_readiness_profile(
            &policy,
            profile.clone(),
            "vault.controller",
        )
        .unwrap();
        let request = P1ExecutionReadinessRequest {
            request_id: "p1.req.reject.bundle".into(),
            run_id: "run.reject.bundle".into(),
            tenant_id: "tenant.a".into(),
            actor_id: "moxi-runtime".into(),
            capability_id: "file.read".into(),
            permission_mode: PermissionMode::ReadOnly,
            risk_level: RiskLevel::Low,
            requires_credential: false,
            evidence_refs: vec!["policy.decision.reject.bundle".into()],
            requested_at: Utc::now(),
        };
        let loaded =
            VaultController::load_p1_execution_readiness_profile(&record, &policy).unwrap();
        let decision =
            VaultController::evaluate_p1_execution_readiness(&loaded, &request, None).unwrap();
        let audit = VaultController::audit_p1_execution_readiness(
            &decision,
            &record,
            "redaction.compliance.v1",
            "auditor.1",
        )
        .unwrap();

        let wrong_audit = AuditExportRecord {
            event_refs: vec![decision.decision_id.clone()],
            ..audit.clone()
        };
        let unbound_error = VaultController::p1_execution_audit_bundle(
            &request,
            &decision,
            &record,
            &wrong_audit,
            None,
        )
        .unwrap_err();
        assert_eq!(unbound_error, VaultError::MissingEvidence);

        let mut tampered_hash_audit = audit.clone();
        tampered_hash_audit
            .event_refs
            .push("unhashed.audit.event".into());
        let tampered_hash_error = VaultController::p1_execution_audit_bundle(
            &request,
            &decision,
            &record,
            &tampered_hash_audit,
            None,
        )
        .unwrap_err();
        assert_eq!(tampered_hash_error, VaultError::MissingEvidence);

        let cross_tenant_request = P1ExecutionReadinessRequest {
            tenant_id: "tenant.b".into(),
            ..request
        };
        let tenant_error = VaultController::p1_execution_audit_bundle(
            &cross_tenant_request,
            &decision,
            &record,
            &audit,
            None,
        )
        .unwrap_err();
        assert_eq!(tenant_error, VaultError::TenantMismatch);
    }

    #[test]
    fn compliance_export_bundle_is_redacted_and_evidence_bound() {
        let policy = tenant_policy();
        let policy_record = VaultController::seal_tenant_policy_pack(
            policy.clone(),
            vec!["policy.approved.1".into()],
            "vault.controller",
        )
        .unwrap();
        let profile = P1ExecutionReadinessProfile::local_read_only("tenant.a");
        let profile_record =
            VaultController::seal_p1_execution_readiness_profile_with_policy_record(
                &policy_record,
                profile.clone(),
                None,
                "vault.controller",
            )
            .unwrap();
        let request = P1ExecutionReadinessRequest {
            request_id: "p1.req.compliance".into(),
            run_id: "run.compliance".into(),
            tenant_id: "tenant.a".into(),
            actor_id: "moxi-runtime".into(),
            capability_id: "file.read".into(),
            permission_mode: PermissionMode::ReadOnly,
            risk_level: RiskLevel::Low,
            requires_credential: false,
            evidence_refs: vec!["policy.decision.compliance".into()],
            requested_at: Utc::now(),
        };
        let decision =
            VaultController::evaluate_p1_execution_readiness(&profile, &request, None).unwrap();
        let readiness_export = VaultController::audit_p1_execution_readiness(
            &decision,
            &profile_record,
            "redaction.compliance.v1",
            "auditor.1",
        )
        .unwrap();
        let p1_bundle = VaultController::p1_execution_audit_bundle(
            &request,
            &decision,
            &profile_record,
            &readiness_export,
            None,
        )
        .unwrap();
        let run_export = VaultController::audit_export_record(
            "tenant.a",
            "run.compliance",
            AuditExportRecordKind::Run,
            "redaction.compliance.v1",
            vec![
                "ledger.run.compliance".into(),
                "proof.run.compliance".into(),
            ],
            "auditor.1",
        )
        .unwrap();

        let bundle = VaultController::compliance_export_bundle(
            "run.compliance",
            &policy_record,
            &[run_export.clone(), readiness_export.clone()],
            std::slice::from_ref(&p1_bundle),
            None,
            "auditor.1",
        )
        .unwrap();

        assert_eq!(bundle.tenant_id, "tenant.a");
        assert_eq!(bundle.scope_ref, "run.compliance");
        assert_eq!(bundle.tenant_policy_record_ref, policy_record.record_id);
        assert_eq!(bundle.tenant_policy_hash, policy_record.policy_hash);
        assert_eq!(bundle.redaction_profile_ref, "redaction.compliance.v1");
        assert!(bundle.production_readiness_ref.is_none());
        assert!(!bundle.contains_secret_material);
        assert!(bundle.audit_export_refs.contains(&run_export.export_id));
        assert!(bundle
            .audit_export_refs
            .contains(&readiness_export.export_id));
        assert!(bundle
            .p1_execution_bundle_refs
            .contains(&p1_bundle.bundle_id));
        assert!(bundle.event_refs.contains(&"ledger.run.compliance".into()));
        assert!(bundle.evidence_refs.contains(&policy_record.policy_hash));
        assert!(bundle
            .bundle_hash
            .starts_with("compliance_export_bundle_hash."));
    }

    #[test]
    fn compliance_export_bundle_preserves_production_readiness_ref() {
        let policy = tenant_policy();
        let policy_record = VaultController::seal_tenant_policy_pack(
            policy.clone(),
            vec!["policy.approved.1".into()],
            "vault.controller",
        )
        .unwrap();
        let signature_decision = VaultController::verify_executor_signature(
            &signature(),
            &[trust_root()],
            RiskLevel::High,
        );
        let production_readiness = VaultController::evaluate_production_readiness(
            &policy,
            &[credential()],
            &[signature_decision],
            &hardening_evidence(),
            &all_adapter_evidence(),
        )
        .unwrap();
        let export = VaultController::audit_export_record(
            "tenant.a",
            "production.enablement",
            AuditExportRecordKind::Run,
            "redaction.compliance.v1",
            vec![production_readiness.decision_id.clone()],
            "auditor.1",
        )
        .unwrap();

        let bundle = VaultController::compliance_export_bundle(
            "production.enablement",
            &policy_record,
            &[export],
            &[],
            Some(&production_readiness),
            "auditor.1",
        )
        .unwrap();

        assert_eq!(
            bundle.production_readiness_ref,
            Some(production_readiness.decision_id.clone())
        );
        assert_eq!(
            bundle.production_readiness_evidence_hash,
            Some(production_readiness_evidence_hash(&production_readiness))
        );
        assert!(bundle
            .evidence_refs
            .contains(&production_readiness.decision_id));
        assert!(bundle
            .evidence_refs
            .contains(bundle.production_readiness_evidence_hash.as_ref().unwrap()));
    }

    #[test]
    fn compliance_export_delivery_decision_is_bundle_hash_bound_and_fail_closed() {
        let policy = tenant_policy();
        let policy_record = VaultController::seal_tenant_policy_pack(
            policy,
            vec!["policy.approved.1".into()],
            "vault.controller",
        )
        .unwrap();
        let export = VaultController::audit_export_record(
            "tenant.a",
            "run.compliance.delivery",
            AuditExportRecordKind::Run,
            "redaction.compliance.v1",
            vec!["ledger.delivery".into(), "proof.delivery".into()],
            "auditor.1",
        )
        .unwrap();
        let bundle = VaultController::compliance_export_bundle(
            "run.compliance.delivery",
            &policy_record,
            std::slice::from_ref(&export),
            &[],
            None,
            "auditor.1",
        )
        .unwrap();
        let evidence = compliance_delivery_evidence(&bundle);
        let decision = VaultController::verify_compliance_export_delivery(&bundle, &evidence);

        assert_eq!(
            decision.decision,
            ComplianceExportDeliveryDecisionKind::Verified
        );
        assert_eq!(decision.tenant_id, bundle.tenant_id);
        assert_eq!(decision.bundle_id, bundle.bundle_id);
        assert_eq!(decision.bundle_hash, bundle.bundle_hash);
        assert_eq!(decision.tenant_policy_hash, bundle.tenant_policy_hash);
        assert_eq!(decision.production_readiness_evidence_hash, None);
        assert_eq!(decision.delivery_evidence_ref, evidence.evidence_id);
        assert!(decision.evidence_refs.contains(&bundle.bundle_hash));
        assert!(decision.evidence_refs.contains(&bundle.tenant_policy_hash));
        assert!(decision.evidence_refs.contains(&evidence.receipt_ref));

        let mut hash_mismatch = evidence.clone();
        hash_mismatch.bundle_hash = "compliance_export_bundle_hash.tampered".into();
        let rejected_hash =
            VaultController::verify_compliance_export_delivery(&bundle, &hash_mismatch);
        assert_eq!(
            rejected_hash.decision,
            ComplianceExportDeliveryDecisionKind::Rejected
        );
        assert!(!rejected_hash.reasons.is_empty());

        let mut placeholder_receipt = evidence;
        placeholder_receipt.receipt_ref = "mock-receipt".into();
        let rejected_placeholder =
            VaultController::verify_compliance_export_delivery(&bundle, &placeholder_receipt);
        assert_eq!(
            rejected_placeholder.decision,
            ComplianceExportDeliveryDecisionKind::Rejected
        );
        assert!(!rejected_placeholder.reasons.is_empty());

        let mut tampered_bundle_hash = bundle.clone();
        tampered_bundle_hash.bundle_hash = "compliance_export_bundle_hash.tampered".into();
        let evidence_for_tampered_hash = compliance_delivery_evidence(&tampered_bundle_hash);
        let rejected_tampered_bundle = VaultController::verify_compliance_export_delivery(
            &tampered_bundle_hash,
            &evidence_for_tampered_hash,
        );
        assert_eq!(
            rejected_tampered_bundle.decision,
            ComplianceExportDeliveryDecisionKind::Rejected
        );
        assert!(!rejected_tampered_bundle.reasons.is_empty());

        let mut evidence_stripped_bundle = bundle;
        evidence_stripped_bundle
            .evidence_refs
            .retain(|evidence_ref| evidence_ref != &evidence_stripped_bundle.tenant_policy_hash);
        let evidence_for_stripped_bundle = compliance_delivery_evidence(&evidence_stripped_bundle);
        let rejected_stripped_bundle = VaultController::verify_compliance_export_delivery(
            &evidence_stripped_bundle,
            &evidence_for_stripped_bundle,
        );
        assert_eq!(
            rejected_stripped_bundle.decision,
            ComplianceExportDeliveryDecisionKind::Rejected
        );
        assert!(!rejected_stripped_bundle.reasons.is_empty());
    }

    #[test]
    fn production_readiness_rejects_tampered_compliance_delivery_decision_id() {
        let mut fixtures = production_hardening_decision_fixtures();
        fixtures.compliance_export_delivery_decisions[0].decision_id =
            "compliance_export_delivery.tampered".into();

        let error = VaultController::evaluate_production_readiness_with_hardening_decision_set(
            &tenant_policy(),
            std::slice::from_ref(&fixtures.credential),
            std::slice::from_ref(&fixtures.signature_decision),
            &fixtures.hardening,
            &fixtures.adapters,
            &fixtures.adapter_decisions,
            fixtures.decision_set(),
        )
        .unwrap_err();

        assert_eq!(error, VaultError::MissingEvidence);
    }

    #[test]
    fn compliance_export_delivery_decision_can_bind_verified_adapter_decision() {
        let policy_record = VaultController::seal_tenant_policy_pack(
            tenant_policy(),
            vec!["policy.approved.1".into()],
            "vault.controller",
        )
        .unwrap();
        let export = VaultController::audit_export_record(
            "tenant.a",
            "run.compliance.adapter",
            AuditExportRecordKind::Run,
            "redaction.compliance.v1",
            vec!["ledger.adapter".into(), "proof.adapter".into()],
            "auditor.1",
        )
        .unwrap();
        let bundle = VaultController::compliance_export_bundle(
            "run.compliance.adapter",
            &policy_record,
            std::slice::from_ref(&export),
            &[],
            None,
            "auditor.1",
        )
        .unwrap();
        let adapter_decision =
            VaultController::verify_production_adapter_evidence(&adapter_evidence(
                ProductionAdapterKind::ComplianceAuditExport,
                "compliance-store://tenant.a/prod-archive",
            ));
        let mut evidence = compliance_delivery_evidence(&bundle);
        evidence.adapter_decision_ref = Some(adapter_decision.decision_id.clone());
        let decision = VaultController::verify_compliance_export_delivery_with_adapter_decision(
            &bundle,
            &evidence,
            &adapter_decision,
        );

        assert_eq!(
            decision.decision,
            ComplianceExportDeliveryDecisionKind::Verified
        );
        assert_eq!(
            decision.adapter_decision_ref,
            Some(adapter_decision.decision_id.clone())
        );
        assert_eq!(decision.tenant_policy_hash, bundle.tenant_policy_hash);
        assert!(decision
            .evidence_refs
            .contains(&adapter_decision.decision_id));
        assert!(decision.evidence_refs.contains(&bundle.bundle_hash));

        let wrong_adapter = VaultController::verify_production_adapter_evidence(&adapter_evidence(
            ProductionAdapterKind::RotationEnforcement,
            "rotation://tenant.a/30d-enforced",
        ));
        let mut wrong_adapter_evidence = evidence.clone();
        wrong_adapter_evidence.adapter_decision_ref = Some(wrong_adapter.decision_id.clone());
        let rejected_kind =
            VaultController::verify_compliance_export_delivery_with_adapter_decision(
                &bundle,
                &wrong_adapter_evidence,
                &wrong_adapter,
            );
        assert_eq!(
            rejected_kind.decision,
            ComplianceExportDeliveryDecisionKind::Rejected
        );
        assert!(!rejected_kind.reasons.is_empty());

        let mismatched_adapter =
            VaultController::verify_production_adapter_evidence(&adapter_evidence(
                ProductionAdapterKind::ComplianceAuditExport,
                "compliance-store://tenant.a/other",
            ));
        let mut mismatched_evidence = evidence.clone();
        mismatched_evidence.adapter_decision_ref = Some(mismatched_adapter.decision_id.clone());
        let rejected_provider =
            VaultController::verify_compliance_export_delivery_with_adapter_decision(
                &bundle,
                &mismatched_evidence,
                &mismatched_adapter,
            );
        assert_eq!(
            rejected_provider.decision,
            ComplianceExportDeliveryDecisionKind::Rejected
        );
        assert!(!rejected_provider.reasons.is_empty());

        let mut missing_ref = evidence.clone();
        missing_ref.adapter_decision_ref = None;
        let rejected_missing_ref =
            VaultController::verify_compliance_export_delivery_with_adapter_decision(
                &bundle,
                &missing_ref,
                &adapter_decision,
            );
        assert_eq!(
            rejected_missing_ref.decision,
            ComplianceExportDeliveryDecisionKind::Rejected
        );
        assert!(!rejected_missing_ref.reasons.is_empty());

        let mut rejected_adapter_decision = adapter_decision;
        rejected_adapter_decision.decision = ProductionAdapterVerificationKind::Rejected;
        let rejected_adapter =
            VaultController::verify_compliance_export_delivery_with_adapter_decision(
                &bundle,
                &evidence,
                &rejected_adapter_decision,
            );
        assert_eq!(
            rejected_adapter.decision,
            ComplianceExportDeliveryDecisionKind::Rejected
        );
        assert!(!rejected_adapter.reasons.is_empty());
    }

    #[test]
    fn compliance_export_delivery_decision_carries_readiness_evidence_hash() {
        let policy = tenant_policy();
        let policy_record = VaultController::seal_tenant_policy_pack(
            policy.clone(),
            vec!["policy.approved.1".into()],
            "vault.controller",
        )
        .unwrap();
        let signature_decision = VaultController::verify_executor_signature(
            &signature(),
            &[trust_root()],
            RiskLevel::High,
        );
        let production_readiness = VaultController::evaluate_production_readiness(
            &policy,
            &[credential()],
            &[signature_decision],
            &hardening_evidence(),
            &all_adapter_evidence(),
        )
        .unwrap();
        let export = VaultController::audit_export_record(
            "tenant.a",
            "production.delivery.readiness",
            AuditExportRecordKind::Run,
            "redaction.compliance.v1",
            vec![production_readiness.decision_id.clone()],
            "auditor.1",
        )
        .unwrap();
        let bundle = VaultController::compliance_export_bundle(
            "production.delivery.readiness",
            &policy_record,
            &[export],
            &[],
            Some(&production_readiness),
            "auditor.1",
        )
        .unwrap();
        let evidence = compliance_delivery_evidence(&bundle);
        let decision = VaultController::verify_compliance_export_delivery(&bundle, &evidence);

        assert_eq!(
            decision.production_readiness_evidence_hash,
            Some(production_readiness_evidence_hash(&production_readiness))
        );
        assert!(decision.evidence_refs.contains(
            decision
                .production_readiness_evidence_hash
                .as_ref()
                .unwrap()
        ));
        assert!(decision.evidence_refs.contains(&bundle.tenant_policy_hash));

        let mut tampered_bundle = bundle;
        tampered_bundle.production_readiness_evidence_hash =
            Some("production_readiness_evidence_hash.tampered".into());
        let tampered_decision =
            VaultController::verify_compliance_export_delivery(&tampered_bundle, &evidence);

        assert_eq!(
            tampered_decision.decision,
            ComplianceExportDeliveryDecisionKind::Rejected
        );
        assert!(!tampered_decision.reasons.is_empty());
    }

    #[test]
    fn compliance_export_bundle_rejects_cross_tenant_or_inconsistent_redaction() {
        let policy = tenant_policy();
        let policy_record = VaultController::seal_tenant_policy_pack(
            policy,
            vec!["policy.approved.1".into()],
            "vault.controller",
        )
        .unwrap();
        let export = VaultController::audit_export_record(
            "tenant.a",
            "run.compliance.reject",
            AuditExportRecordKind::Run,
            "redaction.compliance.v1",
            vec!["ledger.reject".into()],
            "auditor.1",
        )
        .unwrap();
        let other_redaction = VaultController::audit_export_record(
            "tenant.a",
            "run.compliance.reject",
            AuditExportRecordKind::CredentialUse,
            "redaction.other.v1",
            vec!["secret.reject".into()],
            "auditor.1",
        )
        .unwrap();
        let redaction_error = VaultController::compliance_export_bundle(
            "run.compliance.reject",
            &policy_record,
            &[export.clone(), other_redaction],
            &[],
            None,
            "auditor.1",
        )
        .unwrap_err();
        assert_eq!(redaction_error, VaultError::MissingEvidence);

        let cross_tenant = AuditExportRecord {
            tenant_id: "tenant.b".into(),
            ..export.clone()
        };
        let tenant_error = VaultController::compliance_export_bundle(
            "run.compliance.reject",
            &policy_record,
            &[cross_tenant],
            &[],
            None,
            "auditor.1",
        )
        .unwrap_err();
        assert_eq!(tenant_error, VaultError::TenantMismatch);

        let mut tampered_hash = export;
        tampered_hash.redaction_profile_ref = "redaction.changed.without.hash".into();
        let hash_error = VaultController::compliance_export_bundle(
            "run.compliance.reject",
            &policy_record,
            &[tampered_hash],
            &[],
            None,
            "auditor.1",
        )
        .unwrap_err();
        assert_eq!(hash_error, VaultError::MissingEvidence);
    }

    #[test]
    fn production_adapter_evidence_verification_is_tenant_bound_and_fail_closed() {
        let evidence =
            adapter_evidence(ProductionAdapterKind::AuthProvider, "oidc://prod/tenant.a");
        let decision = VaultController::verify_production_adapter_evidence(&evidence);

        assert_eq!(
            decision.decision,
            ProductionAdapterVerificationKind::Verified
        );
        assert_eq!(decision.tenant_id, evidence.tenant_id);
        assert_eq!(decision.evidence_id, evidence.evidence_id);
        assert_eq!(decision.kind, evidence.kind);
        assert!(decision.evidence_refs.contains(&evidence.attestation_ref));
        assert!(decision.evidence_refs.contains(&evidence.healthcheck_ref));

        let mut placeholder = evidence;
        placeholder.healthcheck_ref = "mock-healthcheck".into();
        let rejected = VaultController::verify_production_adapter_evidence(&placeholder);

        assert_eq!(
            rejected.decision,
            ProductionAdapterVerificationKind::Rejected
        );
        assert!(!rejected.reasons.is_empty());
    }

    #[test]
    fn production_auth_decision_is_provider_and_adapter_bound_fail_closed() {
        let hardening = hardening_evidence();
        let adapter_decision = VaultController::verify_production_adapter_evidence(
            &adapter_evidence(ProductionAdapterKind::AuthProvider, "oidc://prod/tenant.a"),
        );
        let evidence = production_auth_evidence(&adapter_decision);
        let decision =
            VaultController::verify_production_auth(&hardening, &adapter_decision, &evidence);

        assert_eq!(decision.decision, ProductionAuthDecisionKind::Verified);
        assert_eq!(decision.tenant_id, "tenant.a");
        assert_eq!(decision.auth_provider_ref, "oidc://prod/tenant.a");
        assert!(decision
            .evidence_refs
            .contains(&adapter_decision.decision_id));
        assert!(decision.evidence_refs.contains(&evidence.evidence_id));
        assert!(decision.evidence_refs.contains(&evidence.jwks_ref));

        let mut placeholder_jwks = evidence.clone();
        placeholder_jwks.jwks_ref = "mock-jwks".into();
        let rejected_jwks = VaultController::verify_production_auth(
            &hardening,
            &adapter_decision,
            &placeholder_jwks,
        );
        assert_eq!(rejected_jwks.decision, ProductionAuthDecisionKind::Rejected);
        assert!(!rejected_jwks.reasons.is_empty());

        let mut provider_mismatch = evidence.clone();
        provider_mismatch.auth_provider_ref = "oidc://prod/tenant.a/other".into();
        let rejected_provider = VaultController::verify_production_auth(
            &hardening,
            &adapter_decision,
            &provider_mismatch,
        );
        assert_eq!(
            rejected_provider.decision,
            ProductionAuthDecisionKind::Rejected
        );
        assert!(!rejected_provider.reasons.is_empty());

        let wrong_adapter = VaultController::verify_production_adapter_evidence(&adapter_evidence(
            ProductionAdapterKind::ExternalSecretManager,
            "kms://tenant.a/prod",
        ));
        let mut wrong_adapter_evidence = evidence;
        wrong_adapter_evidence.adapter_decision_ref = wrong_adapter.decision_id.clone();
        let rejected_adapter = VaultController::verify_production_auth(
            &hardening,
            &wrong_adapter,
            &wrong_adapter_evidence,
        );
        assert_eq!(
            rejected_adapter.decision,
            ProductionAuthDecisionKind::Rejected
        );
        assert!(!rejected_adapter.reasons.is_empty());
    }

    #[test]
    fn external_secret_manager_decision_is_credential_and_adapter_bound_fail_closed() {
        let credential = credential();
        let hardening = hardening_evidence();
        let adapter_decision =
            VaultController::verify_production_adapter_evidence(&adapter_evidence(
                ProductionAdapterKind::ExternalSecretManager,
                "kms://tenant.a/prod",
            ));
        let evidence = external_secret_manager_evidence(&credential, &adapter_decision);
        let decision = VaultController::verify_external_secret_manager(
            &credential,
            &hardening,
            &adapter_decision,
            &evidence,
        );

        assert_eq!(
            decision.decision,
            ExternalSecretManagerDecisionKind::Verified
        );
        assert_eq!(decision.tenant_id, credential.tenant_id);
        assert_eq!(decision.credential_id, credential.credential_id);
        assert_eq!(decision.external_secret_ref, credential.external_secret_ref);
        assert_eq!(decision.secret_manager_ref, "kms://tenant.a/prod");
        assert!(decision
            .evidence_refs
            .contains(&adapter_decision.decision_id));
        assert!(decision.evidence_refs.contains(&evidence.evidence_id));
        assert!(decision.evidence_refs.contains(&evidence.hsm_partition_ref));

        let mut placeholder_hsm = evidence.clone();
        placeholder_hsm.hsm_partition_ref = "mock-hsm".into();
        let rejected_hsm = VaultController::verify_external_secret_manager(
            &credential,
            &hardening,
            &adapter_decision,
            &placeholder_hsm,
        );
        assert_eq!(
            rejected_hsm.decision,
            ExternalSecretManagerDecisionKind::Rejected
        );
        assert!(!rejected_hsm.reasons.is_empty());

        let mut credential_mismatch = evidence.clone();
        credential_mismatch.external_secret_ref = "vault://tenant.a/github/other-token".into();
        let rejected_credential = VaultController::verify_external_secret_manager(
            &credential,
            &hardening,
            &adapter_decision,
            &credential_mismatch,
        );
        assert_eq!(
            rejected_credential.decision,
            ExternalSecretManagerDecisionKind::Rejected
        );
        assert!(!rejected_credential.reasons.is_empty());

        let wrong_adapter = VaultController::verify_production_adapter_evidence(&adapter_evidence(
            ProductionAdapterKind::AuthProvider,
            "oidc://prod/tenant.a",
        ));
        let mut wrong_adapter_evidence = evidence;
        wrong_adapter_evidence.adapter_decision_ref = wrong_adapter.decision_id.clone();
        let rejected_adapter = VaultController::verify_external_secret_manager(
            &credential,
            &hardening,
            &wrong_adapter,
            &wrong_adapter_evidence,
        );
        assert_eq!(
            rejected_adapter.decision,
            ExternalSecretManagerDecisionKind::Rejected
        );
        assert!(!rejected_adapter.reasons.is_empty());
    }

    #[test]
    fn cryptographic_verifier_decision_is_signature_and_trust_root_bound_fail_closed() {
        let hardening = hardening_evidence();
        let trust_root_record = VaultController::seal_trust_root(
            trust_root(),
            vec!["security.import.review".into()],
            "vault.controller",
        )
        .unwrap();
        let signature_decision =
            VaultController::verify_executor_signature_with_trust_root_records(
                &signature(),
                std::slice::from_ref(&trust_root_record),
                RiskLevel::High,
            )
            .unwrap();
        let adapter_decision =
            VaultController::verify_production_adapter_evidence(&adapter_evidence(
                ProductionAdapterKind::CryptographicVerifier,
                "sigstore://tenant.a/verifier",
            ));
        let evidence = cryptographic_verifier_evidence(
            &signature_decision,
            &trust_root_record,
            &adapter_decision,
        );
        let decision = VaultController::verify_cryptographic_verifier(
            &hardening,
            &signature_decision,
            &trust_root_record,
            &adapter_decision,
            &evidence,
        );

        assert_eq!(
            decision.decision,
            CryptographicVerifierDecisionKind::Verified
        );
        assert_eq!(decision.tenant_id, hardening.tenant_id);
        assert_eq!(
            decision.signature_decision_ref,
            signature_decision.decision_id
        );
        assert_eq!(decision.trust_root_record_ref, trust_root_record.record_id);
        assert_eq!(
            decision.cryptographic_verifier_ref,
            "sigstore://tenant.a/verifier"
        );
        assert!(decision
            .evidence_refs
            .contains(&adapter_decision.decision_id));
        assert!(decision
            .evidence_refs
            .contains(&trust_root_record.trust_root_hash));

        let mut placeholder_log = evidence.clone();
        placeholder_log.transparency_log_ref = "mock-log".into();
        let rejected_log = VaultController::verify_cryptographic_verifier(
            &hardening,
            &signature_decision,
            &trust_root_record,
            &adapter_decision,
            &placeholder_log,
        );
        assert_eq!(
            rejected_log.decision,
            CryptographicVerifierDecisionKind::Rejected
        );
        assert!(!rejected_log.reasons.is_empty());

        let mut rejected_signature = signature_decision.clone();
        rejected_signature.decision = SignatureVerificationKind::Rejected;
        let rejected_signature_decision = VaultController::verify_cryptographic_verifier(
            &hardening,
            &rejected_signature,
            &trust_root_record,
            &adapter_decision,
            &evidence,
        );
        assert_eq!(
            rejected_signature_decision.decision,
            CryptographicVerifierDecisionKind::Rejected
        );
        assert!(!rejected_signature_decision.reasons.is_empty());

        let mut hash_mismatch = evidence.clone();
        hash_mismatch.trust_root_hash = "trust_root_hash.tampered".into();
        let rejected_hash = VaultController::verify_cryptographic_verifier(
            &hardening,
            &signature_decision,
            &trust_root_record,
            &adapter_decision,
            &hash_mismatch,
        );
        assert_eq!(
            rejected_hash.decision,
            CryptographicVerifierDecisionKind::Rejected
        );
        assert!(!rejected_hash.reasons.is_empty());

        let wrong_adapter = VaultController::verify_production_adapter_evidence(&adapter_evidence(
            ProductionAdapterKind::AuthProvider,
            "oidc://prod/tenant.a",
        ));
        let mut wrong_adapter_evidence = evidence;
        wrong_adapter_evidence.adapter_decision_ref = wrong_adapter.decision_id.clone();
        let rejected_adapter = VaultController::verify_cryptographic_verifier(
            &hardening,
            &signature_decision,
            &trust_root_record,
            &wrong_adapter,
            &wrong_adapter_evidence,
        );
        assert_eq!(
            rejected_adapter.decision,
            CryptographicVerifierDecisionKind::Rejected
        );
        assert!(!rejected_adapter.reasons.is_empty());
    }

    #[test]
    fn hardened_sandbox_decision_is_profile_and_adapter_bound_fail_closed() {
        let hardening = hardening_evidence();
        let adapter_decision =
            VaultController::verify_production_adapter_evidence(&adapter_evidence(
                ProductionAdapterKind::HardenedSandbox,
                "container://tenant.a/hardened-v1",
            ));
        let evidence = hardened_sandbox_evidence(&adapter_decision);
        let decision =
            VaultController::verify_hardened_sandbox(&hardening, &adapter_decision, &evidence);

        assert_eq!(decision.decision, HardenedSandboxDecisionKind::Verified);
        assert_eq!(decision.tenant_id, hardening.tenant_id);
        assert_eq!(
            decision.hardened_sandbox_profile_ref,
            "container://tenant.a/hardened-v1"
        );
        assert!(decision
            .evidence_refs
            .contains(&adapter_decision.decision_id));
        assert!(decision
            .evidence_refs
            .contains(&"syscall-policy://tenant.a/seccomp-prod".into()));

        let mut placeholder_policy = evidence.clone();
        placeholder_policy.syscall_policy_ref = "mock-syscall-policy".into();
        let rejected_policy = VaultController::verify_hardened_sandbox(
            &hardening,
            &adapter_decision,
            &placeholder_policy,
        );
        assert_eq!(
            rejected_policy.decision,
            HardenedSandboxDecisionKind::Rejected
        );
        assert!(!rejected_policy.reasons.is_empty());

        let mut profile_mismatch = evidence.clone();
        profile_mismatch.hardened_sandbox_profile_ref = "container://tenant.a/hardened-v2".into();
        let rejected_profile = VaultController::verify_hardened_sandbox(
            &hardening,
            &adapter_decision,
            &profile_mismatch,
        );
        assert_eq!(
            rejected_profile.decision,
            HardenedSandboxDecisionKind::Rejected
        );
        assert!(!rejected_profile.reasons.is_empty());

        let wrong_adapter = VaultController::verify_production_adapter_evidence(&adapter_evidence(
            ProductionAdapterKind::SecretInjection,
            "injector://tenant.a/prod",
        ));
        let mut wrong_adapter_evidence = evidence;
        wrong_adapter_evidence.adapter_decision_ref = wrong_adapter.decision_id.clone();
        let rejected_adapter = VaultController::verify_hardened_sandbox(
            &hardening,
            &wrong_adapter,
            &wrong_adapter_evidence,
        );
        assert_eq!(
            rejected_adapter.decision,
            HardenedSandboxDecisionKind::Rejected
        );
        assert!(!rejected_adapter.reasons.is_empty());
    }

    #[test]
    fn production_readiness_requires_verified_adapter_decisions() {
        let policy = tenant_policy();
        let signature_decision = VaultController::verify_executor_signature(
            &signature(),
            &[trust_root()],
            RiskLevel::High,
        );
        let adapters = all_adapter_evidence();
        let adapter_decisions = all_adapter_decisions(&adapters);

        let ready = VaultController::evaluate_production_readiness_with_adapter_decisions(
            &policy,
            &[credential()],
            std::slice::from_ref(&signature_decision),
            &hardening_evidence(),
            &adapters,
            &adapter_decisions,
        )
        .unwrap();

        assert_eq!(ready.decision, ProductionReadinessDecisionKind::Ready);
        assert!(adapter_decisions
            .iter()
            .all(|decision| ready.evidence_refs.contains(&decision.decision_id)));

        let missing_decision_error =
            VaultController::evaluate_production_readiness_with_adapter_decisions(
                &policy,
                &[credential()],
                std::slice::from_ref(&signature_decision),
                &hardening_evidence(),
                &adapters,
                &adapter_decisions[1..],
            )
            .unwrap_err();
        assert_eq!(missing_decision_error, VaultError::MissingEvidence);

        let mut duplicate_decisions = adapter_decisions.clone();
        duplicate_decisions[1] = adapter_decisions[0].clone();
        let duplicate_error =
            VaultController::evaluate_production_readiness_with_adapter_decisions(
                &policy,
                &[credential()],
                std::slice::from_ref(&signature_decision),
                &hardening_evidence(),
                &adapters,
                &duplicate_decisions,
            )
            .unwrap_err();
        assert_eq!(duplicate_error, VaultError::MissingEvidence);

        let mut mismatched_decisions = adapter_decisions.clone();
        mismatched_decisions[0].provider_ref = "oidc://prod/tenant.a/other".into();
        let mismatched_error =
            VaultController::evaluate_production_readiness_with_adapter_decisions(
                &policy,
                &[credential()],
                std::slice::from_ref(&signature_decision),
                &hardening_evidence(),
                &adapters,
                &mismatched_decisions,
            )
            .unwrap_err();
        assert_eq!(mismatched_error, VaultError::MissingEvidence);

        let mut rejected_decisions = adapter_decisions.clone();
        rejected_decisions[0].decision = ProductionAdapterVerificationKind::Rejected;
        let rejected_error = VaultController::evaluate_production_readiness_with_adapter_decisions(
            &policy,
            &[credential()],
            std::slice::from_ref(&signature_decision),
            &hardening_evidence(),
            &adapters,
            &rejected_decisions,
        )
        .unwrap_err();
        assert_eq!(rejected_error, VaultError::MissingEvidence);

        let cross_tenant_decisions = vec![ProductionAdapterVerificationDecision {
            tenant_id: "tenant.b".into(),
            ..adapter_decisions[0].clone()
        }];
        let tenant_error = VaultController::evaluate_production_readiness_with_adapter_decisions(
            &policy,
            &[credential()],
            &[signature_decision],
            &hardening_evidence(),
            &adapters,
            &cross_tenant_decisions,
        )
        .unwrap_err();
        assert_eq!(tenant_error, VaultError::TenantMismatch);
    }

    #[test]
    fn production_readiness_requires_verified_hardened_sandbox_decision_when_supplied() {
        let policy = tenant_policy();
        let credential = credential();
        let hardening = hardening_evidence();
        let signature_decision = VaultController::verify_executor_signature(
            &signature(),
            &[trust_root()],
            RiskLevel::High,
        );
        let adapters = all_adapter_evidence();
        let adapter_decisions = all_adapter_decisions(&adapters);
        let rotation_adapter_decision = adapter_decisions
            .iter()
            .find(|decision| decision.kind == ProductionAdapterKind::RotationEnforcement)
            .unwrap()
            .clone();
        let rotation_decision = VaultController::verify_rotation_enforcement_with_adapter_decision(
            &credential,
            &hardening,
            &rotation_adapter_decision,
        );
        let sandbox_adapter_decision = adapter_decisions
            .iter()
            .find(|decision| decision.kind == ProductionAdapterKind::HardenedSandbox)
            .unwrap()
            .clone();
        let sandbox_evidence = hardened_sandbox_evidence(&sandbox_adapter_decision);
        let sandbox_decision = VaultController::verify_hardened_sandbox(
            &hardening,
            &sandbox_adapter_decision,
            &sandbox_evidence,
        );

        let ready = VaultController::evaluate_production_readiness_with_hardened_sandbox_decisions(
            &policy,
            std::slice::from_ref(&credential),
            std::slice::from_ref(&signature_decision),
            &hardening,
            &adapters,
            &adapter_decisions,
            std::slice::from_ref(&rotation_decision),
            std::slice::from_ref(&sandbox_decision),
        )
        .unwrap();

        assert_eq!(ready.decision, ProductionReadinessDecisionKind::Ready);
        assert!(ready.evidence_refs.contains(&sandbox_decision.decision_id));

        let missing_decision_error =
            VaultController::evaluate_production_readiness_with_hardened_sandbox_decisions(
                &policy,
                std::slice::from_ref(&credential),
                std::slice::from_ref(&signature_decision),
                &hardening,
                &adapters,
                &adapter_decisions,
                std::slice::from_ref(&rotation_decision),
                &[],
            )
            .unwrap_err();
        assert_eq!(missing_decision_error, VaultError::MissingEvidence);

        let duplicate_decisions = vec![sandbox_decision.clone(), sandbox_decision.clone()];
        let duplicate_error =
            VaultController::evaluate_production_readiness_with_hardened_sandbox_decisions(
                &policy,
                std::slice::from_ref(&credential),
                std::slice::from_ref(&signature_decision),
                &hardening,
                &adapters,
                &adapter_decisions,
                std::slice::from_ref(&rotation_decision),
                &duplicate_decisions,
            )
            .unwrap_err();
        assert_eq!(duplicate_error, VaultError::MissingEvidence);

        let mut mismatched_decision = sandbox_decision.clone();
        mismatched_decision.hardened_sandbox_profile_ref = "container://tenant.a/other".into();
        let mismatched_error =
            VaultController::evaluate_production_readiness_with_hardened_sandbox_decisions(
                &policy,
                std::slice::from_ref(&credential),
                std::slice::from_ref(&signature_decision),
                &hardening,
                &adapters,
                &adapter_decisions,
                std::slice::from_ref(&rotation_decision),
                &[mismatched_decision],
            )
            .unwrap_err();
        assert_eq!(mismatched_error, VaultError::MissingEvidence);

        let mut rejected_decision = sandbox_decision;
        rejected_decision.decision = HardenedSandboxDecisionKind::Rejected;
        let rejected_error =
            VaultController::evaluate_production_readiness_with_hardened_sandbox_decisions(
                &policy,
                std::slice::from_ref(&credential),
                std::slice::from_ref(&signature_decision),
                &hardening,
                &adapters,
                &adapter_decisions,
                &[rotation_decision],
                &[rejected_decision],
            )
            .unwrap_err();
        assert_eq!(rejected_error, VaultError::MissingEvidence);
    }

    #[test]
    fn production_readiness_can_require_full_p0_hardening_decision_set() {
        let fixtures = production_hardening_decision_fixtures();

        let ready = VaultController::evaluate_production_readiness_with_hardening_decision_set(
            &tenant_policy(),
            std::slice::from_ref(&fixtures.credential),
            std::slice::from_ref(&fixtures.signature_decision),
            &fixtures.hardening,
            &fixtures.adapters,
            &fixtures.adapter_decisions,
            fixtures.decision_set(),
        )
        .unwrap();

        assert_eq!(ready.decision, ProductionReadinessDecisionKind::Ready);
        assert!(ready
            .evidence_refs
            .contains(&fixtures.auth_decision.decision_id));
        assert!(ready
            .evidence_refs
            .contains(&fixtures.external_secret_manager_decisions[0].decision_id));
        assert!(ready
            .evidence_refs
            .contains(&fixtures.cryptographic_verifier_decisions[0].decision_id));
        assert!(ready
            .evidence_refs
            .contains(&fixtures.secret_injection_decisions[0].decision_id));
        assert!(ready
            .evidence_refs
            .contains(&fixtures.compliance_export_delivery_decisions[0].decision_id));
        assert!(ready
            .evidence_refs
            .contains(&fixtures.trust_root_storage_decisions[0].decision_id));
    }

    #[test]
    fn production_readiness_hardening_decision_set_is_fail_closed() {
        let mut fixtures = production_hardening_decision_fixtures();

        let missing_auth = ProductionHardeningDecisionSet {
            auth_decision: None,
            ..fixtures.decision_set()
        };
        let missing_auth_error =
            VaultController::evaluate_production_readiness_with_hardening_decision_set(
                &tenant_policy(),
                std::slice::from_ref(&fixtures.credential),
                std::slice::from_ref(&fixtures.signature_decision),
                &fixtures.hardening,
                &fixtures.adapters,
                &fixtures.adapter_decisions,
                missing_auth,
            )
            .unwrap_err();
        assert_eq!(missing_auth_error, VaultError::MissingEvidence);

        fixtures.external_secret_manager_decisions.clear();
        let missing_secret_manager_error =
            VaultController::evaluate_production_readiness_with_hardening_decision_set(
                &tenant_policy(),
                std::slice::from_ref(&fixtures.credential),
                std::slice::from_ref(&fixtures.signature_decision),
                &fixtures.hardening,
                &fixtures.adapters,
                &fixtures.adapter_decisions,
                fixtures.decision_set(),
            )
            .unwrap_err();
        assert_eq!(missing_secret_manager_error, VaultError::MissingEvidence);

        let mut fixtures = production_hardening_decision_fixtures();
        fixtures.cryptographic_verifier_decisions[0].decision =
            CryptographicVerifierDecisionKind::Rejected;
        let rejected_crypto_error =
            VaultController::evaluate_production_readiness_with_hardening_decision_set(
                &tenant_policy(),
                std::slice::from_ref(&fixtures.credential),
                std::slice::from_ref(&fixtures.signature_decision),
                &fixtures.hardening,
                &fixtures.adapters,
                &fixtures.adapter_decisions,
                fixtures.decision_set(),
            )
            .unwrap_err();
        assert_eq!(rejected_crypto_error, VaultError::MissingEvidence);

        let mut fixtures = production_hardening_decision_fixtures();
        fixtures.secret_injection_decisions[0].secret_injection_profile_ref =
            "injector://tenant.a/other".into();
        let mismatched_injection_error =
            VaultController::evaluate_production_readiness_with_hardening_decision_set(
                &tenant_policy(),
                std::slice::from_ref(&fixtures.credential),
                std::slice::from_ref(&fixtures.signature_decision),
                &fixtures.hardening,
                &fixtures.adapters,
                &fixtures.adapter_decisions,
                fixtures.decision_set(),
            )
            .unwrap_err();
        assert_eq!(mismatched_injection_error, VaultError::MissingEvidence);

        let mut fixtures = production_hardening_decision_fixtures();
        fixtures.compliance_export_delivery_decisions[0].adapter_decision_ref = None;
        let missing_compliance_adapter_error =
            VaultController::evaluate_production_readiness_with_hardening_decision_set(
                &tenant_policy(),
                std::slice::from_ref(&fixtures.credential),
                std::slice::from_ref(&fixtures.signature_decision),
                &fixtures.hardening,
                &fixtures.adapters,
                &fixtures.adapter_decisions,
                fixtures.decision_set(),
            )
            .unwrap_err();
        assert_eq!(
            missing_compliance_adapter_error,
            VaultError::MissingEvidence
        );

        let mut fixtures = production_hardening_decision_fixtures();
        fixtures.trust_root_storage_decisions[0].root_id = "root.other".into();
        let mismatched_trust_root_storage_error =
            VaultController::evaluate_production_readiness_with_hardening_decision_set(
                &tenant_policy(),
                std::slice::from_ref(&fixtures.credential),
                std::slice::from_ref(&fixtures.signature_decision),
                &fixtures.hardening,
                &fixtures.adapters,
                &fixtures.adapter_decisions,
                fixtures.decision_set(),
            )
            .unwrap_err();
        assert_eq!(
            mismatched_trust_root_storage_error,
            VaultError::MissingEvidence
        );

        let mut fixtures = production_hardening_decision_fixtures();
        fixtures.auth_decision.tenant_id = "tenant.b".into();
        let tenant_error =
            VaultController::evaluate_production_readiness_with_hardening_decision_set(
                &tenant_policy(),
                std::slice::from_ref(&fixtures.credential),
                std::slice::from_ref(&fixtures.signature_decision),
                &fixtures.hardening,
                &fixtures.adapters,
                &fixtures.adapter_decisions,
                fixtures.decision_set(),
            )
            .unwrap_err();
        assert_eq!(tenant_error, VaultError::TenantMismatch);
    }

    #[test]
    fn rotation_enforcement_decision_is_evidence_bound_and_fail_closed() {
        let credential = credential();
        let hardening = hardening_evidence();
        let decision = VaultController::verify_rotation_enforcement(&credential, &hardening);

        assert_eq!(decision.decision, RotationEnforcementDecisionKind::Verified);
        assert_eq!(decision.tenant_id, credential.tenant_id);
        assert_eq!(decision.credential_id, credential.credential_id);
        assert_eq!(decision.rotation_ref, credential.rotation_ref);
        assert_eq!(decision.rotation_policy_ref, hardening.rotation_policy_ref);
        assert!(decision.evidence_refs.contains(&credential.credential_id));
        assert!(decision
            .evidence_refs
            .contains(&"rotation://tenant.a/30d-enforced".into()));

        let mut missing_rotation = credential;
        missing_rotation.rotation_ref = Some("mock-rotation".into());
        let rejected = VaultController::verify_rotation_enforcement(&missing_rotation, &hardening);

        assert_eq!(rejected.decision, RotationEnforcementDecisionKind::Rejected);
        assert!(!rejected.reasons.is_empty());
    }

    #[test]
    fn rotation_enforcement_decision_can_bind_verified_adapter_decision() {
        let credential = credential();
        let hardening = hardening_evidence();
        let adapter_decision =
            VaultController::verify_production_adapter_evidence(&adapter_evidence(
                ProductionAdapterKind::RotationEnforcement,
                "rotation://tenant.a/30d-enforced",
            ));
        let decision = VaultController::verify_rotation_enforcement_with_adapter_decision(
            &credential,
            &hardening,
            &adapter_decision,
        );

        assert_eq!(decision.decision, RotationEnforcementDecisionKind::Verified);
        assert_eq!(
            decision.adapter_decision_ref,
            Some(adapter_decision.decision_id.clone())
        );
        assert!(decision
            .evidence_refs
            .contains(&adapter_decision.decision_id));
        assert!(decision
            .evidence_refs
            .contains(&"rotation://tenant.a/30d-enforced".into()));

        let wrong_adapter = VaultController::verify_production_adapter_evidence(&adapter_evidence(
            ProductionAdapterKind::SecretInjection,
            "injector://tenant.a/prod",
        ));
        let rejected_kind = VaultController::verify_rotation_enforcement_with_adapter_decision(
            &credential,
            &hardening,
            &wrong_adapter,
        );
        assert_eq!(
            rejected_kind.decision,
            RotationEnforcementDecisionKind::Rejected
        );
        assert!(!rejected_kind.reasons.is_empty());

        let mismatched_adapter =
            VaultController::verify_production_adapter_evidence(&adapter_evidence(
                ProductionAdapterKind::RotationEnforcement,
                "rotation://tenant.a/other",
            ));
        let rejected_provider = VaultController::verify_rotation_enforcement_with_adapter_decision(
            &credential,
            &hardening,
            &mismatched_adapter,
        );
        assert_eq!(
            rejected_provider.decision,
            RotationEnforcementDecisionKind::Rejected
        );
        assert!(!rejected_provider.reasons.is_empty());

        let mut rejected_adapter_decision = adapter_decision;
        rejected_adapter_decision.decision = ProductionAdapterVerificationKind::Rejected;
        let rejected_adapter = VaultController::verify_rotation_enforcement_with_adapter_decision(
            &credential,
            &hardening,
            &rejected_adapter_decision,
        );
        assert_eq!(
            rejected_adapter.decision,
            RotationEnforcementDecisionKind::Rejected
        );
        assert!(!rejected_adapter.reasons.is_empty());
    }

    #[test]
    fn secret_injection_decision_is_secret_use_and_sandbox_bound_fail_closed() {
        let credential = credential();
        let secret_use = VaultController::decide_secret_use(
            &credential,
            &secret_request(RiskLevel::High),
            Some(&approval("secret.req.1")),
        )
        .unwrap();
        let hardening = hardening_evidence();
        let adapter_decision =
            VaultController::verify_production_adapter_evidence(&adapter_evidence(
                ProductionAdapterKind::SecretInjection,
                "injector://tenant.a/prod",
            ));
        let evidence = secret_injection_evidence(&credential, &secret_use, &adapter_decision);
        let decision = VaultController::verify_secret_injection(
            &credential,
            &secret_use,
            &hardening,
            &adapter_decision,
            &evidence,
        );

        assert_eq!(decision.decision, SecretInjectionDecisionKind::Verified);
        assert_eq!(decision.tenant_id, credential.tenant_id);
        assert_eq!(decision.credential_id, credential.credential_id);
        assert_eq!(decision.secret_use_decision_id, secret_use.decision_id);
        assert_eq!(
            decision.secret_injection_profile_ref,
            "injector://tenant.a/prod"
        );
        assert_eq!(
            decision.hardened_sandbox_profile_ref,
            "container://tenant.a/hardened-v1"
        );
        assert!(decision.evidence_refs.contains(&secret_use.decision_id));
        assert!(decision
            .evidence_refs
            .contains(&adapter_decision.decision_id));
        assert!(decision
            .evidence_refs
            .contains(&evidence.injection_receipt_ref));

        let mut denied_secret_use = secret_use.clone();
        denied_secret_use.decision = SecretUseDecisionKind::Denied;
        let rejected_secret_use = VaultController::verify_secret_injection(
            &credential,
            &denied_secret_use,
            &hardening,
            &adapter_decision,
            &evidence,
        );
        assert_eq!(
            rejected_secret_use.decision,
            SecretInjectionDecisionKind::Rejected
        );
        assert!(!rejected_secret_use.reasons.is_empty());

        let mut placeholder_receipt = evidence.clone();
        placeholder_receipt.injection_receipt_ref = "mock-receipt".into();
        let rejected_receipt = VaultController::verify_secret_injection(
            &credential,
            &secret_use,
            &hardening,
            &adapter_decision,
            &placeholder_receipt,
        );
        assert_eq!(
            rejected_receipt.decision,
            SecretInjectionDecisionKind::Rejected
        );
        assert!(!rejected_receipt.reasons.is_empty());

        let mut profile_mismatch = evidence.clone();
        profile_mismatch.secret_injection_profile_ref = "injector://tenant.a/other".into();
        let rejected_profile = VaultController::verify_secret_injection(
            &credential,
            &secret_use,
            &hardening,
            &adapter_decision,
            &profile_mismatch,
        );
        assert_eq!(
            rejected_profile.decision,
            SecretInjectionDecisionKind::Rejected
        );
        assert!(!rejected_profile.reasons.is_empty());

        let wrong_adapter = VaultController::verify_production_adapter_evidence(&adapter_evidence(
            ProductionAdapterKind::HardenedSandbox,
            "container://tenant.a/hardened-v1",
        ));
        let mut wrong_adapter_evidence = evidence;
        wrong_adapter_evidence.adapter_decision_ref = wrong_adapter.decision_id.clone();
        let rejected_adapter = VaultController::verify_secret_injection(
            &credential,
            &secret_use,
            &hardening,
            &wrong_adapter,
            &wrong_adapter_evidence,
        );
        assert_eq!(
            rejected_adapter.decision,
            SecretInjectionDecisionKind::Rejected
        );
        assert!(!rejected_adapter.reasons.is_empty());
    }

    #[test]
    fn production_readiness_requires_verified_rotation_decisions_when_refs_exist() {
        let policy = tenant_policy();
        let credential = credential();
        let hardening = hardening_evidence();
        let signature_decision = VaultController::verify_executor_signature(
            &signature(),
            &[trust_root()],
            RiskLevel::High,
        );
        let adapters = all_adapter_evidence();
        let adapter_decisions = all_adapter_decisions(&adapters);
        let rotation_adapter_decision = adapter_decisions
            .iter()
            .find(|decision| decision.kind == ProductionAdapterKind::RotationEnforcement)
            .unwrap()
            .clone();
        let rotation_decision = VaultController::verify_rotation_enforcement_with_adapter_decision(
            &credential,
            &hardening,
            &rotation_adapter_decision,
        );

        let ready = VaultController::evaluate_production_readiness_with_decisions(
            &policy,
            std::slice::from_ref(&credential),
            std::slice::from_ref(&signature_decision),
            &hardening,
            &adapters,
            &adapter_decisions,
            std::slice::from_ref(&rotation_decision),
        )
        .unwrap();

        assert_eq!(ready.decision, ProductionReadinessDecisionKind::Ready);
        assert!(ready.evidence_refs.contains(&rotation_decision.decision_id));
        assert!(ready
            .evidence_refs
            .contains(&rotation_adapter_decision.decision_id));

        let missing_decision_error = VaultController::evaluate_production_readiness_with_decisions(
            &policy,
            std::slice::from_ref(&credential),
            std::slice::from_ref(&signature_decision),
            &hardening,
            &adapters,
            &adapter_decisions,
            &[],
        )
        .unwrap_err();
        assert_eq!(missing_decision_error, VaultError::MissingEvidence);

        let duplicate_decisions = vec![rotation_decision.clone(), rotation_decision.clone()];
        let duplicate_error = VaultController::evaluate_production_readiness_with_decisions(
            &policy,
            std::slice::from_ref(&credential),
            std::slice::from_ref(&signature_decision),
            &hardening,
            &adapters,
            &adapter_decisions,
            &duplicate_decisions,
        )
        .unwrap_err();
        assert_eq!(duplicate_error, VaultError::MissingEvidence);

        let mut mismatched_decision = rotation_decision.clone();
        mismatched_decision.rotation_ref = Some("rotation://tenant.a/other".into());
        let mismatched_error = VaultController::evaluate_production_readiness_with_decisions(
            &policy,
            std::slice::from_ref(&credential),
            std::slice::from_ref(&signature_decision),
            &hardening,
            &adapters,
            &adapter_decisions,
            &[mismatched_decision],
        )
        .unwrap_err();
        assert_eq!(mismatched_error, VaultError::MissingEvidence);

        let mut rejected_decision = rotation_decision;
        rejected_decision.decision = RotationEnforcementDecisionKind::Rejected;
        let rejected_error = VaultController::evaluate_production_readiness_with_decisions(
            &policy,
            std::slice::from_ref(&credential),
            std::slice::from_ref(&signature_decision),
            &hardening,
            &adapters,
            &adapter_decisions,
            &[rejected_decision],
        )
        .unwrap_err();
        assert_eq!(rejected_error, VaultError::MissingEvidence);

        let mut mismatched_adapter_ref =
            VaultController::verify_rotation_enforcement_with_adapter_decision(
                &credential,
                &hardening,
                &rotation_adapter_decision,
            );
        mismatched_adapter_ref.adapter_decision_ref = Some("adapter.decision.missing".into());
        let missing_adapter_error = VaultController::evaluate_production_readiness_with_decisions(
            &policy,
            std::slice::from_ref(&credential),
            std::slice::from_ref(&signature_decision),
            &hardening,
            &adapters,
            &adapter_decisions,
            &[mismatched_adapter_ref],
        )
        .unwrap_err();
        assert_eq!(missing_adapter_error, VaultError::MissingEvidence);
    }

    #[test]
    fn production_readiness_blocks_until_all_p0_hardening_gates_have_evidence() {
        let mut evidence = hardening_evidence();
        evidence.auth_provider_ref = Some("local-test-auth".into());
        evidence.secret_manager_ref = None;
        evidence.hardened_sandbox_profile_ref = Some("mock-sandbox".into());
        evidence.secret_injection_profile_ref = None;
        evidence.rotation_policy_ref = None;
        evidence.compliance_export_profile_ref = None;
        let signature_decision =
            VaultController::verify_executor_signature(&signature(), &[], RiskLevel::High);

        let decision = VaultController::evaluate_production_readiness(
            &tenant_policy(),
            &[credential()],
            &[signature_decision],
            &evidence,
            &[],
        )
        .unwrap();

        assert_eq!(decision.decision, ProductionReadinessDecisionKind::Blocked);
        assert!(decision
            .missing_gates
            .contains(&ProductionReadinessGate::ProductionAuth));
        assert!(decision
            .missing_gates
            .contains(&ProductionReadinessGate::ExternalSecretManager));
        assert!(decision
            .missing_gates
            .contains(&ProductionReadinessGate::HardenedSandbox));
        assert!(decision
            .missing_gates
            .contains(&ProductionReadinessGate::SecretInjection));
        assert!(decision
            .missing_gates
            .contains(&ProductionReadinessGate::RotationEnforcement));
        assert!(decision
            .missing_gates
            .contains(&ProductionReadinessGate::ExecutorTrustRoots));
        assert!(decision
            .missing_gates
            .contains(&ProductionReadinessGate::ComplianceAuditExport));
        assert!(decision
            .reasons
            .iter()
            .any(|reason| reason.contains("KMS/HSM/secret-manager")));
    }

    #[test]
    fn production_readiness_allows_only_verified_hardened_p0_configuration() {
        let signature_decision = VaultController::verify_executor_signature(
            &signature(),
            &[trust_root()],
            RiskLevel::High,
        );

        let decision = VaultController::evaluate_production_readiness(
            &tenant_policy(),
            &[credential()],
            &[signature_decision],
            &hardening_evidence(),
            &all_adapter_evidence(),
        )
        .unwrap();

        assert_eq!(decision.decision, ProductionReadinessDecisionKind::Ready);
        assert!(decision.missing_gates.is_empty());
        assert!(decision
            .reasons
            .contains(&"all production P0 hardening gates are satisfied".into()));
        assert!(decision.evidence_refs.contains(&"cred.github".into()));
        assert!(decision
            .evidence_refs
            .iter()
            .any(|reference| reference.starts_with("adapter.evidence.")));
    }

    #[test]
    fn production_readiness_rejects_cross_tenant_signature_decisions() {
        let mut other_tenant_signature = signature();
        other_tenant_signature.tenant_id = "tenant.b".into();
        let other_tenant_decision = VaultController::verify_executor_signature(
            &other_tenant_signature,
            &[TrustRoot {
                tenant_id: "tenant.b".into(),
                ..trust_root()
            }],
            RiskLevel::High,
        );

        let error = VaultController::evaluate_production_readiness(
            &tenant_policy(),
            &[credential()],
            &[other_tenant_decision],
            &hardening_evidence(),
            &all_adapter_evidence(),
        )
        .unwrap_err();

        assert_eq!(error, VaultError::TenantMismatch);
    }

    #[test]
    fn production_readiness_rejects_placeholder_adapter_evidence() {
        let signature_decision = VaultController::verify_executor_signature(
            &signature(),
            &[trust_root()],
            RiskLevel::High,
        );
        let mut adapters = all_adapter_evidence();
        adapters[0].attestation_ref = "mock-attestation".into();

        let error = VaultController::evaluate_production_readiness(
            &tenant_policy(),
            &[credential()],
            &[signature_decision],
            &hardening_evidence(),
            &adapters,
        )
        .unwrap_err();

        assert_eq!(error, VaultError::MissingEvidence);
    }

    #[test]
    fn p1_local_readiness_allows_bounded_read_only_execution_through_p0() {
        let profile = P1ExecutionReadinessProfile::local_read_only("tenant.a");
        let request = P1ExecutionReadinessRequest {
            request_id: "p1.req.1".into(),
            run_id: "run.1".into(),
            tenant_id: "tenant.a".into(),
            actor_id: "moxi-runtime".into(),
            capability_id: "file.read".into(),
            permission_mode: PermissionMode::ReadOnly,
            risk_level: RiskLevel::Low,
            requires_credential: false,
            evidence_refs: vec!["policy.decision.1".into()],
            requested_at: Utc::now(),
        };

        let decision =
            VaultController::evaluate_p1_execution_readiness(&profile, &request, None).unwrap();

        assert_eq!(decision.decision, P1ExecutionReadinessDecisionKind::Ready);
        assert!(decision.can_enter_p0_execution_chain);
        assert!(!decision.can_issue_ticket_directly);
        assert!(!decision.can_execute_without_p0);
    }

    #[test]
    fn p1_local_readiness_blocks_high_risk_or_credentialed_tasks_without_production_ready_p0() {
        let profile = P1ExecutionReadinessProfile::local_read_only("tenant.a");
        let request = P1ExecutionReadinessRequest {
            request_id: "p1.req.2".into(),
            run_id: "run.2".into(),
            tenant_id: "tenant.a".into(),
            actor_id: "moxi-runtime".into(),
            capability_id: "file.read".into(),
            permission_mode: PermissionMode::ReadOnly,
            risk_level: RiskLevel::High,
            requires_credential: true,
            evidence_refs: vec!["policy.decision.2".into()],
            requested_at: Utc::now(),
        };

        let decision =
            VaultController::evaluate_p1_execution_readiness(&profile, &request, None).unwrap();

        assert_eq!(decision.decision, P1ExecutionReadinessDecisionKind::Blocked);
        assert!(decision
            .blocked_gates
            .contains(&P1ExecutionReadinessGate::RiskCeiling));
        assert!(decision
            .blocked_gates
            .contains(&P1ExecutionReadinessGate::CredentialUse));
        assert!(decision
            .blocked_gates
            .contains(&P1ExecutionReadinessGate::ProductionReadiness));
    }
}
