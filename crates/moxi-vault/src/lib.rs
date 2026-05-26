use chrono::{DateTime, Utc};
use moxi_contracts::{ApprovalPolicy, PermissionMode, RiskLevel};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
pub struct ProductionReadinessDecision {
    pub decision_id: String,
    pub tenant_id: String,
    pub decision: ProductionReadinessDecisionKind,
    pub missing_gates: Vec<ProductionReadinessGate>,
    pub reasons: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub evaluated_at: DateTime<Utc>,
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
    pub readiness_decision_ref: String,
    pub audit_export_ref: String,
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
        let production_readiness_ref = if production_required {
            let production_readiness = production_readiness.ok_or(VaultError::MissingEvidence)?;
            if production_readiness.tenant_id != policy.tenant_id {
                return Err(VaultError::TenantMismatch);
            }
            if production_readiness.decision != ProductionReadinessDecisionKind::Ready
                || !production_readiness.missing_gates.is_empty()
            {
                return Err(VaultError::MissingEvidence);
            }
            Some(production_readiness.decision_id.clone())
        } else {
            None
        };
        let profile_hash = stable_id("p1_execution_profile_hash", &profile);
        let mut evidence_refs = profile.evidence_refs.clone();
        evidence_refs.push(policy.pack_id.clone());
        evidence_refs.push(policy_record.record_id.clone());
        evidence_refs.push(policy_record.policy_hash.clone());
        evidence_refs.extend(policy.credential_scope_refs.clone());
        evidence_refs.extend(policy_record.evidence_refs.clone());
        if let Some(production_readiness) = production_readiness {
            if production_readiness.tenant_id != policy.tenant_id {
                return Err(VaultError::TenantMismatch);
            }
            evidence_refs.push(production_readiness.decision_id.clone());
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
                    &evidence_refs,
                ),
            ),
            tenant_id: profile.tenant_id.clone(),
            profile_id: profile.profile_id.clone(),
            tenant_policy_pack_ref: policy.pack_id.clone(),
            tenant_policy_record_ref: policy_record.record_id.clone(),
            tenant_policy_hash: policy_record.policy_hash.clone(),
            production_readiness_ref,
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
        let expected_hash = stable_id("p1_execution_profile_hash", &record.profile);
        if record.profile_hash != expected_hash || record.profile_id != record.profile.profile_id {
            return Err(VaultError::MissingEvidence);
        }
        let production_required = p1_profile_requires_production_readiness(&record.profile);
        if production_required && record.production_readiness_ref.is_none() {
            return Err(VaultError::MissingEvidence);
        }
        if !production_required && record.production_readiness_ref.is_some() {
            return Err(VaultError::MissingEvidence);
        }

        Ok(record.profile.clone())
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
        if decision.request_id != request.request_id
            || audit_export.kind != AuditExportRecordKind::P1ExecutionReadiness
            || !audit_export.event_refs.contains(&profile_record.record_id)
            || !audit_export.event_refs.contains(&decision.decision_id)
            || !audit_export.event_refs.contains(&request.request_id)
        {
            return Err(VaultError::MissingEvidence);
        }

        match (
            &profile_record.production_readiness_ref,
            production_readiness,
        ) {
            (Some(expected), Some(readiness)) if expected == &readiness.decision_id => {}
            (Some(_), _) => return Err(VaultError::MissingEvidence),
            (None, Some(_)) => return Err(VaultError::MissingEvidence),
            (None, None) => {}
        }

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
            readiness_decision_ref: decision.decision_id.clone(),
            audit_export_ref: audit_export.export_id.clone(),
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

    pub fn evaluate_production_readiness(
        policy: &TenantPolicyPack,
        credentials: &[CredentialRef],
        signature_decisions: &[SignatureVerificationDecision],
        hardening: &ProductionHardeningEvidence,
        adapter_evidence: &[ProductionAdapterEvidence],
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
        {
            return Err(VaultError::TenantMismatch);
        }

        for credential in credentials {
            validate_credential_ref(credential)?;
        }
        for evidence in adapter_evidence {
            validate_adapter_evidence(evidence)?;
        }

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

fn looks_like_raw_secret(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("-----begin")
        || lower.contains("password=")
        || lower.contains("secret=")
        || lower.starts_with("sk-")
        || lower.starts_with("xoxb-")
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

        assert_eq!(record.production_readiness_ref, Some(ready.decision_id));
        assert!(record
            .evidence_refs
            .contains(record.production_readiness_ref.as_ref().unwrap()));
        assert_eq!(
            VaultController::load_p1_execution_readiness_profile(&record, &policy).unwrap(),
            production_profile
        );
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
            production_profile,
            &ready,
            "vault.controller",
        )
        .unwrap();
        record.production_readiness_ref = None;

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
        assert!(bundle
            .evidence_refs
            .contains(&production_readiness.decision_id));
        assert!(bundle.can_enter_p0_execution_chain);
        assert!(!bundle.can_issue_ticket_directly);
        assert!(!bundle.can_execute_without_p0);
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
