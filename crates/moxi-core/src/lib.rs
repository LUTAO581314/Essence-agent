use chrono::{Duration, Utc};
use jsonschema::JSONSchema;
use moxi_contracts::{
    ApprovalGrant, ApprovalPolicy, CapabilityContract, Confidence, Decision, DeltaState,
    EventResult, ExecutionTicket, Intent, LedgerEvent, PermissionMode, PolicyDecision, Proof,
    RequiredApproval, RiskLevel, RunContract, RunStatus, SandboxInput, SandboxResult, WorldDelta,
};
use moxi_sandbox::{sha256_hex, FileReadSandbox, Sandbox, SandboxError};
use moxi_store::{Store, StoreError};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("capability not registered: {0}")]
    CapabilityNotFound(String),
    #[error("run not admitted: {0}")]
    RunNotFound(String),
    #[error("schema validation failed for {0}: {1}")]
    SchemaValidation(String, String),
    #[error("policy denied: {0}")]
    PolicyDenied(String),
    #[error("approval required: {0}")]
    ApprovalRequired(String),
    #[error("approval is not required for policy decision: {0}")]
    ApprovalNotRequired(String),
    #[error("approval grant does not match policy decision")]
    ApprovalGrantMismatch,
    #[error("approval grant expired: {0}")]
    ApprovalGrantExpired(String),
    #[error("ticket expired: {0}")]
    TicketExpired(String),
    #[error("run mismatch")]
    RunMismatch,
    #[error("proof required before successful ledger commit")]
    ProofRequired,
    #[error("store error: {0}")]
    Store(#[from] StoreError),
    #[error("sandbox error: {0}")]
    Sandbox(#[from] SandboxError),
}

pub type CoreResult<T> = Result<T, CoreError>;

#[derive(Default)]
pub struct CapabilityRegistry {
    capabilities: HashMap<String, CapabilityContract>,
}

impl CapabilityRegistry {
    pub fn register(&mut self, contract: CapabilityContract) -> CoreResult<()> {
        validate_schema("input_schema", &contract.input_schema)?;
        validate_schema("output_schema", &contract.output_schema)?;
        validate_schema("error_schema", &contract.error_schema)?;
        self.capabilities
            .insert(contract.capability_id.clone(), contract);
        Ok(())
    }

    pub fn get(&self, capability_id: &str) -> Option<&CapabilityContract> {
        self.capabilities.get(capability_id)
    }

    pub fn list(&self) -> Vec<&CapabilityContract> {
        self.capabilities.values().collect()
    }
}

pub struct Kernel {
    actor_id: String,
    registry: CapabilityRegistry,
    runs: HashMap<String, RunContract>,
    store: Store,
    sandbox: FileReadSandbox,
}

impl Kernel {
    pub fn new_in_memory(workspace_root: impl Into<PathBuf>) -> CoreResult<Self> {
        Ok(Self {
            actor_id: "kernel".into(),
            registry: CapabilityRegistry::default(),
            runs: HashMap::new(),
            store: Store::open_memory()?,
            sandbox: FileReadSandbox::new(workspace_root),
        })
    }

    pub fn with_store(workspace_root: impl Into<PathBuf>, store: Store) -> Self {
        Self {
            actor_id: "kernel".into(),
            registry: CapabilityRegistry::default(),
            runs: HashMap::new(),
            store,
            sandbox: FileReadSandbox::new(workspace_root),
        }
    }

    pub fn register_capability(&mut self, contract: CapabilityContract) -> CoreResult<()> {
        self.registry.register(contract)
    }

    pub fn capability(&self, capability_id: &str) -> Option<&CapabilityContract> {
        self.registry.get(capability_id)
    }

    pub fn admit(&mut self, intent: Intent) -> CoreResult<RunContract> {
        self.admit_with_permission_mode(intent, PermissionMode::ReadOnly)
    }

    pub fn admit_with_permission_mode(
        &mut self,
        intent: Intent,
        permission_mode: PermissionMode,
    ) -> CoreResult<RunContract> {
        let run_id = format!("run_{}", Uuid::new_v4());
        let contract = RunContract {
            status_ref: format!("state_{run_id}"),
            run_id: run_id.clone(),
            intent_id: intent.intent_id,
            tenant_id: intent.tenant_id,
            user_id: intent.user_id,
            risk_level: intent.risk_level,
            permission_mode,
            budget: intent.budget,
            required_capabilities: intent.requested_capabilities,
            checkpoint_ref: None,
            approval_ref: None,
            ledger_scope: "run".into(),
            created_at: Utc::now(),
        };

        self.store
            .initialize_run_budget(&contract.run_id, &contract.budget)?;
        self.store
            .transition_run_status(&contract.run_id, RunStatus::Admitted)?;
        self.runs.insert(contract.run_id.clone(), contract.clone());
        Ok(contract)
    }

    pub fn start_heartbeat(&mut self, run_id: &str) -> CoreResult<()> {
        self.runs
            .get(run_id)
            .ok_or_else(|| CoreError::RunNotFound(run_id.into()))?;
        self.store
            .transition_run_status(run_id, RunStatus::RunningHeartbeat)?;
        self.store.record_heartbeat(run_id)?;
        Ok(())
    }

    pub fn propose_delta(
        &mut self,
        run_id: &str,
        mut delta: WorldDelta,
    ) -> CoreResult<PolicyDecision> {
        let run = self
            .runs
            .get(run_id)
            .ok_or_else(|| CoreError::RunNotFound(run_id.into()))?;

        if delta.run_id != run.run_id {
            return Err(CoreError::RunMismatch);
        }

        self.store.record_step(run_id)?;

        let Some(capability) = self.registry.get(&delta.capability_id) else {
            return Err(CoreError::CapabilityNotFound(delta.capability_id));
        };

        let mut reasons = Vec::new();
        let mut decision = Decision::Allow;
        let mut required_approval = None;

        if !run
            .required_capabilities
            .contains(&capability.capability_id)
        {
            decision = Decision::Deny;
            reasons.push("capability not declared in RunContract".into());
        }

        if let Some(reason) =
            permission_mode_denial(run.permission_mode, &capability.permissions.resources)
        {
            decision = Decision::Deny;
            reasons.push(reason);
        }

        if capability
            .permissions
            .denied
            .iter()
            .any(|item| item == "network")
            || capability
                .permissions
                .denied
                .iter()
                .any(|item| item == "shell")
        {
            reasons.push("network and shell are denied by default".into());
        }

        let risk = std::cmp::max(delta.risk_level, capability.risk_level);
        if matches!(risk, RiskLevel::High | RiskLevel::Critical) && decision == Decision::Allow {
            decision = Decision::RequireApproval;
            required_approval = Some(RequiredApproval {
                approval_policy: ApprovalPolicy::Human,
                approval_ref: None,
            });
            reasons.push("high risk action requires human approval".into());
        }

        if reasons.is_empty() {
            reasons.push("budget, run contract, and capability checks passed".into());
        }

        delta.state = DeltaState::PolicyChecked;
        let policy = PolicyDecision {
            decision_id: format!("pd_{}", Uuid::new_v4()),
            run_id: run.run_id.clone(),
            delta_id: delta.delta_id,
            actor_id: self.actor_id.clone(),
            capability_id: capability.capability_id.clone(),
            decision,
            risk_level: risk,
            reasons,
            required_approval,
            expires_at: Utc::now() + Duration::milliseconds(capability.timeout_ms as i64),
        };

        if policy.decision == Decision::Deny {
            self.store
                .transition_run_status(run_id, RunStatus::Blocked)?;
        } else if policy.decision == Decision::RequireApproval {
            self.store
                .transition_run_status(run_id, RunStatus::AwaitingApproval)?;
        }

        Ok(policy)
    }

    pub fn grant_approval(
        &mut self,
        policy: &PolicyDecision,
        approver_id: impl Into<String>,
        reason: impl Into<String>,
    ) -> CoreResult<ApprovalGrant> {
        self.runs
            .get(&policy.run_id)
            .ok_or_else(|| CoreError::RunNotFound(policy.run_id.clone()))?;

        if policy.decision != Decision::RequireApproval || policy.required_approval.is_none() {
            return Err(CoreError::ApprovalNotRequired(policy.decision_id.clone()));
        }

        if policy.expires_at < Utc::now() {
            return Err(CoreError::ApprovalGrantExpired(policy.decision_id.clone()));
        }

        let grant = ApprovalGrant {
            grant_id: format!("ag_{}", Uuid::new_v4()),
            run_id: policy.run_id.clone(),
            delta_id: policy.delta_id.clone(),
            policy_decision_ref: policy.decision_id.clone(),
            capability_id: policy.capability_id.clone(),
            approver_id: approver_id.into(),
            reason: reason.into(),
            granted_at: Utc::now(),
            expires_at: policy.expires_at,
        };

        self.store.record_approval_grant(&grant)?;
        self.store
            .transition_run_status(&policy.run_id, RunStatus::RunningHeartbeat)?;
        if let Some(run) = self.runs.get_mut(&policy.run_id) {
            run.approval_ref = Some(grant.grant_id.clone());
        }
        Ok(grant)
    }

    pub fn issue_ticket(
        &self,
        policy: &PolicyDecision,
        capability: &CapabilityContract,
    ) -> CoreResult<ExecutionTicket> {
        self.issue_ticket_after_policy(policy, capability, None)
    }

    pub fn issue_ticket_with_grant(
        &self,
        policy: &PolicyDecision,
        capability: &CapabilityContract,
        grant: &ApprovalGrant,
    ) -> CoreResult<ExecutionTicket> {
        self.issue_ticket_after_policy(policy, capability, Some(grant))
    }

    fn issue_ticket_after_policy(
        &self,
        policy: &PolicyDecision,
        capability: &CapabilityContract,
        grant: Option<&ApprovalGrant>,
    ) -> CoreResult<ExecutionTicket> {
        match policy.decision {
            Decision::Allow => {}
            Decision::Deny => {
                return Err(CoreError::PolicyDenied(policy.reasons.join("; ")));
            }
            Decision::RequireApproval => {
                let Some(grant) = grant else {
                    return Err(CoreError::ApprovalRequired(policy.reasons.join("; ")));
                };
                self.validate_approval_grant(policy, capability, grant)?;
            }
        }

        if policy.capability_id != capability.capability_id {
            return Err(CoreError::CapabilityNotFound(policy.capability_id.clone()));
        }

        let ticket = ExecutionTicket {
            ticket_id: format!("ticket_{}", Uuid::new_v4()),
            run_id: policy.run_id.clone(),
            delta_id: policy.delta_id.clone(),
            policy_decision_ref: policy.decision_id.clone(),
            capability_contract_ref: capability.capability_id.clone(),
            sandbox_profile_ref: capability.sandbox_profile.clone(),
            actor_id: self.actor_id.clone(),
            capability_id: capability.capability_id.clone(),
            expires_at: policy.expires_at,
        };
        self.store.record_ticket(&ticket)?;
        Ok(ticket)
    }

    fn validate_approval_grant(
        &self,
        policy: &PolicyDecision,
        capability: &CapabilityContract,
        grant: &ApprovalGrant,
    ) -> CoreResult<()> {
        if grant.run_id != policy.run_id
            || grant.delta_id != policy.delta_id
            || grant.policy_decision_ref != policy.decision_id
            || grant.capability_id != capability.capability_id
            || grant.capability_id != policy.capability_id
        {
            return Err(CoreError::ApprovalGrantMismatch);
        }

        if grant.expires_at < Utc::now() {
            return Err(CoreError::ApprovalGrantExpired(grant.grant_id.clone()));
        }

        let recorded = self
            .store
            .approval_grant(&grant.grant_id)?
            .ok_or(CoreError::ApprovalGrantMismatch)?;
        if recorded != *grant {
            return Err(CoreError::ApprovalGrantMismatch);
        }

        Ok(())
    }

    pub fn execute(
        &mut self,
        ticket: &ExecutionTicket,
        input: SandboxInput,
    ) -> CoreResult<SandboxResult> {
        if ticket.expires_at < Utc::now() {
            return Err(CoreError::TicketExpired(ticket.ticket_id.clone()));
        }

        let capability = self
            .registry
            .get(&ticket.capability_id)
            .ok_or_else(|| CoreError::CapabilityNotFound(ticket.capability_id.clone()))?;

        if input.capability_id != ticket.capability_id {
            return Err(CoreError::CapabilityNotFound(input.capability_id));
        }

        validate_payload("input", &capability.input_schema, &input.payload)?;
        self.store.consume_ticket(&ticket.ticket_id)?;
        self.store.record_tool_call(&ticket.run_id)?;
        self.store
            .transition_run_status(&ticket.run_id, RunStatus::Executing)?;
        let result = self.sandbox.execute(ticket, input)?;
        validate_payload("output", &capability.output_schema, &result.output)?;
        self.store
            .transition_run_status(&ticket.run_id, RunStatus::Observing)?;
        Ok(result)
    }

    pub fn verify(&mut self, result: &SandboxResult) -> CoreResult<Proof> {
        if !result.success {
            return Err(CoreError::PolicyDenied("sandbox result failed".into()));
        }

        self.store
            .transition_run_status(&result.run_id, RunStatus::Verifying)?;

        Ok(Proof {
            proof_id: format!("proof_{}", Uuid::new_v4()),
            run_id: result.run_id.clone(),
            source_type: "tool_output".into(),
            source_ref: result.ticket_id.clone(),
            hash: result.output_hash.clone(),
            claim: format!("{} completed successfully", result.capability_id),
            confidence: Confidence::High,
            collected_at: Utc::now(),
        })
    }

    pub fn commit(&mut self, event: LedgerEvent) -> CoreResult<LedgerEvent> {
        if event.result == EventResult::Success && event.proof_refs.is_empty() {
            return Err(CoreError::ProofRequired);
        }

        self.store
            .transition_run_status(&event.run_id, RunStatus::Persisting)?;
        let event = self.store.append_ledger_event(event)?;
        if event.result == EventResult::Success {
            self.store
                .transition_run_status(&event.run_id, RunStatus::Completed)?;
        }
        Ok(event)
    }

    pub fn run_status(&self, run_id: &str) -> CoreResult<Option<RunStatus>> {
        Ok(self.store.get_run_status(run_id)?)
    }

    pub fn ledger_events_for_run(&self, run_id: &str) -> CoreResult<Vec<LedgerEvent>> {
        Ok(self.store.ledger_events_for_run(run_id)?)
    }

    pub fn validate_ledger(&self) -> CoreResult<()> {
        Ok(self.store.validate_ledger_hash_chain()?)
    }
}

pub fn file_read_capability() -> CapabilityContract {
    CapabilityContract {
        capability_id: "file.read".into(),
        provider: "builtin.fs".into(),
        input_schema: serde_json::json!({
            "type": "object",
            "required": ["path"],
            "additionalProperties": false,
            "properties": {
                "path": { "type": "string", "minLength": 1 }
            }
        }),
        output_schema: serde_json::json!({
            "type": "object",
            "required": ["path", "content"],
            "additionalProperties": false,
            "properties": {
                "path": { "type": "string" },
                "content": { "type": "string" }
            }
        }),
        error_schema: serde_json::json!({
            "type": "object",
            "required": ["code", "message"],
            "properties": {
                "code": { "type": "string" },
                "message": { "type": "string" }
            }
        }),
        permissions: moxi_contracts::Permissions {
            resources: vec!["workspace.read".into()],
            denied: vec!["network".into(), "shell".into()],
        },
        sandbox_profile: "fs-readonly".into(),
        risk_level: RiskLevel::Low,
        timeout_ms: 10_000,
        retry_policy: Default::default(),
        audit_required: true,
        proof_required: true,
        rollback_required: false,
    }
}

pub fn ledger_event_for_success(
    result: &SandboxResult,
    proof: &Proof,
    resource_ref: impl Into<String>,
    policy_decision_ref: impl Into<String>,
    delta_id: impl Into<String>,
) -> LedgerEvent {
    LedgerEvent {
        ledger_event_id: format!("le_{}", Uuid::new_v4()),
        run_id: result.run_id.clone(),
        event_type: "tool.executed".into(),
        actor_id: "kernel".into(),
        resource_ref: resource_ref.into(),
        delta_id: delta_id.into(),
        capability_id: result.capability_id.clone(),
        policy_decision_ref: policy_decision_ref.into(),
        proof_refs: vec![proof.proof_id.clone()],
        input_hash: "".into(),
        output_hash: result.output_hash.clone(),
        previous_event_hash: String::new(),
        event_hash: String::new(),
        result: EventResult::Success,
        timestamp: Utc::now(),
    }
}

fn validate_schema(name: &str, schema: &Value) -> CoreResult<()> {
    JSONSchema::compile(schema)
        .map(|_| ())
        .map_err(|error| CoreError::SchemaValidation(name.into(), error.to_string()))
}

fn validate_payload(name: &str, schema: &Value, payload: &Value) -> CoreResult<()> {
    let compiled = JSONSchema::compile(schema)
        .map_err(|error| CoreError::SchemaValidation(name.into(), error.to_string()))?;
    if let Err(errors) = compiled.validate(payload) {
        let message = errors
            .map(|error| error.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        return Err(CoreError::SchemaValidation(name.into(), message));
    }
    Ok(())
}

fn permission_mode_denial(mode: PermissionMode, resources: &[String]) -> Option<String> {
    resources
        .iter()
        .find(|resource| !permission_mode_allows_resource(mode, resource))
        .map(|resource| {
            format!(
                "permission mode {} does not allow {resource}",
                permission_mode_name(mode)
            )
        })
}

fn permission_mode_allows_resource(mode: PermissionMode, resource: &str) -> bool {
    let resource = resource.to_ascii_lowercase();
    match mode {
        PermissionMode::ReadOnly => is_read_resource(&resource),
        PermissionMode::WorkspaceWrite => {
            !is_network_resource(&resource)
                && !is_shell_resource(&resource)
                && !is_privileged_resource(&resource)
        }
        PermissionMode::Networked => {
            !is_shell_resource(&resource) && !is_privileged_resource(&resource)
        }
        PermissionMode::Privileged => true,
    }
}

fn is_read_resource(resource: &str) -> bool {
    resource.ends_with(".read") || resource == "workspace.read" || resource == "memory.read"
}

fn is_network_resource(resource: &str) -> bool {
    resource.contains("network")
}

fn is_shell_resource(resource: &str) -> bool {
    resource.contains("shell")
}

fn is_privileged_resource(resource: &str) -> bool {
    resource.contains("credential") || resource.contains("privileged")
}

fn permission_mode_name(mode: PermissionMode) -> &'static str {
    match mode {
        PermissionMode::ReadOnly => "read_only",
        PermissionMode::WorkspaceWrite => "workspace_write",
        PermissionMode::Networked => "networked",
        PermissionMode::Privileged => "privileged",
    }
}

#[allow(dead_code)]
fn hash_json(value: &Value) -> String {
    sha256_hex(serde_json::to_vec(value).expect("json serialization cannot fail"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use moxi_contracts::{Budget, DeltaTarget, ResourceType};
    use moxi_store::StoreError;
    use serde_json::json;
    use std::fs;
    use tempfile::tempdir;

    fn intent(root: &std::path::Path, capabilities: Vec<String>) -> Intent {
        intent_with_budget(root, capabilities, Budget::default())
    }

    fn intent_with_budget(
        root: &std::path::Path,
        capabilities: Vec<String>,
        budget: Budget,
    ) -> Intent {
        Intent {
            intent_id: "intent_1".into(),
            tenant_id: "tenant_a".into(),
            user_id: "user_a".into(),
            goal: "read a file".into(),
            requested_capabilities: capabilities,
            risk_level: RiskLevel::Low,
            workspace_root: root.to_string_lossy().into_owned(),
            budget,
        }
    }

    fn delta(run_id: &str, path: &str, capability_id: &str, risk_level: RiskLevel) -> WorldDelta {
        WorldDelta {
            delta_id: "delta_1".into(),
            run_id: run_id.into(),
            proposed_by: "test".into(),
            capability_id: capability_id.into(),
            state: DeltaState::Draft,
            target: DeltaTarget {
                resource_type: ResourceType::File,
                resource_ref: path.into(),
            },
            change_summary: "read authorized file".into(),
            preconditions: vec!["file exists".into()],
            patch_ref: None,
            evidence_refs: vec![],
            risk_level,
            rollback_plan_ref: None,
        }
    }

    fn file_write_capability() -> CapabilityContract {
        let mut capability = file_read_capability();
        capability.capability_id = "file.write".into();
        capability.permissions.resources = vec!["workspace.write".into()];
        capability.permissions.denied = vec!["network".into(), "shell".into()];
        capability
    }

    #[test]
    fn rejects_invalid_capability_schema() {
        let temp = tempdir().unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        let mut capability = file_read_capability();
        capability.input_schema = json!({ "type": "not-a-json-schema-type" });

        assert!(matches!(
            kernel.register_capability(capability),
            Err(CoreError::SchemaValidation(_, _))
        ));
    }

    #[test]
    fn policy_allows_registered_declared_low_risk_capability() {
        let temp = tempdir().unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        kernel.register_capability(file_read_capability()).unwrap();
        let run = kernel
            .admit(intent(temp.path(), vec!["file.read".into()]))
            .unwrap();

        let policy = kernel
            .propose_delta(
                &run.run_id,
                delta(&run.run_id, "hello.txt", "file.read", RiskLevel::Low),
            )
            .unwrap();

        assert_eq!(policy.decision, Decision::Allow);
    }

    #[test]
    fn policy_denies_capability_not_declared_in_run_contract() {
        let temp = tempdir().unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        kernel.register_capability(file_read_capability()).unwrap();
        let run = kernel.admit(intent(temp.path(), vec![])).unwrap();

        let policy = kernel
            .propose_delta(
                &run.run_id,
                delta(&run.run_id, "hello.txt", "file.read", RiskLevel::Low),
            )
            .unwrap();

        assert_eq!(policy.decision, Decision::Deny);
    }

    #[test]
    fn policy_requires_approval_for_high_risk_delta() {
        let temp = tempdir().unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        kernel.register_capability(file_read_capability()).unwrap();
        let run = kernel
            .admit(intent(temp.path(), vec!["file.read".into()]))
            .unwrap();

        let policy = kernel
            .propose_delta(
                &run.run_id,
                delta(&run.run_id, "hello.txt", "file.read", RiskLevel::High),
            )
            .unwrap();

        assert_eq!(policy.decision, Decision::RequireApproval);
    }

    #[test]
    fn approval_grant_resumes_same_run_and_allows_ticket() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("hello.txt"), "hello").unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        kernel.register_capability(file_read_capability()).unwrap();
        let run = kernel
            .admit(intent(temp.path(), vec!["file.read".into()]))
            .unwrap();
        let delta = delta(&run.run_id, "hello.txt", "file.read", RiskLevel::High);
        let policy = kernel.propose_delta(&run.run_id, delta.clone()).unwrap();
        assert_eq!(
            kernel.run_status(&run.run_id).unwrap(),
            Some(RunStatus::AwaitingApproval)
        );

        let grant = kernel
            .grant_approval(&policy, "human_1", "reviewed high-risk file read")
            .unwrap();
        let capability = kernel.capability("file.read").unwrap().clone();
        let ticket = kernel
            .issue_ticket_with_grant(&policy, &capability, &grant)
            .unwrap();
        let result = kernel
            .execute(
                &ticket,
                SandboxInput {
                    capability_id: "file.read".into(),
                    payload: json!({ "path": "hello.txt" }),
                },
            )
            .unwrap();

        assert_eq!(grant.run_id, run.run_id);
        assert_eq!(
            kernel.run_status(&run.run_id).unwrap(),
            Some(RunStatus::Observing)
        );
        assert_eq!(result.output["content"], "hello");
    }

    #[test]
    fn read_only_run_denies_workspace_write_capability() {
        let temp = tempdir().unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        kernel.register_capability(file_write_capability()).unwrap();
        let run = kernel
            .admit(intent(temp.path(), vec!["file.write".into()]))
            .unwrap();

        let policy = kernel
            .propose_delta(
                &run.run_id,
                delta(&run.run_id, "hello.txt", "file.write", RiskLevel::Low),
            )
            .unwrap();

        assert_eq!(policy.decision, Decision::Deny);
        assert!(policy
            .reasons
            .iter()
            .any(|reason| reason.contains("permission mode read_only")));
    }

    #[test]
    fn cannot_issue_ticket_without_allow_policy() {
        let temp = tempdir().unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        kernel.register_capability(file_read_capability()).unwrap();
        let run = kernel.admit(intent(temp.path(), vec![])).unwrap();
        let policy = kernel
            .propose_delta(
                &run.run_id,
                delta(&run.run_id, "hello.txt", "file.read", RiskLevel::Low),
            )
            .unwrap();
        let capability = kernel.capability("file.read").unwrap();

        assert!(matches!(
            kernel.issue_ticket(&policy, capability),
            Err(CoreError::PolicyDenied(_))
        ));
    }

    #[test]
    fn unregistered_capability_is_rejected() {
        let temp = tempdir().unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        let run = kernel
            .admit(intent(temp.path(), vec!["file.read".into()]))
            .unwrap();

        assert!(matches!(
            kernel.propose_delta(
                &run.run_id,
                delta(&run.run_id, "hello.txt", "file.read", RiskLevel::Low)
            ),
            Err(CoreError::CapabilityNotFound(_))
        ));
    }

    #[test]
    fn file_read_end_to_end_produces_proof_ledger_and_completed_state() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("hello.txt"), "hello").unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        kernel.register_capability(file_read_capability()).unwrap();

        let run = kernel
            .admit(intent(temp.path(), vec!["file.read".into()]))
            .unwrap();
        let delta = delta(&run.run_id, "hello.txt", "file.read", RiskLevel::Low);
        let policy = kernel.propose_delta(&run.run_id, delta.clone()).unwrap();
        let capability = kernel.capability("file.read").unwrap().clone();
        let ticket = kernel.issue_ticket(&policy, &capability).unwrap();
        let sandbox_result = kernel
            .execute(
                &ticket,
                SandboxInput {
                    capability_id: "file.read".into(),
                    payload: json!({ "path": "hello.txt" }),
                },
            )
            .unwrap();
        let proof = kernel.verify(&sandbox_result).unwrap();
        let event = ledger_event_for_success(
            &sandbox_result,
            &proof,
            "hello.txt",
            &policy.decision_id,
            &delta.delta_id,
        );
        let committed = kernel.commit(event).unwrap();

        assert_eq!(sandbox_result.output["content"], "hello");
        assert_eq!(
            kernel.run_status(&run.run_id).unwrap(),
            Some(RunStatus::Completed)
        );
        assert_eq!(
            kernel.ledger_events_for_run(&run.run_id).unwrap()[0].ledger_event_id,
            committed.ledger_event_id
        );
        assert!(!committed.event_hash.is_empty());
    }

    #[test]
    fn heartbeat_budget_blocks_extra_heartbeat() {
        let temp = tempdir().unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        let budget = Budget {
            max_heartbeats: 1,
            ..Default::default()
        };
        let run = kernel
            .admit(intent_with_budget(
                temp.path(),
                vec!["file.read".into()],
                budget,
            ))
            .unwrap();

        kernel.start_heartbeat(&run.run_id).unwrap();

        assert!(matches!(
            kernel.start_heartbeat(&run.run_id),
            Err(CoreError::Store(StoreError::BudgetExceeded {
                counter: "heartbeats",
                ..
            }))
        ));
    }

    #[test]
    fn execution_ticket_cannot_be_reused() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("hello.txt"), "hello").unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        kernel.register_capability(file_read_capability()).unwrap();
        let run = kernel
            .admit(intent(temp.path(), vec!["file.read".into()]))
            .unwrap();
        let policy = kernel
            .propose_delta(
                &run.run_id,
                delta(&run.run_id, "hello.txt", "file.read", RiskLevel::Low),
            )
            .unwrap();
        let capability = kernel.capability("file.read").unwrap().clone();
        let ticket = kernel.issue_ticket(&policy, &capability).unwrap();

        kernel
            .execute(
                &ticket,
                SandboxInput {
                    capability_id: "file.read".into(),
                    payload: json!({ "path": "hello.txt" }),
                },
            )
            .unwrap();

        assert!(matches!(
            kernel.execute(
                &ticket,
                SandboxInput {
                    capability_id: "file.read".into(),
                    payload: json!({ "path": "hello.txt" }),
                },
            ),
            Err(CoreError::Store(StoreError::TicketConsumed(_)))
        ));
    }

    #[test]
    fn tool_call_budget_blocks_extra_execution() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("hello.txt"), "hello").unwrap();
        let budget = Budget {
            max_tool_calls: 1,
            ..Default::default()
        };
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        kernel.register_capability(file_read_capability()).unwrap();
        let run = kernel
            .admit(intent_with_budget(
                temp.path(),
                vec!["file.read".into()],
                budget,
            ))
            .unwrap();

        for index in 0..2 {
            let mut next_delta = delta(&run.run_id, "hello.txt", "file.read", RiskLevel::Low);
            next_delta.delta_id = format!("delta_{index}");
            let policy = kernel.propose_delta(&run.run_id, next_delta).unwrap();
            let capability = kernel.capability("file.read").unwrap().clone();
            let ticket = kernel.issue_ticket(&policy, &capability).unwrap();
            let result = kernel.execute(
                &ticket,
                SandboxInput {
                    capability_id: "file.read".into(),
                    payload: json!({ "path": "hello.txt" }),
                },
            );

            if index == 0 {
                result.unwrap();
            } else {
                assert!(matches!(
                    result,
                    Err(CoreError::Store(StoreError::BudgetExceeded {
                        counter: "tool_calls",
                        ..
                    }))
                ));
            }
        }
    }

    #[test]
    fn output_without_proof_cannot_be_committed_successfully() {
        let temp = tempdir().unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        let event = LedgerEvent {
            ledger_event_id: "le_1".into(),
            run_id: "run_1".into(),
            event_type: "tool.executed".into(),
            actor_id: "kernel".into(),
            resource_ref: "hello.txt".into(),
            delta_id: "delta_1".into(),
            capability_id: "file.read".into(),
            policy_decision_ref: "pd_1".into(),
            proof_refs: vec![],
            input_hash: "".into(),
            output_hash: "out".into(),
            previous_event_hash: String::new(),
            event_hash: String::new(),
            result: EventResult::Success,
            timestamp: Utc::now(),
        };

        assert!(matches!(
            kernel.commit(event),
            Err(CoreError::ProofRequired)
        ));
    }

    #[test]
    fn file_read_blocks_workspace_escape() {
        let workspace = tempdir().unwrap();
        let outside = tempdir().unwrap();
        fs::write(outside.path().join("secret.txt"), "secret").unwrap();
        let mut kernel = Kernel::new_in_memory(workspace.path()).unwrap();
        kernel.register_capability(file_read_capability()).unwrap();
        let run = kernel
            .admit(intent(workspace.path(), vec!["file.read".into()]))
            .unwrap();
        let delta = delta(&run.run_id, "secret.txt", "file.read", RiskLevel::Low);
        let policy = kernel.propose_delta(&run.run_id, delta).unwrap();
        let capability = kernel.capability("file.read").unwrap().clone();
        let ticket = kernel.issue_ticket(&policy, &capability).unwrap();

        let err = kernel
            .execute(
                &ticket,
                SandboxInput {
                    capability_id: "file.read".into(),
                    payload: json!({
                        "path": outside.path().join("secret.txt").to_string_lossy()
                    }),
                },
            )
            .unwrap_err();

        assert!(matches!(
            err,
            CoreError::Sandbox(SandboxError::OutsideWorkspace(_))
        ));
    }
}
