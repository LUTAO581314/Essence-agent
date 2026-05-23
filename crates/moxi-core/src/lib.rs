use chrono::{Duration, Utc};
use jsonschema::JSONSchema;
use moxi_contracts::{
    ApprovalGrant, CapabilityContract, Confidence, Decision, DeltaState, EventResult,
    ExecutionTicket, ExecutorIsolation, ExecutorManifest, Intent, LedgerEvent, PermissionMode,
    PolicyConfig, PolicyDecision, Proof, RequiredApproval, RiskLevel, RunContract, RunStatus,
    SandboxInput, SandboxResult, WorldDelta,
};
use moxi_sandbox::{sha256_hex, FileReadSandbox, ProcessSandbox, Sandbox, SandboxError};
use moxi_store::{AuditReplayReport, Store, StoreError};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("capability not registered: {0}")]
    CapabilityNotFound(String),
    #[error("capability executor not registered: {0}")]
    ExecutorNotFound(String),
    #[error("executor isolation is not supported by this runtime: {0:?}")]
    ExecutorIsolationUnsupported(ExecutorIsolation),
    #[error("executor manifest does not match capability contract: {0}")]
    ExecutorManifestMismatch(String),
    #[error("ticket binding does not match current executor or capability contract")]
    ExecutionBindingMismatch,
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
    #[error("run timed out: {0}")]
    RunTimedOut(String),
    #[error("executor result does not match execution ticket")]
    ExecutorResultMismatch,
    #[error("sandbox result was not recorded by this kernel: {0}")]
    ResultNotFound(String),
    #[error("sandbox result does not match recorded execution")]
    ResultBindingMismatch,
    #[error("proof required before successful ledger commit")]
    ProofRequired,
    #[error("proof was not recorded by this kernel: {0}")]
    ProofNotFound(String),
    #[error("proof does not match ledger event")]
    ProofBindingMismatch,
    #[error("store error: {0}")]
    Store(#[from] StoreError),
    #[error("sandbox error: {0}")]
    Sandbox(#[from] SandboxError),
}

pub type CoreResult<T> = Result<T, CoreError>;

pub trait CapabilityExecutor {
    fn execute(&self, ticket: &ExecutionTicket, input: SandboxInput) -> CoreResult<SandboxResult>;
}

#[derive(Debug, Clone)]
pub struct PolicyEngine {
    config: PolicyConfig,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PolicyEvaluation {
    pub decision: Decision,
    pub risk_level: RiskLevel,
    pub reasons: Vec<String>,
    pub required_approval: Option<RequiredApproval>,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new(PolicyConfig::default())
    }
}

impl PolicyEngine {
    pub fn new(config: PolicyConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &PolicyConfig {
        &self.config
    }

    pub fn set_config(&mut self, config: PolicyConfig) {
        self.config = config;
    }

    pub fn evaluate(
        &self,
        run: &RunContract,
        capability: &CapabilityContract,
        delta: &WorldDelta,
    ) -> PolicyEvaluation {
        let mut reasons = Vec::new();
        let risk_level = std::cmp::max(delta.risk_level, capability.risk_level);

        if self.config.require_declared_capabilities
            && !run
                .required_capabilities
                .contains(&capability.capability_id)
        {
            reasons.push("capability not declared in RunContract".into());
        }

        if capability_rule_matches(&self.config.denied_capabilities, &capability.capability_id) {
            reasons.push(format!(
                "capability {} is denied by policy config",
                capability.capability_id
            ));
        }

        if self
            .config
            .deny_at_or_above
            .is_some_and(|threshold| risk_level >= threshold)
        {
            reasons.push(format!(
                "risk level {:?} is denied by policy config",
                risk_level
            ));
        }

        if let Some(reason) =
            permission_mode_denial(run.permission_mode, &capability.permissions.resources)
        {
            reasons.push(reason);
        }

        if let Some(resource) = first_matching_resource(
            &self.config.denied_resource_patterns,
            &capability.permissions.resources,
        ) {
            reasons.push(format!("resource {resource} is denied by policy config"));
        }

        if !reasons.is_empty() {
            return PolicyEvaluation {
                decision: Decision::Deny,
                risk_level,
                reasons,
                required_approval: None,
            };
        }

        let mut approval_reasons = Vec::new();
        if self
            .config
            .approval_required_at_or_above
            .is_some_and(|threshold| risk_level >= threshold)
        {
            approval_reasons.push(format!(
                "risk level {:?} requires {:?} approval",
                risk_level, self.config.approval_policy
            ));
        }

        if capability_rule_matches(
            &self.config.approval_required_capabilities,
            &capability.capability_id,
        ) {
            approval_reasons.push(format!(
                "capability {} requires {:?} approval",
                capability.capability_id, self.config.approval_policy
            ));
        }

        if let Some(resource) = first_matching_resource(
            &self.config.approval_required_resource_patterns,
            &capability.permissions.resources,
        ) {
            approval_reasons.push(format!(
                "resource {resource} requires {:?} approval",
                self.config.approval_policy
            ));
        }

        if !approval_reasons.is_empty() {
            return PolicyEvaluation {
                decision: Decision::RequireApproval,
                risk_level,
                reasons: approval_reasons,
                required_approval: Some(RequiredApproval {
                    approval_policy: self.config.approval_policy,
                    approval_ref: self.config.approval_ref.clone(),
                }),
            };
        }

        PolicyEvaluation {
            decision: Decision::Allow,
            risk_level,
            reasons: vec!["policy config, run contract, and capability checks passed".into()],
            required_approval: None,
        }
    }
}

struct ExecutorRegistration {
    manifest: ExecutorManifest,
    executor: Box<dyn CapabilityExecutor>,
}

impl CapabilityExecutor for FileReadSandbox {
    fn execute(&self, ticket: &ExecutionTicket, input: SandboxInput) -> CoreResult<SandboxResult> {
        Ok(Sandbox::execute(self, ticket, input)?)
    }
}

impl CapabilityExecutor for ProcessSandbox {
    fn execute(&self, ticket: &ExecutionTicket, input: SandboxInput) -> CoreResult<SandboxResult> {
        Ok(Sandbox::execute(self, ticket, input)?)
    }
}

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
    executors: HashMap<String, ExecutorRegistration>,
    runs: HashMap<String, RunContract>,
    policy_engine: PolicyEngine,
    store: Store,
}

impl Kernel {
    pub fn new_in_memory(workspace_root: impl Into<PathBuf>) -> CoreResult<Self> {
        let mut kernel = Self {
            actor_id: "kernel".into(),
            registry: CapabilityRegistry::default(),
            executors: HashMap::new(),
            runs: HashMap::new(),
            policy_engine: PolicyEngine::default(),
            store: Store::open_memory()?,
        };
        let capability = file_read_capability();
        kernel.register_executor(
            file_read_executor_manifest(&capability),
            FileReadSandbox::new(workspace_root),
        )?;
        Ok(kernel)
    }

    pub fn new_in_memory_with_policy_config(
        workspace_root: impl Into<PathBuf>,
        policy_config: PolicyConfig,
    ) -> CoreResult<Self> {
        let mut kernel = Self::new_in_memory(workspace_root)?;
        kernel.set_policy_config(policy_config);
        Ok(kernel)
    }

    pub fn with_store(workspace_root: impl Into<PathBuf>, store: Store) -> Self {
        let mut kernel = Self {
            actor_id: "kernel".into(),
            registry: CapabilityRegistry::default(),
            executors: HashMap::new(),
            runs: HashMap::new(),
            policy_engine: PolicyEngine::default(),
            store,
        };
        let capability = file_read_capability();
        kernel
            .register_executor(
                file_read_executor_manifest(&capability),
                FileReadSandbox::new(workspace_root),
            )
            .expect("built-in file.read executor manifest is valid");
        kernel
    }

    pub fn with_store_and_policy_config(
        workspace_root: impl Into<PathBuf>,
        store: Store,
        policy_config: PolicyConfig,
    ) -> Self {
        let mut kernel = Self::with_store(workspace_root, store);
        kernel.set_policy_config(policy_config);
        kernel
    }

    pub fn policy_config(&self) -> &PolicyConfig {
        self.policy_engine.config()
    }

    pub fn set_policy_config(&mut self, policy_config: PolicyConfig) {
        self.policy_engine.set_config(policy_config);
    }

    pub fn register_capability(&mut self, contract: CapabilityContract) -> CoreResult<()> {
        let capability_id = contract.capability_id.clone();
        self.registry.register(contract)?;
        if let (Some(capability), Some(executor)) = (
            self.registry.get(&capability_id),
            self.executors.get(&capability_id),
        ) {
            validate_executor_manifest(capability, &executor.manifest)?;
        }
        Ok(())
    }

    pub fn register_executor(
        &mut self,
        manifest: ExecutorManifest,
        executor: impl CapabilityExecutor + 'static,
    ) -> CoreResult<()> {
        if !matches!(
            manifest.isolation,
            ExecutorIsolation::InProcessTrusted | ExecutorIsolation::ProcessSandbox
        ) {
            return Err(CoreError::ExecutorIsolationUnsupported(manifest.isolation));
        }
        if let Some(capability) = self.registry.get(&manifest.capability_id) {
            validate_executor_manifest(capability, &manifest)?;
        }
        self.executors.insert(
            manifest.capability_id.clone(),
            ExecutorRegistration {
                manifest,
                executor: Box::new(executor),
            },
        );
        Ok(())
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
            gateway_decision_ref: intent.gateway_decision_ref,
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

    fn enforce_run_timeout(&self, run: &RunContract) -> CoreResult<()> {
        match self
            .store
            .get_run_status(&run.run_id)?
            .ok_or_else(|| CoreError::RunNotFound(run.run_id.clone()))?
        {
            RunStatus::TimedOut => return Err(CoreError::RunTimedOut(run.run_id.clone())),
            RunStatus::Completed
            | RunStatus::Failed
            | RunStatus::Cancelled
            | RunStatus::Blocked
            | RunStatus::RolledBack => return Ok(()),
            _ => {}
        }

        let timeout_ms = std::cmp::min(run.budget.timeout_ms, i64::MAX as u64) as i64;
        if let Some(deadline) = run
            .created_at
            .checked_add_signed(Duration::milliseconds(timeout_ms))
        {
            if Utc::now() >= deadline {
                self.store
                    .transition_run_status(&run.run_id, RunStatus::TimedOut)?;
                return Err(CoreError::RunTimedOut(run.run_id.clone()));
            }
        }

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

        self.enforce_run_timeout(run)?;

        if delta.run_id != run.run_id {
            return Err(CoreError::RunMismatch);
        }

        self.store.record_step(run_id)?;

        let Some(capability) = self.registry.get(&delta.capability_id) else {
            return Err(CoreError::CapabilityNotFound(delta.capability_id));
        };

        let evaluation = self.policy_engine.evaluate(run, capability, &delta);

        delta.state = DeltaState::PolicyChecked;
        let policy = PolicyDecision {
            decision_id: format!("pd_{}", Uuid::new_v4()),
            run_id: run.run_id.clone(),
            delta_id: delta.delta_id,
            actor_id: self.actor_id.clone(),
            capability_id: capability.capability_id.clone(),
            decision: evaluation.decision,
            risk_level: evaluation.risk_level,
            reasons: evaluation.reasons,
            required_approval: evaluation.required_approval,
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
        let run = self
            .runs
            .get(&policy.run_id)
            .ok_or_else(|| CoreError::RunNotFound(policy.run_id.clone()))?;
        self.enforce_run_timeout(run)?;

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

        let executor = self
            .executors
            .get(&capability.capability_id)
            .ok_or_else(|| CoreError::ExecutorNotFound(capability.capability_id.clone()))?;
        validate_executor_manifest(capability, &executor.manifest)?;
        let capability_contract_hash = capability_contract_hash(capability);
        let executor_manifest_hash = executor_manifest_hash(&executor.manifest);

        let ticket = ExecutionTicket {
            ticket_id: format!("ticket_{}", Uuid::new_v4()),
            run_id: policy.run_id.clone(),
            delta_id: policy.delta_id.clone(),
            policy_decision_ref: policy.decision_id.clone(),
            capability_contract_ref: capability.capability_id.clone(),
            capability_contract_hash,
            executor_ref: executor.manifest.executor_id.clone(),
            executor_version: executor.manifest.executor_version.clone(),
            executor_artifact_hash: executor.manifest.artifact_hash.clone(),
            executor_signature_ref: executor_signature_ref(&executor.manifest)?,
            executor_signing_key_ref: executor.manifest.signing_key_ref.clone(),
            executor_manifest_hash,
            executor_isolation: executor.manifest.isolation,
            retry_policy: capability.retry_policy.clone(),
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
        let run = self
            .runs
            .get(&ticket.run_id)
            .ok_or_else(|| CoreError::RunNotFound(ticket.run_id.clone()))?;
        self.enforce_run_timeout(run)?;

        if ticket.expires_at < Utc::now() {
            return Err(CoreError::TicketExpired(ticket.ticket_id.clone()));
        }

        let stored_ticket = self
            .store
            .execution_ticket(&ticket.ticket_id)?
            .ok_or_else(|| CoreError::Store(StoreError::TicketUnknown(ticket.ticket_id.clone())))?;
        if stored_ticket != *ticket {
            return Err(CoreError::ExecutionBindingMismatch);
        }

        let capability = self
            .registry
            .get(&ticket.capability_id)
            .ok_or_else(|| CoreError::CapabilityNotFound(ticket.capability_id.clone()))?;

        if input.capability_id != ticket.capability_id {
            return Err(CoreError::CapabilityNotFound(input.capability_id));
        }

        let executor = self
            .executors
            .get(&ticket.capability_id)
            .ok_or_else(|| CoreError::ExecutorNotFound(ticket.capability_id.clone()))?;
        validate_execution_binding(ticket, capability, &executor.manifest)?;

        let input_hash = hash_json(
            &serde_json::to_value(&input).expect("sandbox input serialization cannot fail"),
        );
        validate_payload("input", &capability.input_schema, &input.payload)?;
        self.store.consume_ticket(&ticket.ticket_id)?;
        self.store.record_tool_call(&ticket.run_id)?;
        self.store
            .transition_run_status(&ticket.run_id, RunStatus::Executing)?;
        let mut result = match executor.executor.execute(ticket, input) {
            Ok(result) => result,
            Err(error) => {
                self.store
                    .transition_run_status(&ticket.run_id, RunStatus::Failed)?;
                return Err(error);
            }
        };
        if result.ticket_id != ticket.ticket_id
            || result.run_id != ticket.run_id
            || result.capability_id != ticket.capability_id
        {
            self.store
                .transition_run_status(&ticket.run_id, RunStatus::Failed)?;
            return Err(CoreError::ExecutorResultMismatch);
        }
        result.policy_decision_ref = ticket.policy_decision_ref.clone();
        result.capability_contract_ref = ticket.capability_contract_ref.clone();
        result.capability_contract_hash = ticket.capability_contract_hash.clone();
        result.executor_ref = ticket.executor_ref.clone();
        result.executor_version = ticket.executor_version.clone();
        result.executor_artifact_hash = ticket.executor_artifact_hash.clone();
        result.executor_signature_ref = ticket.executor_signature_ref.clone();
        result.executor_signing_key_ref = ticket.executor_signing_key_ref.clone();
        result.executor_manifest_hash = ticket.executor_manifest_hash.clone();
        result.gateway_decision_ref = run.gateway_decision_ref.clone();
        result.input_hash = input_hash;
        result.output_hash = hash_json(&result.output);
        if let Err(error) = validate_payload("output", &capability.output_schema, &result.output) {
            self.store
                .transition_run_status(&ticket.run_id, RunStatus::Failed)?;
            return Err(error);
        }
        self.store.record_sandbox_result(&result)?;
        self.store
            .transition_run_status(&ticket.run_id, RunStatus::Observing)?;
        Ok(result)
    }

    pub fn verify(&mut self, result: &SandboxResult) -> CoreResult<Proof> {
        if !result.success {
            return Err(CoreError::PolicyDenied("sandbox result failed".into()));
        }
        if result.output_hash != hash_json(&result.output) {
            return Err(CoreError::ResultBindingMismatch);
        }

        let stored_result = self
            .store
            .sandbox_result(&result.ticket_id)?
            .ok_or_else(|| CoreError::ResultNotFound(result.ticket_id.clone()))?;
        if stored_result != *result {
            return Err(CoreError::ResultBindingMismatch);
        }

        let stored_ticket = self
            .store
            .execution_ticket(&result.ticket_id)?
            .ok_or_else(|| CoreError::Store(StoreError::TicketUnknown(result.ticket_id.clone())))?;
        validate_result_ticket_binding(result, &stored_ticket)?;

        self.store
            .transition_run_status(&result.run_id, RunStatus::Verifying)?;

        let evidence_hash = hash_json(&serde_json::json!({
            "ticket_id": result.ticket_id.clone(),
            "run_id": result.run_id.clone(),
            "capability_id": result.capability_id.clone(),
            "policy_decision_ref": result.policy_decision_ref.clone(),
            "capability_contract_ref": result.capability_contract_ref.clone(),
            "capability_contract_hash": result.capability_contract_hash.clone(),
            "executor_ref": result.executor_ref.clone(),
            "executor_version": result.executor_version.clone(),
            "executor_artifact_hash": result.executor_artifact_hash.clone(),
            "executor_signature_ref": result.executor_signature_ref.clone(),
            "executor_signing_key_ref": result.executor_signing_key_ref.clone(),
            "executor_manifest_hash": result.executor_manifest_hash.clone(),
            "gateway_decision_ref": result.gateway_decision_ref.clone(),
            "input_hash": result.input_hash.clone(),
            "output_hash": result.output_hash.clone(),
        }));

        let proof = Proof {
            proof_id: format!("proof_{}", Uuid::new_v4()),
            run_id: result.run_id.clone(),
            policy_decision_ref: result.policy_decision_ref.clone(),
            capability_contract_ref: result.capability_contract_ref.clone(),
            capability_contract_hash: result.capability_contract_hash.clone(),
            executor_ref: result.executor_ref.clone(),
            executor_version: result.executor_version.clone(),
            executor_artifact_hash: result.executor_artifact_hash.clone(),
            executor_signature_ref: result.executor_signature_ref.clone(),
            executor_signing_key_ref: result.executor_signing_key_ref.clone(),
            executor_manifest_hash: result.executor_manifest_hash.clone(),
            gateway_decision_ref: result.gateway_decision_ref.clone(),
            input_hash: result.input_hash.clone(),
            output_hash: result.output_hash.clone(),
            source_type: "tool_output".into(),
            source_ref: result.ticket_id.clone(),
            hash: evidence_hash,
            claim: format!("{} completed successfully", result.capability_id),
            confidence: Confidence::High,
            collected_at: Utc::now(),
        };
        self.store.record_proof(&proof)?;
        Ok(proof)
    }

    pub fn commit(&mut self, event: LedgerEvent) -> CoreResult<LedgerEvent> {
        if event.result == EventResult::Success {
            validate_event_proofs(&self.store, &event)?;
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

    pub fn execution_ticket(&self, ticket_id: &str) -> CoreResult<Option<ExecutionTicket>> {
        Ok(self.store.execution_ticket(ticket_id)?)
    }

    pub fn proof(&self, proof_id: &str) -> CoreResult<Option<Proof>> {
        Ok(self.store.proof(proof_id)?)
    }

    pub fn sandbox_result(&self, ticket_id: &str) -> CoreResult<Option<SandboxResult>> {
        Ok(self.store.sandbox_result(ticket_id)?)
    }

    pub fn ledger_events_for_run(&self, run_id: &str) -> CoreResult<Vec<LedgerEvent>> {
        Ok(self.store.ledger_events_for_run(run_id)?)
    }

    pub fn validate_ledger(&self) -> CoreResult<()> {
        Ok(self.store.validate_ledger_hash_chain()?)
    }

    pub fn replay_ledger_audit(&self) -> CoreResult<AuditReplayReport> {
        Ok(self.store.replay_ledger_audit()?)
    }
}

pub fn file_read_capability() -> CapabilityContract {
    CapabilityContract {
        capability_id: "file.read".into(),
        capability_version: "0.2.0".into(),
        provider: "builtin.fs".into(),
        provider_identity: "moxi.builtin.fs".into(),
        manifest_ref: Some("builtin://moxi/file.read".into()),
        signature_ref: None,
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

pub fn file_read_executor_manifest(capability: &CapabilityContract) -> ExecutorManifest {
    ExecutorManifest {
        executor_id: "moxi.builtin.fs.file_read".into(),
        capability_id: capability.capability_id.clone(),
        capability_contract_hash: capability_contract_hash(capability),
        provider_identity: capability.provider_identity.clone(),
        executor_version: capability.capability_version.clone(),
        artifact_hash: executor_artifact_hash(
            "moxi.builtin.fs.file_read",
            &capability.capability_version,
        ),
        signing_key_ref: "builtin://moxi/signing-key".into(),
        isolation: ExecutorIsolation::InProcessTrusted,
        sandbox_profile: capability.sandbox_profile.clone(),
        manifest_ref: Some("builtin://moxi/file.read/executor".into()),
        signature_ref: Some("builtin://moxi/file.read/executor/signature".into()),
        attestation_ref: Some("builtin://moxi/file.read/executor/attestation".into()),
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
        execution_ticket_ref: result.ticket_id.clone(),
        capability_contract_ref: result.capability_contract_ref.clone(),
        capability_contract_hash: result.capability_contract_hash.clone(),
        executor_ref: result.executor_ref.clone(),
        executor_version: result.executor_version.clone(),
        executor_artifact_hash: result.executor_artifact_hash.clone(),
        executor_signature_ref: result.executor_signature_ref.clone(),
        executor_signing_key_ref: result.executor_signing_key_ref.clone(),
        executor_manifest_hash: result.executor_manifest_hash.clone(),
        gateway_decision_ref: result.gateway_decision_ref.clone(),
        proof_refs: vec![proof.proof_id.clone()],
        input_hash: result.input_hash.clone(),
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

pub fn capability_contract_hash(capability: &CapabilityContract) -> String {
    sha256_hex(serde_json::to_vec(capability).expect("capability serialization cannot fail"))
}

pub fn executor_manifest_hash(manifest: &ExecutorManifest) -> String {
    sha256_hex(serde_json::to_vec(manifest).expect("executor manifest serialization cannot fail"))
}

pub fn executor_artifact_hash(executor_id: &str, executor_version: &str) -> String {
    format!(
        "sha256:{}",
        sha256_hex(format!("{executor_id}@{executor_version}").as_bytes())
    )
}

fn validate_executor_manifest(
    capability: &CapabilityContract,
    manifest: &ExecutorManifest,
) -> CoreResult<()> {
    if manifest.capability_id != capability.capability_id {
        return Err(CoreError::ExecutorManifestMismatch(
            "capability id mismatch".into(),
        ));
    }
    if manifest.capability_contract_hash != capability_contract_hash(capability) {
        return Err(CoreError::ExecutorManifestMismatch(
            "capability contract hash mismatch".into(),
        ));
    }
    if manifest.provider_identity != capability.provider_identity {
        return Err(CoreError::ExecutorManifestMismatch(
            "provider identity mismatch".into(),
        ));
    }
    if manifest.sandbox_profile != capability.sandbox_profile {
        return Err(CoreError::ExecutorManifestMismatch(
            "sandbox profile mismatch".into(),
        ));
    }
    validate_executor_identity(manifest)?;
    Ok(())
}

fn validate_executor_identity(manifest: &ExecutorManifest) -> CoreResult<()> {
    if !is_sha256_ref(&manifest.artifact_hash) {
        return Err(CoreError::ExecutorManifestMismatch(
            "executor artifact hash must be sha256:<64 lowercase hex chars>".into(),
        ));
    }
    if manifest.signing_key_ref.trim().is_empty() {
        return Err(CoreError::ExecutorManifestMismatch(
            "executor signing key ref is required".into(),
        ));
    }
    executor_signature_ref(manifest)?;
    Ok(())
}

fn executor_signature_ref(manifest: &ExecutorManifest) -> CoreResult<String> {
    manifest
        .signature_ref
        .as_ref()
        .map(|signature_ref| signature_ref.trim())
        .filter(|signature_ref| !signature_ref.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            CoreError::ExecutorManifestMismatch("executor signature ref is required".into())
        })
}

fn is_sha256_ref(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .chars()
            .all(|char| char.is_ascii_hexdigit() && !char.is_ascii_uppercase())
}

fn validate_execution_binding(
    ticket: &ExecutionTicket,
    capability: &CapabilityContract,
    manifest: &ExecutorManifest,
) -> CoreResult<()> {
    validate_executor_manifest(capability, manifest)?;
    let signature_ref = executor_signature_ref(manifest)?;
    if ticket.capability_contract_hash != capability_contract_hash(capability)
        || ticket.executor_ref != manifest.executor_id
        || ticket.executor_version != manifest.executor_version
        || ticket.executor_artifact_hash != manifest.artifact_hash
        || ticket.executor_signature_ref != signature_ref
        || ticket.executor_signing_key_ref != manifest.signing_key_ref
        || ticket.executor_manifest_hash != executor_manifest_hash(manifest)
        || ticket.executor_isolation != manifest.isolation
    {
        return Err(CoreError::ExecutionBindingMismatch);
    }
    Ok(())
}

fn validate_result_ticket_binding(
    result: &SandboxResult,
    ticket: &ExecutionTicket,
) -> CoreResult<()> {
    if result.ticket_id != ticket.ticket_id
        || result.run_id != ticket.run_id
        || result.capability_id != ticket.capability_id
        || result.policy_decision_ref != ticket.policy_decision_ref
        || result.capability_contract_ref != ticket.capability_contract_ref
        || result.capability_contract_hash != ticket.capability_contract_hash
        || result.executor_ref != ticket.executor_ref
        || result.executor_version != ticket.executor_version
        || result.executor_artifact_hash != ticket.executor_artifact_hash
        || result.executor_signature_ref != ticket.executor_signature_ref
        || result.executor_signing_key_ref != ticket.executor_signing_key_ref
        || result.executor_manifest_hash != ticket.executor_manifest_hash
    {
        return Err(CoreError::ResultBindingMismatch);
    }
    Ok(())
}

fn validate_event_proofs(store: &Store, event: &LedgerEvent) -> CoreResult<()> {
    if event.proof_refs.is_empty() {
        return Err(CoreError::ProofRequired);
    }

    for proof_ref in &event.proof_refs {
        let proof = store
            .proof(proof_ref)?
            .ok_or_else(|| CoreError::ProofNotFound(proof_ref.clone()))?;
        validate_event_proof_binding(event, &proof)?;
    }
    Ok(())
}

fn validate_event_proof_binding(event: &LedgerEvent, proof: &Proof) -> CoreResult<()> {
    if proof.run_id != event.run_id
        || proof.policy_decision_ref != event.policy_decision_ref
        || proof.source_ref != event.execution_ticket_ref
        || proof.capability_contract_ref != event.capability_contract_ref
        || proof.capability_contract_hash != event.capability_contract_hash
        || proof.executor_ref != event.executor_ref
        || proof.executor_version != event.executor_version
        || proof.executor_artifact_hash != event.executor_artifact_hash
        || proof.executor_signature_ref != event.executor_signature_ref
        || proof.executor_signing_key_ref != event.executor_signing_key_ref
        || proof.executor_manifest_hash != event.executor_manifest_hash
        || proof.gateway_decision_ref != event.gateway_decision_ref
        || proof.input_hash != event.input_hash
        || proof.output_hash != event.output_hash
    {
        return Err(CoreError::ProofBindingMismatch);
    }
    Ok(())
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

fn capability_rule_matches(patterns: &[String], capability_id: &str) -> bool {
    patterns
        .iter()
        .any(|pattern| exact_or_prefix_pattern_matches(pattern, capability_id))
}

fn first_matching_resource(patterns: &[String], resources: &[String]) -> Option<String> {
    resources
        .iter()
        .find(|resource| {
            patterns
                .iter()
                .any(|pattern| resource_pattern_matches(pattern, resource))
        })
        .cloned()
}

fn exact_or_prefix_pattern_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.trim().to_ascii_lowercase();
    let value = value.to_ascii_lowercase();
    if pattern.is_empty() {
        return false;
    }
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return value.starts_with(prefix);
    }
    value == pattern
}

fn resource_pattern_matches(pattern: &str, resource: &str) -> bool {
    let pattern = pattern.trim().to_ascii_lowercase();
    if pattern.is_empty() {
        return false;
    }
    exact_or_prefix_pattern_matches(&pattern, resource)
        || resource.to_ascii_lowercase().contains(&pattern)
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
    use moxi_contracts::{ApprovalPolicy, Budget, DeltaTarget, ResourceType};
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
            gateway_decision_ref: None,
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

    fn age_run_past_timeout(kernel: &mut Kernel, run_id: &str, elapsed_ms: i64) {
        kernel.runs.get_mut(run_id).unwrap().created_at =
            Utc::now() - Duration::milliseconds(elapsed_ms);
    }

    fn file_write_capability() -> CapabilityContract {
        let mut capability = file_read_capability();
        capability.capability_id = "file.write".into();
        capability.permissions.resources = vec!["workspace.write".into()];
        capability.permissions.denied = vec!["network".into(), "shell".into()];
        capability
    }

    fn memory_echo_capability() -> CapabilityContract {
        CapabilityContract {
            capability_id: "memory.echo".into(),
            capability_version: "0.2.0-test".into(),
            provider: "test.memory".into(),
            provider_identity: "moxi.test.memory".into(),
            manifest_ref: Some("test://memory.echo".into()),
            signature_ref: None,
            input_schema: serde_json::json!({
                "type": "object",
                "required": ["text"],
                "additionalProperties": false,
                "properties": {
                    "text": { "type": "string" }
                }
            }),
            output_schema: serde_json::json!({
                "type": "object",
                "required": ["echo"],
                "additionalProperties": false,
                "properties": {
                    "echo": { "type": "string" }
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
                resources: vec!["memory.read".into()],
                denied: vec!["network".into(), "shell".into()],
            },
            sandbox_profile: "test-echo".into(),
            risk_level: RiskLevel::Low,
            timeout_ms: 10_000,
            retry_policy: Default::default(),
            audit_required: true,
            proof_required: true,
            rollback_required: false,
        }
    }

    fn memory_echo_executor_manifest(capability: &CapabilityContract) -> ExecutorManifest {
        ExecutorManifest {
            executor_id: "moxi.test.memory.echo".into(),
            capability_id: capability.capability_id.clone(),
            capability_contract_hash: capability_contract_hash(capability),
            provider_identity: capability.provider_identity.clone(),
            executor_version: capability.capability_version.clone(),
            artifact_hash: executor_artifact_hash(
                "moxi.test.memory.echo",
                &capability.capability_version,
            ),
            signing_key_ref: "test://moxi/signing-key".into(),
            isolation: ExecutorIsolation::InProcessTrusted,
            sandbox_profile: capability.sandbox_profile.clone(),
            manifest_ref: Some("test://memory.echo/executor".into()),
            signature_ref: Some("test://memory.echo/executor/signature".into()),
            attestation_ref: Some("test://memory.echo/executor/attestation".into()),
        }
    }

    fn memory_echo_process_executor_manifest(capability: &CapabilityContract) -> ExecutorManifest {
        let mut manifest = memory_echo_executor_manifest(capability);
        manifest.executor_id = "moxi.test.memory.echo.process".into();
        manifest.isolation = ExecutorIsolation::ProcessSandbox;
        manifest.artifact_hash = executor_artifact_hash(
            "moxi.test.memory.echo.process",
            &capability.capability_version,
        );
        manifest.manifest_ref = Some("test://memory.echo/process-executor".into());
        manifest.signature_ref = Some("test://memory.echo/process-executor/signature".into());
        manifest.attestation_ref = Some("test://memory.echo/process-executor/attestation".into());
        manifest
    }

    #[cfg(windows)]
    fn json_process_executor() -> ProcessSandbox {
        ProcessSandbox::new("powershell.exe")
            .args([
                "-NoProfile",
                "-Command",
                "$input | Out-Null; Write-Output '{\"success\":true,\"output\":{\"echo\":\"process executor\"}}'",
            ])
            .timeout_ms(5_000)
    }

    #[cfg(not(windows))]
    fn json_process_executor() -> ProcessSandbox {
        ProcessSandbox::new("/bin/sh")
            .args([
                "-c",
                "cat >/dev/null; printf '%s\n' '{\"success\":true,\"output\":{\"echo\":\"process executor\"}}'",
            ])
            .timeout_ms(5_000)
    }

    struct EchoExecutor;

    impl CapabilityExecutor for EchoExecutor {
        fn execute(
            &self,
            ticket: &ExecutionTicket,
            input: SandboxInput,
        ) -> CoreResult<SandboxResult> {
            let started_at = Utc::now();
            let text = input
                .payload
                .get("text")
                .and_then(|value| value.as_str())
                .unwrap_or_default();
            let output = json!({ "echo": text });
            let output_hash = hash_json(&output);

            Ok(SandboxResult {
                ticket_id: ticket.ticket_id.clone(),
                run_id: ticket.run_id.clone(),
                capability_id: ticket.capability_id.clone(),
                policy_decision_ref: String::new(),
                capability_contract_ref: String::new(),
                capability_contract_hash: String::new(),
                executor_ref: String::new(),
                executor_version: String::new(),
                executor_artifact_hash: String::new(),
                executor_signature_ref: String::new(),
                executor_signing_key_ref: String::new(),
                executor_manifest_hash: String::new(),
                gateway_decision_ref: None,
                input_hash: String::new(),
                success: true,
                output,
                error: None,
                started_at,
                finished_at: Utc::now(),
                output_hash,
            })
        }
    }

    struct WrongCapabilityExecutor;

    impl CapabilityExecutor for WrongCapabilityExecutor {
        fn execute(
            &self,
            ticket: &ExecutionTicket,
            _input: SandboxInput,
        ) -> CoreResult<SandboxResult> {
            Ok(SandboxResult {
                ticket_id: ticket.ticket_id.clone(),
                run_id: ticket.run_id.clone(),
                capability_id: "file.read".into(),
                policy_decision_ref: String::new(),
                capability_contract_ref: String::new(),
                capability_contract_hash: String::new(),
                executor_ref: String::new(),
                executor_version: String::new(),
                executor_artifact_hash: String::new(),
                executor_signature_ref: String::new(),
                executor_signing_key_ref: String::new(),
                executor_manifest_hash: String::new(),
                gateway_decision_ref: None,
                input_hash: String::new(),
                success: true,
                output: json!({ "echo": "wrong capability" }),
                error: None,
                started_at: Utc::now(),
                finished_at: Utc::now(),
                output_hash: "wrong".into(),
            })
        }
    }

    struct BadOutputHashExecutor;

    impl CapabilityExecutor for BadOutputHashExecutor {
        fn execute(
            &self,
            ticket: &ExecutionTicket,
            input: SandboxInput,
        ) -> CoreResult<SandboxResult> {
            let text = input
                .payload
                .get("text")
                .and_then(|value| value.as_str())
                .unwrap_or_default();
            Ok(SandboxResult {
                ticket_id: ticket.ticket_id.clone(),
                run_id: ticket.run_id.clone(),
                capability_id: ticket.capability_id.clone(),
                policy_decision_ref: String::new(),
                capability_contract_ref: String::new(),
                capability_contract_hash: String::new(),
                executor_ref: String::new(),
                executor_version: String::new(),
                executor_artifact_hash: String::new(),
                executor_signature_ref: String::new(),
                executor_signing_key_ref: String::new(),
                executor_manifest_hash: String::new(),
                gateway_decision_ref: None,
                input_hash: String::new(),
                success: true,
                output: json!({ "echo": text }),
                error: None,
                started_at: Utc::now(),
                finished_at: Utc::now(),
                output_hash: "executor-controlled".into(),
            })
        }
    }

    struct InvalidOutputExecutor;

    impl CapabilityExecutor for InvalidOutputExecutor {
        fn execute(
            &self,
            ticket: &ExecutionTicket,
            _input: SandboxInput,
        ) -> CoreResult<SandboxResult> {
            Ok(SandboxResult {
                ticket_id: ticket.ticket_id.clone(),
                run_id: ticket.run_id.clone(),
                capability_id: ticket.capability_id.clone(),
                policy_decision_ref: String::new(),
                capability_contract_ref: String::new(),
                capability_contract_hash: String::new(),
                executor_ref: String::new(),
                executor_version: String::new(),
                executor_artifact_hash: String::new(),
                executor_signature_ref: String::new(),
                executor_signing_key_ref: String::new(),
                executor_manifest_hash: String::new(),
                gateway_decision_ref: None,
                input_hash: String::new(),
                success: true,
                output: json!({ "not_echo": "invalid shape" }),
                error: None,
                started_at: Utc::now(),
                finished_at: Utc::now(),
                output_hash: "executor-controlled".into(),
            })
        }
    }

    struct FailingExecutor;

    impl CapabilityExecutor for FailingExecutor {
        fn execute(
            &self,
            _ticket: &ExecutionTicket,
            _input: SandboxInput,
        ) -> CoreResult<SandboxResult> {
            Err(CoreError::PolicyDenied("executor failed".into()))
        }
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
    fn policy_config_can_allow_registered_undeclared_capability() {
        let temp = tempdir().unwrap();
        let config = PolicyConfig {
            require_declared_capabilities: false,
            ..Default::default()
        };
        let mut kernel = Kernel::new_in_memory_with_policy_config(temp.path(), config).unwrap();
        kernel.register_capability(file_read_capability()).unwrap();
        let run = kernel.admit(intent(temp.path(), vec![])).unwrap();

        let policy = kernel
            .propose_delta(
                &run.run_id,
                delta(&run.run_id, "hello.txt", "file.read", RiskLevel::Low),
            )
            .unwrap();

        assert_eq!(policy.decision, Decision::Allow);
    }

    #[test]
    fn policy_config_can_deny_capability_by_rule() {
        let temp = tempdir().unwrap();
        let config = PolicyConfig {
            denied_capabilities: vec!["file.*".into()],
            ..Default::default()
        };
        let mut kernel = Kernel::new_in_memory_with_policy_config(temp.path(), config).unwrap();
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

        assert_eq!(policy.decision, Decision::Deny);
        assert!(policy
            .reasons
            .iter()
            .any(|reason| reason.contains("denied by policy config")));
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
    fn policy_config_controls_risk_approval_threshold_and_policy() {
        let temp = tempdir().unwrap();
        let config = PolicyConfig {
            approval_required_at_or_above: Some(RiskLevel::Medium),
            approval_policy: ApprovalPolicy::Admin,
            approval_ref: Some("approval://admin-duty".into()),
            ..Default::default()
        };
        let mut kernel = Kernel::new_in_memory_with_policy_config(temp.path(), config).unwrap();
        kernel.register_capability(file_read_capability()).unwrap();
        let run = kernel
            .admit(intent(temp.path(), vec!["file.read".into()]))
            .unwrap();

        let policy = kernel
            .propose_delta(
                &run.run_id,
                delta(&run.run_id, "hello.txt", "file.read", RiskLevel::Medium),
            )
            .unwrap();

        assert_eq!(policy.decision, Decision::RequireApproval);
        assert_eq!(
            policy.required_approval,
            Some(RequiredApproval {
                approval_policy: ApprovalPolicy::Admin,
                approval_ref: Some("approval://admin-duty".into()),
            })
        );
    }

    #[test]
    fn policy_config_can_require_approval_for_resource_pattern() {
        let temp = tempdir().unwrap();
        let config = PolicyConfig {
            approval_required_at_or_above: None,
            approval_required_resource_patterns: vec!["workspace.write".into()],
            ..Default::default()
        };
        let mut kernel = Kernel::new_in_memory_with_policy_config(temp.path(), config).unwrap();
        kernel.register_capability(file_write_capability()).unwrap();
        let run = kernel
            .admit_with_permission_mode(
                intent(temp.path(), vec!["file.write".into()]),
                PermissionMode::WorkspaceWrite,
            )
            .unwrap();

        let policy = kernel
            .propose_delta(
                &run.run_id,
                delta(&run.run_id, "hello.txt", "file.write", RiskLevel::Low),
            )
            .unwrap();

        assert_eq!(policy.decision, Decision::RequireApproval);
        assert!(policy
            .reasons
            .iter()
            .any(|reason| reason.contains("resource workspace.write")));
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
        let audit_report = kernel.replay_ledger_audit().unwrap();
        assert_eq!(audit_report.ledger_events, 1);
        assert_eq!(audit_report.successful_events, 1);
        assert_eq!(audit_report.proofs, 1);
    }

    #[test]
    fn custom_executor_runs_through_policy_ticket_proof_and_ledger() {
        let temp = tempdir().unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        let capability = memory_echo_capability();
        let manifest = memory_echo_executor_manifest(&capability);
        kernel.register_capability(capability).unwrap();
        kernel.register_executor(manifest, EchoExecutor).unwrap();
        let run = kernel
            .admit(intent(temp.path(), vec!["memory.echo".into()]))
            .unwrap();
        let mut delta = delta(&run.run_id, "memory://echo", "memory.echo", RiskLevel::Low);
        delta.target.resource_type = ResourceType::Memory;

        let policy = kernel.propose_delta(&run.run_id, delta.clone()).unwrap();
        let capability = kernel.capability("memory.echo").unwrap().clone();
        let ticket = kernel.issue_ticket(&policy, &capability).unwrap();
        assert_eq!(ticket.retry_policy, capability.retry_policy);
        assert_eq!(
            kernel.execution_ticket(&ticket.ticket_id).unwrap(),
            Some(ticket.clone())
        );
        let result = kernel
            .execute(
                &ticket,
                SandboxInput {
                    capability_id: "memory.echo".into(),
                    payload: json!({ "text": "hello executor" }),
                },
            )
            .unwrap();
        assert_eq!(
            kernel.sandbox_result(&ticket.ticket_id).unwrap(),
            Some(result.clone())
        );
        let proof = kernel.verify(&result).unwrap();
        assert_eq!(kernel.proof(&proof.proof_id).unwrap(), Some(proof.clone()));
        let event = ledger_event_for_success(
            &result,
            &proof,
            "memory://echo",
            &policy.decision_id,
            &delta.delta_id,
        );
        let committed = kernel.commit(event).unwrap();

        assert_eq!(result.output["echo"], "hello executor");
        assert_eq!(committed.capability_id, "memory.echo");
        assert_eq!(
            kernel.run_status(&run.run_id).unwrap(),
            Some(RunStatus::Completed)
        );
    }

    #[test]
    fn process_sandbox_executor_runs_through_trusted_chain() {
        let temp = tempdir().unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        let capability = memory_echo_capability();
        let manifest = memory_echo_process_executor_manifest(&capability);
        kernel.register_capability(capability).unwrap();
        kernel
            .register_executor(manifest, json_process_executor())
            .unwrap();
        let run = kernel
            .admit(intent(temp.path(), vec!["memory.echo".into()]))
            .unwrap();
        let mut delta = delta(&run.run_id, "memory://echo", "memory.echo", RiskLevel::Low);
        delta.target.resource_type = ResourceType::Memory;

        let policy = kernel.propose_delta(&run.run_id, delta.clone()).unwrap();
        let capability = kernel.capability("memory.echo").unwrap().clone();
        let ticket = kernel.issue_ticket(&policy, &capability).unwrap();
        assert_eq!(ticket.executor_isolation, ExecutorIsolation::ProcessSandbox);
        let result = kernel
            .execute(
                &ticket,
                SandboxInput {
                    capability_id: "memory.echo".into(),
                    payload: json!({ "text": "hello executor" }),
                },
            )
            .unwrap();
        let proof = kernel.verify(&result).unwrap();
        let event = ledger_event_for_success(
            &result,
            &proof,
            "memory://echo",
            &policy.decision_id,
            &delta.delta_id,
        );
        let committed = kernel.commit(event).unwrap();

        assert_eq!(result.output["echo"], "process executor");
        assert_eq!(committed.executor_ref, "moxi.test.memory.echo.process");
        assert_eq!(
            kernel.run_status(&run.run_id).unwrap(),
            Some(RunStatus::Completed)
        );
    }

    #[test]
    fn stored_ticket_payload_is_enforced_before_execution() {
        let temp = tempdir().unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        let capability = memory_echo_capability();
        let manifest = memory_echo_executor_manifest(&capability);
        kernel.register_capability(capability).unwrap();
        kernel.register_executor(manifest, EchoExecutor).unwrap();
        let run = kernel
            .admit(intent(temp.path(), vec!["memory.echo".into()]))
            .unwrap();
        let delta = delta(&run.run_id, "memory://echo", "memory.echo", RiskLevel::Low);
        let policy = kernel.propose_delta(&run.run_id, delta).unwrap();
        let capability = kernel.capability("memory.echo").unwrap().clone();
        let ticket = kernel.issue_ticket(&policy, &capability).unwrap();
        let mut tampered_ticket = ticket.clone();
        tampered_ticket.actor_id = "attacker".into();

        let rejected = kernel.execute(
            &tampered_ticket,
            SandboxInput {
                capability_id: "memory.echo".into(),
                payload: json!({ "text": "hello executor" }),
            },
        );
        let accepted = kernel.execute(
            &ticket,
            SandboxInput {
                capability_id: "memory.echo".into(),
                payload: json!({ "text": "hello executor" }),
            },
        );

        assert!(matches!(rejected, Err(CoreError::ExecutionBindingMismatch)));
        assert!(accepted.is_ok());
    }

    #[test]
    fn executor_result_must_match_execution_ticket() {
        let temp = tempdir().unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        let capability = memory_echo_capability();
        let manifest = memory_echo_executor_manifest(&capability);
        kernel.register_capability(capability).unwrap();
        kernel
            .register_executor(manifest, WrongCapabilityExecutor)
            .unwrap();
        let run = kernel
            .admit(intent(temp.path(), vec!["memory.echo".into()]))
            .unwrap();
        let delta = delta(&run.run_id, "memory://echo", "memory.echo", RiskLevel::Low);
        let policy = kernel.propose_delta(&run.run_id, delta).unwrap();
        let capability = kernel.capability("memory.echo").unwrap().clone();
        let ticket = kernel.issue_ticket(&policy, &capability).unwrap();

        let result = kernel.execute(
            &ticket,
            SandboxInput {
                capability_id: "memory.echo".into(),
                payload: json!({ "text": "hello executor" }),
            },
        );

        assert!(matches!(result, Err(CoreError::ExecutorResultMismatch)));
        assert_eq!(
            kernel.run_status(&run.run_id).unwrap(),
            Some(RunStatus::Failed)
        );
    }

    #[test]
    fn kernel_recomputes_executor_output_hash() {
        let temp = tempdir().unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        let capability = memory_echo_capability();
        let manifest = memory_echo_executor_manifest(&capability);
        kernel.register_capability(capability).unwrap();
        kernel
            .register_executor(manifest, BadOutputHashExecutor)
            .unwrap();
        let run = kernel
            .admit(intent(temp.path(), vec!["memory.echo".into()]))
            .unwrap();
        let delta = delta(&run.run_id, "memory://echo", "memory.echo", RiskLevel::Low);
        let policy = kernel.propose_delta(&run.run_id, delta).unwrap();
        let capability = kernel.capability("memory.echo").unwrap().clone();
        let ticket = kernel.issue_ticket(&policy, &capability).unwrap();

        let result = kernel
            .execute(
                &ticket,
                SandboxInput {
                    capability_id: "memory.echo".into(),
                    payload: json!({ "text": "hello executor" }),
                },
            )
            .unwrap();

        assert_eq!(result.output_hash, hash_json(&result.output));
        assert_ne!(result.output_hash, "executor-controlled");
    }

    #[test]
    fn verify_rejects_result_that_was_not_recorded_by_execute() {
        let temp = tempdir().unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        let capability = memory_echo_capability();
        let manifest = memory_echo_executor_manifest(&capability);
        kernel.register_capability(capability).unwrap();
        kernel.register_executor(manifest, EchoExecutor).unwrap();
        let run = kernel
            .admit(intent(temp.path(), vec!["memory.echo".into()]))
            .unwrap();
        let delta = delta(&run.run_id, "memory://echo", "memory.echo", RiskLevel::Low);
        let policy = kernel.propose_delta(&run.run_id, delta).unwrap();
        let capability = kernel.capability("memory.echo").unwrap().clone();
        let ticket = kernel.issue_ticket(&policy, &capability).unwrap();
        let output = json!({ "echo": "forged" });

        let forged = SandboxResult {
            ticket_id: ticket.ticket_id.clone(),
            run_id: ticket.run_id.clone(),
            capability_id: ticket.capability_id.clone(),
            policy_decision_ref: ticket.policy_decision_ref.clone(),
            capability_contract_ref: ticket.capability_contract_ref.clone(),
            capability_contract_hash: ticket.capability_contract_hash.clone(),
            executor_ref: ticket.executor_ref.clone(),
            executor_version: ticket.executor_version.clone(),
            executor_artifact_hash: ticket.executor_artifact_hash.clone(),
            executor_signature_ref: ticket.executor_signature_ref.clone(),
            executor_signing_key_ref: ticket.executor_signing_key_ref.clone(),
            executor_manifest_hash: ticket.executor_manifest_hash.clone(),
            gateway_decision_ref: None,
            input_hash: hash_json(&json!({
                "capability_id": "memory.echo",
                "payload": { "text": "forged" }
            })),
            success: true,
            output,
            error: None,
            started_at: Utc::now(),
            finished_at: Utc::now(),
            output_hash: hash_json(&json!({ "echo": "forged" })),
        };

        assert!(matches!(
            kernel.verify(&forged),
            Err(CoreError::ResultNotFound(_))
        ));
    }

    #[test]
    fn verify_rejects_tampered_recorded_result() {
        let temp = tempdir().unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        let capability = memory_echo_capability();
        let manifest = memory_echo_executor_manifest(&capability);
        kernel.register_capability(capability).unwrap();
        kernel.register_executor(manifest, EchoExecutor).unwrap();
        let run = kernel
            .admit(intent(temp.path(), vec!["memory.echo".into()]))
            .unwrap();
        let delta = delta(&run.run_id, "memory://echo", "memory.echo", RiskLevel::Low);
        let policy = kernel.propose_delta(&run.run_id, delta).unwrap();
        let capability = kernel.capability("memory.echo").unwrap().clone();
        let ticket = kernel.issue_ticket(&policy, &capability).unwrap();
        let result = kernel
            .execute(
                &ticket,
                SandboxInput {
                    capability_id: "memory.echo".into(),
                    payload: json!({ "text": "hello executor" }),
                },
            )
            .unwrap();
        let mut tampered = result.clone();
        tampered.output = json!({ "echo": "tampered" });
        tampered.output_hash = hash_json(&tampered.output);

        assert!(matches!(
            kernel.verify(&tampered),
            Err(CoreError::ResultBindingMismatch)
        ));
        assert!(kernel.verify(&result).is_ok());
    }

    #[test]
    fn invalid_executor_output_marks_run_failed() {
        let temp = tempdir().unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        let capability = memory_echo_capability();
        let manifest = memory_echo_executor_manifest(&capability);
        kernel.register_capability(capability).unwrap();
        kernel
            .register_executor(manifest, InvalidOutputExecutor)
            .unwrap();
        let run = kernel
            .admit(intent(temp.path(), vec!["memory.echo".into()]))
            .unwrap();
        let delta = delta(&run.run_id, "memory://echo", "memory.echo", RiskLevel::Low);
        let policy = kernel.propose_delta(&run.run_id, delta).unwrap();
        let capability = kernel.capability("memory.echo").unwrap().clone();
        let ticket = kernel.issue_ticket(&policy, &capability).unwrap();

        let result = kernel.execute(
            &ticket,
            SandboxInput {
                capability_id: "memory.echo".into(),
                payload: json!({ "text": "hello executor" }),
            },
        );

        assert!(matches!(result, Err(CoreError::SchemaValidation(_, _))));
        assert_eq!(
            kernel.run_status(&run.run_id).unwrap(),
            Some(RunStatus::Failed)
        );
    }

    #[test]
    fn commit_requires_recorded_matching_proof() {
        let temp = tempdir().unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        let capability = memory_echo_capability();
        let manifest = memory_echo_executor_manifest(&capability);
        kernel.register_capability(capability).unwrap();
        kernel.register_executor(manifest, EchoExecutor).unwrap();
        let run = kernel
            .admit(intent(temp.path(), vec!["memory.echo".into()]))
            .unwrap();
        let delta = delta(&run.run_id, "memory://echo", "memory.echo", RiskLevel::Low);
        let policy = kernel.propose_delta(&run.run_id, delta.clone()).unwrap();
        let capability = kernel.capability("memory.echo").unwrap().clone();
        let ticket = kernel.issue_ticket(&policy, &capability).unwrap();
        let result = kernel
            .execute(
                &ticket,
                SandboxInput {
                    capability_id: "memory.echo".into(),
                    payload: json!({ "text": "hello executor" }),
                },
            )
            .unwrap();
        let proof = kernel.verify(&result).unwrap();
        let event = ledger_event_for_success(
            &result,
            &proof,
            "memory://echo",
            &policy.decision_id,
            &delta.delta_id,
        );
        let mut missing_proof = event.clone();
        missing_proof.proof_refs = vec!["proof_missing".into()];
        let mut mismatched = event.clone();
        mismatched.output_hash = "tampered".into();

        assert!(matches!(
            kernel.commit(missing_proof),
            Err(CoreError::ProofNotFound(_))
        ));
        assert!(matches!(
            kernel.commit(mismatched),
            Err(CoreError::ProofBindingMismatch)
        ));
        assert!(kernel.commit(event).is_ok());
    }

    #[test]
    fn unsupported_executor_isolation_is_rejected() {
        let temp = tempdir().unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        let capability = memory_echo_capability();
        let mut manifest = memory_echo_executor_manifest(&capability);
        manifest.isolation = ExecutorIsolation::PluginHost;

        assert!(matches!(
            kernel.register_executor(manifest, EchoExecutor),
            Err(CoreError::ExecutorIsolationUnsupported(
                ExecutorIsolation::PluginHost
            ))
        ));
    }

    #[test]
    fn executor_manifest_must_match_capability_contract_hash() {
        let temp = tempdir().unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        let capability = memory_echo_capability();
        let mut manifest = memory_echo_executor_manifest(&capability);
        manifest.capability_contract_hash = "tampered".into();
        kernel.register_capability(capability).unwrap();

        assert!(matches!(
            kernel.register_executor(manifest, EchoExecutor),
            Err(CoreError::ExecutorManifestMismatch(_))
        ));
    }

    #[test]
    fn executor_manifest_requires_artifact_identity_and_signature_refs() {
        let temp = tempdir().unwrap();
        let capability = memory_echo_capability();

        let mut missing_artifact_kernel = Kernel::new_in_memory(temp.path()).unwrap();
        missing_artifact_kernel
            .register_capability(capability.clone())
            .unwrap();
        let mut missing_artifact = memory_echo_executor_manifest(&capability);
        missing_artifact.artifact_hash.clear();
        assert!(matches!(
            missing_artifact_kernel.register_executor(missing_artifact, EchoExecutor),
            Err(CoreError::ExecutorManifestMismatch(_))
        ));

        let mut missing_signature_kernel = Kernel::new_in_memory(temp.path()).unwrap();
        missing_signature_kernel
            .register_capability(capability.clone())
            .unwrap();
        let mut missing_signature = memory_echo_executor_manifest(&capability);
        missing_signature.signature_ref = None;
        assert!(matches!(
            missing_signature_kernel.register_executor(missing_signature, EchoExecutor),
            Err(CoreError::ExecutorManifestMismatch(_))
        ));

        let mut missing_signing_key_kernel = Kernel::new_in_memory(temp.path()).unwrap();
        missing_signing_key_kernel
            .register_capability(capability.clone())
            .unwrap();
        let mut missing_signing_key = memory_echo_executor_manifest(&capability);
        missing_signing_key.signing_key_ref.clear();
        assert!(matches!(
            missing_signing_key_kernel.register_executor(missing_signing_key, EchoExecutor),
            Err(CoreError::ExecutorManifestMismatch(_))
        ));
    }

    #[test]
    fn ticket_binding_rejects_executor_artifact_swaps_before_consumption() {
        let temp = tempdir().unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        let capability = memory_echo_capability();
        let original_manifest = memory_echo_executor_manifest(&capability);
        let mut swapped_manifest = original_manifest.clone();
        swapped_manifest.artifact_hash =
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into();
        kernel.register_capability(capability).unwrap();
        kernel
            .register_executor(original_manifest.clone(), EchoExecutor)
            .unwrap();
        let run = kernel
            .admit(intent(temp.path(), vec!["memory.echo".into()]))
            .unwrap();
        let delta = delta(&run.run_id, "memory://echo", "memory.echo", RiskLevel::Low);
        let policy = kernel.propose_delta(&run.run_id, delta).unwrap();
        let capability = kernel.capability("memory.echo").unwrap().clone();
        let ticket = kernel.issue_ticket(&policy, &capability).unwrap();

        kernel
            .register_executor(swapped_manifest, EchoExecutor)
            .unwrap();
        let rejected = kernel.execute(
            &ticket,
            SandboxInput {
                capability_id: "memory.echo".into(),
                payload: json!({ "text": "hello executor" }),
            },
        );
        kernel
            .register_executor(original_manifest, EchoExecutor)
            .unwrap();
        let retried = kernel.execute(
            &ticket,
            SandboxInput {
                capability_id: "memory.echo".into(),
                payload: json!({ "text": "hello executor" }),
            },
        );

        assert!(matches!(rejected, Err(CoreError::ExecutionBindingMismatch)));
        assert!(retried.is_ok());
    }

    #[test]
    fn ticket_binding_rejects_executor_manifest_swaps_before_consumption() {
        let temp = tempdir().unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        let capability = memory_echo_capability();
        let original_manifest = memory_echo_executor_manifest(&capability);
        let mut swapped_manifest = original_manifest.clone();
        swapped_manifest.executor_id = "moxi.test.memory.echo.v2".into();
        swapped_manifest.executor_version = "0.2.1-test".into();
        kernel.register_capability(capability).unwrap();
        kernel
            .register_executor(original_manifest.clone(), EchoExecutor)
            .unwrap();
        let run = kernel
            .admit(intent(temp.path(), vec!["memory.echo".into()]))
            .unwrap();
        let delta = delta(&run.run_id, "memory://echo", "memory.echo", RiskLevel::Low);
        let policy = kernel.propose_delta(&run.run_id, delta).unwrap();
        let capability = kernel.capability("memory.echo").unwrap().clone();
        let ticket = kernel.issue_ticket(&policy, &capability).unwrap();

        kernel
            .register_executor(swapped_manifest, EchoExecutor)
            .unwrap();
        let rejected = kernel.execute(
            &ticket,
            SandboxInput {
                capability_id: "memory.echo".into(),
                payload: json!({ "text": "hello executor" }),
            },
        );
        kernel
            .register_executor(original_manifest, EchoExecutor)
            .unwrap();
        let retried = kernel.execute(
            &ticket,
            SandboxInput {
                capability_id: "memory.echo".into(),
                payload: json!({ "text": "hello executor" }),
            },
        );

        assert!(matches!(rejected, Err(CoreError::ExecutionBindingMismatch)));
        assert!(retried.is_ok());
    }

    #[test]
    fn executor_failure_consumes_ticket_and_marks_run_failed() {
        let temp = tempdir().unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        let capability = memory_echo_capability();
        let manifest = memory_echo_executor_manifest(&capability);
        kernel.register_capability(capability).unwrap();
        kernel.register_executor(manifest, FailingExecutor).unwrap();
        let run = kernel
            .admit(intent(temp.path(), vec!["memory.echo".into()]))
            .unwrap();
        let delta = delta(&run.run_id, "memory://echo", "memory.echo", RiskLevel::Low);
        let policy = kernel.propose_delta(&run.run_id, delta).unwrap();
        let capability = kernel.capability("memory.echo").unwrap().clone();
        let ticket = kernel.issue_ticket(&policy, &capability).unwrap();

        let failed = kernel.execute(
            &ticket,
            SandboxInput {
                capability_id: "memory.echo".into(),
                payload: json!({ "text": "hello executor" }),
            },
        );
        let retried = kernel.execute(
            &ticket,
            SandboxInput {
                capability_id: "memory.echo".into(),
                payload: json!({ "text": "hello executor" }),
            },
        );

        assert!(matches!(failed, Err(CoreError::PolicyDenied(_))));
        assert!(matches!(
            retried,
            Err(CoreError::Store(StoreError::TicketConsumed(_)))
        ));
        assert_eq!(
            kernel.run_status(&run.run_id).unwrap(),
            Some(RunStatus::Failed)
        );
    }

    #[test]
    fn missing_executor_is_rejected_before_ticket_issuing() {
        let temp = tempdir().unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        let capability = memory_echo_capability();
        let manifest = memory_echo_executor_manifest(&capability);
        kernel.register_capability(capability).unwrap();
        let run = kernel
            .admit(intent(temp.path(), vec!["memory.echo".into()]))
            .unwrap();
        let delta = delta(&run.run_id, "memory://echo", "memory.echo", RiskLevel::Low);
        let policy = kernel.propose_delta(&run.run_id, delta).unwrap();
        let capability = kernel.capability("memory.echo").unwrap().clone();

        assert!(matches!(
            kernel.issue_ticket(&policy, &capability),
            Err(CoreError::ExecutorNotFound(_))
        ));

        kernel.register_executor(manifest, EchoExecutor).unwrap();
        let ticket = kernel.issue_ticket(&policy, &capability).unwrap();
        let executed = kernel.execute(
            &ticket,
            SandboxInput {
                capability_id: "memory.echo".into(),
                payload: json!({ "text": "hello executor" }),
            },
        );

        assert!(executed.is_ok());
    }

    #[test]
    fn run_timeout_blocks_delta_proposal() {
        let temp = tempdir().unwrap();
        let budget = Budget {
            timeout_ms: 5,
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
        age_run_past_timeout(&mut kernel, &run.run_id, 10);

        let proposed = kernel.propose_delta(
            &run.run_id,
            delta(&run.run_id, "hello.txt", "file.read", RiskLevel::Low),
        );

        assert!(matches!(proposed, Err(CoreError::RunTimedOut(_))));
        assert_eq!(
            kernel.run_status(&run.run_id).unwrap(),
            Some(RunStatus::TimedOut)
        );
    }

    #[test]
    fn run_timeout_blocks_ticket_issuance() {
        let temp = tempdir().unwrap();
        let budget = Budget {
            timeout_ms: 5,
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
        let policy = kernel
            .propose_delta(
                &run.run_id,
                delta(&run.run_id, "hello.txt", "file.read", RiskLevel::Low),
            )
            .unwrap();
        let capability = kernel.capability("file.read").unwrap().clone();
        age_run_past_timeout(&mut kernel, &run.run_id, 10);

        assert!(matches!(
            kernel.issue_ticket(&policy, &capability),
            Err(CoreError::RunTimedOut(_))
        ));
        assert_eq!(
            kernel.run_status(&run.run_id).unwrap(),
            Some(RunStatus::TimedOut)
        );
    }

    #[test]
    fn run_timeout_blocks_execution() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("hello.txt"), "hello").unwrap();
        let budget = Budget {
            timeout_ms: 5,
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
        let policy = kernel
            .propose_delta(
                &run.run_id,
                delta(&run.run_id, "hello.txt", "file.read", RiskLevel::Low),
            )
            .unwrap();
        let capability = kernel.capability("file.read").unwrap().clone();
        let ticket = kernel.issue_ticket(&policy, &capability).unwrap();
        age_run_past_timeout(&mut kernel, &run.run_id, 10);

        let executed = kernel.execute(
            &ticket,
            SandboxInput {
                capability_id: "file.read".into(),
                payload: json!({ "path": "hello.txt" }),
            },
        );

        assert!(matches!(executed, Err(CoreError::RunTimedOut(_))));
        assert_eq!(
            kernel.run_status(&run.run_id).unwrap(),
            Some(RunStatus::TimedOut)
        );
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
            execution_ticket_ref: "ticket_1".into(),
            capability_contract_ref: "file.read".into(),
            capability_contract_hash: "contract_hash_1".into(),
            executor_ref: "moxi.builtin.fs.file_read".into(),
            executor_version: "0.2.0".into(),
            executor_artifact_hash:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            executor_signature_ref: "builtin://moxi/file.read/executor/signature".into(),
            executor_signing_key_ref: "builtin://moxi/signing-key".into(),
            executor_manifest_hash: "executor_manifest_hash_1".into(),
            gateway_decision_ref: None,
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
