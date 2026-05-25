use chrono::{DateTime, Utc};
use moxi_contracts::{
    CapabilityContract, DeltaState, DeltaTarget, EventResult, ExecutionTicket, Intent, LedgerEvent,
    ModuleManifest, PermissionMode, ResourceType, RiskLevel, RunContract, RuntimeInputMetadata,
    SandboxInput, SkillManifest, WorldDelta,
};
use moxi_core::{capability_contract_hash, CoreError, Kernel};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};
use thiserror::Error;
use uuid::Uuid;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

const RUNTIME_STORE_SCHEMA_VERSION: u32 = 4;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("runtime plan is empty")]
    EmptyPlan,
    #[error("runtime task not found: {0}")]
    TaskNotFound(String),
    #[error("runtime graph not found: {0}")]
    GraphNotFound(String),
    #[error("runtime task is not ready: {0}")]
    TaskNotReady(String),
    #[error("runtime task requires manual approval: {0}")]
    ApprovalRequired(String),
    #[error("runtime task capability is not registered: {0}")]
    CapabilityNotFound(String),
    #[error("runtime task target is unsupported for this v0 runtime: {0}")]
    UnsupportedTarget(String),
    #[error("runtime skill has no required capability: {0}")]
    SkillMissingCapability(String),
    #[error("runtime skill references unknown module {module_id}: {skill_id}")]
    SkillModuleNotFound { skill_id: String, module_id: String },
    #[error("runtime module references unknown dependency {dependency_id}: {module_id}")]
    ModuleDependencyNotFound {
        module_id: String,
        dependency_id: String,
    },
    #[error("runtime module dependency cycle: {0}")]
    ModuleDependencyCycle(String),
    #[error("runtime module references unknown profile {profile_id}: {module_id}")]
    ModuleProfileNotFound {
        module_id: String,
        profile_id: String,
    },
    #[error("runtime skill capability {capability_id} is not supported by module {module_id}: {skill_id}")]
    SkillModuleCapabilityMismatch {
        skill_id: String,
        module_id: String,
        capability_id: String,
    },
    #[error("runtime skill cannot be routed to capability {capability_id}: {skill_id}")]
    SkillCapabilityMismatch {
        skill_id: String,
        capability_id: String,
    },
    #[error("runtime skill is not allowed by this runtime profile: {0}")]
    SkillNotAllowed(String),
    #[error("runtime profile rejected execution plan: {0}")]
    ProfileRejected(String),
    #[error("runtime planner step not found: {0}")]
    PlannerStepNotFound(String),
    #[error("runtime planner step has no capability: {0}")]
    PlannerStepMissingCapability(String),
    #[error("runtime planner step dependency is invalid: {step_id} -> {dependency_id}")]
    PlannerDependencyNotFound {
        step_id: String,
        dependency_id: String,
    },
    #[error("runtime profile not found: {0}")]
    ProfileNotFound(String),
    #[error("runtime profile inheritance cycle: {0}")]
    ProfileInheritanceCycle(String),
    #[error("runtime task dependency cycle or missing dependency")]
    TaskDependencyCycle,
    #[error("runtime journal replay failed at line {line}: {source}")]
    JournalReplay {
        line: usize,
        source: serde_json::Error,
    },
    #[error("runtime journal is already locked: {0}")]
    JournalLocked(PathBuf),
    #[error("runtime journal lock is not stale: {0}")]
    JournalLockNotStale(PathBuf),
    #[error("runtime store schema version {found} is newer than supported version {supported}")]
    RuntimeStoreSchemaVersionTooNew { found: u32, supported: u32 },
    #[error("runtime retry lease already active for task {task_id}: {lease_id}")]
    RetryLeaseActive { task_id: String, lease_id: String },
    #[error("runtime retry lease persistence mismatch for task {task_id}: expected {expected_lease_id}, got {actual_lease_id}")]
    RetryLeasePersistenceMismatch {
        task_id: String,
        expected_lease_id: String,
        actual_lease_id: String,
    },
    #[error("runtime attempt not found: {0}")]
    AttemptNotFound(String),
    #[error("runtime adoption probe mismatch for {probe_id}: {reason}")]
    AdoptionProbeMismatch { probe_id: String, reason: String },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("core error: {0}")]
    Core(#[from] CoreError),
}

pub type RuntimeResult<T> = Result<T, RuntimeError>;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePath {
    FastPath,
    TaskPath,
    TrustedExecutionPath,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeStage {
    Planned,
    Admitted,
    PolicyChecked,
    AwaitingApproval,
    TicketIssued,
    Executing,
    Verifying,
    Committing,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    Planned,
    Ready,
    AwaitingApproval,
    Running,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskNode {
    pub task_id: String,
    pub skill_id: Option<String>,
    pub capability_id: String,
    pub target: DeltaTarget,
    pub input: Value,
    pub risk_level: RiskLevel,
    pub depends_on: Vec<String>,
    pub state: TaskState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskGraph {
    pub graph_id: String,
    pub goal: String,
    pub path: RuntimePath,
    pub tasks: Vec<TaskNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExecutionPlan {
    pub planner: PlannerPlan,
    pub graph: TaskGraph,
    pub ready_order: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PlannerSource {
    Deterministic,
    SkillRegistry,
    ModelProposed,
    HumanAuthored,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlannerConstraint {
    pub constraint_id: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PlannerStep {
    pub step_id: String,
    pub skill_id: Option<String>,
    pub capability_id: String,
    pub target: DeltaTarget,
    pub input: Value,
    pub risk_level: RiskLevel,
    pub depends_on: Vec<String>,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PlannerPlan {
    pub plan_id: String,
    pub intent_id: String,
    pub goal: String,
    pub source: PlannerSource,
    pub constraints: Vec<PlannerConstraint>,
    pub steps: Vec<PlannerStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimePlannerRecord {
    pub plan_id: String,
    pub graph_id: String,
    pub intent_id: String,
    pub source: PlannerSource,
    pub step_count: usize,
    pub plan_hash: String,
    pub plan: PlannerPlan,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub graph_id: Option<String>,
    pub run_id: Option<String>,
    pub task_id: Option<String>,
    pub stage: RuntimeStage,
    pub message: String,
    pub progress: f32,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeEventFeedSnapshot {
    pub schema_version: u32,
    pub graph_id: Option<String>,
    pub from_cursor: usize,
    pub next_cursor: usize,
    pub event_count: usize,
    pub events: Vec<RuntimeEvent>,
    pub latest_stage: Option<RuntimeStage>,
    pub latest_message: Option<String>,
    pub latest_progress: f32,
    pub current_task_id: Option<String>,
    pub blockers: BTreeMap<String, ResumeBlocker>,
    pub is_complete: bool,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeTaskOutcome {
    pub task_id: String,
    pub idempotency_key: String,
    pub ticket: ExecutionTicket,
    pub ledger_event: LedgerEvent,
    pub output: Value,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeAttemptStage {
    Started,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeTaskAttempt {
    pub attempt_id: String,
    pub graph_id: String,
    pub task_id: String,
    pub run_id: String,
    pub capability_id: String,
    pub idempotency_key: String,
    pub retry_safe: bool,
    pub stage: RuntimeAttemptStage,
    pub ticket_id: Option<String>,
    pub ledger_event_id: Option<String>,
    pub error: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeRunReport {
    pub primary_run: RunContract,
    pub planner: RuntimePlannerRecord,
    pub graph: TaskGraph,
    pub events: Vec<RuntimeEvent>,
    pub outcomes: Vec<RuntimeTaskOutcome>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeResumeReport {
    pub graph: TaskGraph,
    pub before: RuntimeResumePlan,
    pub after: RuntimeResumePlan,
    pub events: Vec<RuntimeEvent>,
    pub outcomes: Vec<RuntimeTaskOutcome>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeTaskRecord {
    pub graph_id: String,
    pub task: TaskNode,
    pub last_event_id: Option<String>,
    pub last_stage: Option<RuntimeStage>,
    pub last_attempt_id: Option<String>,
    pub idempotency_key: Option<String>,
    pub retry_safe: Option<bool>,
    pub message: Option<String>,
    pub progress: f32,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeGraphSnapshot {
    pub graph: TaskGraph,
    pub planner: Option<RuntimePlannerRecord>,
    pub tasks: Vec<RuntimeTaskRecord>,
    pub attempts: Vec<RuntimeTaskAttempt>,
    #[serde(default)]
    pub adoption_probes: Vec<RuntimeAdoptionProbeRecord>,
    pub events: Vec<RuntimeEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeTaskView {
    pub task_id: String,
    pub skill_id: Option<String>,
    pub capability_id: String,
    pub target: DeltaTarget,
    pub state: TaskState,
    pub last_stage: Option<RuntimeStage>,
    pub progress: f32,
    pub message: Option<String>,
    pub idempotency_key: Option<String>,
    pub retry_safe: Option<bool>,
    pub blocker: Option<ResumeBlocker>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeGraphListItem {
    pub graph_id: String,
    pub goal: String,
    pub path: RuntimePath,
    pub task_count: usize,
    pub completed_count: usize,
    pub running_count: usize,
    pub blocked_count: usize,
    pub awaiting_approval_count: usize,
    pub failed_count: usize,
    pub is_complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeQuerySnapshot {
    pub graph: RuntimeGraphListItem,
    pub planner: Option<RuntimePlannerRecord>,
    pub tasks: Vec<RuntimeTaskView>,
    pub attempts: Vec<RuntimeTaskAttempt>,
    #[serde(default)]
    pub adoption_probes: Vec<RuntimeAdoptionProbeRecord>,
    pub events: Vec<RuntimeEvent>,
    pub resume_plan: RuntimeResumePlan,
    pub event_cursor: usize,
    pub policy_profile: RuntimePolicyProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeAdoptionAction {
    AlreadyCommitted,
    RetryReady,
    InspectRequired,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeAdoptionProbeStatus {
    NotFound,
    Pending,
    Committed,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeAdoptionProbeResult {
    pub task_id: String,
    pub attempt_id: String,
    pub idempotency_key: String,
    pub status: RuntimeAdoptionProbeStatus,
    pub provider_ref: Option<String>,
    pub evidence_ref: Option<String>,
    pub message: Option<String>,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeAdoptionProbeRecord {
    pub probe_id: String,
    pub graph_id: String,
    pub result: RuntimeAdoptionProbeResult,
    pub recorded_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeAdoptionRecommendation {
    pub task_id: String,
    pub action: RuntimeAdoptionAction,
    pub reason: String,
    pub attempt_id: Option<String>,
    pub idempotency_key: Option<String>,
    pub ticket_id: Option<String>,
    pub ledger_event_id: Option<String>,
    #[serde(default)]
    pub provider_probe: Option<RuntimeAdoptionProbeResult>,
}

pub trait RuntimeAdoptionProbe {
    fn probe(
        &self,
        task: &RuntimeTaskRecord,
        attempt: &RuntimeTaskAttempt,
    ) -> RuntimeResult<Option<RuntimeAdoptionProbeResult>>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "scope", content = "id", rename_all = "snake_case")]
pub enum RuntimeAdoptionProbeKey {
    Capability(String),
    Provider(String),
}

#[derive(Default)]
pub struct RuntimeAdoptionProbeRegistry {
    probes: BTreeMap<RuntimeAdoptionProbeKey, Box<dyn RuntimeAdoptionProbe>>,
}

impl RuntimeAdoptionProbeRegistry {
    pub fn register_capability(
        &mut self,
        capability_id: impl Into<String>,
        probe: impl RuntimeAdoptionProbe + 'static,
    ) {
        self.probes.insert(
            RuntimeAdoptionProbeKey::Capability(capability_id.into()),
            Box::new(probe),
        );
    }

    pub fn register_provider(
        &mut self,
        provider_id: impl Into<String>,
        probe: impl RuntimeAdoptionProbe + 'static,
    ) {
        self.probes.insert(
            RuntimeAdoptionProbeKey::Provider(provider_id.into()),
            Box::new(probe),
        );
    }

    pub fn probe_for_task(&self, task: &TaskNode) -> Option<&dyn RuntimeAdoptionProbe> {
        self.probe_for_capability(&task.capability_id)
    }

    pub fn probe_for_capability(&self, capability_id: &str) -> Option<&dyn RuntimeAdoptionProbe> {
        let capability_key = RuntimeAdoptionProbeKey::Capability(capability_id.into());
        if let Some(probe) = self.probes.get(&capability_key) {
            return Some(probe.as_ref());
        }
        provider_id_from_capability(capability_id).and_then(|provider_id| {
            let provider_key = RuntimeAdoptionProbeKey::Provider(provider_id);
            self.probes.get(&provider_key).map(|probe| probe.as_ref())
        })
    }

    pub fn contains_capability(&self, capability_id: &str) -> bool {
        self.probes
            .contains_key(&RuntimeAdoptionProbeKey::Capability(capability_id.into()))
    }

    pub fn contains_provider(&self, provider_id: &str) -> bool {
        self.probes
            .contains_key(&RuntimeAdoptionProbeKey::Provider(provider_id.into()))
    }

    pub fn len(&self) -> usize {
        self.probes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.probes.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeProjectionSnapshot {
    pub schema_version: u32,
    pub task_store: RuntimeTaskStore,
    pub event_stream: RuntimeEventStream,
    pub policy_profile: RuntimePolicyProfile,
    pub running_task_policy: RunningTaskPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeTaskIndexEntry {
    pub graph_id: String,
    pub task: RuntimeTaskView,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeTaskIndexSnapshot {
    pub schema_version: u32,
    pub generated_at: DateTime<Utc>,
    pub graphs: Vec<RuntimeGraphListItem>,
    pub tasks: Vec<RuntimeTaskIndexEntry>,
    pub event_cursor: usize,
    pub policy_profile: RuntimePolicyProfile,
    pub running_task_policy: RunningTaskPolicy,
}

impl RuntimeTaskIndexSnapshot {
    pub fn graph(&self, graph_id: &str) -> Option<&RuntimeGraphListItem> {
        self.graphs.iter().find(|graph| graph.graph_id == graph_id)
    }

    pub fn graph_list(&self) -> &[RuntimeGraphListItem] {
        &self.graphs
    }

    pub fn tasks_for_graph(&self, graph_id: &str) -> Vec<RuntimeTaskView> {
        self.tasks
            .iter()
            .filter(|entry| entry.graph_id == graph_id)
            .map(|entry| entry.task.clone())
            .collect()
    }

    pub fn tasks_by_state(&self, state: TaskState) -> Vec<RuntimeTaskIndexEntry> {
        self.tasks
            .iter()
            .filter(|entry| entry.task.state == state)
            .cloned()
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResumeBlocker {
    AwaitingApproval,
    DependencyIncomplete,
    RunningCheckpoint,
    NonIdempotentRunningCheckpoint,
    Failed,
    AlreadyFinished,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunningTaskPolicy {
    RequireInspection,
    RetryReady,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeRetryLeaseState {
    Active,
    Released,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeRetryLease {
    pub lease_id: String,
    pub graph_id: String,
    pub task_id: String,
    pub run_id: String,
    pub idempotency_key: String,
    pub holder_ref: String,
    pub state: RuntimeRetryLeaseState,
    pub acquired_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub released_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimePolicyProfile {
    pub profile_id: String,
    pub allowed_capabilities: Vec<String>,
    pub allow_fast_path: bool,
    pub allow_task_path: bool,
    pub allow_trusted_execution_path: bool,
    pub allow_skills: bool,
    pub allow_running_task_retry: bool,
    pub max_tasks_per_graph: usize,
}

impl Default for RuntimePolicyProfile {
    fn default() -> Self {
        Self {
            profile_id: "runtime.default".into(),
            allowed_capabilities: vec![],
            allow_fast_path: true,
            allow_task_path: true,
            allow_trusted_execution_path: true,
            allow_skills: true,
            allow_running_task_retry: true,
            max_tasks_per_graph: 32,
        }
    }
}

impl RuntimePolicyProfile {
    pub fn fast_only() -> Self {
        Self {
            profile_id: "runtime.fast_only".into(),
            allowed_capabilities: vec![],
            allow_fast_path: true,
            allow_task_path: false,
            allow_trusted_execution_path: false,
            allow_skills: false,
            allow_running_task_retry: false,
            max_tasks_per_graph: 1,
        }
    }

    pub fn shell_cli_fast() -> Self {
        Self {
            profile_id: "shell.cli.fast".into(),
            allowed_capabilities: vec!["file.read".into()],
            allow_fast_path: true,
            allow_task_path: false,
            allow_trusted_execution_path: false,
            allow_skills: false,
            allow_running_task_retry: false,
            max_tasks_per_graph: 1,
        }
    }

    pub fn shell_ide_readonly() -> Self {
        Self {
            profile_id: "shell.ide.readonly".into(),
            allowed_capabilities: vec!["file.read".into()],
            allow_fast_path: true,
            allow_task_path: true,
            allow_trusted_execution_path: false,
            allow_skills: true,
            allow_running_task_retry: true,
            max_tasks_per_graph: 8,
        }
    }

    pub fn shell_digital_human_readonly() -> Self {
        Self {
            profile_id: "shell.digital_human.readonly".into(),
            allowed_capabilities: vec!["file.read".into(), "memory.read".into()],
            allow_fast_path: true,
            allow_task_path: true,
            allow_trusted_execution_path: false,
            allow_skills: true,
            allow_running_task_retry: false,
            max_tasks_per_graph: 4,
        }
    }

    pub fn shell_trusted_review() -> Self {
        Self {
            profile_id: "shell.trusted.review".into(),
            allowed_capabilities: vec!["file.read".into()],
            allow_fast_path: true,
            allow_task_path: true,
            allow_trusted_execution_path: true,
            allow_skills: true,
            allow_running_task_retry: false,
            max_tasks_per_graph: 12,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeShellProfilePack {
    pub schema_version: u32,
    pub profiles: Vec<RuntimeProfileManifest>,
}

impl Default for RuntimeShellProfilePack {
    fn default() -> Self {
        Self {
            schema_version: 1,
            profiles: vec![
                RuntimeProfileManifest {
                    profile: RuntimePolicyProfile::shell_cli_fast(),
                    parent_profile_id: Some("runtime.default".into()),
                },
                RuntimeProfileManifest {
                    profile: RuntimePolicyProfile::shell_ide_readonly(),
                    parent_profile_id: Some("runtime.default".into()),
                },
                RuntimeProfileManifest {
                    profile: RuntimePolicyProfile::shell_digital_human_readonly(),
                    parent_profile_id: Some("runtime.default".into()),
                },
                RuntimeProfileManifest {
                    profile: RuntimePolicyProfile::shell_trusted_review(),
                    parent_profile_id: Some("runtime.default".into()),
                },
            ],
        }
    }
}

impl RuntimeShellProfilePack {
    pub fn standard() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeProfileManifest {
    pub profile: RuntimePolicyProfile,
    pub parent_profile_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeProfileRegistry {
    pub schema_version: u32,
    pub profiles: Vec<RuntimeProfileManifest>,
}

impl Default for RuntimeProfileRegistry {
    fn default() -> Self {
        Self {
            schema_version: 1,
            profiles: vec![RuntimeProfileManifest {
                profile: RuntimePolicyProfile::default(),
                parent_profile_id: None,
            }],
        }
    }
}

impl RuntimeProfileRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_standard_shell_profiles() -> Self {
        let mut registry = Self::new();
        registry.extend(RuntimeShellProfilePack::standard());
        registry
    }

    pub fn insert(&mut self, manifest: RuntimeProfileManifest) {
        self.profiles
            .retain(|existing| existing.profile.profile_id != manifest.profile.profile_id);
        self.profiles.push(manifest);
    }

    pub fn extend(&mut self, pack: RuntimeShellProfilePack) {
        for manifest in pack.profiles {
            self.insert(manifest);
        }
    }

    pub fn resolve(&self, profile_id: &str) -> RuntimeResult<RuntimePolicyProfile> {
        self.resolve_inner(profile_id, &mut Vec::new())
    }

    pub fn write(&self, path: impl AsRef<Path>) -> RuntimeResult<()> {
        write_json_file(path, self)
    }

    pub fn read(path: impl AsRef<Path>) -> RuntimeResult<Self> {
        read_json_file(path)
    }

    fn resolve_inner(
        &self,
        profile_id: &str,
        visiting: &mut Vec<String>,
    ) -> RuntimeResult<RuntimePolicyProfile> {
        if visiting.iter().any(|id| id == profile_id) {
            return Err(RuntimeError::ProfileInheritanceCycle(profile_id.into()));
        }
        let manifest = self
            .profiles
            .iter()
            .find(|manifest| manifest.profile.profile_id == profile_id)
            .ok_or_else(|| RuntimeError::ProfileNotFound(profile_id.into()))?;
        let Some(parent_id) = &manifest.parent_profile_id else {
            return Ok(manifest.profile.clone());
        };
        visiting.push(profile_id.into());
        let parent = self.resolve_inner(parent_id, visiting)?;
        visiting.pop();
        Ok(merge_runtime_profiles(parent, manifest.profile.clone()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeManifestRegistry {
    pub schema_version: u32,
    pub modules: Vec<ModuleManifest>,
    pub skills: Vec<SkillManifest>,
}

impl Default for RuntimeManifestRegistry {
    fn default() -> Self {
        Self {
            schema_version: 1,
            modules: vec![],
            skills: vec![],
        }
    }
}

impl RuntimeManifestRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_module(&mut self, module: ModuleManifest) {
        self.modules
            .retain(|existing| existing.module_id != module.module_id);
        self.modules.push(module);
    }

    pub fn register_skill(&mut self, skill: SkillManifest) -> RuntimeResult<()> {
        validate_skill_manifest(&skill)?;
        let module = self
            .modules
            .iter()
            .find(|module| module.module_id == skill.module_ref)
            .ok_or_else(|| RuntimeError::SkillModuleNotFound {
                skill_id: skill.skill_id.clone(),
                module_id: skill.module_ref.clone(),
            })?;
        validate_skill_module_binding(&skill, module)?;
        self.skills
            .retain(|existing| existing.skill_id != skill.skill_id);
        self.skills.push(skill);
        Ok(())
    }

    pub fn validate(&self) -> RuntimeResult<()> {
        validate_manifest_registry(self)
    }

    pub fn validate_with_profiles(
        &self,
        profile_registry: &RuntimeProfileRegistry,
    ) -> RuntimeResult<()> {
        self.validate()?;
        for module in &self.modules {
            let Some(profile_id) = &module.policy_profile_ref else {
                continue;
            };
            match profile_registry.resolve(profile_id) {
                Ok(_) => {}
                Err(RuntimeError::ProfileNotFound(_)) => {
                    return Err(RuntimeError::ModuleProfileNotFound {
                        module_id: module.module_id.clone(),
                        profile_id: profile_id.clone(),
                    });
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    pub fn skills_for_profile(
        &self,
        profile: &RuntimePolicyProfile,
    ) -> RuntimeResult<Vec<SkillManifest>> {
        self.validate()?;
        if !profile.allow_skills {
            return Ok(vec![]);
        }
        self.skills
            .iter()
            .filter(|skill| skill_allowed_by_profile(skill, profile))
            .cloned()
            .map(|skill| {
                validate_skill_manifest(&skill)?;
                Ok(skill)
            })
            .collect()
    }

    pub fn write(&self, path: impl AsRef<Path>) -> RuntimeResult<()> {
        write_json_file(path, self)
    }

    pub fn read(path: impl AsRef<Path>) -> RuntimeResult<Self> {
        read_json_file(path)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeResumePlan {
    pub graph_id: String,
    pub completed_task_ids: Vec<String>,
    pub ready_task_ids: Vec<String>,
    pub blocked_task_ids: Vec<String>,
    pub running_task_ids: Vec<String>,
    pub awaiting_approval_task_ids: Vec<String>,
    pub failed_task_ids: Vec<String>,
    pub blockers: BTreeMap<String, ResumeBlocker>,
    #[serde(default)]
    pub adoption_recommendations: BTreeMap<String, RuntimeAdoptionRecommendation>,
    pub running_task_policy: RunningTaskPolicy,
    pub is_complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "record_type", rename_all = "snake_case")]
pub enum RuntimeJournalRecord {
    Planner { planner: RuntimePlannerRecord },
    Graph { graph: TaskGraph },
    Event { event: RuntimeEvent },
    Attempt { attempt: RuntimeTaskAttempt },
    RetryLease { lease: RuntimeRetryLease },
    AdoptionProbe { probe: RuntimeAdoptionProbeRecord },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct RuntimeTaskStore {
    #[serde(default)]
    planners: BTreeMap<String, RuntimePlannerRecord>,
    graphs: BTreeMap<String, TaskGraph>,
    tasks: BTreeMap<String, RuntimeTaskRecord>,
    attempts: BTreeMap<String, RuntimeTaskAttempt>,
    #[serde(default)]
    retry_leases: BTreeMap<String, RuntimeRetryLease>,
    #[serde(default)]
    adoption_probes: BTreeMap<String, RuntimeAdoptionProbeRecord>,
}

impl RuntimeTaskStore {
    pub fn save_planner_record(&mut self, planner: RuntimePlannerRecord) {
        self.planners.insert(planner.graph_id.clone(), planner);
    }

    pub fn save_graph(&mut self, graph: &TaskGraph) {
        self.graphs.insert(graph.graph_id.clone(), graph.clone());
        let now = Utc::now();
        for task in &graph.tasks {
            self.tasks.insert(
                task.task_id.clone(),
                RuntimeTaskRecord {
                    graph_id: graph.graph_id.clone(),
                    task: task.clone(),
                    last_event_id: None,
                    last_stage: None,
                    last_attempt_id: None,
                    idempotency_key: None,
                    retry_safe: None,
                    message: None,
                    progress: 0.0,
                    updated_at: now,
                },
            );
        }
    }

    pub fn graph(&self, graph_id: &str) -> Option<&TaskGraph> {
        self.graphs.get(graph_id)
    }

    pub fn planner_record(&self, graph_id: &str) -> Option<&RuntimePlannerRecord> {
        self.planners.get(graph_id)
    }

    pub fn graph_ids(&self) -> Vec<String> {
        self.graphs.keys().cloned().collect()
    }

    pub fn task(&self, task_id: &str) -> Option<&RuntimeTaskRecord> {
        self.tasks.get(task_id)
    }

    pub fn graphs(&self) -> Vec<TaskGraph> {
        self.graphs.values().cloned().collect()
    }

    pub fn tasks_for_graph(&self, graph_id: &str) -> Vec<RuntimeTaskRecord> {
        let mut tasks = self
            .tasks
            .values()
            .filter(|record| record.graph_id == graph_id)
            .cloned()
            .collect::<Vec<_>>();
        order_task_records_by_dependency(&mut tasks);
        tasks
    }

    pub fn attempts_for_graph(&self, graph_id: &str) -> Vec<RuntimeTaskAttempt> {
        self.attempts
            .values()
            .filter(|attempt| attempt.graph_id == graph_id)
            .cloned()
            .collect()
    }

    pub fn adoption_probes_for_graph(&self, graph_id: &str) -> Vec<RuntimeAdoptionProbeRecord> {
        let mut probes = self
            .adoption_probes
            .values()
            .filter(|probe| probe.graph_id == graph_id)
            .cloned()
            .collect::<Vec<_>>();
        probes.sort_by_key(|probe| (probe.recorded_at, probe.probe_id.clone()));
        probes
    }

    pub fn latest_attempt_for_task(&self, task_id: &str) -> Option<&RuntimeTaskAttempt> {
        self.attempts
            .values()
            .filter(|attempt| attempt.task_id == task_id)
            .max_by_key(|attempt| attempt.created_at)
    }

    pub fn latest_adoption_probe_for_attempt(
        &self,
        attempt_id: &str,
    ) -> Option<&RuntimeAdoptionProbeRecord> {
        self.adoption_probes
            .values()
            .filter(|probe| probe.result.attempt_id == attempt_id)
            .max_by_key(|probe| probe.recorded_at)
    }

    pub fn active_retry_lease_for_task(&self, task_id: &str) -> Option<&RuntimeRetryLease> {
        let now = Utc::now();
        self.retry_leases.values().find(|lease| {
            lease.task_id == task_id
                && lease.state == RuntimeRetryLeaseState::Active
                && lease.expires_at > now
        })
    }

    pub fn retry_leases_for_graph(&self, graph_id: &str) -> Vec<RuntimeRetryLease> {
        self.retry_leases
            .values()
            .filter(|lease| lease.graph_id == graph_id)
            .cloned()
            .collect()
    }

    pub fn adoption_recommendation_for_task(
        &self,
        task_id: &str,
    ) -> RuntimeResult<RuntimeAdoptionRecommendation> {
        let task = self
            .task(task_id)
            .ok_or_else(|| RuntimeError::TaskNotFound(task_id.into()))?;
        Ok(adoption_recommendation_for_task(self, task, None))
    }

    pub fn adoption_recommendations_for_graph(
        &self,
        graph_id: &str,
    ) -> RuntimeResult<BTreeMap<String, RuntimeAdoptionRecommendation>> {
        self.graph(graph_id)
            .ok_or_else(|| RuntimeError::GraphNotFound(graph_id.into()))?;
        let mut recommendations = BTreeMap::new();
        for task in self.tasks_for_graph(graph_id) {
            recommendations.insert(
                task.task.task_id.clone(),
                adoption_recommendation_for_task(self, &task, None),
            );
        }
        Ok(recommendations)
    }

    pub fn acquire_retry_lease(&mut self, lease: RuntimeRetryLease) -> RuntimeResult<()> {
        if let Some(active) = self.active_retry_lease_for_task(&lease.task_id) {
            return Err(RuntimeError::RetryLeaseActive {
                task_id: lease.task_id,
                lease_id: active.lease_id.clone(),
            });
        }
        self.retry_leases.insert(lease.lease_id.clone(), lease);
        Ok(())
    }

    pub fn release_retry_lease(
        &mut self,
        lease_id: &str,
        released_at: DateTime<Utc>,
    ) -> RuntimeResult<()> {
        let Some(lease) = self.retry_leases.get_mut(lease_id) else {
            return Ok(());
        };
        lease.state = RuntimeRetryLeaseState::Released;
        lease.released_at = Some(released_at);
        Ok(())
    }

    pub fn upsert_retry_lease(&mut self, lease: RuntimeRetryLease) {
        self.retry_leases.insert(lease.lease_id.clone(), lease);
    }

    pub fn record_adoption_probe(
        &mut self,
        probe: RuntimeAdoptionProbeRecord,
    ) -> RuntimeResult<()> {
        if self.graph(&probe.graph_id).is_none() {
            return Err(RuntimeError::GraphNotFound(probe.graph_id));
        }
        if self.task(&probe.result.task_id).is_none() {
            return Err(RuntimeError::TaskNotFound(probe.result.task_id));
        }
        let attempt = self
            .attempts
            .get(&probe.result.attempt_id)
            .ok_or_else(|| RuntimeError::AttemptNotFound(probe.result.attempt_id.clone()))?;
        validate_adoption_probe_matches_attempt(&probe, attempt)?;
        self.adoption_probes.insert(probe.probe_id.clone(), probe);
        Ok(())
    }

    pub fn record_attempt(&mut self, attempt: RuntimeTaskAttempt) -> RuntimeResult<()> {
        let record = self
            .tasks
            .get_mut(&attempt.task_id)
            .ok_or_else(|| RuntimeError::TaskNotFound(attempt.task_id.clone()))?;
        record.last_attempt_id = Some(attempt.attempt_id.clone());
        record.idempotency_key = Some(attempt.idempotency_key.clone());
        record.retry_safe = Some(attempt.retry_safe);
        record.updated_at = Utc::now();
        self.attempts.insert(attempt.attempt_id.clone(), attempt);
        Ok(())
    }

    pub fn update_task_state(
        &mut self,
        graph_id: &str,
        task_id: &str,
        state: TaskState,
        event: Option<&RuntimeEvent>,
    ) -> RuntimeResult<()> {
        let graph = self
            .graphs
            .get_mut(graph_id)
            .ok_or_else(|| RuntimeError::GraphNotFound(graph_id.into()))?;
        let graph_task = graph
            .tasks
            .iter_mut()
            .find(|task| task.task_id == task_id)
            .ok_or_else(|| RuntimeError::TaskNotFound(task_id.into()))?;
        graph_task.state = merge_task_state(graph_task.state, state);

        let record = self
            .tasks
            .get_mut(task_id)
            .ok_or_else(|| RuntimeError::TaskNotFound(task_id.into()))?;
        record.task.state = merge_task_state(record.task.state, state);
        if let Some(event) = event {
            record.last_event_id = Some(event.event_id.clone());
            record.last_stage = Some(event.stage);
            record.message = Some(event.message.clone());
            record.progress = event.progress;
        } else {
            record.last_stage = Some(runtime_stage_for_task_state(state));
        }
        record.updated_at = Utc::now();
        Ok(())
    }
}

pub struct RuntimeSqliteStore {
    conn: Connection,
}

impl RuntimeSqliteStore {
    pub fn open(path: impl AsRef<Path>) -> RuntimeResult<Self> {
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent)?;
        }
        let store = Self {
            conn: Connection::open(path)?,
        };
        store.init()?;
        Ok(store)
    }

    pub fn open_memory() -> RuntimeResult<Self> {
        let store = Self {
            conn: Connection::open_in_memory()?,
        };
        store.init()?;
        Ok(store)
    }

    pub fn schema_version(&self) -> RuntimeResult<u32> {
        let value = self
            .conn
            .query_row(
                "SELECT value FROM runtime_store_meta WHERE key = 'schema_version'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        Ok(value
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or_default())
    }

    pub fn save_graph(&self, graph: &TaskGraph) -> RuntimeResult<()> {
        self.upsert_graph_payload(graph)?;

        let now = Utc::now();
        for task in &graph.tasks {
            let mut record =
                self.task_record(&task.task_id)?
                    .unwrap_or_else(|| RuntimeTaskRecord {
                        graph_id: graph.graph_id.clone(),
                        task: task.clone(),
                        last_event_id: None,
                        last_stage: None,
                        last_attempt_id: None,
                        idempotency_key: None,
                        retry_safe: None,
                        message: None,
                        progress: 0.0,
                        updated_at: now,
                    });
            record.graph_id = graph.graph_id.clone();
            let merged_state = merge_task_state(record.task.state, task.state);
            record.task = task.clone();
            record.task.state = merged_state;
            record.updated_at = now;
            self.upsert_task_record(&record)?;
        }

        Ok(())
    }

    fn upsert_graph_payload(&self, graph: &TaskGraph) -> RuntimeResult<()> {
        let graph_json = serde_json::to_string(graph)?;
        self.conn.execute(
            r#"
            INSERT INTO runtime_graphs (graph_id, path, goal, payload_json, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(graph_id) DO UPDATE SET
                path = excluded.path,
                goal = excluded.goal,
                payload_json = excluded.payload_json,
                updated_at = excluded.updated_at
            "#,
            params![
                graph.graph_id,
                runtime_path_key(graph.path),
                graph.goal,
                graph_json,
                Utc::now().to_rfc3339()
            ],
        )?;
        Ok(())
    }

    pub fn save_planner_record(&self, planner: &RuntimePlannerRecord) -> RuntimeResult<()> {
        self.conn.execute(
            r#"
            INSERT INTO runtime_planner_records
                (plan_id, graph_id, intent_id, source, step_count, plan_hash, created_at, payload_json)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ON CONFLICT(plan_id) DO UPDATE SET
                graph_id = excluded.graph_id,
                intent_id = excluded.intent_id,
                source = excluded.source,
                step_count = excluded.step_count,
                plan_hash = excluded.plan_hash,
                payload_json = excluded.payload_json
            "#,
            params![
                planner.plan_id,
                planner.graph_id,
                planner.intent_id,
                planner_source_key(planner.source),
                planner.step_count as i64,
                planner.plan_hash,
                planner.created_at.to_rfc3339(),
                serde_json::to_string(planner)?,
            ],
        )?;
        Ok(())
    }

    pub fn record_attempt(&self, attempt: &RuntimeTaskAttempt) -> RuntimeResult<()> {
        self.conn.execute(
            r#"
            INSERT INTO runtime_attempts
                (attempt_id, graph_id, task_id, stage, idempotency_key, retry_safe, created_at, payload_json)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ON CONFLICT(attempt_id) DO UPDATE SET
                stage = excluded.stage,
                idempotency_key = excluded.idempotency_key,
                retry_safe = excluded.retry_safe,
                payload_json = excluded.payload_json
            "#,
            params![
                attempt.attempt_id,
                attempt.graph_id,
                attempt.task_id,
                runtime_attempt_stage_key(attempt.stage),
                attempt.idempotency_key,
                if attempt.retry_safe { 1 } else { 0 },
                attempt.created_at.to_rfc3339(),
                serde_json::to_string(attempt)?,
            ],
        )?;

        self.conn.execute(
            r#"
            UPDATE runtime_tasks
            SET last_attempt_id = ?1,
                idempotency_key = ?2,
                retry_safe = ?3,
                updated_at = ?4
            WHERE task_id = ?5
            "#,
            params![
                attempt.attempt_id,
                attempt.idempotency_key,
                if attempt.retry_safe { 1 } else { 0 },
                Utc::now().to_rfc3339(),
                attempt.task_id,
            ],
        )?;

        if let Some(mut record) = self.task_record(&attempt.task_id)? {
            record.last_attempt_id = Some(attempt.attempt_id.clone());
            record.idempotency_key = Some(attempt.idempotency_key.clone());
            record.retry_safe = Some(attempt.retry_safe);
            record.updated_at = Utc::now();
            self.upsert_task_record(&record)?;
        }

        Ok(())
    }

    pub fn record_event(&self, event: &RuntimeEvent) -> RuntimeResult<()> {
        let cursor = self.next_event_cursor()?;
        self.conn.execute(
            r#"
            INSERT INTO runtime_events
                (event_id, cursor, graph_id, task_id, stage, progress, timestamp, payload_json)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ON CONFLICT(event_id) DO UPDATE SET
                graph_id = excluded.graph_id,
                task_id = excluded.task_id,
                stage = excluded.stage,
                progress = excluded.progress,
                timestamp = excluded.timestamp,
                payload_json = excluded.payload_json
            "#,
            params![
                event.event_id,
                cursor,
                event.graph_id,
                event.task_id,
                runtime_stage_key(event.stage),
                event.progress,
                event.timestamp.to_rfc3339(),
                serde_json::to_string(event)?,
            ],
        )?;

        if let (Some(graph_id), Some(task_id)) = (&event.graph_id, &event.task_id) {
            let mut store = self.load_task_store()?;
            let state = task_state_for_stage(event.stage);
            store.update_task_state(graph_id, task_id, state, Some(event))?;
            let record = store.task(task_id).cloned();
            let graph = store.graph(graph_id).cloned();
            if let Some(graph) = graph {
                self.upsert_graph_payload(&graph)?;
            }
            if let Some(record) = record {
                self.upsert_task_record(&record)?;
            }
        }

        Ok(())
    }

    pub fn acquire_retry_lease(&mut self, lease: &RuntimeRetryLease) -> RuntimeResult<()> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = Utc::now().to_rfc3339();
        let active = tx
            .query_row(
                r#"
                SELECT payload_json FROM runtime_retry_leases
                WHERE task_id = ?1 AND state = 'active' AND expires_at > ?2
                ORDER BY expires_at DESC
                LIMIT 1
                "#,
                params![lease.task_id, now],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(active) = active {
            let active: RuntimeRetryLease = serde_json::from_str(&active)?;
            return Err(RuntimeError::RetryLeaseActive {
                task_id: lease.task_id.clone(),
                lease_id: active.lease_id,
            });
        }
        upsert_retry_lease_tx(&tx, lease)?;
        tx.commit()?;
        Ok(())
    }

    pub fn release_retry_lease(
        &self,
        lease_id: &str,
        released_at: DateTime<Utc>,
    ) -> RuntimeResult<()> {
        let Some(mut lease) = self.retry_lease(lease_id)? else {
            return Ok(());
        };
        lease.state = RuntimeRetryLeaseState::Released;
        lease.released_at = Some(released_at);
        self.upsert_retry_lease(&lease)
    }

    pub fn active_retry_lease_for_task(
        &self,
        task_id: &str,
    ) -> RuntimeResult<Option<RuntimeRetryLease>> {
        let now = Utc::now().to_rfc3339();
        let payload = self
            .conn
            .query_row(
                r#"
                SELECT payload_json FROM runtime_retry_leases
                WHERE task_id = ?1 AND state = 'active' AND expires_at > ?2
                ORDER BY expires_at DESC
                LIMIT 1
                "#,
                params![task_id, now],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        payload
            .map(|payload| serde_json::from_str(&payload).map_err(RuntimeError::from))
            .transpose()
    }

    pub fn retry_leases_for_graph(&self, graph_id: &str) -> RuntimeResult<Vec<RuntimeRetryLease>> {
        let mut stmt = self
            .conn
            .prepare("SELECT payload_json FROM runtime_retry_leases WHERE graph_id = ?1")?;
        let leases = stmt.query_map(params![graph_id], |row| row.get::<_, String>(0))?;
        let mut result = Vec::new();
        for lease in leases {
            result.push(serde_json::from_str(&lease?)?);
        }
        Ok(result)
    }

    pub fn save_retry_lease(&self, lease: &RuntimeRetryLease) -> RuntimeResult<()> {
        self.upsert_retry_lease(lease)
    }

    pub fn record_adoption_probe(&self, probe: &RuntimeAdoptionProbeRecord) -> RuntimeResult<()> {
        self.conn.execute(
            r#"
            INSERT INTO runtime_adoption_probes
                (probe_id, graph_id, task_id, attempt_id, idempotency_key, status,
                 provider_ref, evidence_ref, observed_at, recorded_at, payload_json)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            ON CONFLICT(probe_id) DO UPDATE SET
                graph_id = excluded.graph_id,
                task_id = excluded.task_id,
                attempt_id = excluded.attempt_id,
                idempotency_key = excluded.idempotency_key,
                status = excluded.status,
                provider_ref = excluded.provider_ref,
                evidence_ref = excluded.evidence_ref,
                observed_at = excluded.observed_at,
                recorded_at = excluded.recorded_at,
                payload_json = excluded.payload_json
            "#,
            params![
                probe.probe_id,
                probe.graph_id,
                probe.result.task_id,
                probe.result.attempt_id,
                probe.result.idempotency_key,
                adoption_probe_status_key(probe.result.status),
                probe.result.provider_ref,
                probe.result.evidence_ref,
                probe.result.observed_at.to_rfc3339(),
                probe.recorded_at.to_rfc3339(),
                serde_json::to_string(probe)?,
            ],
        )?;
        Ok(())
    }

    fn task_record(&self, task_id: &str) -> RuntimeResult<Option<RuntimeTaskRecord>> {
        let payload = self
            .conn
            .query_row(
                "SELECT payload_json FROM runtime_tasks WHERE task_id = ?1",
                params![task_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        payload
            .map(|payload| serde_json::from_str(&payload).map_err(RuntimeError::from))
            .transpose()
    }

    pub fn load_task_store(&self) -> RuntimeResult<RuntimeTaskStore> {
        let mut store = RuntimeTaskStore::default();
        let mut graph_stmt = self
            .conn
            .prepare("SELECT payload_json FROM runtime_graphs ORDER BY graph_id")?;
        let graphs = graph_stmt.query_map([], |row| row.get::<_, String>(0))?;
        for graph_json in graphs {
            let graph: TaskGraph = serde_json::from_str(&graph_json?)?;
            store.save_graph(&graph);
        }

        let mut task_stmt = self
            .conn
            .prepare("SELECT payload_json FROM runtime_tasks ORDER BY graph_id, task_id")?;
        let tasks = task_stmt.query_map([], |row| row.get::<_, String>(0))?;
        for task_json in tasks {
            let record: RuntimeTaskRecord = serde_json::from_str(&task_json?)?;
            store.tasks.insert(record.task.task_id.clone(), record);
        }

        let mut attempt_stmt = self
            .conn
            .prepare("SELECT payload_json FROM runtime_attempts ORDER BY created_at, attempt_id")?;
        let attempts = attempt_stmt.query_map([], |row| row.get::<_, String>(0))?;
        for attempt_json in attempts {
            let attempt: RuntimeTaskAttempt = serde_json::from_str(&attempt_json?)?;
            store.attempts.insert(attempt.attempt_id.clone(), attempt);
        }

        let mut lease_stmt = self.conn.prepare(
            "SELECT payload_json FROM runtime_retry_leases ORDER BY acquired_at, lease_id",
        )?;
        let leases = lease_stmt.query_map([], |row| row.get::<_, String>(0))?;
        for lease_json in leases {
            let lease: RuntimeRetryLease = serde_json::from_str(&lease_json?)?;
            store.upsert_retry_lease(lease);
        }

        let mut adoption_probe_stmt = self.conn.prepare(
            "SELECT payload_json FROM runtime_adoption_probes ORDER BY recorded_at, probe_id",
        )?;
        let adoption_probes = adoption_probe_stmt.query_map([], |row| row.get::<_, String>(0))?;
        for probe_json in adoption_probes {
            let probe: RuntimeAdoptionProbeRecord = serde_json::from_str(&probe_json?)?;
            store.record_adoption_probe(probe)?;
        }

        let mut planner_stmt = self.conn.prepare(
            "SELECT payload_json FROM runtime_planner_records ORDER BY created_at, plan_id",
        )?;
        let planners = planner_stmt.query_map([], |row| row.get::<_, String>(0))?;
        for planner_json in planners {
            let planner: RuntimePlannerRecord = serde_json::from_str(&planner_json?)?;
            store.save_planner_record(planner);
        }

        Ok(store)
    }

    pub fn load_event_stream(&self) -> RuntimeResult<RuntimeEventStream> {
        let mut stream = RuntimeEventStream::default();
        let mut stmt = self
            .conn
            .prepare("SELECT payload_json FROM runtime_events ORDER BY cursor")?;
        let events = stmt.query_map([], |row| row.get::<_, String>(0))?;
        for event_json in events {
            let event: RuntimeEvent = serde_json::from_str(&event_json?)?;
            stream.push(event);
        }
        Ok(stream)
    }

    pub fn graph_list(
        &self,
        running_task_policy: RunningTaskPolicy,
    ) -> RuntimeResult<Vec<RuntimeGraphListItem>> {
        let task_store = self.load_task_store()?;
        graph_list_from(&task_store, running_task_policy)
    }

    pub fn query_snapshot(
        &self,
        graph_id: &str,
        running_task_policy: RunningTaskPolicy,
        policy_profile: RuntimePolicyProfile,
    ) -> RuntimeResult<RuntimeQuerySnapshot> {
        let task_store = self.load_task_store()?;
        let event_stream = self.load_event_stream()?;
        query_snapshot_from(
            &task_store,
            event_stream.all(),
            graph_id,
            running_task_policy,
            policy_profile,
        )
    }

    pub fn task_index_snapshot(
        &self,
        running_task_policy: RunningTaskPolicy,
        policy_profile: RuntimePolicyProfile,
    ) -> RuntimeResult<RuntimeTaskIndexSnapshot> {
        let task_store = self.load_task_store()?;
        let event_stream = self.load_event_stream()?;
        task_index_snapshot_from(
            &task_store,
            event_stream.all(),
            running_task_policy,
            policy_profile,
        )
    }

    pub fn event_feed(
        &self,
        cursor: usize,
        graph_id: Option<&str>,
        running_task_policy: RunningTaskPolicy,
    ) -> RuntimeResult<RuntimeEventFeedSnapshot> {
        let task_store = self.load_task_store()?;
        let event_stream = self.load_event_stream()?;
        event_feed_snapshot_from(
            &task_store,
            event_stream.all(),
            cursor,
            graph_id,
            running_task_policy,
        )
    }

    fn init(&self) -> RuntimeResult<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS runtime_store_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            "#,
        )?;
        let version = self.schema_version()?;
        if version > RUNTIME_STORE_SCHEMA_VERSION {
            return Err(RuntimeError::RuntimeStoreSchemaVersionTooNew {
                found: version,
                supported: RUNTIME_STORE_SCHEMA_VERSION,
            });
        }
        if version < 1 {
            self.migrate_to_v1()?;
        }
        if version < 2 {
            self.migrate_to_v2()?;
        }
        if version < 3 {
            self.migrate_to_v3()?;
        }
        if version < 4 {
            self.migrate_to_v4()?;
        }
        Ok(())
    }

    fn migrate_to_v1(&self) -> RuntimeResult<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS runtime_graphs (
                graph_id TEXT PRIMARY KEY,
                path TEXT NOT NULL,
                goal TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS runtime_tasks (
                task_id TEXT PRIMARY KEY,
                graph_id TEXT NOT NULL,
                state TEXT NOT NULL,
                capability_id TEXT NOT NULL,
                last_stage TEXT,
                progress REAL NOT NULL,
                last_event_id TEXT,
                last_attempt_id TEXT,
                idempotency_key TEXT,
                retry_safe INTEGER,
                payload_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS runtime_events (
                event_id TEXT PRIMARY KEY,
                cursor INTEGER NOT NULL,
                graph_id TEXT,
                task_id TEXT,
                stage TEXT NOT NULL,
                progress REAL NOT NULL,
                timestamp TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS runtime_attempts (
                attempt_id TEXT PRIMARY KEY,
                graph_id TEXT NOT NULL,
                task_id TEXT NOT NULL,
                stage TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                retry_safe INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_runtime_tasks_graph_state
                ON runtime_tasks(graph_id, state);
            CREATE INDEX IF NOT EXISTS idx_runtime_tasks_state
                ON runtime_tasks(state);
            CREATE INDEX IF NOT EXISTS idx_runtime_events_graph_cursor
                ON runtime_events(graph_id, cursor);
            CREATE INDEX IF NOT EXISTS idx_runtime_events_cursor
                ON runtime_events(cursor);
            CREATE INDEX IF NOT EXISTS idx_runtime_attempts_task_created
                ON runtime_attempts(task_id, created_at);
            "#,
        )?;
        self.set_schema_version(1)
    }

    fn migrate_to_v2(&self) -> RuntimeResult<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS runtime_retry_leases (
                lease_id TEXT PRIMARY KEY,
                graph_id TEXT NOT NULL,
                task_id TEXT NOT NULL,
                run_id TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                holder_ref TEXT NOT NULL,
                state TEXT NOT NULL,
                acquired_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                released_at TEXT,
                payload_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_runtime_retry_leases_task_state_expires
                ON runtime_retry_leases(task_id, state, expires_at);
            CREATE INDEX IF NOT EXISTS idx_runtime_retry_leases_graph
                ON runtime_retry_leases(graph_id);
            "#,
        )?;
        self.set_schema_version(2)
    }

    fn migrate_to_v3(&self) -> RuntimeResult<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS runtime_planner_records (
                plan_id TEXT PRIMARY KEY,
                graph_id TEXT NOT NULL,
                intent_id TEXT NOT NULL,
                source TEXT NOT NULL,
                step_count INTEGER NOT NULL,
                plan_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_runtime_planner_records_graph
                ON runtime_planner_records(graph_id);
            CREATE INDEX IF NOT EXISTS idx_runtime_planner_records_intent
                ON runtime_planner_records(intent_id);
            "#,
        )?;
        self.set_schema_version(3)
    }

    fn migrate_to_v4(&self) -> RuntimeResult<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS runtime_adoption_probes (
                probe_id TEXT PRIMARY KEY,
                graph_id TEXT NOT NULL,
                task_id TEXT NOT NULL,
                attempt_id TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                status TEXT NOT NULL,
                provider_ref TEXT,
                evidence_ref TEXT,
                observed_at TEXT NOT NULL,
                recorded_at TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_runtime_adoption_probes_graph
                ON runtime_adoption_probes(graph_id);
            CREATE INDEX IF NOT EXISTS idx_runtime_adoption_probes_attempt_recorded
                ON runtime_adoption_probes(attempt_id, recorded_at);
            CREATE INDEX IF NOT EXISTS idx_runtime_adoption_probes_idempotency_key
                ON runtime_adoption_probes(idempotency_key);
            "#,
        )?;
        self.set_schema_version(4)
    }

    fn set_schema_version(&self, version: u32) -> RuntimeResult<()> {
        self.conn.execute(
            r#"
            INSERT INTO runtime_store_meta (key, value)
            VALUES ('schema_version', ?1)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            "#,
            params![version.to_string()],
        )?;
        Ok(())
    }

    fn upsert_task_record(&self, record: &RuntimeTaskRecord) -> RuntimeResult<()> {
        self.conn.execute(
            r#"
            INSERT INTO runtime_tasks
                (task_id, graph_id, state, capability_id, last_stage, progress, last_event_id,
                 last_attempt_id, idempotency_key, retry_safe, payload_json, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
            ON CONFLICT(task_id) DO UPDATE SET
                graph_id = excluded.graph_id,
                state = excluded.state,
                capability_id = excluded.capability_id,
                last_stage = excluded.last_stage,
                progress = excluded.progress,
                last_event_id = excluded.last_event_id,
                last_attempt_id = excluded.last_attempt_id,
                idempotency_key = excluded.idempotency_key,
                retry_safe = excluded.retry_safe,
                payload_json = excluded.payload_json,
                updated_at = excluded.updated_at
            "#,
            params![
                record.task.task_id,
                record.graph_id,
                task_state_key(record.task.state),
                record.task.capability_id,
                record.last_stage.map(runtime_stage_key),
                record.progress,
                record.last_event_id,
                record.last_attempt_id,
                record.idempotency_key,
                record
                    .retry_safe
                    .map(|retry_safe| if retry_safe { 1 } else { 0 }),
                serde_json::to_string(record)?,
                record.updated_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    fn retry_lease(&self, lease_id: &str) -> RuntimeResult<Option<RuntimeRetryLease>> {
        let payload = self
            .conn
            .query_row(
                "SELECT payload_json FROM runtime_retry_leases WHERE lease_id = ?1",
                params![lease_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        payload
            .map(|payload| serde_json::from_str(&payload).map_err(RuntimeError::from))
            .transpose()
    }

    fn upsert_retry_lease(&self, lease: &RuntimeRetryLease) -> RuntimeResult<()> {
        upsert_retry_lease_conn(&self.conn, lease)?;
        Ok(())
    }

    fn next_event_cursor(&self) -> RuntimeResult<i64> {
        let cursor = self.conn.query_row(
            "SELECT COALESCE(MAX(cursor), -1) + 1 FROM runtime_events",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        Ok(cursor)
    }
}

fn upsert_retry_lease_conn(conn: &Connection, lease: &RuntimeRetryLease) -> RuntimeResult<()> {
    conn.execute(
        r#"
        INSERT INTO runtime_retry_leases
            (lease_id, graph_id, task_id, run_id, idempotency_key, holder_ref, state,
             acquired_at, expires_at, released_at, payload_json)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
        ON CONFLICT(lease_id) DO UPDATE SET
            state = excluded.state,
            expires_at = excluded.expires_at,
            released_at = excluded.released_at,
            payload_json = excluded.payload_json
        "#,
        retry_lease_params(lease)?,
    )?;
    Ok(())
}

fn upsert_retry_lease_tx(
    tx: &rusqlite::Transaction<'_>,
    lease: &RuntimeRetryLease,
) -> RuntimeResult<()> {
    tx.execute(
        r#"
        INSERT INTO runtime_retry_leases
            (lease_id, graph_id, task_id, run_id, idempotency_key, holder_ref, state,
             acquired_at, expires_at, released_at, payload_json)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
        ON CONFLICT(lease_id) DO UPDATE SET
            state = excluded.state,
            expires_at = excluded.expires_at,
            released_at = excluded.released_at,
            payload_json = excluded.payload_json
        "#,
        retry_lease_params(lease)?,
    )?;
    Ok(())
}

type RetryLeaseParams<'a> = (
    &'a str,
    &'a str,
    &'a str,
    &'a str,
    &'a str,
    &'a str,
    &'static str,
    String,
    String,
    Option<String>,
    String,
);

fn retry_lease_params(lease: &RuntimeRetryLease) -> RuntimeResult<RetryLeaseParams<'_>> {
    Ok((
        lease.lease_id.as_str(),
        lease.graph_id.as_str(),
        lease.task_id.as_str(),
        lease.run_id.as_str(),
        lease.idempotency_key.as_str(),
        lease.holder_ref.as_str(),
        runtime_retry_lease_state_key(lease.state),
        lease.acquired_at.to_rfc3339(),
        lease.expires_at.to_rfc3339(),
        lease
            .released_at
            .map(|released_at| released_at.to_rfc3339()),
        serde_json::to_string(lease)?,
    ))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct RuntimeEventStream {
    events: Vec<RuntimeEvent>,
}

impl RuntimeEventStream {
    pub fn push(&mut self, event: RuntimeEvent) {
        self.events.push(event);
    }

    pub fn all(&self) -> &[RuntimeEvent] {
        &self.events
    }

    pub fn since(&self, cursor: usize) -> &[RuntimeEvent] {
        if cursor >= self.events.len() {
            &[]
        } else {
            &self.events[cursor..]
        }
    }

    pub fn cursor(&self) -> usize {
        self.events.len()
    }
}

#[derive(Debug)]
pub struct RuntimeJournal {
    path: PathBuf,
    writer: File,
    lock_path: PathBuf,
    lock_file: Option<File>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeJournalLockInfo {
    pub schema_version: u32,
    pub journal_path: PathBuf,
    pub lock_path: PathBuf,
    pub owner_pid: u32,
    pub created_at: DateTime<Utc>,
}

impl RuntimeJournal {
    pub fn open(path: impl AsRef<Path>) -> RuntimeResult<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let lock_path = journal_lock_path(&path);
        let lock_file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(RuntimeError::JournalLocked(lock_path));
            }
            Err(error) => return Err(error.into()),
        };
        let lock_info = RuntimeJournalLockInfo {
            schema_version: 1,
            journal_path: path.clone(),
            lock_path: lock_path.clone(),
            owner_pid: std::process::id(),
            created_at: Utc::now(),
        };
        write_lock_info(&lock_file, &lock_info)?;
        let writer = match OpenOptions::new().create(true).append(true).open(&path) {
            Ok(writer) => writer,
            Err(error) => {
                drop(lock_file);
                let _ = fs::remove_file(&lock_path);
                return Err(error.into());
            }
        };
        Ok(Self {
            path,
            writer,
            lock_path,
            lock_file: Some(lock_file),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn lock_path(&self) -> &Path {
        &self.lock_path
    }

    pub fn lock_info(path: impl AsRef<Path>) -> RuntimeResult<Option<RuntimeJournalLockInfo>> {
        let lock_path = journal_lock_path(path.as_ref());
        read_lock_info_if_exists(&lock_path)
    }

    pub fn clear_stale_lock(path: impl AsRef<Path>, older_than_ms: i64) -> RuntimeResult<bool> {
        let path = path.as_ref();
        let lock_path = journal_lock_path(path);
        let Some(lock_info) = read_lock_info_if_exists(&lock_path)? else {
            return Ok(false);
        };
        let age_ms = (Utc::now() - lock_info.created_at).num_milliseconds();
        if age_ms < older_than_ms {
            return Err(RuntimeError::JournalLockNotStale(lock_path));
        }
        fs::remove_file(&lock_path)?;
        Ok(true)
    }

    pub fn append(&mut self, record: &RuntimeJournalRecord) -> RuntimeResult<()> {
        serde_json::to_writer(&mut self.writer, record)?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        Ok(())
    }

    pub fn replay(path: impl AsRef<Path>) -> RuntimeResult<RuntimeReplay> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(RuntimeReplay::default());
        }

        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut replay = RuntimeReplay::default();
        for (index, line) in reader.lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let record: RuntimeJournalRecord =
                serde_json::from_str(&line).map_err(|source| RuntimeError::JournalReplay {
                    line: index + 1,
                    source,
                })?;
            replay.apply(record)?;
        }

        Ok(replay)
    }
}

impl Drop for RuntimeJournal {
    fn drop(&mut self) {
        drop(self.lock_file.take());
        let _ = fs::remove_file(&self.lock_path);
    }
}

fn journal_lock_path(path: &Path) -> PathBuf {
    let mut lock_name = path
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_else(|| "runtime.jsonl".into());
    lock_name.push(".lock");
    path.with_file_name(lock_name)
}

fn write_lock_info(file: &File, lock_info: &RuntimeJournalLockInfo) -> RuntimeResult<()> {
    let mut writer = file.try_clone()?;
    serde_json::to_writer_pretty(&mut writer, lock_info)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

fn read_lock_info_if_exists(path: &Path) -> RuntimeResult<Option<RuntimeJournalLockInfo>> {
    if !path.exists() {
        return Ok(None);
    }
    read_json_file(path).map(Some)
}

#[derive(Debug, Clone, Default)]
pub struct RuntimeReplay {
    pub task_store: RuntimeTaskStore,
    pub event_stream: RuntimeEventStream,
}

impl RuntimeReplay {
    pub fn events(&self) -> &[RuntimeEvent] {
        self.event_stream.all()
    }

    pub fn events_since(&self, cursor: usize) -> &[RuntimeEvent] {
        self.event_stream.since(cursor)
    }

    pub fn event_feed(
        &self,
        cursor: usize,
        graph_id: Option<&str>,
    ) -> RuntimeResult<RuntimeEventFeedSnapshot> {
        event_feed_snapshot_from(
            &self.task_store,
            self.event_stream.all(),
            cursor,
            graph_id,
            RunningTaskPolicy::RequireInspection,
        )
    }

    pub fn graph_snapshot(&self, graph_id: &str) -> RuntimeResult<RuntimeGraphSnapshot> {
        graph_snapshot_from(&self.task_store, self.event_stream.all(), graph_id)
    }

    pub fn graph_list(&self) -> RuntimeResult<Vec<RuntimeGraphListItem>> {
        graph_list_from(&self.task_store, RunningTaskPolicy::RequireInspection)
    }

    pub fn query_snapshot(&self, graph_id: &str) -> RuntimeResult<RuntimeQuerySnapshot> {
        query_snapshot_from(
            &self.task_store,
            self.event_stream.all(),
            graph_id,
            RunningTaskPolicy::RequireInspection,
            RuntimePolicyProfile::default(),
        )
    }

    pub fn projection_snapshot(&self) -> RuntimeProjectionSnapshot {
        RuntimeProjectionSnapshot {
            schema_version: 1,
            task_store: self.task_store.clone(),
            event_stream: self.event_stream.clone(),
            policy_profile: RuntimePolicyProfile::default(),
            running_task_policy: RunningTaskPolicy::RequireInspection,
        }
    }

    pub fn write_projection(
        &self,
        path: impl AsRef<Path>,
    ) -> RuntimeResult<RuntimeProjectionSnapshot> {
        let snapshot = self.projection_snapshot();
        write_projection_snapshot(path, &snapshot)?;
        Ok(snapshot)
    }

    pub fn task_index_snapshot(&self) -> RuntimeResult<RuntimeTaskIndexSnapshot> {
        task_index_snapshot_from(
            &self.task_store,
            self.event_stream.all(),
            RunningTaskPolicy::RequireInspection,
            RuntimePolicyProfile::default(),
        )
    }

    pub fn write_task_index(
        &self,
        path: impl AsRef<Path>,
    ) -> RuntimeResult<RuntimeTaskIndexSnapshot> {
        let snapshot = self.task_index_snapshot()?;
        write_task_index_snapshot(path, &snapshot)?;
        Ok(snapshot)
    }

    pub fn resume_plan(&self, graph_id: &str) -> RuntimeResult<RuntimeResumePlan> {
        resume_plan_from(
            &self.task_store,
            graph_id,
            RunningTaskPolicy::RequireInspection,
            None,
        )
    }

    pub fn resume_plan_with_policy(
        &self,
        graph_id: &str,
        running_task_policy: RunningTaskPolicy,
    ) -> RuntimeResult<RuntimeResumePlan> {
        resume_plan_from(&self.task_store, graph_id, running_task_policy, None)
    }

    pub fn resume_plan_with_policy_and_probe(
        &self,
        graph_id: &str,
        running_task_policy: RunningTaskPolicy,
        adoption_probe: &dyn RuntimeAdoptionProbe,
    ) -> RuntimeResult<RuntimeResumePlan> {
        resume_plan_from(
            &self.task_store,
            graph_id,
            running_task_policy,
            Some(adoption_probe),
        )
    }

    pub fn resume_plans(&self) -> RuntimeResult<Vec<RuntimeResumePlan>> {
        self.task_store
            .graphs()
            .iter()
            .map(|graph| self.resume_plan(&graph.graph_id))
            .collect()
    }

    fn apply(&mut self, record: RuntimeJournalRecord) -> RuntimeResult<()> {
        match record {
            RuntimeJournalRecord::Planner { planner } => {
                self.task_store.save_planner_record(planner);
            }
            RuntimeJournalRecord::Graph { graph } => {
                self.task_store.save_graph(&graph);
            }
            RuntimeJournalRecord::Attempt { attempt } => {
                self.task_store.record_attempt(attempt)?;
            }
            RuntimeJournalRecord::Event { event } => {
                if let (Some(graph_id), Some(task_id)) = (&event.graph_id, &event.task_id) {
                    let state = task_state_for_stage(event.stage);
                    self.task_store
                        .update_task_state(graph_id, task_id, state, Some(&event))?;
                }
                self.event_stream.push(event);
            }
            RuntimeJournalRecord::RetryLease { lease } => {
                self.task_store.upsert_retry_lease(lease);
            }
            RuntimeJournalRecord::AdoptionProbe { probe } => {
                self.task_store.record_adoption_probe(probe)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct SkillRegistry {
    skills: Vec<SkillManifest>,
}

impl SkillRegistry {
    pub fn register(&mut self, skill: SkillManifest) -> RuntimeResult<()> {
        validate_skill_manifest(&skill)?;
        self.skills.push(skill);
        Ok(())
    }

    pub fn list(&self) -> &[SkillManifest] {
        &self.skills
    }

    fn matching_skills(&self, intent: &Intent) -> Vec<SkillManifest> {
        self.skills
            .iter()
            .filter(|skill| skill_matches_intent(skill, intent))
            .cloned()
            .collect()
    }
}

pub struct RuntimeSession {
    kernel: Kernel,
    skills: SkillRegistry,
    event_stream: RuntimeEventStream,
    task_store: RuntimeTaskStore,
    journal: Option<RuntimeJournal>,
    sqlite_store: Option<RuntimeSqliteStore>,
    adoption_probes: RuntimeAdoptionProbeRegistry,
    policy_profile: RuntimePolicyProfile,
    running_task_policy: RunningTaskPolicy,
    retry_lease_ttl_ms: i64,
}

impl RuntimeSession {
    pub fn new(kernel: Kernel) -> Self {
        Self {
            kernel,
            skills: SkillRegistry::default(),
            event_stream: RuntimeEventStream::default(),
            task_store: RuntimeTaskStore::default(),
            journal: None,
            sqlite_store: None,
            adoption_probes: RuntimeAdoptionProbeRegistry::default(),
            policy_profile: RuntimePolicyProfile::default(),
            running_task_policy: RunningTaskPolicy::RequireInspection,
            retry_lease_ttl_ms: 30_000,
        }
    }

    pub fn with_journal(kernel: Kernel, path: impl AsRef<Path>) -> RuntimeResult<Self> {
        let journal = RuntimeJournal::open(path)?;
        Ok(Self {
            kernel,
            skills: SkillRegistry::default(),
            event_stream: RuntimeEventStream::default(),
            task_store: RuntimeTaskStore::default(),
            journal: Some(journal),
            sqlite_store: None,
            adoption_probes: RuntimeAdoptionProbeRegistry::default(),
            policy_profile: RuntimePolicyProfile::default(),
            running_task_policy: RunningTaskPolicy::RequireInspection,
            retry_lease_ttl_ms: 30_000,
        })
    }

    pub fn with_replayed_journal(kernel: Kernel, path: impl AsRef<Path>) -> RuntimeResult<Self> {
        let journal = RuntimeJournal::open(path)?;
        let replay = RuntimeJournal::replay(journal.path())?;
        Ok(Self {
            kernel,
            skills: SkillRegistry::default(),
            event_stream: replay.event_stream,
            task_store: replay.task_store,
            journal: Some(journal),
            sqlite_store: None,
            adoption_probes: RuntimeAdoptionProbeRegistry::default(),
            policy_profile: RuntimePolicyProfile::default(),
            running_task_policy: RunningTaskPolicy::RequireInspection,
            retry_lease_ttl_ms: 30_000,
        })
    }

    pub fn with_sqlite_store(kernel: Kernel, path: impl AsRef<Path>) -> RuntimeResult<Self> {
        Self::with_sqlite_store_instance(kernel, RuntimeSqliteStore::open(path)?)
    }

    pub fn with_sqlite_store_instance(
        kernel: Kernel,
        sqlite_store: RuntimeSqliteStore,
    ) -> RuntimeResult<Self> {
        let task_store = sqlite_store.load_task_store()?;
        let event_stream = sqlite_store.load_event_stream()?;
        Ok(Self {
            kernel,
            skills: SkillRegistry::default(),
            event_stream,
            task_store,
            journal: None,
            sqlite_store: Some(sqlite_store),
            adoption_probes: RuntimeAdoptionProbeRegistry::default(),
            policy_profile: RuntimePolicyProfile::default(),
            running_task_policy: RunningTaskPolicy::RequireInspection,
            retry_lease_ttl_ms: 30_000,
        })
    }

    pub fn with_running_task_policy(mut self, policy: RunningTaskPolicy) -> Self {
        if policy == RunningTaskPolicy::RetryReady && !self.policy_profile.allow_running_task_retry
        {
            self.running_task_policy = RunningTaskPolicy::RequireInspection;
        } else {
            self.running_task_policy = policy;
        }
        self
    }

    pub fn with_retry_lease_ttl_ms(mut self, ttl_ms: i64) -> Self {
        self.retry_lease_ttl_ms = ttl_ms.max(1);
        self
    }

    pub fn with_adoption_probe_for_capability(
        mut self,
        capability_id: impl Into<String>,
        probe: impl RuntimeAdoptionProbe + 'static,
    ) -> Self {
        self.register_adoption_probe_for_capability(capability_id, probe);
        self
    }

    pub fn with_adoption_probe_for_provider(
        mut self,
        provider_id: impl Into<String>,
        probe: impl RuntimeAdoptionProbe + 'static,
    ) -> Self {
        self.register_adoption_probe_for_provider(provider_id, probe);
        self
    }

    pub fn with_policy_profile(mut self, profile: RuntimePolicyProfile) -> Self {
        if !profile.allow_running_task_retry {
            self.running_task_policy = RunningTaskPolicy::RequireInspection;
        }
        self.policy_profile = profile;
        self
    }

    pub fn with_profile_registry(
        self,
        registry: &RuntimeProfileRegistry,
        profile_id: &str,
    ) -> RuntimeResult<Self> {
        Ok(self.with_policy_profile(registry.resolve(profile_id)?))
    }

    pub fn replay_journal(path: impl AsRef<Path>) -> RuntimeResult<RuntimeReplay> {
        RuntimeJournal::replay(path)
    }

    pub fn read_projection(path: impl AsRef<Path>) -> RuntimeResult<RuntimeProjectionSnapshot> {
        read_projection_snapshot(path)
    }

    pub fn read_task_index(path: impl AsRef<Path>) -> RuntimeResult<RuntimeTaskIndexSnapshot> {
        read_task_index_snapshot(path)
    }

    pub fn kernel(&self) -> &Kernel {
        &self.kernel
    }

    pub fn kernel_mut(&mut self) -> &mut Kernel {
        &mut self.kernel
    }

    pub fn events(&self) -> &[RuntimeEvent] {
        self.event_stream.all()
    }

    pub fn event_cursor(&self) -> usize {
        self.event_stream.cursor()
    }

    pub fn events_since(&self, cursor: usize) -> &[RuntimeEvent] {
        self.event_stream.since(cursor)
    }

    pub fn event_feed(
        &self,
        cursor: usize,
        graph_id: Option<&str>,
    ) -> RuntimeResult<RuntimeEventFeedSnapshot> {
        event_feed_snapshot_from(
            &self.task_store,
            self.events(),
            cursor,
            graph_id,
            self.running_task_policy,
        )
    }

    pub fn task_store(&self) -> &RuntimeTaskStore {
        &self.task_store
    }

    pub fn policy_profile(&self) -> &RuntimePolicyProfile {
        &self.policy_profile
    }

    pub fn journal_path(&self) -> Option<&Path> {
        self.journal.as_ref().map(RuntimeJournal::path)
    }

    pub fn has_sqlite_store(&self) -> bool {
        self.sqlite_store.is_some()
    }

    pub fn register_adoption_probe_for_capability(
        &mut self,
        capability_id: impl Into<String>,
        probe: impl RuntimeAdoptionProbe + 'static,
    ) {
        self.adoption_probes
            .register_capability(capability_id, probe);
    }

    pub fn register_adoption_probe_for_provider(
        &mut self,
        provider_id: impl Into<String>,
        probe: impl RuntimeAdoptionProbe + 'static,
    ) {
        self.adoption_probes.register_provider(provider_id, probe);
    }

    pub fn adoption_probe_registry(&self) -> &RuntimeAdoptionProbeRegistry {
        &self.adoption_probes
    }

    pub fn graph_snapshot(&self, graph_id: &str) -> RuntimeResult<RuntimeGraphSnapshot> {
        graph_snapshot_from(&self.task_store, self.events(), graph_id)
    }

    pub fn planner_record(&self, graph_id: &str) -> Option<&RuntimePlannerRecord> {
        self.task_store.planner_record(graph_id)
    }

    pub fn graph_list(&self) -> RuntimeResult<Vec<RuntimeGraphListItem>> {
        graph_list_from(&self.task_store, self.running_task_policy)
    }

    pub fn query_snapshot(&self, graph_id: &str) -> RuntimeResult<RuntimeQuerySnapshot> {
        query_snapshot_from(
            &self.task_store,
            self.events(),
            graph_id,
            self.running_task_policy,
            self.policy_profile.clone(),
        )
    }

    pub fn projection_snapshot(&self) -> RuntimeProjectionSnapshot {
        RuntimeProjectionSnapshot {
            schema_version: 1,
            task_store: self.task_store.clone(),
            event_stream: self.event_stream.clone(),
            policy_profile: self.policy_profile.clone(),
            running_task_policy: self.running_task_policy,
        }
    }

    pub fn write_projection(
        &self,
        path: impl AsRef<Path>,
    ) -> RuntimeResult<RuntimeProjectionSnapshot> {
        let snapshot = self.projection_snapshot();
        write_projection_snapshot(path, &snapshot)?;
        Ok(snapshot)
    }

    pub fn task_index_snapshot(&self) -> RuntimeResult<RuntimeTaskIndexSnapshot> {
        task_index_snapshot_from(
            &self.task_store,
            self.events(),
            self.running_task_policy,
            self.policy_profile.clone(),
        )
    }

    pub fn write_task_index(
        &self,
        path: impl AsRef<Path>,
    ) -> RuntimeResult<RuntimeTaskIndexSnapshot> {
        let snapshot = self.task_index_snapshot()?;
        write_task_index_snapshot(path, &snapshot)?;
        Ok(snapshot)
    }

    pub fn resume_plan(&self, graph_id: &str) -> RuntimeResult<RuntimeResumePlan> {
        resume_plan_from(&self.task_store, graph_id, self.running_task_policy, None)
    }

    pub fn resume_plan_with_probe(
        &self,
        graph_id: &str,
        adoption_probe: &dyn RuntimeAdoptionProbe,
    ) -> RuntimeResult<RuntimeResumePlan> {
        resume_plan_from(
            &self.task_store,
            graph_id,
            self.running_task_policy,
            Some(adoption_probe),
        )
    }

    pub fn record_adoption_probe_result(
        &mut self,
        graph_id: &str,
        result: RuntimeAdoptionProbeResult,
    ) -> RuntimeResult<RuntimeAdoptionProbeRecord> {
        self.task_store
            .graph(graph_id)
            .ok_or_else(|| RuntimeError::GraphNotFound(graph_id.into()))?;
        let attempt = self
            .task_store
            .latest_attempt_for_task(&result.task_id)
            .ok_or_else(|| RuntimeError::AttemptNotFound(result.attempt_id.clone()))?;
        if attempt.attempt_id != result.attempt_id {
            return Err(RuntimeError::AdoptionProbeMismatch {
                probe_id: result.attempt_id.clone(),
                reason: "probe attempt is not the latest attempt for task".into(),
            });
        }
        if attempt.graph_id != graph_id {
            return Err(RuntimeError::AdoptionProbeMismatch {
                probe_id: result.attempt_id.clone(),
                reason: "probe graph does not match attempt graph".into(),
            });
        }
        let record = RuntimeAdoptionProbeRecord {
            probe_id: format!("rap_{}", Uuid::new_v4()),
            graph_id: graph_id.into(),
            result,
            recorded_at: Utc::now(),
        };
        self.task_store.record_adoption_probe(record.clone())?;
        self.persist(RuntimeJournalRecord::AdoptionProbe {
            probe: record.clone(),
        })?;
        Ok(record)
    }

    pub fn probe_adoption_and_resume_plan(
        &mut self,
        graph_id: &str,
        adoption_probe: &dyn RuntimeAdoptionProbe,
    ) -> RuntimeResult<RuntimeResumePlan> {
        let tasks = self.task_store.tasks_for_graph(graph_id);
        for task in tasks {
            let Some(attempt) = self
                .task_store
                .latest_attempt_for_task(&task.task.task_id)
                .cloned()
            else {
                continue;
            };
            if let Some(result) = adoption_probe.probe(&task, &attempt)? {
                self.record_adoption_probe_result(graph_id, result)?;
            }
        }
        self.resume_plan(graph_id)
    }

    pub fn probe_registered_adoption_and_resume_plan(
        &mut self,
        graph_id: &str,
    ) -> RuntimeResult<RuntimeResumePlan> {
        let tasks = self.task_store.tasks_for_graph(graph_id);
        for task in tasks {
            let Some(attempt) = self
                .task_store
                .latest_attempt_for_task(&task.task.task_id)
                .cloned()
            else {
                continue;
            };
            let Some(probe) = self.adoption_probes.probe_for_task(&task.task) else {
                continue;
            };
            if let Some(result) = probe.probe(&task, &attempt)? {
                self.record_adoption_probe_result(graph_id, result)?;
            }
        }
        self.resume_plan(graph_id)
    }

    pub fn resume_plans(&self) -> RuntimeResult<Vec<RuntimeResumePlan>> {
        self.task_store
            .graphs()
            .iter()
            .map(|graph| self.resume_plan(&graph.graph_id))
            .collect()
    }

    pub fn register_skill(&mut self, skill: SkillManifest) -> RuntimeResult<()> {
        if !self.policy_profile.allow_skills {
            return Err(RuntimeError::SkillNotAllowed(skill.skill_id));
        }
        if !skill_allowed_by_profile(&skill, &self.policy_profile) {
            return Err(RuntimeError::SkillNotAllowed(skill.skill_id));
        }
        self.skills.register(skill)
    }

    pub fn load_manifest_registry(
        &mut self,
        registry: &RuntimeManifestRegistry,
    ) -> RuntimeResult<usize> {
        let skills = registry.skills_for_profile(&self.policy_profile)?;
        let count = skills.len();
        for skill in skills {
            self.register_skill(skill)?;
        }
        Ok(count)
    }

    pub fn skills(&self) -> &[SkillManifest] {
        self.skills.list()
    }

    pub fn planner_plan(&self, intent: &Intent) -> RuntimeResult<PlannerPlan> {
        let steps = self.plan_steps(intent)?;
        let source = if steps.iter().any(|step| step.skill_id.is_some()) {
            PlannerSource::SkillRegistry
        } else {
            PlannerSource::Deterministic
        };
        Ok(PlannerPlan {
            plan_id: format!("plan_{}", Uuid::new_v4()),
            intent_id: intent.intent_id.clone(),
            goal: intent.goal.clone(),
            source,
            constraints: planner_constraints_for_profile(&self.policy_profile),
            steps,
        })
    }

    pub fn plan(&self, intent: &Intent) -> RuntimeResult<TaskGraph> {
        self.execution_plan(intent).map(|plan| plan.graph)
    }

    pub fn compile_planner_plan(&self, plan: PlannerPlan) -> RuntimeResult<TaskGraph> {
        let graph = task_graph_from_planner_plan(plan)?;
        self.validate_profile(&graph)?;
        Ok(graph)
    }

    pub fn execution_plan(&self, intent: &Intent) -> RuntimeResult<ExecutionPlan> {
        let planner = self.planner_plan(intent)?;
        let graph = self.compile_planner_plan(planner.clone())?;
        let ready_order = plan_ready_order(&graph)?;
        Ok(ExecutionPlan {
            planner,
            graph,
            ready_order,
        })
    }

    pub fn run(&mut self, intent: Intent) -> RuntimeResult<RuntimeRunReport> {
        let execution_plan = self.execution_plan(&intent)?;
        let planner = runtime_planner_record(&execution_plan.planner, &execution_plan.graph)?;
        let mut graph = execution_plan.graph;
        if graph.tasks.is_empty() {
            return Err(RuntimeError::EmptyPlan);
        }
        self.task_store.save_planner_record(planner.clone());
        self.persist(RuntimeJournalRecord::Planner {
            planner: planner.clone(),
        })?;
        self.task_store.save_graph(&graph);
        self.persist(RuntimeJournalRecord::Graph {
            graph: graph.clone(),
        })?;

        let mut primary_run = None;
        let mut outcomes = Vec::new();
        for task_id in execution_plan.ready_order {
            let run = self.kernel.admit(intent.clone())?;
            if primary_run.is_none() {
                primary_run = Some(run.clone());
            }
            self.emit(
                Some(graph.graph_id.clone()),
                Some(run.run_id.clone()),
                Some(task_id.clone()),
                RuntimeStage::Admitted,
                "task run admitted",
                0.15,
            )?;
            let outcome = self.run_task_by_id(&run, &mut graph, &task_id)?;
            outcomes.push(outcome);
        }
        let primary_run = primary_run.ok_or(RuntimeError::EmptyPlan)?;

        self.emit(
            Some(graph.graph_id.clone()),
            Some(primary_run.run_id.clone()),
            None,
            RuntimeStage::Completed,
            "runtime graph completed",
            1.0,
        )?;

        Ok(RuntimeRunReport {
            primary_run,
            planner,
            graph,
            events: self.events().to_vec(),
            outcomes,
        })
    }

    pub fn resume_ready_tasks(
        &mut self,
        intent: Intent,
        graph_id: &str,
    ) -> RuntimeResult<RuntimeResumeReport> {
        let before = self.resume_plan(graph_id)?;
        let mut graph = self
            .task_store
            .graph(graph_id)
            .cloned()
            .ok_or_else(|| RuntimeError::GraphNotFound(graph_id.into()))?;
        let mut outcomes = Vec::new();
        let mut current = before.clone();

        while !current.ready_task_ids.is_empty() {
            for task_id in current.ready_task_ids.clone() {
                let run = self.kernel.admit(intent.clone())?;
                self.emit(
                    Some(graph.graph_id.clone()),
                    Some(run.run_id.clone()),
                    Some(task_id.clone()),
                    RuntimeStage::Admitted,
                    "resume task run admitted",
                    0.15,
                )?;
                let outcome = self.run_task_by_id(&run, &mut graph, &task_id)?;
                outcomes.push(outcome);
            }
            current = self.resume_plan(graph_id)?;
        }

        if !before.ready_task_ids.is_empty() && current.is_complete {
            self.emit(
                Some(graph.graph_id.clone()),
                None,
                None,
                RuntimeStage::Completed,
                "runtime graph resume completed",
                1.0,
            )?;
        }

        let after = self.resume_plan(graph_id)?;
        let graph = self
            .task_store
            .graph(graph_id)
            .cloned()
            .ok_or_else(|| RuntimeError::GraphNotFound(graph_id.into()))?;
        Ok(RuntimeResumeReport {
            graph,
            before,
            after,
            events: self.events().to_vec(),
            outcomes,
        })
    }

    fn plan_steps(&self, intent: &Intent) -> RuntimeResult<Vec<PlannerStep>> {
        let skills = self.skills.matching_skills(intent);
        if skills.is_empty() {
            return Ok(vec![deterministic_step_from_intent(intent)?]);
        }

        let mut steps: Vec<PlannerStep> = Vec::new();
        for (index, skill) in skills.iter().enumerate() {
            let step_id = format!("step_{}", Uuid::new_v4());
            let capability_id = skill
                .required_capabilities
                .first()
                .cloned()
                .ok_or_else(|| RuntimeError::SkillMissingCapability(skill.skill_id.clone()))?;
            if !intent.requested_capabilities.contains(&capability_id) {
                return Err(RuntimeError::SkillCapabilityMismatch {
                    skill_id: skill.skill_id.clone(),
                    capability_id,
                });
            }
            let target = skill_target(intent, skill);
            let input = skill_input(intent, skill, &target);
            steps.push(PlannerStep {
                step_id,
                skill_id: Some(skill.skill_id.clone()),
                capability_id,
                target,
                input,
                risk_level: std::cmp::max(intent.risk_level, skill.risk_level),
                depends_on: if index == 0 {
                    vec![]
                } else {
                    vec![steps[index - 1].step_id.clone()]
                },
                rationale: format!("matched skill {}", skill.skill_id),
            });
        }

        order_steps_by_dependency(&mut steps);
        Ok(steps)
    }

    fn validate_profile(&self, graph: &TaskGraph) -> RuntimeResult<()> {
        if graph.tasks.len() > self.policy_profile.max_tasks_per_graph {
            return Err(RuntimeError::ProfileRejected(format!(
                "task count {} exceeds profile limit {}",
                graph.tasks.len(),
                self.policy_profile.max_tasks_per_graph
            )));
        }
        match graph.path {
            RuntimePath::FastPath if !self.policy_profile.allow_fast_path => {
                return Err(RuntimeError::ProfileRejected(
                    "fast path is disabled by runtime profile".into(),
                ));
            }
            RuntimePath::TaskPath if !self.policy_profile.allow_task_path => {
                return Err(RuntimeError::ProfileRejected(
                    "task path is disabled by runtime profile".into(),
                ));
            }
            RuntimePath::TrustedExecutionPath
                if !self.policy_profile.allow_trusted_execution_path =>
            {
                return Err(RuntimeError::ProfileRejected(
                    "trusted execution path is disabled by runtime profile".into(),
                ));
            }
            _ => {}
        }
        for task in &graph.tasks {
            if !self.policy_profile.allowed_capabilities.is_empty()
                && !self
                    .policy_profile
                    .allowed_capabilities
                    .contains(&task.capability_id)
            {
                return Err(RuntimeError::ProfileRejected(format!(
                    "capability {} is disabled by runtime profile",
                    task.capability_id
                )));
            }
            if task.skill_id.is_some() && !self.policy_profile.allow_skills {
                return Err(RuntimeError::ProfileRejected(
                    "skills are disabled by runtime profile".into(),
                ));
            }
        }
        Ok(())
    }

    fn run_task_by_id(
        &mut self,
        run: &RunContract,
        graph: &mut TaskGraph,
        task_id: &str,
    ) -> RuntimeResult<RuntimeTaskOutcome> {
        let task_index = graph
            .tasks
            .iter()
            .position(|task| task.task_id == task_id)
            .ok_or_else(|| RuntimeError::TaskNotFound(task_id.into()))?;
        if !task_dependencies_completed(graph, task_id) {
            return Err(RuntimeError::TaskNotReady(task_id.into()));
        }

        graph.tasks[task_index].state = TaskState::Running;
        self.task_store
            .update_task_state(&graph.graph_id, task_id, TaskState::Running, None)?;
        let task = graph.tasks[task_index].clone();
        let capability = self
            .kernel
            .capability(&task.capability_id)
            .cloned()
            .ok_or_else(|| RuntimeError::CapabilityNotFound(task.capability_id.clone()))?;
        let started_attempt = self.record_started_attempt(graph, &task, run, &capability)?;
        let retry_lease = self.acquire_retry_lease(
            graph,
            &task,
            run,
            &started_attempt.idempotency_key,
            "runtime-session",
        )?;

        self.emit(
            Some(graph.graph_id.clone()),
            Some(run.run_id.clone()),
            Some(task.task_id.clone()),
            RuntimeStage::Planned,
            "task selected",
            0.25,
        )?;

        let delta = WorldDelta {
            delta_id: format!("delta_{}", Uuid::new_v4()),
            run_id: run.run_id.clone(),
            proposed_by: "moxi-runtime".into(),
            capability_id: task.capability_id.clone(),
            state: DeltaState::Draft,
            target: task.target.clone(),
            change_summary: format!("runtime task {}", task.task_id),
            preconditions: vec![],
            patch_ref: None,
            evidence_refs: vec![],
            risk_level: task.risk_level,
            rollback_plan_ref: None,
        };
        let policy = self.kernel.propose_delta(&run.run_id, delta.clone())?;
        self.emit(
            Some(graph.graph_id.clone()),
            Some(run.run_id.clone()),
            Some(task.task_id.clone()),
            RuntimeStage::PolicyChecked,
            "policy checked",
            0.4,
        )?;

        if policy.decision == moxi_contracts::Decision::RequireApproval {
            graph.tasks[task_index].state = TaskState::AwaitingApproval;
            let event = self.emit(
                Some(graph.graph_id.clone()),
                Some(run.run_id.clone()),
                Some(task.task_id.clone()),
                RuntimeStage::AwaitingApproval,
                "approval required",
                0.45,
            )?;
            self.task_store.update_task_state(
                &graph.graph_id,
                &task.task_id,
                TaskState::AwaitingApproval,
                Some(&event),
            )?;
            return Err(RuntimeError::ApprovalRequired(policy.decision_id));
        }

        let ticket = self.kernel.issue_ticket(&policy, &capability)?;
        self.emit(
            Some(graph.graph_id.clone()),
            Some(run.run_id.clone()),
            Some(task.task_id.clone()),
            RuntimeStage::TicketIssued,
            "execution ticket issued",
            0.55,
        )?;

        let input = SandboxInput {
            capability_id: task.capability_id.clone(),
            payload: task.input.clone(),
            runtime_metadata: Some(RuntimeInputMetadata {
                idempotency_key: started_attempt.idempotency_key.clone(),
                source: "moxi-runtime".into(),
            }),
        };
        self.emit(
            Some(graph.graph_id.clone()),
            Some(run.run_id.clone()),
            Some(task.task_id.clone()),
            RuntimeStage::Executing,
            "executing through trusted kernel",
            0.7,
        )?;
        let result = self.kernel.execute(&ticket, input)?;

        self.emit(
            Some(graph.graph_id.clone()),
            Some(run.run_id.clone()),
            Some(task.task_id.clone()),
            RuntimeStage::Verifying,
            "collecting proof",
            0.82,
        )?;
        let proof = self.kernel.verify(&result)?;

        self.emit(
            Some(graph.graph_id.clone()),
            Some(run.run_id.clone()),
            Some(task.task_id.clone()),
            RuntimeStage::Committing,
            "committing ledger event",
            0.93,
        )?;
        let ledger_event = self.kernel.commit(ledger_event_for_success(
            &capability,
            &result,
            &proof.proof_id,
            &task.target.resource_ref,
            &delta.delta_id,
        ))?;

        graph.tasks[task_index].state = TaskState::Completed;
        let event = self.emit(
            Some(graph.graph_id.clone()),
            Some(run.run_id.clone()),
            Some(task.task_id.clone()),
            RuntimeStage::Completed,
            "task completed",
            1.0,
        )?;
        self.task_store.update_task_state(
            &graph.graph_id,
            &task.task_id,
            TaskState::Completed,
            Some(&event),
        )?;
        let completed_attempt =
            self.record_completed_attempt(graph, &task, run, &capability, &ticket, &ledger_event)?;
        self.release_retry_lease(&retry_lease.lease_id)?;

        Ok(RuntimeTaskOutcome {
            task_id: task.task_id,
            idempotency_key: completed_attempt.idempotency_key,
            ticket,
            ledger_event,
            output: result.output,
        })
    }

    fn emit(
        &mut self,
        graph_id: Option<String>,
        run_id: Option<String>,
        task_id: Option<String>,
        stage: RuntimeStage,
        message: impl Into<String>,
        progress: f32,
    ) -> RuntimeResult<RuntimeEvent> {
        let event_id = format!("re_{}", Uuid::new_v4());
        let event = RuntimeEvent {
            event_id: event_id.clone(),
            graph_id,
            run_id,
            task_id,
            stage,
            message: message.into(),
            progress: progress.clamp(0.0, 1.0),
            timestamp: Utc::now(),
        };
        if let (Some(graph_id), Some(task_id)) = (&event.graph_id, &event.task_id) {
            let state = task_state_for_stage(event.stage);
            self.task_store
                .update_task_state(graph_id, task_id, state, Some(&event))?;
        }
        self.event_stream.push(event.clone());
        self.persist(RuntimeJournalRecord::Event {
            event: event.clone(),
        })?;
        Ok(event)
    }

    fn record_started_attempt(
        &mut self,
        graph: &TaskGraph,
        task: &TaskNode,
        run: &RunContract,
        capability: &CapabilityContract,
    ) -> RuntimeResult<RuntimeTaskAttempt> {
        self.persist_task_attempt(RuntimeTaskAttempt {
            attempt_id: format!("rta_{}", Uuid::new_v4()),
            graph_id: graph.graph_id.clone(),
            task_id: task.task_id.clone(),
            run_id: run.run_id.clone(),
            capability_id: task.capability_id.clone(),
            idempotency_key: runtime_idempotency_key(graph, task, capability),
            retry_safe: runtime_retry_safe(capability, task),
            stage: RuntimeAttemptStage::Started,
            ticket_id: None,
            ledger_event_id: None,
            error: None,
            created_at: Utc::now(),
        })
    }

    fn record_completed_attempt(
        &mut self,
        graph: &TaskGraph,
        task: &TaskNode,
        run: &RunContract,
        capability: &CapabilityContract,
        ticket: &ExecutionTicket,
        ledger_event: &LedgerEvent,
    ) -> RuntimeResult<RuntimeTaskAttempt> {
        self.persist_task_attempt(RuntimeTaskAttempt {
            attempt_id: format!("rta_{}", Uuid::new_v4()),
            graph_id: graph.graph_id.clone(),
            task_id: task.task_id.clone(),
            run_id: run.run_id.clone(),
            capability_id: task.capability_id.clone(),
            idempotency_key: runtime_idempotency_key(graph, task, capability),
            retry_safe: runtime_retry_safe(capability, task),
            stage: RuntimeAttemptStage::Completed,
            ticket_id: Some(ticket.ticket_id.clone()),
            ledger_event_id: Some(ledger_event.ledger_event_id.clone()),
            error: None,
            created_at: Utc::now(),
        })
    }

    fn acquire_retry_lease(
        &mut self,
        graph: &TaskGraph,
        task: &TaskNode,
        run: &RunContract,
        idempotency_key: &str,
        holder_ref: impl Into<String>,
    ) -> RuntimeResult<RuntimeRetryLease> {
        let acquired_at = Utc::now();
        let lease = RuntimeRetryLease {
            lease_id: format!("rtl_{}", Uuid::new_v4()),
            graph_id: graph.graph_id.clone(),
            task_id: task.task_id.clone(),
            run_id: run.run_id.clone(),
            idempotency_key: idempotency_key.into(),
            holder_ref: holder_ref.into(),
            state: RuntimeRetryLeaseState::Active,
            acquired_at,
            expires_at: acquired_at + chrono::Duration::milliseconds(self.retry_lease_ttl_ms),
            released_at: None,
        };
        if let Some(store) = &mut self.sqlite_store {
            store.acquire_retry_lease(&lease)?;
        }
        self.task_store.acquire_retry_lease(lease.clone())?;
        self.persist_journal_only(RuntimeJournalRecord::RetryLease {
            lease: lease.clone(),
        })?;
        Ok(lease)
    }

    fn release_retry_lease(&mut self, lease_id: &str) -> RuntimeResult<()> {
        let released_at = Utc::now();
        self.task_store.release_retry_lease(lease_id, released_at)?;
        let Some(lease) = self.task_store.retry_leases.get(lease_id).cloned() else {
            return Ok(());
        };
        self.persist(RuntimeJournalRecord::RetryLease { lease })
    }

    fn persist_task_attempt(
        &mut self,
        attempt: RuntimeTaskAttempt,
    ) -> RuntimeResult<RuntimeTaskAttempt> {
        self.task_store.record_attempt(attempt.clone())?;
        self.persist(RuntimeJournalRecord::Attempt {
            attempt: attempt.clone(),
        })?;
        Ok(attempt)
    }

    fn persist(&mut self, record: RuntimeJournalRecord) -> RuntimeResult<()> {
        if let Some(journal) = &mut self.journal {
            journal.append(&record)?;
        }
        if let Some(store) = &self.sqlite_store {
            match &record {
                RuntimeJournalRecord::Planner { planner } => {
                    store.save_planner_record(planner)?;
                }
                RuntimeJournalRecord::Graph { graph } => {
                    store.save_graph(graph)?;
                }
                RuntimeJournalRecord::Event { event } => {
                    store.record_event(event)?;
                }
                RuntimeJournalRecord::Attempt { attempt } => {
                    store.record_attempt(attempt)?;
                }
                RuntimeJournalRecord::RetryLease { lease } => {
                    store.save_retry_lease(lease)?;
                }
                RuntimeJournalRecord::AdoptionProbe { probe } => {
                    store.record_adoption_probe(probe)?;
                }
            }
        }
        Ok(())
    }

    fn persist_journal_only(&mut self, record: RuntimeJournalRecord) -> RuntimeResult<()> {
        if let Some(journal) = &mut self.journal {
            journal.append(&record)?;
        }
        Ok(())
    }
}

fn deterministic_step_from_intent(intent: &Intent) -> RuntimeResult<PlannerStep> {
    let capability_id = intent
        .requested_capabilities
        .first()
        .cloned()
        .unwrap_or_else(|| "file.read".into());
    if capability_id != "file.read" {
        return Err(RuntimeError::UnsupportedTarget(capability_id));
    }
    let path = extract_file_path(&intent.goal).unwrap_or_else(|| "README.md".into());
    Ok(PlannerStep {
        step_id: "step_0".into(),
        skill_id: None,
        capability_id,
        target: DeltaTarget {
            resource_type: ResourceType::File,
            resource_ref: path.clone(),
        },
        input: serde_json::json!({ "path": path }),
        risk_level: intent.risk_level,
        depends_on: vec![],
        rationale: "deterministic fallback from intent".into(),
    })
}

fn planner_constraints_for_profile(profile: &RuntimePolicyProfile) -> Vec<PlannerConstraint> {
    let mut constraints = vec![PlannerConstraint {
        constraint_id: "p0_trusted_execution_chain".into(),
        description: "external effects must execute through P0 admission, policy, ticket, sandbox, proof, and ledger".into(),
    }];
    if !profile.allowed_capabilities.is_empty() {
        constraints.push(PlannerConstraint {
            constraint_id: "allowed_capabilities".into(),
            description: format!(
                "planner may use only these capabilities: {}",
                profile.allowed_capabilities.join(", ")
            ),
        });
    }
    constraints.push(PlannerConstraint {
        constraint_id: "max_tasks_per_graph".into(),
        description: format!(
            "planner may create at most {} tasks",
            profile.max_tasks_per_graph
        ),
    });
    constraints
}

fn task_graph_from_planner_plan(plan: PlannerPlan) -> RuntimeResult<TaskGraph> {
    validate_planner_plan(&plan)?;
    let mut tasks = plan
        .steps
        .iter()
        .map(|step| TaskNode {
            task_id: task_id_from_step_id(&step.step_id),
            skill_id: step.skill_id.clone(),
            capability_id: step.capability_id.clone(),
            target: step.target.clone(),
            input: step.input.clone(),
            risk_level: step.risk_level,
            depends_on: step
                .depends_on
                .iter()
                .map(|dependency| task_id_from_step_id(dependency))
                .collect(),
            state: TaskState::Ready,
        })
        .collect::<Vec<_>>();
    order_tasks_by_dependency(&mut tasks);
    let path = if tasks.iter().any(|task| task.risk_level >= RiskLevel::High) {
        RuntimePath::TrustedExecutionPath
    } else if tasks.len() > 1 {
        RuntimePath::TaskPath
    } else {
        RuntimePath::FastPath
    };
    Ok(TaskGraph {
        graph_id: format!("tg_{}", plan.plan_id),
        goal: plan.goal,
        path,
        tasks,
    })
}

fn validate_planner_plan(plan: &PlannerPlan) -> RuntimeResult<()> {
    if plan.steps.is_empty() {
        return Err(RuntimeError::EmptyPlan);
    }
    let mut step_ids = BTreeSet::new();
    for step in &plan.steps {
        if step.capability_id.is_empty() {
            return Err(RuntimeError::PlannerStepMissingCapability(
                step.step_id.clone(),
            ));
        }
        step_ids.insert(step.step_id.clone());
    }
    for step in &plan.steps {
        for dependency in &step.depends_on {
            if !step_ids.contains(dependency) {
                return Err(RuntimeError::PlannerDependencyNotFound {
                    step_id: step.step_id.clone(),
                    dependency_id: dependency.clone(),
                });
            }
        }
    }
    Ok(())
}

fn task_id_from_step_id(step_id: &str) -> String {
    if let Some(suffix) = step_id.strip_prefix("step_") {
        format!("task_{suffix}")
    } else {
        format!("task_{step_id}")
    }
}

fn runtime_planner_record(
    plan: &PlannerPlan,
    graph: &TaskGraph,
) -> RuntimeResult<RuntimePlannerRecord> {
    Ok(RuntimePlannerRecord {
        plan_id: plan.plan_id.clone(),
        graph_id: graph.graph_id.clone(),
        intent_id: plan.intent_id.clone(),
        source: plan.source,
        step_count: plan.steps.len(),
        plan_hash: planner_plan_hash(plan)?,
        plan: plan.clone(),
        created_at: Utc::now(),
    })
}

fn planner_plan_hash(plan: &PlannerPlan) -> RuntimeResult<String> {
    let bytes = serde_json::to_vec(plan)?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn graph_snapshot_from(
    task_store: &RuntimeTaskStore,
    events: &[RuntimeEvent],
    graph_id: &str,
) -> RuntimeResult<RuntimeGraphSnapshot> {
    let graph = task_store
        .graph(graph_id)
        .cloned()
        .ok_or_else(|| RuntimeError::GraphNotFound(graph_id.into()))?;
    let planner = task_store.planner_record(graph_id).cloned();
    let tasks = task_store.tasks_for_graph(graph_id);
    let attempts = task_store.attempts_for_graph(graph_id);
    let adoption_probes = task_store.adoption_probes_for_graph(graph_id);
    let events = events
        .iter()
        .filter(|event| event.graph_id.as_deref() == Some(graph_id))
        .cloned()
        .collect();
    Ok(RuntimeGraphSnapshot {
        graph,
        planner,
        tasks,
        attempts,
        adoption_probes,
        events,
    })
}

fn graph_list_from(
    task_store: &RuntimeTaskStore,
    running_task_policy: RunningTaskPolicy,
) -> RuntimeResult<Vec<RuntimeGraphListItem>> {
    task_store
        .graph_ids()
        .iter()
        .map(|graph_id| graph_list_item_from(task_store, graph_id, running_task_policy))
        .collect()
}

fn graph_list_item_from(
    task_store: &RuntimeTaskStore,
    graph_id: &str,
    running_task_policy: RunningTaskPolicy,
) -> RuntimeResult<RuntimeGraphListItem> {
    let graph = task_store
        .graph(graph_id)
        .ok_or_else(|| RuntimeError::GraphNotFound(graph_id.into()))?;
    let plan = resume_plan_from(task_store, graph_id, running_task_policy, None)?;
    Ok(RuntimeGraphListItem {
        graph_id: graph.graph_id.clone(),
        goal: graph.goal.clone(),
        path: graph.path,
        task_count: graph.tasks.len(),
        completed_count: plan.completed_task_ids.len(),
        running_count: plan.running_task_ids.len(),
        blocked_count: plan.blocked_task_ids.len(),
        awaiting_approval_count: plan.awaiting_approval_task_ids.len(),
        failed_count: plan.failed_task_ids.len(),
        is_complete: plan.is_complete,
    })
}

fn query_snapshot_from(
    task_store: &RuntimeTaskStore,
    events: &[RuntimeEvent],
    graph_id: &str,
    running_task_policy: RunningTaskPolicy,
    policy_profile: RuntimePolicyProfile,
) -> RuntimeResult<RuntimeQuerySnapshot> {
    let graph = graph_list_item_from(task_store, graph_id, running_task_policy)?;
    let planner = task_store.planner_record(graph_id).cloned();
    let resume_plan = resume_plan_from(task_store, graph_id, running_task_policy, None)?;
    let tasks = task_store
        .tasks_for_graph(graph_id)
        .into_iter()
        .map(|record| {
            let task_id = record.task.task_id;
            let blocker = resume_plan.blockers.get(&task_id).cloned();
            RuntimeTaskView {
                task_id,
                skill_id: record.task.skill_id,
                capability_id: record.task.capability_id,
                target: record.task.target,
                state: record.task.state,
                last_stage: record.last_stage,
                progress: record.progress,
                message: record.message,
                idempotency_key: record.idempotency_key,
                retry_safe: record.retry_safe,
                blocker,
                updated_at: record.updated_at,
            }
        })
        .collect();
    let attempts = task_store.attempts_for_graph(graph_id);
    let adoption_probes = task_store.adoption_probes_for_graph(graph_id);
    let event_cursor = events.len();
    let events = events
        .iter()
        .filter(|event| event.graph_id.as_deref() == Some(graph_id))
        .cloned()
        .collect::<Vec<_>>();
    Ok(RuntimeQuerySnapshot {
        graph,
        planner,
        tasks,
        attempts,
        adoption_probes,
        events,
        resume_plan,
        event_cursor,
        policy_profile,
    })
}

fn event_feed_snapshot_from(
    task_store: &RuntimeTaskStore,
    events: &[RuntimeEvent],
    cursor: usize,
    graph_id: Option<&str>,
    running_task_policy: RunningTaskPolicy,
) -> RuntimeResult<RuntimeEventFeedSnapshot> {
    if let Some(graph_id) = graph_id {
        task_store
            .graph(graph_id)
            .ok_or_else(|| RuntimeError::GraphNotFound(graph_id.into()))?;
    }

    let from_cursor = cursor.min(events.len());
    let filtered_events = events[from_cursor..]
        .iter()
        .filter(|event| graph_id.is_none_or(|id| event.graph_id.as_deref() == Some(id)))
        .cloned()
        .collect::<Vec<_>>();

    let latest_event = events
        .iter()
        .filter(|event| graph_id.is_none_or(|id| event.graph_id.as_deref() == Some(id)))
        .max_by_key(|event| event.timestamp);
    let latest_progress = latest_event.map(|event| event.progress).unwrap_or(0.0);
    let current_task_id = latest_event
        .and_then(|event| event.task_id.clone())
        .or_else(|| {
            graph_id.and_then(|id| {
                task_store
                    .tasks_for_graph(id)
                    .into_iter()
                    .find(|record| {
                        matches!(
                            record.task.state,
                            TaskState::Running | TaskState::AwaitingApproval | TaskState::Ready
                        )
                    })
                    .map(|record| record.task.task_id)
            })
        });

    let (blockers, is_complete) = if let Some(graph_id) = graph_id {
        let plan = resume_plan_from(task_store, graph_id, running_task_policy, None)?;
        (plan.blockers, plan.is_complete)
    } else {
        let mut blockers = BTreeMap::new();
        let mut all_complete = true;
        for graph in task_store.graphs() {
            let plan = resume_plan_from(task_store, &graph.graph_id, running_task_policy, None)?;
            all_complete &= plan.is_complete;
            blockers.extend(
                plan.blockers
                    .into_iter()
                    .map(|(task_id, blocker)| (format!("{}:{task_id}", graph.graph_id), blocker)),
            );
        }
        (blockers, !task_store.graph_ids().is_empty() && all_complete)
    };

    Ok(RuntimeEventFeedSnapshot {
        schema_version: 1,
        graph_id: graph_id.map(str::to_string),
        from_cursor,
        next_cursor: events.len(),
        event_count: filtered_events.len(),
        events: filtered_events,
        latest_stage: latest_event.map(|event| event.stage),
        latest_message: latest_event.map(|event| event.message.clone()),
        latest_progress,
        current_task_id,
        blockers,
        is_complete,
        generated_at: Utc::now(),
    })
}

fn task_index_snapshot_from(
    task_store: &RuntimeTaskStore,
    events: &[RuntimeEvent],
    running_task_policy: RunningTaskPolicy,
    policy_profile: RuntimePolicyProfile,
) -> RuntimeResult<RuntimeTaskIndexSnapshot> {
    let graphs = graph_list_from(task_store, running_task_policy)?;
    let mut tasks = Vec::new();
    for graph in &graphs {
        let query = query_snapshot_from(
            task_store,
            events,
            &graph.graph_id,
            running_task_policy,
            policy_profile.clone(),
        )?;
        tasks.extend(query.tasks.into_iter().map(|task| RuntimeTaskIndexEntry {
            graph_id: graph.graph_id.clone(),
            task,
        }));
    }

    Ok(RuntimeTaskIndexSnapshot {
        schema_version: 1,
        generated_at: Utc::now(),
        graphs,
        tasks,
        event_cursor: events.len(),
        policy_profile,
        running_task_policy,
    })
}

fn write_projection_snapshot(
    path: impl AsRef<Path>,
    snapshot: &RuntimeProjectionSnapshot,
) -> RuntimeResult<()> {
    write_json_file(path, snapshot)
}

fn read_projection_snapshot(path: impl AsRef<Path>) -> RuntimeResult<RuntimeProjectionSnapshot> {
    read_json_file(path)
}

fn write_task_index_snapshot(
    path: impl AsRef<Path>,
    snapshot: &RuntimeTaskIndexSnapshot,
) -> RuntimeResult<()> {
    write_json_file(path, snapshot)
}

fn read_task_index_snapshot(path: impl AsRef<Path>) -> RuntimeResult<RuntimeTaskIndexSnapshot> {
    read_json_file(path)
}

fn write_json_file<T: Serialize>(path: impl AsRef<Path>, value: &T) -> RuntimeResult<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = File::create(path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.flush()?;
    Ok(())
}

fn read_json_file<T: for<'de> Deserialize<'de>>(path: impl AsRef<Path>) -> RuntimeResult<T> {
    let file = File::open(path)?;
    Ok(serde_json::from_reader(file)?)
}

fn runtime_path_key(path: RuntimePath) -> &'static str {
    match path {
        RuntimePath::FastPath => "fast_path",
        RuntimePath::TaskPath => "task_path",
        RuntimePath::TrustedExecutionPath => "trusted_execution_path",
    }
}

fn planner_source_key(source: PlannerSource) -> &'static str {
    match source {
        PlannerSource::Deterministic => "deterministic",
        PlannerSource::SkillRegistry => "skill_registry",
        PlannerSource::ModelProposed => "model_proposed",
        PlannerSource::HumanAuthored => "human_authored",
    }
}

fn runtime_stage_key(stage: RuntimeStage) -> &'static str {
    match stage {
        RuntimeStage::Planned => "planned",
        RuntimeStage::Admitted => "admitted",
        RuntimeStage::PolicyChecked => "policy_checked",
        RuntimeStage::AwaitingApproval => "awaiting_approval",
        RuntimeStage::TicketIssued => "ticket_issued",
        RuntimeStage::Executing => "executing",
        RuntimeStage::Verifying => "verifying",
        RuntimeStage::Committing => "committing",
        RuntimeStage::Completed => "completed",
        RuntimeStage::Failed => "failed",
    }
}

fn task_state_key(state: TaskState) -> &'static str {
    match state {
        TaskState::Planned => "planned",
        TaskState::Ready => "ready",
        TaskState::AwaitingApproval => "awaiting_approval",
        TaskState::Running => "running",
        TaskState::Completed => "completed",
        TaskState::Failed => "failed",
    }
}

fn runtime_attempt_stage_key(stage: RuntimeAttemptStage) -> &'static str {
    match stage {
        RuntimeAttemptStage::Started => "started",
        RuntimeAttemptStage::Completed => "completed",
        RuntimeAttemptStage::Failed => "failed",
    }
}

fn adoption_probe_status_key(status: RuntimeAdoptionProbeStatus) -> &'static str {
    match status {
        RuntimeAdoptionProbeStatus::NotFound => "not_found",
        RuntimeAdoptionProbeStatus::Pending => "pending",
        RuntimeAdoptionProbeStatus::Committed => "committed",
        RuntimeAdoptionProbeStatus::Failed => "failed",
        RuntimeAdoptionProbeStatus::Unknown => "unknown",
    }
}

fn provider_id_from_capability(capability_id: &str) -> Option<String> {
    capability_id
        .split_once('.')
        .map(|(provider_id, _)| provider_id.to_string())
        .filter(|provider_id| !provider_id.is_empty())
}

fn runtime_retry_lease_state_key(state: RuntimeRetryLeaseState) -> &'static str {
    match state {
        RuntimeRetryLeaseState::Active => "active",
        RuntimeRetryLeaseState::Released => "released",
        RuntimeRetryLeaseState::Expired => "expired",
    }
}

fn merge_runtime_profiles(
    parent: RuntimePolicyProfile,
    child: RuntimePolicyProfile,
) -> RuntimePolicyProfile {
    RuntimePolicyProfile {
        profile_id: child.profile_id,
        allowed_capabilities: merge_allowed_capabilities(
            &parent.allowed_capabilities,
            &child.allowed_capabilities,
        ),
        allow_fast_path: parent.allow_fast_path && child.allow_fast_path,
        allow_task_path: parent.allow_task_path && child.allow_task_path,
        allow_trusted_execution_path: parent.allow_trusted_execution_path
            && child.allow_trusted_execution_path,
        allow_skills: parent.allow_skills && child.allow_skills,
        allow_running_task_retry: parent.allow_running_task_retry && child.allow_running_task_retry,
        max_tasks_per_graph: parent.max_tasks_per_graph.min(child.max_tasks_per_graph),
    }
}

fn merge_allowed_capabilities(parent: &[String], child: &[String]) -> Vec<String> {
    if parent.is_empty() {
        return child.to_vec();
    }
    if child.is_empty() {
        return parent.to_vec();
    }
    child
        .iter()
        .filter(|capability| parent.contains(capability))
        .cloned()
        .collect()
}

fn resume_plan_from(
    task_store: &RuntimeTaskStore,
    graph_id: &str,
    running_task_policy: RunningTaskPolicy,
    adoption_probe: Option<&dyn RuntimeAdoptionProbe>,
) -> RuntimeResult<RuntimeResumePlan> {
    let graph = task_store
        .graph(graph_id)
        .ok_or_else(|| RuntimeError::GraphNotFound(graph_id.into()))?;
    let tasks = task_store.tasks_for_graph(graph_id);
    let mut completed_task_ids = Vec::new();
    let mut ready_task_ids = Vec::new();
    let mut blocked_task_ids = Vec::new();
    let mut running_task_ids = Vec::new();
    let mut awaiting_approval_task_ids = Vec::new();
    let mut failed_task_ids = Vec::new();
    let mut blockers = BTreeMap::new();
    let mut adoption_recommendations = BTreeMap::new();

    for task in &tasks {
        let recommendation = adoption_recommendation_for_task(task_store, task, adoption_probe);
        adoption_recommendations.insert(task.task.task_id.clone(), recommendation.clone());
        match task.task.state {
            TaskState::Completed => {
                completed_task_ids.push(task.task.task_id.clone());
                blockers.insert(task.task.task_id.clone(), ResumeBlocker::AlreadyFinished);
            }
            TaskState::AwaitingApproval => {
                awaiting_approval_task_ids.push(task.task.task_id.clone());
                blockers.insert(task.task.task_id.clone(), ResumeBlocker::AwaitingApproval);
            }
            TaskState::Failed => match running_task_policy {
                RunningTaskPolicy::RetryReady
                    if recommendation.action == RuntimeAdoptionAction::RetryReady
                        && dependencies_completed(&tasks, &task.task.depends_on) =>
                {
                    ready_task_ids.push(task.task.task_id.clone());
                }
                _ => {
                    failed_task_ids.push(task.task.task_id.clone());
                    blockers.insert(task.task.task_id.clone(), ResumeBlocker::Failed);
                }
            },
            TaskState::Running => match running_task_policy {
                RunningTaskPolicy::RequireInspection => {
                    running_task_ids.push(task.task.task_id.clone());
                    blockers.insert(task.task.task_id.clone(), ResumeBlocker::RunningCheckpoint);
                }
                RunningTaskPolicy::RetryReady => {
                    if task_store
                        .active_retry_lease_for_task(&task.task.task_id)
                        .is_some()
                    {
                        running_task_ids.push(task.task.task_id.clone());
                        blockers
                            .insert(task.task.task_id.clone(), ResumeBlocker::RunningCheckpoint);
                        continue;
                    }
                    let retry_safe = task_store
                        .latest_attempt_for_task(&task.task.task_id)
                        .map(|attempt| attempt.retry_safe)
                        .unwrap_or(false);
                    if !retry_safe {
                        running_task_ids.push(task.task.task_id.clone());
                        blockers.insert(
                            task.task.task_id.clone(),
                            ResumeBlocker::NonIdempotentRunningCheckpoint,
                        );
                    } else if dependencies_completed(&tasks, &task.task.depends_on) {
                        ready_task_ids.push(task.task.task_id.clone());
                    } else {
                        blocked_task_ids.push(task.task.task_id.clone());
                        blockers.insert(
                            task.task.task_id.clone(),
                            ResumeBlocker::DependencyIncomplete,
                        );
                    }
                }
            },
            TaskState::Planned | TaskState::Ready => {
                if dependencies_completed(&tasks, &task.task.depends_on) {
                    ready_task_ids.push(task.task.task_id.clone());
                } else {
                    blocked_task_ids.push(task.task.task_id.clone());
                    blockers.insert(
                        task.task.task_id.clone(),
                        ResumeBlocker::DependencyIncomplete,
                    );
                }
            }
        }
    }

    let is_complete = graph
        .tasks
        .iter()
        .all(|task| task.state == TaskState::Completed);

    Ok(RuntimeResumePlan {
        graph_id: graph_id.into(),
        completed_task_ids,
        ready_task_ids,
        blocked_task_ids,
        running_task_ids,
        awaiting_approval_task_ids,
        failed_task_ids,
        blockers,
        adoption_recommendations,
        running_task_policy,
        is_complete,
    })
}

fn adoption_recommendation_for_task(
    task_store: &RuntimeTaskStore,
    task: &RuntimeTaskRecord,
    adoption_probe: Option<&dyn RuntimeAdoptionProbe>,
) -> RuntimeAdoptionRecommendation {
    let latest = task_store.latest_attempt_for_task(&task.task.task_id);
    let Some(attempt) = latest else {
        return RuntimeAdoptionRecommendation {
            task_id: task.task.task_id.clone(),
            action: RuntimeAdoptionAction::InspectRequired,
            reason: "no runtime attempt evidence exists for this task".into(),
            attempt_id: None,
            idempotency_key: task.idempotency_key.clone(),
            ticket_id: None,
            ledger_event_id: None,
            provider_probe: None,
        };
    };

    if attempt.ledger_event_id.is_some() {
        return RuntimeAdoptionRecommendation {
            task_id: task.task.task_id.clone(),
            action: RuntimeAdoptionAction::AlreadyCommitted,
            reason: "latest attempt already has a ledger event reference".into(),
            attempt_id: Some(attempt.attempt_id.clone()),
            idempotency_key: Some(attempt.idempotency_key.clone()),
            ticket_id: attempt.ticket_id.clone(),
            ledger_event_id: attempt.ledger_event_id.clone(),
            provider_probe: None,
        };
    }

    if let Some(recorded_probe) = task_store.latest_adoption_probe_for_attempt(&attempt.attempt_id)
    {
        return adoption_recommendation_from_probe(task, attempt, recorded_probe.result.clone());
    }

    let probe_result = adoption_probe
        .and_then(|probe| probe.probe(task, attempt).ok().flatten())
        .filter(|probe_result| {
            probe_result.task_id == task.task.task_id
                && probe_result.attempt_id == attempt.attempt_id
                && probe_result.idempotency_key == attempt.idempotency_key
        });

    if let Some(probe_result) = probe_result {
        return adoption_recommendation_from_probe(task, attempt, probe_result);
    }

    if attempt.retry_safe && attempt.ticket_id.is_none() {
        return RuntimeAdoptionRecommendation {
            task_id: task.task.task_id.clone(),
            action: RuntimeAdoptionAction::RetryReady,
            reason: "latest attempt is retry-safe and has no issued ticket evidence".into(),
            attempt_id: Some(attempt.attempt_id.clone()),
            idempotency_key: Some(attempt.idempotency_key.clone()),
            ticket_id: None,
            ledger_event_id: None,
            provider_probe: None,
        };
    }

    RuntimeAdoptionRecommendation {
        task_id: task.task.task_id.clone(),
        action: RuntimeAdoptionAction::InspectRequired,
        reason: "latest attempt may have external side effects and requires inspection".into(),
        attempt_id: Some(attempt.attempt_id.clone()),
        idempotency_key: Some(attempt.idempotency_key.clone()),
        ticket_id: attempt.ticket_id.clone(),
        ledger_event_id: attempt.ledger_event_id.clone(),
        provider_probe: None,
    }
}

fn adoption_recommendation_from_probe(
    task: &RuntimeTaskRecord,
    attempt: &RuntimeTaskAttempt,
    probe_result: RuntimeAdoptionProbeResult,
) -> RuntimeAdoptionRecommendation {
    let (action, reason) = match probe_result.status {
        RuntimeAdoptionProbeStatus::Committed => (
            RuntimeAdoptionAction::AlreadyCommitted,
            "provider probe found committed side-effect evidence",
        ),
        RuntimeAdoptionProbeStatus::NotFound
            if attempt.retry_safe && attempt.ticket_id.is_none() =>
        {
            (
                RuntimeAdoptionAction::RetryReady,
                "provider probe found no side effect and latest attempt is retry-safe",
            )
        }
        RuntimeAdoptionProbeStatus::Failed if attempt.retry_safe && attempt.ticket_id.is_none() => {
            (
                RuntimeAdoptionAction::RetryReady,
                "provider probe found failed side-effect evidence and latest attempt is retry-safe",
            )
        }
        RuntimeAdoptionProbeStatus::NotFound => (
            RuntimeAdoptionAction::InspectRequired,
            "provider probe found no side effect but latest attempt is not retry-safe",
        ),
        RuntimeAdoptionProbeStatus::Failed => (
            RuntimeAdoptionAction::InspectRequired,
            "provider probe found failed side-effect evidence but latest attempt is not retry-safe",
        ),
        RuntimeAdoptionProbeStatus::Pending => (
            RuntimeAdoptionAction::InspectRequired,
            "provider probe found pending side-effect evidence",
        ),
        RuntimeAdoptionProbeStatus::Unknown => (
            RuntimeAdoptionAction::InspectRequired,
            "provider probe could not determine side-effect state",
        ),
    };

    RuntimeAdoptionRecommendation {
        task_id: task.task.task_id.clone(),
        action,
        reason: reason.into(),
        attempt_id: Some(attempt.attempt_id.clone()),
        idempotency_key: Some(attempt.idempotency_key.clone()),
        ticket_id: attempt.ticket_id.clone(),
        ledger_event_id: attempt.ledger_event_id.clone(),
        provider_probe: Some(probe_result),
    }
}

fn validate_adoption_probe_matches_attempt(
    probe: &RuntimeAdoptionProbeRecord,
    attempt: &RuntimeTaskAttempt,
) -> RuntimeResult<()> {
    if probe.graph_id != attempt.graph_id {
        return Err(RuntimeError::AdoptionProbeMismatch {
            probe_id: probe.probe_id.clone(),
            reason: "probe graph does not match attempt graph".into(),
        });
    }
    if probe.result.task_id != attempt.task_id {
        return Err(RuntimeError::AdoptionProbeMismatch {
            probe_id: probe.probe_id.clone(),
            reason: "probe task does not match attempt task".into(),
        });
    }
    if probe.result.idempotency_key != attempt.idempotency_key {
        return Err(RuntimeError::AdoptionProbeMismatch {
            probe_id: probe.probe_id.clone(),
            reason: "probe idempotency key does not match attempt".into(),
        });
    }
    Ok(())
}

fn runtime_idempotency_key(
    graph: &TaskGraph,
    task: &TaskNode,
    capability: &CapabilityContract,
) -> String {
    let payload = serde_json::json!({
        "graph_id": graph.graph_id,
        "task_id": task.task_id,
        "capability_id": task.capability_id,
        "capability_contract_hash": capability_contract_hash(capability),
        "target": task.target,
        "input": task.input,
    });
    let bytes = serde_json::to_vec(&payload).expect("runtime idempotency payload serializes");
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn runtime_retry_safe(capability: &CapabilityContract, task: &TaskNode) -> bool {
    capability.retry_policy.retry_non_idempotent
        || task.target.resource_type == ResourceType::File
            && capability
                .permissions
                .resources
                .iter()
                .any(|resource| resource == "workspace.read")
            && !capability
                .permissions
                .resources
                .iter()
                .any(|resource| resource.contains("write"))
            && !capability
                .permissions
                .denied
                .iter()
                .any(|resource| resource == "workspace.read")
}

fn task_state_for_stage(stage: RuntimeStage) -> TaskState {
    match stage {
        RuntimeStage::Planned
        | RuntimeStage::Admitted
        | RuntimeStage::PolicyChecked
        | RuntimeStage::TicketIssued => TaskState::Ready,
        RuntimeStage::AwaitingApproval => TaskState::AwaitingApproval,
        RuntimeStage::Executing | RuntimeStage::Verifying | RuntimeStage::Committing => {
            TaskState::Running
        }
        RuntimeStage::Completed => TaskState::Completed,
        RuntimeStage::Failed => TaskState::Failed,
    }
}

fn merge_task_state(current: TaskState, next: TaskState) -> TaskState {
    if task_state_rank(next) >= task_state_rank(current) {
        next
    } else {
        current
    }
}

fn task_state_rank(state: TaskState) -> u8 {
    match state {
        TaskState::Planned => 0,
        TaskState::Ready => 1,
        TaskState::Running => 2,
        TaskState::AwaitingApproval => 3,
        TaskState::Completed => 4,
        TaskState::Failed => 5,
    }
}

fn order_tasks_by_dependency(tasks: &mut [TaskNode]) {
    let order = dependency_order_index(tasks);
    tasks.sort_by_key(|task| order.get(&task.task_id).copied().unwrap_or(usize::MAX));
}

fn order_steps_by_dependency(steps: &mut [PlannerStep]) {
    let order = step_dependency_order_index(steps);
    steps.sort_by_key(|step| order.get(&step.step_id).copied().unwrap_or(usize::MAX));
}

fn order_task_records_by_dependency(records: &mut [RuntimeTaskRecord]) {
    let tasks = records
        .iter()
        .map(|record| record.task.clone())
        .collect::<Vec<_>>();
    let order = dependency_order_index(&tasks);
    records.sort_by_key(|record| {
        order
            .get(&record.task.task_id)
            .copied()
            .unwrap_or(usize::MAX)
    });
}

fn dependency_order_index(tasks: &[TaskNode]) -> BTreeMap<String, usize> {
    let mut completed = Vec::<String>::new();
    let mut remaining = tasks.to_vec();
    let mut order = BTreeMap::new();

    while !remaining.is_empty() {
        let Some(index) = remaining.iter().position(|task| {
            task.depends_on
                .iter()
                .all(|dependency| completed.contains(dependency))
        }) else {
            break;
        };
        let task = remaining.remove(index);
        let next_index = completed.len();
        completed.push(task.task_id.clone());
        order.insert(task.task_id, next_index);
    }

    order
}

fn step_dependency_order_index(steps: &[PlannerStep]) -> BTreeMap<String, usize> {
    let mut completed = Vec::<String>::new();
    let mut remaining = steps.to_vec();
    let mut order = BTreeMap::new();

    while !remaining.is_empty() {
        let Some(index) = remaining.iter().position(|step| {
            step.depends_on
                .iter()
                .all(|dependency| completed.contains(dependency))
        }) else {
            break;
        };
        let step = remaining.remove(index);
        let next_index = completed.len();
        completed.push(step.step_id.clone());
        order.insert(step.step_id, next_index);
    }

    order
}

fn dependencies_completed(tasks: &[RuntimeTaskRecord], dependencies: &[String]) -> bool {
    dependencies.iter().all(|dependency| {
        tasks.iter().any(|candidate| {
            candidate.task.task_id == *dependency && candidate.task.state == TaskState::Completed
        })
    })
}

fn runtime_stage_for_task_state(state: TaskState) -> RuntimeStage {
    match state {
        TaskState::Planned => RuntimeStage::Planned,
        TaskState::Ready => RuntimeStage::Planned,
        TaskState::AwaitingApproval => RuntimeStage::AwaitingApproval,
        TaskState::Running => RuntimeStage::Executing,
        TaskState::Completed => RuntimeStage::Completed,
        TaskState::Failed => RuntimeStage::Failed,
    }
}

fn validate_skill_manifest(skill: &SkillManifest) -> RuntimeResult<()> {
    let capability_id = skill
        .required_capabilities
        .first()
        .ok_or_else(|| RuntimeError::SkillMissingCapability(skill.skill_id.clone()))?;
    if !skill.provided_capabilities.is_empty()
        && !skill
            .provided_capabilities
            .iter()
            .any(|id| id == capability_id)
    {
        return Err(RuntimeError::SkillCapabilityMismatch {
            skill_id: skill.skill_id.clone(),
            capability_id: capability_id.clone(),
        });
    }
    if skill.permission_mode != PermissionMode::ReadOnly {
        return Err(RuntimeError::SkillNotAllowed(skill.skill_id.clone()));
    }
    Ok(())
}

fn validate_manifest_registry(registry: &RuntimeManifestRegistry) -> RuntimeResult<()> {
    let module_ids = registry
        .modules
        .iter()
        .map(|module| module.module_id.clone())
        .collect::<BTreeSet<_>>();

    for module in &registry.modules {
        for dependency_id in &module.required_modules {
            if !module_ids.contains(dependency_id) {
                return Err(RuntimeError::ModuleDependencyNotFound {
                    module_id: module.module_id.clone(),
                    dependency_id: dependency_id.clone(),
                });
            }
        }
    }
    validate_module_dependency_graph(&registry.modules)?;

    for skill in &registry.skills {
        validate_skill_manifest(skill)?;
        let module = registry
            .modules
            .iter()
            .find(|module| module.module_id == skill.module_ref)
            .ok_or_else(|| RuntimeError::SkillModuleNotFound {
                skill_id: skill.skill_id.clone(),
                module_id: skill.module_ref.clone(),
            })?;
        validate_skill_module_binding(skill, module)?;
    }

    Ok(())
}

fn validate_module_dependency_graph(modules: &[ModuleManifest]) -> RuntimeResult<()> {
    let dependencies = modules
        .iter()
        .map(|module| (module.module_id.clone(), module.required_modules.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut visited = BTreeSet::new();
    let mut visiting = Vec::<String>::new();

    for module_id in dependencies.keys() {
        validate_module_dependency_node(module_id, &dependencies, &mut visiting, &mut visited)?;
    }

    Ok(())
}

fn validate_module_dependency_node(
    module_id: &str,
    dependencies: &BTreeMap<String, Vec<String>>,
    visiting: &mut Vec<String>,
    visited: &mut BTreeSet<String>,
) -> RuntimeResult<()> {
    if visited.contains(module_id) {
        return Ok(());
    }
    if visiting.iter().any(|id| id == module_id) {
        return Err(RuntimeError::ModuleDependencyCycle(module_id.into()));
    }

    visiting.push(module_id.into());
    if let Some(required_modules) = dependencies.get(module_id) {
        for dependency_id in required_modules {
            validate_module_dependency_node(dependency_id, dependencies, visiting, visited)?;
        }
    }
    visiting.pop();
    visited.insert(module_id.into());
    Ok(())
}

fn validate_skill_module_binding(
    skill: &SkillManifest,
    module: &ModuleManifest,
) -> RuntimeResult<()> {
    let supported_capabilities = module
        .required_capabilities
        .iter()
        .chain(module.provided_capabilities.iter())
        .cloned()
        .collect::<BTreeSet<_>>();

    for capability_id in skill
        .required_capabilities
        .iter()
        .chain(skill.provided_capabilities.iter())
    {
        if !supported_capabilities.contains(capability_id) {
            return Err(RuntimeError::SkillModuleCapabilityMismatch {
                skill_id: skill.skill_id.clone(),
                module_id: module.module_id.clone(),
                capability_id: capability_id.clone(),
            });
        }
    }

    Ok(())
}

fn skill_allowed_by_profile(skill: &SkillManifest, profile: &RuntimePolicyProfile) -> bool {
    if !profile.allow_skills {
        return false;
    }
    if profile.allowed_capabilities.is_empty() {
        return true;
    }
    skill
        .required_capabilities
        .iter()
        .all(|capability| profile.allowed_capabilities.contains(capability))
}

fn skill_matches_intent(skill: &SkillManifest, intent: &Intent) -> bool {
    let Some(capability_id) = skill.required_capabilities.first() else {
        return false;
    };
    let goal = intent.goal.to_ascii_lowercase();
    intent.requested_capabilities.contains(capability_id)
        && (goal.contains(&skill.skill_id.to_ascii_lowercase())
            || goal.contains(&capability_id.to_ascii_lowercase()))
}

fn skill_target(intent: &Intent, skill: &SkillManifest) -> DeltaTarget {
    let path = extract_file_path(&skill.entrypoint_ref)
        .or_else(|| extract_file_path(&intent.goal))
        .unwrap_or_else(|| "README.md".into());
    DeltaTarget {
        resource_type: ResourceType::File,
        resource_ref: path,
    }
}

fn skill_input(_intent: &Intent, _skill: &SkillManifest, target: &DeltaTarget) -> Value {
    serde_json::json!({ "path": target.resource_ref })
}

fn plan_ready_order(graph: &TaskGraph) -> RuntimeResult<Vec<String>> {
    let mut completed = Vec::<String>::new();
    let mut remaining = graph.tasks.clone();

    while !remaining.is_empty() {
        let Some(index) = remaining.iter().position(|task| {
            task.depends_on
                .iter()
                .all(|dependency| completed.contains(dependency))
        }) else {
            return Err(RuntimeError::TaskDependencyCycle);
        };
        let task = remaining.remove(index);
        completed.push(task.task_id);
    }

    Ok(completed)
}

fn extract_file_path(goal: &str) -> Option<String> {
    goal.split_whitespace()
        .find(|part| part.contains('.') || part.contains('/') || part.contains('\\'))
        .map(|part| {
            part.trim_matches(|char| char == '"' || char == '\'')
                .to_string()
        })
}

fn task_dependencies_completed(graph: &TaskGraph, task_id: &str) -> bool {
    let Some(task) = graph.tasks.iter().find(|task| task.task_id == task_id) else {
        return false;
    };
    task.depends_on.iter().all(|dependency| {
        graph.tasks.iter().any(|candidate| {
            candidate.task_id == *dependency && candidate.state == TaskState::Completed
        })
    })
}

fn ledger_event_for_success(
    capability: &CapabilityContract,
    result: &moxi_contracts::SandboxResult,
    proof_id: &str,
    resource_ref: &str,
    delta_id: &str,
) -> LedgerEvent {
    LedgerEvent {
        ledger_event_id: format!("le_{}", Uuid::new_v4()),
        run_id: result.run_id.clone(),
        event_type: "runtime.task.completed".into(),
        actor_id: "kernel".into(),
        resource_ref: resource_ref.into(),
        delta_id: delta_id.into(),
        capability_id: result.capability_id.clone(),
        policy_decision_ref: result.policy_decision_ref.clone(),
        execution_ticket_ref: result.ticket_id.clone(),
        capability_contract_ref: result.capability_contract_ref.clone(),
        capability_contract_hash: capability_contract_hash(capability),
        executor_ref: result.executor_ref.clone(),
        executor_version: result.executor_version.clone(),
        executor_artifact_hash: result.executor_artifact_hash.clone(),
        executor_signature_ref: result.executor_signature_ref.clone(),
        executor_signing_key_ref: result.executor_signing_key_ref.clone(),
        executor_manifest_hash: result.executor_manifest_hash.clone(),
        gateway_decision_ref: result.gateway_decision_ref.clone(),
        proof_refs: vec![proof_id.into()],
        input_hash: result.input_hash.clone(),
        output_hash: result.output_hash.clone(),
        previous_event_hash: String::new(),
        event_hash: String::new(),
        result: EventResult::Success,
        timestamp: Utc::now(),
    }
}

pub fn read_only_intent(
    goal: impl Into<String>,
    workspace_root: impl Into<String>,
    capability_id: impl Into<String>,
) -> Intent {
    Intent {
        intent_id: format!("intent_{}", Uuid::new_v4()),
        tenant_id: "local".into(),
        user_id: "local-user".into(),
        gateway_decision_ref: None,
        goal: goal.into(),
        requested_capabilities: vec![capability_id.into()],
        risk_level: RiskLevel::Low,
        workspace_root: workspace_root.into(),
        budget: Default::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use moxi_contracts::{ModuleKind, ModuleStability, PermissionMode, SkillInvocationMode};
    use moxi_core::{file_read_capability, Kernel};
    use std::fs;
    use tempfile::tempdir;

    fn read_skill(skill_id: &str, entrypoint_ref: &str) -> SkillManifest {
        SkillManifest {
            skill_id: skill_id.into(),
            skill_version: "0.1.0".into(),
            module_ref: "module.files".into(),
            invocation_mode: SkillInvocationMode::InProcess,
            entrypoint_ref: entrypoint_ref.into(),
            required_capabilities: vec!["file.read".into()],
            provided_capabilities: vec!["file.read".into()],
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: serde_json::json!({"type": "object"}),
            permission_mode: PermissionMode::ReadOnly,
            risk_level: RiskLevel::Low,
            proof_required: true,
            approval_required: false,
        }
    }

    fn file_module(module_id: &str) -> ModuleManifest {
        ModuleManifest {
            module_id: module_id.into(),
            module_version: "0.1.0".into(),
            kind: ModuleKind::Skill,
            stability: ModuleStability::Preview,
            owner: "moxi".into(),
            summary: "file skills".into(),
            required_capabilities: vec!["file.read".into()],
            provided_capabilities: vec!["file.read".into()],
            required_modules: vec![],
            policy_profile_ref: None,
            manifest_ref: None,
            signature_ref: None,
        }
    }

    fn stored_graph() -> TaskGraph {
        TaskGraph {
            graph_id: "tg_store".into(),
            goal: "read stored.txt".into(),
            path: RuntimePath::FastPath,
            tasks: vec![TaskNode {
                task_id: "task_store_read".into(),
                skill_id: None,
                capability_id: "file.read".into(),
                target: DeltaTarget {
                    resource_type: ResourceType::File,
                    resource_ref: "stored.txt".into(),
                },
                input: serde_json::json!({"path": "stored.txt"}),
                risk_level: RiskLevel::Low,
                depends_on: vec![],
                state: TaskState::Ready,
            }],
        }
    }

    fn stored_graph_with_capability(capability_id: &str) -> TaskGraph {
        let mut graph = stored_graph();
        graph.tasks[0].capability_id = capability_id.into();
        graph
    }

    fn stored_planner_record(graph: &TaskGraph) -> RuntimePlannerRecord {
        let plan = PlannerPlan {
            plan_id: "plan_store".into(),
            intent_id: "intent_store".into(),
            goal: graph.goal.clone(),
            source: PlannerSource::Deterministic,
            constraints: vec![PlannerConstraint {
                constraint_id: "p0_trusted_execution_chain".into(),
                description: "external effects must execute through P0".into(),
            }],
            steps: vec![PlannerStep {
                step_id: "step_store_read".into(),
                skill_id: None,
                capability_id: "file.read".into(),
                target: graph.tasks[0].target.clone(),
                input: graph.tasks[0].input.clone(),
                risk_level: RiskLevel::Low,
                depends_on: vec![],
                rationale: "stored deterministic plan".into(),
            }],
        };
        runtime_planner_record(&plan, graph).unwrap()
    }

    struct StaticAdoptionProbe {
        status: RuntimeAdoptionProbeStatus,
        provider_ref: Option<String>,
        evidence_ref: Option<String>,
    }

    impl StaticAdoptionProbe {
        fn new(status: RuntimeAdoptionProbeStatus) -> Self {
            Self {
                status,
                provider_ref: Some("provider:test".into()),
                evidence_ref: Some("evidence:test".into()),
            }
        }
    }

    impl RuntimeAdoptionProbe for StaticAdoptionProbe {
        fn probe(
            &self,
            task: &RuntimeTaskRecord,
            attempt: &RuntimeTaskAttempt,
        ) -> RuntimeResult<Option<RuntimeAdoptionProbeResult>> {
            Ok(Some(RuntimeAdoptionProbeResult {
                task_id: task.task.task_id.clone(),
                attempt_id: attempt.attempt_id.clone(),
                idempotency_key: attempt.idempotency_key.clone(),
                status: self.status,
                provider_ref: self.provider_ref.clone(),
                evidence_ref: self.evidence_ref.clone(),
                message: Some("static probe".into()),
                observed_at: Utc::now(),
            }))
        }
    }

    fn adoption_probe_record_for(
        graph: &TaskGraph,
        attempt: &RuntimeTaskAttempt,
        status: RuntimeAdoptionProbeStatus,
    ) -> RuntimeAdoptionProbeRecord {
        RuntimeAdoptionProbeRecord {
            probe_id: format!("rap_{}", attempt.attempt_id),
            graph_id: graph.graph_id.clone(),
            result: RuntimeAdoptionProbeResult {
                task_id: attempt.task_id.clone(),
                attempt_id: attempt.attempt_id.clone(),
                idempotency_key: attempt.idempotency_key.clone(),
                status,
                provider_ref: Some("provider:test".into()),
                evidence_ref: Some("evidence:test".into()),
                message: Some("stored probe".into()),
                observed_at: Utc::now(),
            },
            recorded_at: Utc::now(),
        }
    }

    fn failed_attempt_for_graph(
        graph: &TaskGraph,
        attempt_id: &str,
        retry_safe: bool,
        ticket_id: Option<&str>,
    ) -> RuntimeTaskAttempt {
        let capability = file_read_capability();
        RuntimeTaskAttempt {
            attempt_id: attempt_id.into(),
            graph_id: graph.graph_id.clone(),
            task_id: graph.tasks[0].task_id.clone(),
            run_id: format!("run_{attempt_id}"),
            capability_id: graph.tasks[0].capability_id.clone(),
            idempotency_key: runtime_idempotency_key(graph, &graph.tasks[0], &capability),
            retry_safe,
            stage: RuntimeAttemptStage::Failed,
            ticket_id: ticket_id.map(str::to_string),
            ledger_event_id: None,
            error: Some("failed attempt fixture".into()),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn plans_file_read_fast_path_from_intent() {
        let temp = tempdir().unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        kernel.register_capability(file_read_capability()).unwrap();
        let runtime = RuntimeSession::new(kernel);
        let intent = read_only_intent("read README.md", temp.path().to_string_lossy(), "file.read");

        let graph = runtime.plan(&intent).unwrap();

        assert_eq!(graph.path, RuntimePath::FastPath);
        assert_eq!(graph.tasks.len(), 1);
        assert_eq!(graph.tasks[0].capability_id, "file.read");
        assert_eq!(graph.tasks[0].target.resource_ref, "README.md");
    }

    #[test]
    fn execution_plan_exposes_planner_ir_and_stable_hash() {
        let temp = tempdir().unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        kernel.register_capability(file_read_capability()).unwrap();
        let runtime = RuntimeSession::new(kernel);
        let intent = read_only_intent("read README.md", temp.path().to_string_lossy(), "file.read");

        let execution = runtime.execution_plan(&intent).unwrap();
        let planner = runtime_planner_record(&execution.planner, &execution.graph).unwrap();

        assert_eq!(execution.planner.intent_id, intent.intent_id);
        assert_eq!(execution.planner.source, PlannerSource::Deterministic);
        assert_eq!(execution.planner.steps.len(), 1);
        assert_eq!(
            execution.ready_order,
            vec![execution.graph.tasks[0].task_id.clone()]
        );
        assert_eq!(planner.graph_id, execution.graph.graph_id);
        assert_eq!(planner.step_count, 1);
        assert!(planner.plan_hash.starts_with("sha256:"));
        assert_eq!(
            planner.plan_hash,
            planner_plan_hash(&execution.planner).unwrap()
        );
    }

    #[test]
    fn runs_file_read_through_p0_kernel_and_emits_events() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("hello.txt"), "hello runtime").unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        kernel.register_capability(file_read_capability()).unwrap();
        let mut runtime = RuntimeSession::new(kernel);
        let intent = read_only_intent("read hello.txt", temp.path().to_string_lossy(), "file.read");

        let report = runtime.run(intent).unwrap();

        assert_eq!(report.outcomes.len(), 1);
        assert_eq!(report.outcomes[0].output["content"], "hello runtime");
        assert!(report.outcomes[0].idempotency_key.starts_with("sha256:"));
        assert!(report
            .events
            .iter()
            .any(|event| event.stage == RuntimeStage::TicketIssued));
        assert_eq!(
            runtime
                .kernel()
                .replay_ledger_audit()
                .unwrap()
                .successful_events,
            1
        );
        let snapshot = runtime.graph_snapshot(&report.graph.graph_id).unwrap();
        assert_eq!(
            snapshot.planner.as_ref().unwrap().plan_hash,
            report.planner.plan_hash
        );
        assert_eq!(snapshot.attempts.len(), 2);
        assert!(snapshot
            .attempts
            .iter()
            .any(|attempt| attempt.stage == RuntimeAttemptStage::Started && attempt.retry_safe));
        assert!(snapshot
            .attempts
            .iter()
            .any(|attempt| attempt.stage == RuntimeAttemptStage::Completed
                && attempt.idempotency_key == report.outcomes[0].idempotency_key));
    }

    #[test]
    fn exposes_runtime_event_cursor_and_task_store_projection() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("hello.txt"), "hello runtime").unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        kernel.register_capability(file_read_capability()).unwrap();
        let mut runtime = RuntimeSession::new(kernel);
        let cursor = runtime.event_cursor();
        let intent = read_only_intent("read hello.txt", temp.path().to_string_lossy(), "file.read");

        let report = runtime.run(intent).unwrap();

        let graph_id = &report.graph.graph_id;
        let incremental_events = runtime.events_since(cursor);
        assert!(!incremental_events.is_empty());
        assert!(incremental_events
            .iter()
            .all(|event| event.graph_id.as_deref() == Some(graph_id)));
        let feed = runtime.event_feed(cursor, Some(graph_id)).unwrap();
        assert_eq!(feed.schema_version, 1);
        assert_eq!(feed.graph_id.as_deref(), Some(graph_id.as_str()));
        assert_eq!(feed.from_cursor, cursor);
        assert_eq!(feed.next_cursor, runtime.event_cursor());
        assert_eq!(feed.event_count, incremental_events.len());
        assert_eq!(feed.latest_stage, Some(RuntimeStage::Completed));
        assert_eq!(
            feed.latest_message.as_deref(),
            Some("runtime graph completed")
        );
        assert_eq!(feed.latest_progress, 1.0);
        assert!(feed.current_task_id.is_none());
        assert!(feed.is_complete);

        let snapshot = runtime.graph_snapshot(graph_id).unwrap();
        assert_eq!(snapshot.graph.graph_id, *graph_id);
        assert_eq!(snapshot.tasks.len(), 1);
        assert_eq!(snapshot.tasks[0].task.state, TaskState::Completed);
        assert_eq!(snapshot.tasks[0].last_stage, Some(RuntimeStage::Completed));
        assert_eq!(snapshot.tasks[0].progress, 1.0);
        assert_eq!(snapshot.events.len(), incremental_events.len());

        let graph_list = runtime.graph_list().unwrap();
        assert_eq!(graph_list.len(), 1);
        assert_eq!(graph_list[0].graph_id, *graph_id);
        assert_eq!(graph_list[0].completed_count, 1);
        assert!(graph_list[0].is_complete);

        let query = runtime.query_snapshot(graph_id).unwrap();
        assert_eq!(query.graph.graph_id, *graph_id);
        assert_eq!(
            query.planner.as_ref().unwrap().plan_id,
            report.planner.plan_id
        );
        assert_eq!(query.tasks.len(), 1);
        assert_eq!(query.tasks[0].state, TaskState::Completed);
        assert_eq!(query.tasks[0].blocker, Some(ResumeBlocker::AlreadyFinished));
        assert_eq!(query.attempts.len(), 2);
        assert_eq!(query.event_cursor, runtime.event_cursor());
        assert_eq!(
            query.resume_plan.completed_task_ids,
            vec![query.tasks[0].task_id.clone()]
        );
        assert_eq!(query.policy_profile.profile_id, "runtime.default");

        let projection_path = temp.path().join("runtime-projection.json");
        let projection = runtime.write_projection(&projection_path).unwrap();
        let restored = RuntimeSession::read_projection(&projection_path).unwrap();
        assert_eq!(restored.schema_version, 1);
        assert_eq!(restored.event_stream.cursor(), runtime.event_cursor());
        assert_eq!(restored.task_store.graph_ids(), vec![graph_id.clone()]);
        assert_eq!(restored, projection);

        let index_path = temp.path().join("runtime-task-index.json");
        let index = runtime.write_task_index(&index_path).unwrap();
        let restored_index = RuntimeSession::read_task_index(&index_path).unwrap();
        assert_eq!(restored_index.schema_version, 1);
        assert_eq!(restored_index.event_cursor, runtime.event_cursor());
        assert_eq!(restored_index.graph_list().len(), 1);
        assert_eq!(restored_index.graph(graph_id).unwrap().completed_count, 1);
        assert_eq!(restored_index.tasks_for_graph(graph_id).len(), 1);
        assert_eq!(restored_index.tasks_by_state(TaskState::Completed).len(), 1);
        assert_eq!(restored_index, index);
    }

    #[test]
    fn runtime_sqlite_store_persists_indexed_runtime_state() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("runtime-store.sqlite");
        let store = RuntimeSqliteStore::open(&path).unwrap();
        assert_eq!(
            store.schema_version().unwrap(),
            RUNTIME_STORE_SCHEMA_VERSION
        );
        let graph = stored_graph();
        let planner = stored_planner_record(&graph);
        store.save_planner_record(&planner).unwrap();
        store.save_graph(&graph).unwrap();
        let capability = file_read_capability();
        let attempt = RuntimeTaskAttempt {
            attempt_id: "rta_store_started".into(),
            graph_id: graph.graph_id.clone(),
            task_id: graph.tasks[0].task_id.clone(),
            run_id: "run_store".into(),
            capability_id: "file.read".into(),
            idempotency_key: runtime_idempotency_key(&graph, &graph.tasks[0], &capability),
            retry_safe: true,
            stage: RuntimeAttemptStage::Started,
            ticket_id: None,
            ledger_event_id: None,
            error: None,
            created_at: Utc::now(),
        };
        store.record_attempt(&attempt).unwrap();
        let adoption_probe =
            adoption_probe_record_for(&graph, &attempt, RuntimeAdoptionProbeStatus::NotFound);
        store.record_adoption_probe(&adoption_probe).unwrap();
        let event = RuntimeEvent {
            event_id: "re_store_completed".into(),
            graph_id: Some(graph.graph_id.clone()),
            run_id: Some("run_store".into()),
            task_id: Some(graph.tasks[0].task_id.clone()),
            stage: RuntimeStage::Completed,
            message: "task completed".into(),
            progress: 1.0,
            timestamp: Utc::now(),
        };
        store.record_event(&event).unwrap();
        drop(store);

        let restored = RuntimeSqliteStore::open(&path).unwrap();
        let task_store = restored.load_task_store().unwrap();
        assert_eq!(
            task_store
                .planner_record(&graph.graph_id)
                .unwrap()
                .plan_hash,
            planner.plan_hash
        );
        assert_eq!(task_store.graph_ids(), vec![graph.graph_id.clone()]);
        assert_eq!(
            task_store.task(&graph.tasks[0].task_id).unwrap().task.state,
            TaskState::Completed
        );
        let event_stream = restored.load_event_stream().unwrap();
        assert_eq!(event_stream.cursor(), 1);
        assert_eq!(event_stream.all()[0].event_id, "re_store_completed");

        let graph_list = restored
            .graph_list(RunningTaskPolicy::RequireInspection)
            .unwrap();
        assert_eq!(graph_list[0].completed_count, 1);
        let query = restored
            .query_snapshot(
                &graph.graph_id,
                RunningTaskPolicy::RequireInspection,
                RuntimePolicyProfile::default(),
            )
            .unwrap();
        assert_eq!(query.planner.as_ref().unwrap().plan_id, planner.plan_id);
        assert_eq!(query.tasks[0].state, TaskState::Completed);
        assert_eq!(query.adoption_probes.len(), 1);
        let index = restored
            .task_index_snapshot(
                RunningTaskPolicy::RequireInspection,
                RuntimePolicyProfile::default(),
            )
            .unwrap();
        assert_eq!(index.tasks_by_state(TaskState::Completed).len(), 1);
        let feed = restored
            .event_feed(
                0,
                Some(&graph.graph_id),
                RunningTaskPolicy::RequireInspection,
            )
            .unwrap();
        assert_eq!(feed.event_count, 1);
        assert_eq!(feed.latest_stage, Some(RuntimeStage::Completed));
        assert!(feed.is_complete);
    }

    #[test]
    fn runtime_sqlite_retry_lease_acquire_is_atomic() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("runtime-store.sqlite");
        let mut first_store = RuntimeSqliteStore::open(&path).unwrap();
        let mut second_store = RuntimeSqliteStore::open(&path).unwrap();
        let graph = stored_graph();
        first_store.save_graph(&graph).unwrap();
        let now = Utc::now();
        let lease = RuntimeRetryLease {
            lease_id: "rtl_sqlite_active".into(),
            graph_id: graph.graph_id.clone(),
            task_id: graph.tasks[0].task_id.clone(),
            run_id: "run_store".into(),
            idempotency_key: "sha256:lease-key".into(),
            holder_ref: "first".into(),
            state: RuntimeRetryLeaseState::Active,
            acquired_at: now,
            expires_at: now + chrono::Duration::seconds(60),
            released_at: None,
        };

        first_store.acquire_retry_lease(&lease).unwrap();
        let blocked = second_store.acquire_retry_lease(&RuntimeRetryLease {
            lease_id: "rtl_sqlite_second".into(),
            holder_ref: "second".into(),
            ..lease.clone()
        });

        assert!(matches!(
            blocked,
            Err(RuntimeError::RetryLeaseActive { task_id, lease_id })
                if task_id == graph.tasks[0].task_id && lease_id == "rtl_sqlite_active"
        ));
        first_store
            .release_retry_lease("rtl_sqlite_active", Utc::now())
            .unwrap();
        second_store
            .acquire_retry_lease(&RuntimeRetryLease {
                lease_id: "rtl_sqlite_after_release".into(),
                holder_ref: "second".into(),
                ..lease
            })
            .unwrap();
    }

    #[test]
    fn runtime_sqlite_store_recovers_adoption_probe_resume_evidence() {
        let temp = tempdir().unwrap();
        let sqlite_path = temp.path().join("runtime-adoption.sqlite");
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        kernel.register_capability(file_read_capability()).unwrap();
        let mut runtime = RuntimeSession::with_sqlite_store(kernel, &sqlite_path)
            .unwrap()
            .with_running_task_policy(RunningTaskPolicy::RetryReady);
        let mut graph = stored_graph();
        graph.tasks[0].state = TaskState::Failed;
        runtime.task_store.save_graph(&graph);
        runtime
            .persist(RuntimeJournalRecord::Graph {
                graph: graph.clone(),
            })
            .unwrap();
        let capability = file_read_capability();
        let attempt = RuntimeTaskAttempt {
            attempt_id: "rta_sqlite_probe".into(),
            graph_id: graph.graph_id.clone(),
            task_id: graph.tasks[0].task_id.clone(),
            run_id: "run_sqlite_probe".into(),
            capability_id: "file.read".into(),
            idempotency_key: runtime_idempotency_key(&graph, &graph.tasks[0], &capability),
            retry_safe: true,
            stage: RuntimeAttemptStage::Failed,
            ticket_id: Some("ticket_provider_uncertain".into()),
            ledger_event_id: None,
            error: Some("provider result unknown".into()),
            created_at: Utc::now(),
        };
        runtime.persist_task_attempt(attempt).unwrap();
        let probe = StaticAdoptionProbe::new(RuntimeAdoptionProbeStatus::Committed);
        let plan = runtime
            .probe_adoption_and_resume_plan(&graph.graph_id, &probe)
            .unwrap();
        assert_eq!(
            plan.adoption_recommendations
                .get(&graph.tasks[0].task_id)
                .unwrap()
                .action,
            RuntimeAdoptionAction::AlreadyCommitted
        );
        drop(runtime);

        let restored_store = RuntimeSqliteStore::open(&sqlite_path).unwrap();
        let query = restored_store
            .query_snapshot(
                &graph.graph_id,
                RunningTaskPolicy::RetryReady,
                RuntimePolicyProfile::default(),
            )
            .unwrap();
        let recommendation = query
            .resume_plan
            .adoption_recommendations
            .get(&graph.tasks[0].task_id)
            .unwrap();

        assert_eq!(query.adoption_probes.len(), 1);
        assert!(query.resume_plan.ready_task_ids.is_empty());
        assert_eq!(
            recommendation.provider_probe.as_ref().unwrap().status,
            RuntimeAdoptionProbeStatus::Committed
        );

        let mut replay_kernel = Kernel::new_in_memory(temp.path()).unwrap();
        replay_kernel
            .register_capability(file_read_capability())
            .unwrap();
        let replayed = RuntimeSession::with_sqlite_store(replay_kernel, &sqlite_path)
            .unwrap()
            .with_running_task_policy(RunningTaskPolicy::RetryReady);
        let replay_plan = replayed.resume_plan(&graph.graph_id).unwrap();
        assert_eq!(
            replay_plan
                .adoption_recommendations
                .get(&graph.tasks[0].task_id)
                .unwrap()
                .action,
            RuntimeAdoptionAction::AlreadyCommitted
        );
    }

    #[test]
    fn runtime_session_persists_live_state_to_sqlite_store() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("hello.txt"), "hello sqlite runtime").unwrap();
        let sqlite_path = temp.path().join("runtime-live.sqlite");
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        kernel.register_capability(file_read_capability()).unwrap();
        let mut runtime = RuntimeSession::with_sqlite_store(kernel, &sqlite_path).unwrap();
        assert!(runtime.has_sqlite_store());
        let intent = read_only_intent("read hello.txt", temp.path().to_string_lossy(), "file.read");

        let report = runtime.run(intent).unwrap();
        let graph_id = report.graph.graph_id.clone();
        let event_cursor = runtime.event_cursor();
        drop(runtime);

        let restored_store = RuntimeSqliteStore::open(&sqlite_path).unwrap();
        let query = restored_store
            .query_snapshot(
                &graph_id,
                RunningTaskPolicy::RequireInspection,
                RuntimePolicyProfile::default(),
            )
            .unwrap();
        assert_eq!(
            query.planner.as_ref().unwrap().plan_hash,
            report.planner.plan_hash
        );
        assert_eq!(query.graph.completed_count, 1);
        assert_eq!(
            query.tasks[0].idempotency_key,
            Some(report.outcomes[0].idempotency_key.clone())
        );
        assert_eq!(query.attempts.len(), 2);
        assert_eq!(query.events.len(), event_cursor);

        let leases = restored_store.retry_leases_for_graph(&graph_id).unwrap();
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].state, RuntimeRetryLeaseState::Released);

        let mut replay_kernel = Kernel::new_in_memory(temp.path()).unwrap();
        replay_kernel
            .register_capability(file_read_capability())
            .unwrap();
        let replayed = RuntimeSession::with_sqlite_store(replay_kernel, &sqlite_path).unwrap();
        assert_eq!(replayed.event_cursor(), event_cursor);
        let snapshot = replayed.graph_snapshot(&graph_id).unwrap();
        assert_eq!(snapshot.planner.unwrap().plan_id, report.planner.plan_id);
        assert_eq!(snapshot.tasks[0].task.state, TaskState::Completed);
    }

    #[test]
    fn retry_lease_blocks_retry_until_expired_or_released() {
        let mut store = RuntimeTaskStore::default();
        let graph = stored_graph();
        store.save_graph(&graph);
        let now = Utc::now();
        let lease = RuntimeRetryLease {
            lease_id: "rtl_active".into(),
            graph_id: graph.graph_id.clone(),
            task_id: graph.tasks[0].task_id.clone(),
            run_id: "run_store".into(),
            idempotency_key: "sha256:lease-key".into(),
            holder_ref: "test".into(),
            state: RuntimeRetryLeaseState::Active,
            acquired_at: now,
            expires_at: now + chrono::Duration::seconds(60),
            released_at: None,
        };
        store.acquire_retry_lease(lease.clone()).unwrap();
        assert!(matches!(
            store.acquire_retry_lease(RuntimeRetryLease {
                lease_id: "rtl_second".into(),
                ..lease.clone()
            }),
            Err(RuntimeError::RetryLeaseActive { task_id, lease_id })
                if task_id == graph.tasks[0].task_id && lease_id == "rtl_active"
        ));
        store.release_retry_lease("rtl_active", Utc::now()).unwrap();
        assert!(store
            .acquire_retry_lease(RuntimeRetryLease {
                lease_id: "rtl_after_release".into(),
                ..lease
            })
            .is_ok());
    }

    #[test]
    fn retry_ready_resume_respects_active_retry_lease() {
        let mut store = RuntimeTaskStore::default();
        let mut graph = stored_graph();
        graph.tasks[0].state = TaskState::Running;
        store.save_graph(&graph);
        let capability = file_read_capability();
        let attempt = RuntimeTaskAttempt {
            attempt_id: "rta_retry_safe".into(),
            graph_id: graph.graph_id.clone(),
            task_id: graph.tasks[0].task_id.clone(),
            run_id: "run_store".into(),
            capability_id: "file.read".into(),
            idempotency_key: runtime_idempotency_key(&graph, &graph.tasks[0], &capability),
            retry_safe: true,
            stage: RuntimeAttemptStage::Started,
            ticket_id: None,
            ledger_event_id: None,
            error: None,
            created_at: Utc::now(),
        };
        store.record_attempt(attempt.clone()).unwrap();
        let without_lease =
            resume_plan_from(&store, &graph.graph_id, RunningTaskPolicy::RetryReady, None).unwrap();
        assert_eq!(
            without_lease.ready_task_ids,
            vec![graph.tasks[0].task_id.clone()]
        );

        let now = Utc::now();
        store
            .acquire_retry_lease(RuntimeRetryLease {
                lease_id: "rtl_active".into(),
                graph_id: graph.graph_id.clone(),
                task_id: graph.tasks[0].task_id.clone(),
                run_id: "run_store".into(),
                idempotency_key: attempt.idempotency_key,
                holder_ref: "test".into(),
                state: RuntimeRetryLeaseState::Active,
                acquired_at: now,
                expires_at: now + chrono::Duration::seconds(60),
                released_at: None,
            })
            .unwrap();
        let with_lease =
            resume_plan_from(&store, &graph.graph_id, RunningTaskPolicy::RetryReady, None).unwrap();
        assert!(with_lease.ready_task_ids.is_empty());
        assert_eq!(
            with_lease.running_task_ids,
            vec![graph.tasks[0].task_id.clone()]
        );
        assert_eq!(
            with_lease.blockers.get(&graph.tasks[0].task_id),
            Some(&ResumeBlocker::RunningCheckpoint)
        );
    }

    #[test]
    fn failed_retry_safe_attempt_without_ticket_can_be_retried() {
        let mut store = RuntimeTaskStore::default();
        let mut graph = stored_graph();
        graph.tasks[0].state = TaskState::Failed;
        store.save_graph(&graph);
        let capability = file_read_capability();
        let attempt = RuntimeTaskAttempt {
            attempt_id: "rta_failed_retry_safe".into(),
            graph_id: graph.graph_id.clone(),
            task_id: graph.tasks[0].task_id.clone(),
            run_id: "run_failed_retry_safe".into(),
            capability_id: "file.read".into(),
            idempotency_key: runtime_idempotency_key(&graph, &graph.tasks[0], &capability),
            retry_safe: true,
            stage: RuntimeAttemptStage::Failed,
            ticket_id: None,
            ledger_event_id: None,
            error: Some("crashed before ticket issuing".into()),
            created_at: Utc::now(),
        };
        store.record_attempt(attempt.clone()).unwrap();

        let inspect_plan = resume_plan_from(
            &store,
            &graph.graph_id,
            RunningTaskPolicy::RequireInspection,
            None,
        )
        .unwrap();
        assert_eq!(
            inspect_plan.failed_task_ids,
            vec![graph.tasks[0].task_id.clone()]
        );
        assert_eq!(
            inspect_plan
                .adoption_recommendations
                .get(&graph.tasks[0].task_id)
                .unwrap()
                .action,
            RuntimeAdoptionAction::RetryReady
        );

        let retry_plan =
            resume_plan_from(&store, &graph.graph_id, RunningTaskPolicy::RetryReady, None).unwrap();
        assert_eq!(
            retry_plan.ready_task_ids,
            vec![graph.tasks[0].task_id.clone()]
        );
        assert!(retry_plan.failed_task_ids.is_empty());
        assert_eq!(
            retry_plan
                .adoption_recommendations
                .get(&graph.tasks[0].task_id)
                .unwrap()
                .attempt_id,
            Some(attempt.attempt_id)
        );
    }

    #[test]
    fn failed_attempt_with_ticket_requires_inspection_even_when_retry_safe() {
        let mut store = RuntimeTaskStore::default();
        let mut graph = stored_graph();
        graph.tasks[0].state = TaskState::Failed;
        store.save_graph(&graph);
        let capability = file_read_capability();
        store
            .record_attempt(RuntimeTaskAttempt {
                attempt_id: "rta_failed_with_ticket".into(),
                graph_id: graph.graph_id.clone(),
                task_id: graph.tasks[0].task_id.clone(),
                run_id: "run_failed_with_ticket".into(),
                capability_id: "file.read".into(),
                idempotency_key: runtime_idempotency_key(&graph, &graph.tasks[0], &capability),
                retry_safe: true,
                stage: RuntimeAttemptStage::Failed,
                ticket_id: Some("ticket_maybe_used".into()),
                ledger_event_id: None,
                error: Some("crashed after ticket issuing".into()),
                created_at: Utc::now(),
            })
            .unwrap();

        let retry_plan =
            resume_plan_from(&store, &graph.graph_id, RunningTaskPolicy::RetryReady, None).unwrap();

        assert!(retry_plan.ready_task_ids.is_empty());
        assert_eq!(
            retry_plan.failed_task_ids,
            vec![graph.tasks[0].task_id.clone()]
        );
        assert_eq!(
            retry_plan
                .adoption_recommendations
                .get(&graph.tasks[0].task_id)
                .unwrap()
                .action,
            RuntimeAdoptionAction::InspectRequired
        );
    }

    #[test]
    fn provider_committed_probe_marks_failed_attempt_already_committed() {
        let mut store = RuntimeTaskStore::default();
        let mut graph = stored_graph();
        graph.tasks[0].state = TaskState::Failed;
        store.save_graph(&graph);
        let capability = file_read_capability();
        store
            .record_attempt(RuntimeTaskAttempt {
                attempt_id: "rta_provider_committed".into(),
                graph_id: graph.graph_id.clone(),
                task_id: graph.tasks[0].task_id.clone(),
                run_id: "run_provider_committed".into(),
                capability_id: "file.read".into(),
                idempotency_key: runtime_idempotency_key(&graph, &graph.tasks[0], &capability),
                retry_safe: true,
                stage: RuntimeAttemptStage::Failed,
                ticket_id: Some("ticket_external_uncertain".into()),
                ledger_event_id: None,
                error: Some("crashed after provider accepted request".into()),
                created_at: Utc::now(),
            })
            .unwrap();
        let probe = StaticAdoptionProbe::new(RuntimeAdoptionProbeStatus::Committed);

        let plan = resume_plan_from(
            &store,
            &graph.graph_id,
            RunningTaskPolicy::RetryReady,
            Some(&probe),
        )
        .unwrap();
        let recommendation = plan
            .adoption_recommendations
            .get(&graph.tasks[0].task_id)
            .unwrap();

        assert!(plan.ready_task_ids.is_empty());
        assert_eq!(plan.failed_task_ids, vec![graph.tasks[0].task_id.clone()]);
        assert_eq!(
            recommendation.action,
            RuntimeAdoptionAction::AlreadyCommitted
        );
        assert_eq!(
            recommendation.provider_probe.as_ref().unwrap().status,
            RuntimeAdoptionProbeStatus::Committed
        );
    }

    #[test]
    fn provider_not_found_probe_can_unlock_retry_safe_failed_attempt() {
        let mut store = RuntimeTaskStore::default();
        let mut graph = stored_graph();
        graph.tasks[0].state = TaskState::Failed;
        store.save_graph(&graph);
        let capability = file_read_capability();
        store
            .record_attempt(RuntimeTaskAttempt {
                attempt_id: "rta_provider_not_found".into(),
                graph_id: graph.graph_id.clone(),
                task_id: graph.tasks[0].task_id.clone(),
                run_id: "run_provider_not_found".into(),
                capability_id: "file.read".into(),
                idempotency_key: runtime_idempotency_key(&graph, &graph.tasks[0], &capability),
                retry_safe: true,
                stage: RuntimeAttemptStage::Failed,
                ticket_id: None,
                ledger_event_id: None,
                error: Some("crashed before provider side effect".into()),
                created_at: Utc::now(),
            })
            .unwrap();
        let probe = StaticAdoptionProbe::new(RuntimeAdoptionProbeStatus::NotFound);

        let plan = resume_plan_from(
            &store,
            &graph.graph_id,
            RunningTaskPolicy::RetryReady,
            Some(&probe),
        )
        .unwrap();
        let recommendation = plan
            .adoption_recommendations
            .get(&graph.tasks[0].task_id)
            .unwrap();

        assert_eq!(plan.ready_task_ids, vec![graph.tasks[0].task_id.clone()]);
        assert!(plan.failed_task_ids.is_empty());
        assert_eq!(recommendation.action, RuntimeAdoptionAction::RetryReady);
        assert_eq!(
            recommendation.provider_probe.as_ref().unwrap().status,
            RuntimeAdoptionProbeStatus::NotFound
        );
    }

    #[test]
    fn adoption_probe_registry_routes_by_capability_then_provider() {
        let task = stored_graph_with_capability("stripe.payment.create").tasks[0].clone();
        let mut registry = RuntimeAdoptionProbeRegistry::default();
        registry.register_provider(
            "stripe",
            StaticAdoptionProbe::new(RuntimeAdoptionProbeStatus::Pending),
        );

        let provider_probe = registry.probe_for_task(&task).unwrap();
        let task_record = RuntimeTaskRecord {
            graph_id: "tg_registry".into(),
            task: task.clone(),
            last_event_id: None,
            last_stage: None,
            last_attempt_id: None,
            idempotency_key: None,
            retry_safe: None,
            message: None,
            progress: 0.0,
            updated_at: Utc::now(),
        };
        let attempt = failed_attempt_for_graph(
            &stored_graph_with_capability("stripe.payment.create"),
            "rta_registry",
            false,
            Some("ticket_registry"),
        );
        assert_eq!(
            provider_probe
                .probe(&task_record, &attempt)
                .unwrap()
                .unwrap()
                .status,
            RuntimeAdoptionProbeStatus::Pending
        );

        registry.register_capability(
            "stripe.payment.create",
            StaticAdoptionProbe::new(RuntimeAdoptionProbeStatus::Committed),
        );
        let capability_probe = registry.probe_for_task(&task).unwrap();
        assert_eq!(
            capability_probe
                .probe(&task_record, &attempt)
                .unwrap()
                .unwrap()
                .status,
            RuntimeAdoptionProbeStatus::Committed
        );
        assert!(registry.contains_provider("stripe"));
        assert!(registry.contains_capability("stripe.payment.create"));
        assert_eq!(registry.len(), 2);
        assert_eq!(
            provider_id_from_capability("stripe.payment.create").as_deref(),
            Some("stripe")
        );
    }

    #[test]
    fn recorded_provider_probe_drives_resume_plan_without_live_probe() {
        let mut store = RuntimeTaskStore::default();
        let mut graph = stored_graph();
        graph.tasks[0].state = TaskState::Failed;
        store.save_graph(&graph);
        let capability = file_read_capability();
        let attempt = RuntimeTaskAttempt {
            attempt_id: "rta_recorded_probe".into(),
            graph_id: graph.graph_id.clone(),
            task_id: graph.tasks[0].task_id.clone(),
            run_id: "run_recorded_probe".into(),
            capability_id: "file.read".into(),
            idempotency_key: runtime_idempotency_key(&graph, &graph.tasks[0], &capability),
            retry_safe: true,
            stage: RuntimeAttemptStage::Failed,
            ticket_id: Some("ticket_uncertain".into()),
            ledger_event_id: None,
            error: Some("provider accepted but runtime crashed".into()),
            created_at: Utc::now(),
        };
        store.record_attempt(attempt.clone()).unwrap();
        store
            .record_adoption_probe(adoption_probe_record_for(
                &graph,
                &attempt,
                RuntimeAdoptionProbeStatus::Committed,
            ))
            .unwrap();

        let plan =
            resume_plan_from(&store, &graph.graph_id, RunningTaskPolicy::RetryReady, None).unwrap();
        let recommendation = plan
            .adoption_recommendations
            .get(&graph.tasks[0].task_id)
            .unwrap();

        assert!(plan.ready_task_ids.is_empty());
        assert_eq!(
            recommendation.action,
            RuntimeAdoptionAction::AlreadyCommitted
        );
        assert_eq!(
            recommendation.provider_probe.as_ref().unwrap().status,
            RuntimeAdoptionProbeStatus::Committed
        );
    }

    #[test]
    fn runtime_session_uses_registered_provider_probe_for_adoption() {
        let temp = tempdir().unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        kernel.register_capability(file_read_capability()).unwrap();
        let mut runtime = RuntimeSession::new(kernel)
            .with_running_task_policy(RunningTaskPolicy::RetryReady)
            .with_adoption_probe_for_provider(
                "stripe",
                StaticAdoptionProbe::new(RuntimeAdoptionProbeStatus::Committed),
            );
        let mut graph = stored_graph_with_capability("stripe.payment.create");
        graph.tasks[0].state = TaskState::Failed;
        runtime.task_store.save_graph(&graph);
        let attempt = failed_attempt_for_graph(
            &graph,
            "rta_registered_provider_probe",
            true,
            Some("ticket_provider_uncertain"),
        );
        runtime.task_store.record_attempt(attempt).unwrap();

        let plan = runtime
            .probe_registered_adoption_and_resume_plan(&graph.graph_id)
            .unwrap();
        let recommendation = plan
            .adoption_recommendations
            .get(&graph.tasks[0].task_id)
            .unwrap();

        assert_eq!(
            recommendation.action,
            RuntimeAdoptionAction::AlreadyCommitted
        );
        assert_eq!(
            recommendation.provider_probe.as_ref().unwrap().status,
            RuntimeAdoptionProbeStatus::Committed
        );
        assert_eq!(
            runtime
                .task_store()
                .adoption_probes_for_graph(&graph.graph_id)
                .len(),
            1
        );
        assert!(runtime
            .adoption_probe_registry()
            .contains_provider("stripe"));
    }

    #[test]
    fn runtime_session_registered_capability_probe_overrides_provider_probe() {
        let temp = tempdir().unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        kernel.register_capability(file_read_capability()).unwrap();
        let mut runtime = RuntimeSession::new(kernel)
            .with_running_task_policy(RunningTaskPolicy::RetryReady)
            .with_adoption_probe_for_provider(
                "stripe",
                StaticAdoptionProbe::new(RuntimeAdoptionProbeStatus::Pending),
            )
            .with_adoption_probe_for_capability(
                "stripe.payment.create",
                StaticAdoptionProbe::new(RuntimeAdoptionProbeStatus::NotFound),
            );
        let mut graph = stored_graph_with_capability("stripe.payment.create");
        graph.tasks[0].state = TaskState::Failed;
        runtime.task_store.save_graph(&graph);
        let attempt =
            failed_attempt_for_graph(&graph, "rta_registered_capability_probe", true, None);
        runtime.task_store.record_attempt(attempt).unwrap();

        let plan = runtime
            .probe_registered_adoption_and_resume_plan(&graph.graph_id)
            .unwrap();
        let recommendation = plan
            .adoption_recommendations
            .get(&graph.tasks[0].task_id)
            .unwrap();

        assert_eq!(plan.ready_task_ids, vec![graph.tasks[0].task_id.clone()]);
        assert_eq!(recommendation.action, RuntimeAdoptionAction::RetryReady);
        assert_eq!(
            recommendation.provider_probe.as_ref().unwrap().status,
            RuntimeAdoptionProbeStatus::NotFound
        );
        assert!(runtime
            .adoption_probe_registry()
            .contains_capability("stripe.payment.create"));
    }

    #[test]
    fn runtime_session_exposes_resume_plan_with_provider_probe() {
        let temp = tempdir().unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        kernel.register_capability(file_read_capability()).unwrap();
        let mut runtime =
            RuntimeSession::new(kernel).with_running_task_policy(RunningTaskPolicy::RetryReady);
        let mut graph = stored_graph();
        graph.tasks[0].state = TaskState::Failed;
        runtime.task_store.save_graph(&graph);
        let capability = file_read_capability();
        runtime
            .task_store
            .record_attempt(RuntimeTaskAttempt {
                attempt_id: "rta_session_probe".into(),
                graph_id: graph.graph_id.clone(),
                task_id: graph.tasks[0].task_id.clone(),
                run_id: "run_session_probe".into(),
                capability_id: "file.read".into(),
                idempotency_key: runtime_idempotency_key(&graph, &graph.tasks[0], &capability),
                retry_safe: false,
                stage: RuntimeAttemptStage::Failed,
                ticket_id: Some("ticket_pending".into()),
                ledger_event_id: None,
                error: Some("pending provider result".into()),
                created_at: Utc::now(),
            })
            .unwrap();
        let probe = StaticAdoptionProbe::new(RuntimeAdoptionProbeStatus::Pending);

        let plan = runtime
            .resume_plan_with_probe(&graph.graph_id, &probe)
            .unwrap();
        let recommendation = plan
            .adoption_recommendations
            .get(&graph.tasks[0].task_id)
            .unwrap();

        assert!(plan.ready_task_ids.is_empty());
        assert_eq!(plan.failed_task_ids, vec![graph.tasks[0].task_id.clone()]);
        assert_eq!(
            recommendation.action,
            RuntimeAdoptionAction::InspectRequired
        );
        assert_eq!(
            recommendation.provider_probe.as_ref().unwrap().status,
            RuntimeAdoptionProbeStatus::Pending
        );
    }

    #[test]
    fn runtime_session_persists_adoption_probe_to_journal() {
        let temp = tempdir().unwrap();
        let journal_path = temp.path().join("adoption-probe.jsonl");
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        kernel.register_capability(file_read_capability()).unwrap();
        let mut runtime = RuntimeSession::with_journal(kernel, &journal_path)
            .unwrap()
            .with_running_task_policy(RunningTaskPolicy::RetryReady);
        let mut graph = stored_graph();
        graph.tasks[0].state = TaskState::Failed;
        runtime.task_store.save_graph(&graph);
        runtime
            .persist(RuntimeJournalRecord::Graph {
                graph: graph.clone(),
            })
            .unwrap();
        let capability = file_read_capability();
        let attempt = RuntimeTaskAttempt {
            attempt_id: "rta_journal_probe".into(),
            graph_id: graph.graph_id.clone(),
            task_id: graph.tasks[0].task_id.clone(),
            run_id: "run_journal_probe".into(),
            capability_id: "file.read".into(),
            idempotency_key: runtime_idempotency_key(&graph, &graph.tasks[0], &capability),
            retry_safe: true,
            stage: RuntimeAttemptStage::Failed,
            ticket_id: None,
            ledger_event_id: None,
            error: Some("crashed before side effect".into()),
            created_at: Utc::now(),
        };
        runtime.persist_task_attempt(attempt).unwrap();
        let probe = StaticAdoptionProbe::new(RuntimeAdoptionProbeStatus::NotFound);

        let plan = runtime
            .probe_adoption_and_resume_plan(&graph.graph_id, &probe)
            .unwrap();
        let recommendation = plan
            .adoption_recommendations
            .get(&graph.tasks[0].task_id)
            .unwrap();
        assert_eq!(recommendation.action, RuntimeAdoptionAction::RetryReady);
        assert_eq!(
            runtime
                .task_store
                .adoption_probes_for_graph(&graph.graph_id)
                .len(),
            1
        );
        drop(runtime);

        let replay = RuntimeSession::replay_journal(&journal_path).unwrap();
        let replay_plan = replay
            .resume_plan_with_policy(&graph.graph_id, RunningTaskPolicy::RetryReady)
            .unwrap();
        let replay_recommendation = replay_plan
            .adoption_recommendations
            .get(&graph.tasks[0].task_id)
            .unwrap();

        assert_eq!(
            replay_plan.ready_task_ids,
            vec![graph.tasks[0].task_id.clone()]
        );
        assert_eq!(
            replay_recommendation
                .provider_probe
                .as_ref()
                .unwrap()
                .status,
            RuntimeAdoptionProbeStatus::NotFound
        );
        assert_eq!(
            replay
                .graph_snapshot(&graph.graph_id)
                .unwrap()
                .adoption_probes
                .len(),
            1
        );
    }

    #[test]
    fn runtime_execution_releases_retry_lease_and_exposes_idempotency_key() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("hello.txt"), "hello runtime").unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        kernel.register_capability(file_read_capability()).unwrap();
        let mut runtime = RuntimeSession::new(kernel).with_retry_lease_ttl_ms(1_000);
        let intent = read_only_intent("read hello.txt", temp.path().to_string_lossy(), "file.read");

        let report = runtime.run(intent).unwrap();
        let leases = runtime
            .task_store()
            .retry_leases_for_graph(&report.graph.graph_id);

        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].state, RuntimeRetryLeaseState::Released);
        assert_eq!(
            leases[0].idempotency_key,
            report.outcomes[0].idempotency_key
        );
        assert!(runtime
            .task_store()
            .active_retry_lease_for_task(&report.graph.tasks[0].task_id)
            .is_none());
    }

    #[test]
    fn writes_runtime_journal_and_replays_graph_snapshot() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("hello.txt"), "hello runtime").unwrap();
        let journal_path = temp.path().join("runtime").join("session.jsonl");
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        kernel.register_capability(file_read_capability()).unwrap();
        let mut runtime = RuntimeSession::with_journal(kernel, &journal_path).unwrap();
        assert_eq!(runtime.journal_path(), Some(journal_path.as_path()));
        let intent = read_only_intent("read hello.txt", temp.path().to_string_lossy(), "file.read");

        let report = runtime.run(intent).unwrap();

        assert!(journal_path.exists());
        let replay = RuntimeSession::replay_journal(&journal_path).unwrap();
        let snapshot = replay.graph_snapshot(&report.graph.graph_id).unwrap();
        assert_eq!(snapshot.graph.graph_id, report.graph.graph_id);
        assert_eq!(
            snapshot.planner.as_ref().unwrap().plan_hash,
            report.planner.plan_hash
        );
        assert_eq!(snapshot.tasks.len(), 1);
        assert_eq!(snapshot.tasks[0].task.state, TaskState::Completed);
        assert_eq!(snapshot.events.len(), report.events.len());
        let query = replay.query_snapshot(&report.graph.graph_id).unwrap();
        assert_eq!(query.graph.completed_count, 1);
        assert_eq!(
            query.planner.as_ref().unwrap().source,
            PlannerSource::Deterministic
        );
        assert_eq!(
            query.tasks[0].idempotency_key,
            Some(report.outcomes[0].idempotency_key.clone())
        );
        assert_eq!(query.attempts.len(), 2);
        let projection_path = temp.path().join("runtime").join("projection.json");
        let projection = replay.write_projection(&projection_path).unwrap();
        let graph_id = report.graph.graph_id.clone();
        assert_eq!(projection.task_store.graph_ids(), vec![graph_id.clone()]);
        assert_eq!(projection.event_stream.cursor(), report.events.len());

        let index_path = temp.path().join("runtime").join("task-index.json");
        let index = replay.write_task_index(&index_path).unwrap();
        let restored_index = RuntimeSession::read_task_index(&index_path).unwrap();
        assert_eq!(restored_index.graph_list().len(), 1);
        assert_eq!(restored_index.tasks_by_state(TaskState::Completed).len(), 1);
        assert_eq!(restored_index.event_cursor, report.events.len());
        assert_eq!(restored_index, index);

        let feed = replay.event_feed(0, Some(&graph_id)).unwrap();
        assert_eq!(feed.event_count, report.events.len());
        assert_eq!(feed.next_cursor, report.events.len());
        assert_eq!(feed.latest_stage, Some(RuntimeStage::Completed));
        assert_eq!(feed.latest_progress, 1.0);
        assert!(feed.is_complete);
        let empty_feed = replay
            .event_feed(feed.next_cursor, Some(&graph_id))
            .unwrap();
        assert_eq!(empty_feed.event_count, 0);
        assert_eq!(empty_feed.latest_stage, Some(RuntimeStage::Completed));
    }

    #[test]
    fn journal_lock_blocks_second_writer_until_drop() {
        let temp = tempdir().unwrap();
        let journal_path = temp.path().join("locked.jsonl");
        let first_journal = RuntimeJournal::open(&journal_path).unwrap();
        assert!(first_journal.lock_path().exists());
        let lock_info = RuntimeJournal::lock_info(&journal_path).unwrap().unwrap();
        assert_eq!(lock_info.schema_version, 1);
        assert_eq!(lock_info.journal_path, journal_path);
        assert_eq!(lock_info.lock_path, first_journal.lock_path());
        assert_eq!(lock_info.owner_pid, std::process::id());

        let second_open = RuntimeJournal::open(&journal_path);

        assert!(matches!(
            second_open,
            Err(RuntimeError::JournalLocked(ref path)) if path == first_journal.lock_path()
        ));
        drop(first_journal);
        assert!(!journal_lock_path(&journal_path).exists());
        assert!(RuntimeJournal::open(&journal_path).is_ok());
    }

    #[test]
    fn journal_lock_stale_cleanup_is_explicit_and_age_guarded() {
        let temp = tempdir().unwrap();
        let journal_path = temp.path().join("stale.jsonl");
        let lock_path = journal_lock_path(&journal_path);
        let lock_info = RuntimeJournalLockInfo {
            schema_version: 1,
            journal_path: journal_path.clone(),
            lock_path: lock_path.clone(),
            owner_pid: 42,
            created_at: Utc::now() - chrono::Duration::seconds(60),
        };
        write_json_file(&lock_path, &lock_info).unwrap();

        assert!(matches!(
            RuntimeJournal::clear_stale_lock(&journal_path, 120_000),
            Err(RuntimeError::JournalLockNotStale(path)) if path == lock_path
        ));
        assert!(lock_path.exists());

        assert!(RuntimeJournal::clear_stale_lock(&journal_path, 1_000).unwrap());
        assert!(!lock_path.exists());
        assert!(!RuntimeJournal::clear_stale_lock(&journal_path, 1_000).unwrap());
    }

    #[test]
    fn replayed_journal_respects_active_writer_lock() {
        let temp = tempdir().unwrap();
        let journal_path = temp.path().join("replay-locked.jsonl");
        let mut first_kernel = Kernel::new_in_memory(temp.path()).unwrap();
        first_kernel
            .register_capability(file_read_capability())
            .unwrap();
        let first_runtime = RuntimeSession::with_journal(first_kernel, &journal_path).unwrap();

        let mut second_kernel = Kernel::new_in_memory(temp.path()).unwrap();
        second_kernel
            .register_capability(file_read_capability())
            .unwrap();
        let second_runtime = RuntimeSession::with_replayed_journal(second_kernel, &journal_path);

        assert!(matches!(
            second_runtime,
            Err(RuntimeError::JournalLocked(ref path))
                if path == &journal_lock_path(&journal_path)
        ));
        drop(first_runtime);

        let mut third_kernel = Kernel::new_in_memory(temp.path()).unwrap();
        third_kernel
            .register_capability(file_read_capability())
            .unwrap();
        assert!(RuntimeSession::with_replayed_journal(third_kernel, &journal_path).is_ok());
    }

    #[test]
    fn can_continue_appending_after_replayed_journal() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("a.txt"), "alpha").unwrap();
        fs::write(temp.path().join("b.txt"), "beta").unwrap();
        let journal_path = temp.path().join("runtime.jsonl");
        let mut first_kernel = Kernel::new_in_memory(temp.path()).unwrap();
        first_kernel
            .register_capability(file_read_capability())
            .unwrap();
        let mut first_runtime = RuntimeSession::with_journal(first_kernel, &journal_path).unwrap();
        let first_intent =
            read_only_intent("read a.txt", temp.path().to_string_lossy(), "file.read");
        let first_report = first_runtime.run(first_intent).unwrap();
        let first_event_count = first_runtime.event_cursor();
        drop(first_runtime);

        let mut second_kernel = Kernel::new_in_memory(temp.path()).unwrap();
        second_kernel
            .register_capability(file_read_capability())
            .unwrap();
        let mut second_runtime =
            RuntimeSession::with_replayed_journal(second_kernel, &journal_path).unwrap();
        assert_eq!(second_runtime.event_cursor(), first_event_count);
        assert!(second_runtime
            .graph_snapshot(&first_report.graph.graph_id)
            .is_ok());
        let second_intent =
            read_only_intent("read b.txt", temp.path().to_string_lossy(), "file.read");

        let second_report = second_runtime.run(second_intent).unwrap();

        assert!(second_runtime.event_cursor() > first_event_count);
        let replay = RuntimeSession::replay_journal(&journal_path).unwrap();
        assert!(replay.graph_snapshot(&first_report.graph.graph_id).is_ok());
        assert!(replay.graph_snapshot(&second_report.graph.graph_id).is_ok());
    }

    #[test]
    fn replayed_journal_builds_resume_plan_for_incomplete_graph() {
        let temp = tempdir().unwrap();
        let journal_path = temp.path().join("resume.jsonl");
        let mut graph = TaskGraph {
            graph_id: "tg_resume".into(),
            goal: "resume multi-step read".into(),
            path: RuntimePath::TaskPath,
            tasks: vec![
                TaskNode {
                    task_id: "task_done".into(),
                    skill_id: Some("skill.done".into()),
                    capability_id: "file.read".into(),
                    target: DeltaTarget {
                        resource_type: ResourceType::File,
                        resource_ref: "a.txt".into(),
                    },
                    input: serde_json::json!({"path": "a.txt"}),
                    risk_level: RiskLevel::Low,
                    depends_on: vec![],
                    state: TaskState::Ready,
                },
                TaskNode {
                    task_id: "task_ready".into(),
                    skill_id: Some("skill.ready".into()),
                    capability_id: "file.read".into(),
                    target: DeltaTarget {
                        resource_type: ResourceType::File,
                        resource_ref: "b.txt".into(),
                    },
                    input: serde_json::json!({"path": "b.txt"}),
                    risk_level: RiskLevel::Low,
                    depends_on: vec!["task_done".into()],
                    state: TaskState::Ready,
                },
                TaskNode {
                    task_id: "task_blocked".into(),
                    skill_id: Some("skill.blocked".into()),
                    capability_id: "file.read".into(),
                    target: DeltaTarget {
                        resource_type: ResourceType::File,
                        resource_ref: "c.txt".into(),
                    },
                    input: serde_json::json!({"path": "c.txt"}),
                    risk_level: RiskLevel::Low,
                    depends_on: vec!["task_ready".into()],
                    state: TaskState::Ready,
                },
            ],
        };
        order_tasks_by_dependency(&mut graph.tasks);
        let mut journal = RuntimeJournal::open(&journal_path).unwrap();
        journal
            .append(&RuntimeJournalRecord::Graph {
                graph: graph.clone(),
            })
            .unwrap();
        journal
            .append(&RuntimeJournalRecord::Event {
                event: RuntimeEvent {
                    event_id: "re_done".into(),
                    graph_id: Some(graph.graph_id.clone()),
                    run_id: Some("run_done".into()),
                    task_id: Some("task_done".into()),
                    stage: RuntimeStage::Completed,
                    message: "task completed".into(),
                    progress: 1.0,
                    timestamp: Utc::now(),
                },
            })
            .unwrap();
        drop(journal);

        let replay = RuntimeSession::replay_journal(&journal_path).unwrap();
        let plan = replay.resume_plan(&graph.graph_id).unwrap();

        assert!(!plan.is_complete);
        assert_eq!(plan.completed_task_ids, vec!["task_done"]);
        assert_eq!(plan.ready_task_ids, vec!["task_ready"]);
        assert_eq!(plan.blocked_task_ids, vec!["task_blocked"]);
        assert_eq!(
            plan.blockers.get("task_blocked"),
            Some(&ResumeBlocker::DependencyIncomplete)
        );
        assert_eq!(replay.resume_plans().unwrap().len(), 1);
    }

    #[test]
    fn resume_ready_tasks_executes_remaining_tasks_through_p0() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("done.txt"), "done").unwrap();
        fs::write(temp.path().join("next.txt"), "next").unwrap();
        let journal_path = temp.path().join("resume-run.jsonl");
        let mut graph = TaskGraph {
            graph_id: "tg_resume_run".into(),
            goal: "resume remaining read".into(),
            path: RuntimePath::TaskPath,
            tasks: vec![
                TaskNode {
                    task_id: "task_done".into(),
                    skill_id: Some("skill.done".into()),
                    capability_id: "file.read".into(),
                    target: DeltaTarget {
                        resource_type: ResourceType::File,
                        resource_ref: "done.txt".into(),
                    },
                    input: serde_json::json!({"path": "done.txt"}),
                    risk_level: RiskLevel::Low,
                    depends_on: vec![],
                    state: TaskState::Ready,
                },
                TaskNode {
                    task_id: "task_next".into(),
                    skill_id: Some("skill.next".into()),
                    capability_id: "file.read".into(),
                    target: DeltaTarget {
                        resource_type: ResourceType::File,
                        resource_ref: "next.txt".into(),
                    },
                    input: serde_json::json!({"path": "next.txt"}),
                    risk_level: RiskLevel::Low,
                    depends_on: vec!["task_done".into()],
                    state: TaskState::Ready,
                },
            ],
        };
        order_tasks_by_dependency(&mut graph.tasks);
        let mut journal = RuntimeJournal::open(&journal_path).unwrap();
        journal
            .append(&RuntimeJournalRecord::Graph {
                graph: graph.clone(),
            })
            .unwrap();
        journal
            .append(&RuntimeJournalRecord::Event {
                event: RuntimeEvent {
                    event_id: "re_done".into(),
                    graph_id: Some(graph.graph_id.clone()),
                    run_id: Some("run_done".into()),
                    task_id: Some("task_done".into()),
                    stage: RuntimeStage::Completed,
                    message: "task completed".into(),
                    progress: 1.0,
                    timestamp: Utc::now(),
                },
            })
            .unwrap();
        drop(journal);
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        kernel.register_capability(file_read_capability()).unwrap();
        let mut runtime = RuntimeSession::with_replayed_journal(kernel, &journal_path).unwrap();
        let intent = read_only_intent(
            "resume file.read next.txt",
            temp.path().to_string_lossy(),
            "file.read",
        );

        let report = runtime.resume_ready_tasks(intent, &graph.graph_id).unwrap();

        assert_eq!(report.before.ready_task_ids, vec!["task_next"]);
        assert!(report.after.is_complete);
        assert_eq!(report.outcomes.len(), 1);
        assert_eq!(report.outcomes[0].task_id, "task_next");
        assert_eq!(report.outcomes[0].output["content"], "next");
        assert_eq!(
            runtime
                .kernel()
                .replay_ledger_audit()
                .unwrap()
                .successful_events,
            1
        );

        let replay = RuntimeSession::replay_journal(&journal_path).unwrap();
        assert!(replay.resume_plan(&graph.graph_id).unwrap().is_complete);
    }

    #[test]
    fn running_checkpoint_requires_inspection_unless_retry_is_explicit() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("running.txt"), "running").unwrap();
        let journal_path = temp.path().join("running-checkpoint.jsonl");
        let graph = TaskGraph {
            graph_id: "tg_running".into(),
            goal: "resume running task".into(),
            path: RuntimePath::FastPath,
            tasks: vec![TaskNode {
                task_id: "task_running".into(),
                skill_id: Some("skill.running".into()),
                capability_id: "file.read".into(),
                target: DeltaTarget {
                    resource_type: ResourceType::File,
                    resource_ref: "running.txt".into(),
                },
                input: serde_json::json!({"path": "running.txt"}),
                risk_level: RiskLevel::Low,
                depends_on: vec![],
                state: TaskState::Ready,
            }],
        };
        let mut journal = RuntimeJournal::open(&journal_path).unwrap();
        journal
            .append(&RuntimeJournalRecord::Graph {
                graph: graph.clone(),
            })
            .unwrap();
        journal
            .append(&RuntimeJournalRecord::Attempt {
                attempt: RuntimeTaskAttempt {
                    attempt_id: "rta_running".into(),
                    graph_id: graph.graph_id.clone(),
                    task_id: "task_running".into(),
                    run_id: "run_running".into(),
                    capability_id: "file.read".into(),
                    idempotency_key: "sha256:read-safe".into(),
                    retry_safe: true,
                    stage: RuntimeAttemptStage::Started,
                    ticket_id: None,
                    ledger_event_id: None,
                    error: None,
                    created_at: Utc::now(),
                },
            })
            .unwrap();
        journal
            .append(&RuntimeJournalRecord::Event {
                event: RuntimeEvent {
                    event_id: "re_running".into(),
                    graph_id: Some(graph.graph_id.clone()),
                    run_id: Some("run_running".into()),
                    task_id: Some("task_running".into()),
                    stage: RuntimeStage::Executing,
                    message: "executing through trusted kernel".into(),
                    progress: 0.7,
                    timestamp: Utc::now(),
                },
            })
            .unwrap();
        drop(journal);

        let replay = RuntimeSession::replay_journal(&journal_path).unwrap();
        let default_plan = replay.resume_plan(&graph.graph_id).unwrap();
        assert!(default_plan.ready_task_ids.is_empty());
        assert_eq!(default_plan.running_task_ids, vec!["task_running"]);
        assert_eq!(
            default_plan.blockers.get("task_running"),
            Some(&ResumeBlocker::RunningCheckpoint)
        );

        let retry_plan = replay
            .resume_plan_with_policy(&graph.graph_id, RunningTaskPolicy::RetryReady)
            .unwrap();
        assert_eq!(retry_plan.ready_task_ids, vec!["task_running"]);
        assert!(retry_plan.running_task_ids.is_empty());

        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        kernel.register_capability(file_read_capability()).unwrap();
        let mut runtime = RuntimeSession::with_replayed_journal(kernel, &journal_path)
            .unwrap()
            .with_running_task_policy(RunningTaskPolicy::RetryReady);
        let intent = read_only_intent(
            "retry file.read running.txt",
            temp.path().to_string_lossy(),
            "file.read",
        );

        let report = runtime.resume_ready_tasks(intent, &graph.graph_id).unwrap();

        assert_eq!(report.before.ready_task_ids, vec!["task_running"]);
        assert!(report.after.is_complete);
        assert_eq!(report.outcomes.len(), 1);
        assert_eq!(report.outcomes[0].output["content"], "running");
    }

    #[test]
    fn non_idempotent_running_checkpoint_stays_blocked_even_with_retry_policy() {
        let temp = tempdir().unwrap();
        let journal_path = temp.path().join("non-idempotent-running.jsonl");
        let graph = TaskGraph {
            graph_id: "tg_non_idempotent".into(),
            goal: "resume external side effect".into(),
            path: RuntimePath::TrustedExecutionPath,
            tasks: vec![TaskNode {
                task_id: "task_side_effect".into(),
                skill_id: Some("skill.side.effect".into()),
                capability_id: "network.post".into(),
                target: DeltaTarget {
                    resource_type: ResourceType::Network,
                    resource_ref: "https://api.example.test/payments".into(),
                },
                input: serde_json::json!({"amount": 10}),
                risk_level: RiskLevel::High,
                depends_on: vec![],
                state: TaskState::Ready,
            }],
        };
        let mut journal = RuntimeJournal::open(&journal_path).unwrap();
        journal
            .append(&RuntimeJournalRecord::Graph {
                graph: graph.clone(),
            })
            .unwrap();
        journal
            .append(&RuntimeJournalRecord::Attempt {
                attempt: RuntimeTaskAttempt {
                    attempt_id: "rta_side_effect".into(),
                    graph_id: graph.graph_id.clone(),
                    task_id: "task_side_effect".into(),
                    run_id: "run_side_effect".into(),
                    capability_id: "network.post".into(),
                    idempotency_key: "sha256:unsafe-side-effect".into(),
                    retry_safe: false,
                    stage: RuntimeAttemptStage::Started,
                    ticket_id: None,
                    ledger_event_id: None,
                    error: None,
                    created_at: Utc::now(),
                },
            })
            .unwrap();
        journal
            .append(&RuntimeJournalRecord::Event {
                event: RuntimeEvent {
                    event_id: "re_side_effect".into(),
                    graph_id: Some(graph.graph_id.clone()),
                    run_id: Some("run_side_effect".into()),
                    task_id: Some("task_side_effect".into()),
                    stage: RuntimeStage::Executing,
                    message: "executing side effect".into(),
                    progress: 0.7,
                    timestamp: Utc::now(),
                },
            })
            .unwrap();
        drop(journal);

        let replay = RuntimeSession::replay_journal(&journal_path).unwrap();
        let retry_plan = replay
            .resume_plan_with_policy(&graph.graph_id, RunningTaskPolicy::RetryReady)
            .unwrap();

        assert!(retry_plan.ready_task_ids.is_empty());
        assert_eq!(retry_plan.running_task_ids, vec!["task_side_effect"]);
        assert_eq!(
            retry_plan.blockers.get("task_side_effect"),
            Some(&ResumeBlocker::NonIdempotentRunningCheckpoint)
        );
    }

    #[test]
    fn resume_ready_tasks_does_not_execute_when_only_approval_blocked() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("hello.txt"), "hello runtime").unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        kernel.register_capability(file_read_capability()).unwrap();
        let mut runtime = RuntimeSession::new(kernel);
        let mut intent =
            read_only_intent("read hello.txt", temp.path().to_string_lossy(), "file.read");
        intent.risk_level = RiskLevel::High;
        let result = runtime.run(intent.clone());
        assert!(matches!(result, Err(RuntimeError::ApprovalRequired(_))));
        let graph_id = runtime
            .events()
            .iter()
            .find_map(|event| event.graph_id.clone())
            .unwrap();

        let report = runtime.resume_ready_tasks(intent, &graph_id).unwrap();

        assert!(report.before.ready_task_ids.is_empty());
        assert_eq!(report.before.awaiting_approval_task_ids.len(), 1);
        assert!(report.outcomes.is_empty());
        assert_eq!(
            runtime
                .kernel()
                .replay_ledger_audit()
                .unwrap()
                .successful_events,
            0
        );
    }

    #[test]
    fn approval_required_tasks_stop_before_ticket_issuing() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("hello.txt"), "hello runtime").unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        kernel.register_capability(file_read_capability()).unwrap();
        let mut runtime = RuntimeSession::new(kernel);
        let mut intent =
            read_only_intent("read hello.txt", temp.path().to_string_lossy(), "file.read");
        intent.risk_level = RiskLevel::High;

        let result = runtime.run(intent);

        assert!(matches!(result, Err(RuntimeError::ApprovalRequired(_))));
        assert!(runtime
            .events()
            .iter()
            .any(|event| event.stage == RuntimeStage::AwaitingApproval));
        let graph_id = runtime
            .events()
            .iter()
            .find_map(|event| event.graph_id.clone())
            .unwrap();
        let snapshot = runtime.graph_snapshot(&graph_id).unwrap();
        assert_eq!(snapshot.tasks[0].task.state, TaskState::AwaitingApproval);
        assert_eq!(
            snapshot.tasks[0].last_stage,
            Some(RuntimeStage::AwaitingApproval)
        );
        let plan = runtime.resume_plan(&graph_id).unwrap();
        assert!(!plan.is_complete);
        assert_eq!(
            plan.awaiting_approval_task_ids,
            vec![snapshot.tasks[0].task.task_id.clone()]
        );
        assert_eq!(
            plan.blockers.get(&snapshot.tasks[0].task.task_id),
            Some(&ResumeBlocker::AwaitingApproval)
        );
    }

    #[test]
    fn registers_skill_manifest_and_builds_task_path_plan() {
        let temp = tempdir().unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        kernel.register_capability(file_read_capability()).unwrap();
        let mut runtime = RuntimeSession::new(kernel);
        runtime
            .register_skill(read_skill("skill.file.read", "README.md"))
            .unwrap();
        runtime
            .register_skill(read_skill("skill.file.read.again", "README.md"))
            .unwrap();
        let intent = read_only_intent(
            "use skill.file.read and skill.file.read.again for file.read README.md",
            temp.path().to_string_lossy(),
            "file.read",
        );

        let plan = runtime.execution_plan(&intent).unwrap();

        assert_eq!(plan.graph.path, RuntimePath::TaskPath);
        assert_eq!(plan.graph.tasks.len(), 2);
        assert_eq!(plan.ready_order.len(), 2);
        assert_eq!(
            plan.graph.tasks[1].depends_on,
            vec![plan.graph.tasks[0].task_id.clone()]
        );
    }

    #[test]
    fn runtime_manifest_registry_persists_deduplicates_and_loads_skills() {
        let temp = tempdir().unwrap();
        let mut registry = RuntimeManifestRegistry::new();
        registry.register_module(file_module("module.files"));
        registry
            .register_skill(read_skill("skill.file.read", "a.txt"))
            .unwrap();
        registry
            .register_skill(read_skill("skill.file.read", "b.txt"))
            .unwrap();
        let path = temp.path().join("manifests.json");
        registry.write(&path).unwrap();

        let restored = RuntimeManifestRegistry::read(&path).unwrap();

        assert_eq!(restored.modules.len(), 1);
        assert_eq!(restored.skills.len(), 1);
        assert_eq!(restored.skills[0].entrypoint_ref, "b.txt");

        fs::write(temp.path().join("b.txt"), "beta").unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        kernel.register_capability(file_read_capability()).unwrap();
        let mut runtime = RuntimeSession::new(kernel);

        let loaded = runtime.load_manifest_registry(&restored).unwrap();

        assert_eq!(loaded, 1);
        assert_eq!(runtime.skills().len(), 1);
        let intent = read_only_intent(
            "run skill.file.read with file.read",
            temp.path().to_string_lossy(),
            "file.read",
        );
        let report = runtime.run(intent).unwrap();
        assert_eq!(report.outcomes[0].output["content"], "beta");
    }

    #[test]
    fn runtime_manifest_registry_rejects_skill_without_module() {
        let mut registry = RuntimeManifestRegistry::new();

        assert!(matches!(
            registry.register_skill(read_skill("skill.missing.module", "README.md")),
            Err(RuntimeError::SkillModuleNotFound {
                skill_id,
                module_id
            }) if skill_id == "skill.missing.module" && module_id == "module.files"
        ));
    }

    #[test]
    fn runtime_manifest_registry_filters_skills_by_profile() {
        let mut registry = RuntimeManifestRegistry::new();
        registry.register_module(file_module("module.files"));
        registry
            .register_skill(read_skill("skill.file.read", "a.txt"))
            .unwrap();
        let profile = RuntimePolicyProfile {
            profile_id: "runtime.memory_only".into(),
            allowed_capabilities: vec!["memory.read".into()],
            ..Default::default()
        };

        let skills = registry.skills_for_profile(&profile).unwrap();

        assert!(skills.is_empty());
    }

    #[test]
    fn runtime_manifest_registry_validates_module_dependencies() {
        let mut registry = RuntimeManifestRegistry::new();
        let mut dependent = file_module("module.reader");
        dependent.required_modules = vec!["module.files".into()];
        registry.register_module(dependent);

        assert!(matches!(
            registry.validate(),
            Err(RuntimeError::ModuleDependencyNotFound {
                module_id,
                dependency_id
            }) if module_id == "module.reader" && dependency_id == "module.files"
        ));

        registry.register_module(file_module("module.files"));
        assert!(registry.validate().is_ok());
    }

    #[test]
    fn runtime_manifest_registry_detects_module_dependency_cycles() {
        let mut registry = RuntimeManifestRegistry::new();
        let mut first = file_module("module.first");
        first.required_modules = vec!["module.second".into()];
        let mut second = file_module("module.second");
        second.required_modules = vec!["module.first".into()];
        registry.register_module(first);
        registry.register_module(second);

        assert!(matches!(
            registry.validate(),
            Err(RuntimeError::ModuleDependencyCycle(module_id))
                if module_id == "module.first" || module_id == "module.second"
        ));
    }

    #[test]
    fn runtime_manifest_registry_rejects_skill_outside_module_capabilities() {
        let mut registry = RuntimeManifestRegistry::new();
        let mut module = file_module("module.files");
        module.required_capabilities = vec!["memory.read".into()];
        module.provided_capabilities = vec!["memory.read".into()];
        registry.register_module(module);

        assert!(matches!(
            registry.register_skill(read_skill("skill.file.read", "a.txt")),
            Err(RuntimeError::SkillModuleCapabilityMismatch {
                skill_id,
                module_id,
                capability_id
            }) if skill_id == "skill.file.read"
                && module_id == "module.files"
                && capability_id == "file.read"
        ));
    }

    #[test]
    fn runtime_manifest_registry_validates_module_profile_refs() {
        let mut registry = RuntimeManifestRegistry::new();
        let mut module = file_module("module.files");
        module.policy_profile_ref = Some("shell.cli.readonly".into());
        registry.register_module(module);
        let profiles = RuntimeProfileRegistry::new();

        assert!(matches!(
            registry.validate_with_profiles(&profiles),
            Err(RuntimeError::ModuleProfileNotFound {
                module_id,
                profile_id
            }) if module_id == "module.files" && profile_id == "shell.cli.readonly"
        ));

        let mut profiles = RuntimeProfileRegistry::new();
        profiles.insert(RuntimeProfileManifest {
            profile: RuntimePolicyProfile {
                profile_id: "shell.cli.readonly".into(),
                allowed_capabilities: vec!["file.read".into()],
                allow_trusted_execution_path: false,
                ..Default::default()
            },
            parent_profile_id: Some("runtime.default".into()),
        });

        assert!(registry.validate_with_profiles(&profiles).is_ok());
    }

    #[test]
    fn fast_only_profile_allows_simple_fast_path_and_rejects_skills() {
        let temp = tempdir().unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        kernel.register_capability(file_read_capability()).unwrap();
        let mut runtime =
            RuntimeSession::new(kernel).with_policy_profile(RuntimePolicyProfile::fast_only());
        let intent = read_only_intent("read README.md", temp.path().to_string_lossy(), "file.read");

        assert_eq!(runtime.plan(&intent).unwrap().path, RuntimePath::FastPath);
        assert!(matches!(
            runtime.register_skill(read_skill("skill.file.read", "README.md")),
            Err(RuntimeError::SkillNotAllowed(skill_id)) if skill_id == "skill.file.read"
        ));
    }

    #[test]
    fn runtime_profile_rejects_disallowed_capability() {
        let temp = tempdir().unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        kernel.register_capability(file_read_capability()).unwrap();
        let profile = RuntimePolicyProfile {
            profile_id: "runtime.no_file_read".into(),
            allowed_capabilities: vec!["memory.read".into()],
            ..Default::default()
        };
        let runtime = RuntimeSession::new(kernel).with_policy_profile(profile);
        let intent = read_only_intent("read README.md", temp.path().to_string_lossy(), "file.read");

        assert!(matches!(
            runtime.plan(&intent),
            Err(RuntimeError::ProfileRejected(message))
                if message.contains("capability file.read")
        ));
    }

    #[test]
    fn runtime_profile_registry_persists_and_resolves_inheritance() {
        let temp = tempdir().unwrap();
        let mut registry = RuntimeProfileRegistry::new();
        let parent = RuntimePolicyProfile {
            profile_id: "shell.ide".into(),
            allowed_capabilities: vec!["file.read".into(), "memory.read".into()],
            allow_trusted_execution_path: false,
            max_tasks_per_graph: 8,
            ..Default::default()
        };
        registry.insert(RuntimeProfileManifest {
            profile: parent,
            parent_profile_id: None,
        });
        let child = RuntimePolicyProfile {
            profile_id: "shell.ide.fast".into(),
            allowed_capabilities: vec!["file.read".into()],
            allow_task_path: false,
            max_tasks_per_graph: 3,
            ..Default::default()
        };
        registry.insert(RuntimeProfileManifest {
            profile: child,
            parent_profile_id: Some("shell.ide".into()),
        });
        let path = temp.path().join("profiles.json");
        registry.write(&path).unwrap();

        let restored = RuntimeProfileRegistry::read(&path).unwrap();
        let resolved = restored.resolve("shell.ide.fast").unwrap();

        assert_eq!(resolved.profile_id, "shell.ide.fast");
        assert_eq!(resolved.allowed_capabilities, vec!["file.read"]);
        assert!(resolved.allow_fast_path);
        assert!(!resolved.allow_task_path);
        assert!(!resolved.allow_trusted_execution_path);
        assert_eq!(resolved.max_tasks_per_graph, 3);
    }

    #[test]
    fn runtime_profile_registry_detects_inheritance_cycles() {
        let mut registry = RuntimeProfileRegistry {
            schema_version: 1,
            profiles: vec![],
        };
        let a = RuntimePolicyProfile {
            profile_id: "a".into(),
            ..Default::default()
        };
        let b = RuntimePolicyProfile {
            profile_id: "b".into(),
            ..Default::default()
        };
        registry.insert(RuntimeProfileManifest {
            profile: a,
            parent_profile_id: Some("b".into()),
        });
        registry.insert(RuntimeProfileManifest {
            profile: b,
            parent_profile_id: Some("a".into()),
        });

        assert!(matches!(
            registry.resolve("a"),
            Err(RuntimeError::ProfileInheritanceCycle(profile_id)) if profile_id == "a"
        ));
    }

    #[test]
    fn runtime_profile_registry_includes_standard_shell_profiles() {
        let registry = RuntimeProfileRegistry::with_standard_shell_profiles();

        let cli = registry.resolve("shell.cli.fast").unwrap();
        assert_eq!(cli.allowed_capabilities, vec!["file.read"]);
        assert!(cli.allow_fast_path);
        assert!(!cli.allow_task_path);
        assert!(!cli.allow_trusted_execution_path);
        assert!(!cli.allow_skills);
        assert_eq!(cli.max_tasks_per_graph, 1);

        let ide = registry.resolve("shell.ide.readonly").unwrap();
        assert!(ide.allow_task_path);
        assert!(!ide.allow_trusted_execution_path);
        assert_eq!(ide.max_tasks_per_graph, 8);

        let digital_human = registry.resolve("shell.digital_human.readonly").unwrap();
        assert_eq!(
            digital_human.allowed_capabilities,
            vec!["file.read", "memory.read"]
        );
        assert!(!digital_human.allow_running_task_retry);

        let trusted_review = registry.resolve("shell.trusted.review").unwrap();
        assert!(trusted_review.allow_trusted_execution_path);
        assert!(!trusted_review.allow_running_task_retry);
    }

    #[test]
    fn runtime_session_can_apply_profile_from_registry() {
        let temp = tempdir().unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        kernel.register_capability(file_read_capability()).unwrap();
        let mut registry = RuntimeProfileRegistry::new();
        let mut cli_profile = RuntimePolicyProfile::fast_only();
        cli_profile.profile_id = "shell.cli.fast".into();
        registry.insert(RuntimeProfileManifest {
            profile: cli_profile,
            parent_profile_id: Some("runtime.default".into()),
        });

        let runtime = RuntimeSession::new(kernel)
            .with_profile_registry(&registry, "shell.cli.fast")
            .unwrap();

        assert_eq!(runtime.policy_profile().profile_id, "shell.cli.fast");
        assert!(!runtime.policy_profile().allow_task_path);
    }

    #[test]
    fn runtime_profile_can_disable_running_task_retry() {
        let temp = tempdir().unwrap();
        let journal_path = temp.path().join("profile-no-retry.jsonl");
        let graph = TaskGraph {
            graph_id: "tg_profile_no_retry".into(),
            goal: "resume running task".into(),
            path: RuntimePath::FastPath,
            tasks: vec![TaskNode {
                task_id: "task_running".into(),
                skill_id: None,
                capability_id: "file.read".into(),
                target: DeltaTarget {
                    resource_type: ResourceType::File,
                    resource_ref: "running.txt".into(),
                },
                input: serde_json::json!({"path": "running.txt"}),
                risk_level: RiskLevel::Low,
                depends_on: vec![],
                state: TaskState::Ready,
            }],
        };
        let mut journal = RuntimeJournal::open(&journal_path).unwrap();
        journal
            .append(&RuntimeJournalRecord::Graph {
                graph: graph.clone(),
            })
            .unwrap();
        journal
            .append(&RuntimeJournalRecord::Attempt {
                attempt: RuntimeTaskAttempt {
                    attempt_id: "rta_profile_no_retry".into(),
                    graph_id: graph.graph_id.clone(),
                    task_id: "task_running".into(),
                    run_id: "run_running".into(),
                    capability_id: "file.read".into(),
                    idempotency_key: "sha256:read-safe".into(),
                    retry_safe: true,
                    stage: RuntimeAttemptStage::Started,
                    ticket_id: None,
                    ledger_event_id: None,
                    error: None,
                    created_at: Utc::now(),
                },
            })
            .unwrap();
        journal
            .append(&RuntimeJournalRecord::Event {
                event: RuntimeEvent {
                    event_id: "re_running".into(),
                    graph_id: Some(graph.graph_id.clone()),
                    run_id: Some("run_running".into()),
                    task_id: Some("task_running".into()),
                    stage: RuntimeStage::Executing,
                    message: "executing through trusted kernel".into(),
                    progress: 0.7,
                    timestamp: Utc::now(),
                },
            })
            .unwrap();
        drop(journal);

        let profile = RuntimePolicyProfile {
            profile_id: "runtime.no_retry".into(),
            allow_running_task_retry: false,
            ..Default::default()
        };
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        kernel.register_capability(file_read_capability()).unwrap();
        let runtime = RuntimeSession::with_replayed_journal(kernel, &journal_path)
            .unwrap()
            .with_running_task_policy(RunningTaskPolicy::RetryReady)
            .with_policy_profile(profile);
        let plan = runtime.resume_plan(&graph.graph_id).unwrap();

        assert!(plan.ready_task_ids.is_empty());
        assert_eq!(plan.running_task_ids, vec!["task_running"]);
        assert_eq!(
            plan.running_task_policy,
            RunningTaskPolicy::RequireInspection
        );
    }

    #[test]
    fn runs_two_skill_tasks_in_dependency_order() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("a.txt"), "alpha").unwrap();
        fs::write(temp.path().join("b.txt"), "beta").unwrap();
        let mut kernel = Kernel::new_in_memory(temp.path()).unwrap();
        kernel.register_capability(file_read_capability()).unwrap();
        let mut runtime = RuntimeSession::new(kernel);
        runtime
            .register_skill(read_skill("skill.file.read.a", "a.txt"))
            .unwrap();
        runtime
            .register_skill(read_skill("skill.file.read.b", "b.txt"))
            .unwrap();
        let intent = read_only_intent(
            "run skill.file.read.a and skill.file.read.b with file.read",
            temp.path().to_string_lossy(),
            "file.read",
        );

        let report = runtime.run(intent).unwrap();

        assert_eq!(report.graph.path, RuntimePath::TaskPath);
        assert_eq!(report.outcomes.len(), 2);
        assert_eq!(report.outcomes[0].output["content"], "alpha");
        assert_eq!(report.outcomes[1].output["content"], "beta");
        let snapshot = runtime.graph_snapshot(&report.graph.graph_id).unwrap();
        assert_eq!(snapshot.tasks.len(), 2);
        assert_eq!(
            snapshot.tasks[0].task.task_id,
            report.graph.tasks[0].task_id
        );
        assert!(snapshot
            .tasks
            .iter()
            .all(|record| record.task.state == TaskState::Completed));
        assert_eq!(
            runtime
                .kernel()
                .replay_ledger_audit()
                .unwrap()
                .successful_events,
            2
        );
    }

    #[test]
    fn rejects_non_read_only_skill_manifest() {
        let temp = tempdir().unwrap();
        let kernel = Kernel::new_in_memory(temp.path()).unwrap();
        let mut runtime = RuntimeSession::new(kernel);
        let mut skill = read_skill("skill.file.write", "README.md");
        skill.permission_mode = PermissionMode::WorkspaceWrite;

        assert!(matches!(
            runtime.register_skill(skill),
            Err(RuntimeError::SkillNotAllowed(_))
        ));
    }
}
