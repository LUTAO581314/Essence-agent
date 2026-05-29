use chrono::{DateTime, Utc};
use moxi_contracts::{PermissionMode, RiskLevel, RunStatus, ShellAdapterManifest, ShellSurface};
use moxi_entry::{
    normalize_entry, EntryChannel, EntryContext, EntryError, EntryRequest, NormalizedEntry,
};
use moxi_runtime::{
    ResumeBlocker, RuntimeEventFeedSnapshot, RuntimeGraphListItem, RuntimePath,
    RuntimePolicyProfile, RuntimeProfileRegistry, RuntimeQuerySnapshot, RuntimeStage,
    RuntimeTaskView,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ShellError {
    #[error("entry normalization failed: {0}")]
    Entry(#[from] EntryError),
    #[error("runtime profile is incompatible with shell surface {surface:?}: {profile_id}")]
    IncompatibleProfile {
        surface: ShellSurface,
        profile_id: String,
    },
    #[error("shell surface {surface:?} does not support channel {channel:?}")]
    UnsupportedChannel {
        surface: ShellSurface,
        channel: EntryChannel,
    },
    #[error("shell surface {surface:?} does not support permission mode {permission_mode:?}")]
    UnsupportedPermissionMode {
        surface: ShellSurface,
        permission_mode: PermissionMode,
    },
}

pub type ShellResult<T> = Result<T, ShellError>;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ShellCommandKind {
    SubmitEntry,
    ShowStatus,
    ShowGraph,
    ShowApprovals,
    ShowAudit,
    Cancel,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ShellTrustBoundary {
    SubmitOnly,
    ProjectionOnly,
    ApprovalDisplayOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShellRequestDraft {
    pub surface: ShellSurface,
    pub tenant_id: String,
    pub user_id: String,
    pub workspace_root: String,
    pub goal: String,
    pub requested_capabilities: Vec<String>,
    pub risk_level: RiskLevel,
    pub permission_mode: PermissionMode,
    pub profile_id: Option<String>,
    pub session_id: Option<String>,
    pub request_id: Option<String>,
    pub source_ref: Option<String>,
}

impl ShellRequestDraft {
    pub fn cli_readonly(
        tenant_id: impl Into<String>,
        user_id: impl Into<String>,
        workspace_root: impl Into<String>,
        goal: impl Into<String>,
    ) -> Self {
        Self {
            surface: ShellSurface::Cli,
            tenant_id: tenant_id.into(),
            user_id: user_id.into(),
            workspace_root: workspace_root.into(),
            goal: goal.into(),
            requested_capabilities: vec!["file.read".into()],
            risk_level: RiskLevel::Low,
            permission_mode: PermissionMode::ReadOnly,
            profile_id: Some("shell.cli.fast".into()),
            session_id: None,
            request_id: None,
            source_ref: None,
        }
    }

    fn entry_channel(&self) -> EntryChannel {
        channel_for_surface(self.surface)
    }

    fn into_entry_request(self) -> EntryRequest {
        EntryRequest {
            context: EntryContext {
                channel: self.entry_channel(),
                tenant_id: self.tenant_id,
                user_id: self.user_id,
                workspace_root: self.workspace_root,
                session_id: self.session_id,
                request_id: self.request_id,
                source_ref: self.source_ref,
            },
            goal: self.goal,
            requested_capabilities: self.requested_capabilities,
            risk_level: self.risk_level,
            permission_mode: self.permission_mode,
            budget: Default::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ShellAdmission {
    pub surface: ShellSurface,
    pub command: ShellCommandKind,
    pub normalized_entry: NormalizedEntry,
    pub policy_profile: RuntimePolicyProfile,
    pub adapter_manifest: ShellAdapterManifest,
    pub trust_boundaries: Vec<ShellTrustBoundary>,
    pub cannot_execute_directly: bool,
    pub cannot_authorize: bool,
    pub requires_trusted_execution_path: bool,
    pub approval_hint: Option<ApprovalPrompt>,
    pub admitted_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalPrompt {
    pub approval_ref: Option<String>,
    pub status: RunStatus,
    pub risk_level: RiskLevel,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ShellProjection {
    pub surface: ShellSurface,
    pub profile_id: String,
    pub graph_id: Option<String>,
    pub graph_goal: Option<String>,
    pub runtime_path: Option<RuntimePath>,
    pub latest_stage: Option<RuntimeStage>,
    pub latest_message: Option<String>,
    pub latest_progress: f32,
    pub current_task_id: Option<String>,
    pub blockers: Vec<ShellBlockerView>,
    pub graphs: Vec<ShellGraphView>,
    pub tasks: Vec<ShellTaskView>,
    pub event_cursor: usize,
    pub is_complete: bool,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShellBlockerView {
    pub task_ref: String,
    pub blocker: ResumeBlocker,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ShellGraphView {
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
pub struct ShellTaskView {
    pub task_id: String,
    pub skill_id: Option<String>,
    pub capability_id: String,
    pub state: String,
    pub last_stage: Option<RuntimeStage>,
    pub progress: f32,
    pub message: Option<String>,
    pub blocker: Option<ResumeBlocker>,
}

pub struct ShellController {
    profile_registry: RuntimeProfileRegistry,
}

impl Default for ShellController {
    fn default() -> Self {
        Self {
            profile_registry: RuntimeProfileRegistry::with_standard_shell_profiles(),
        }
    }
}

impl ShellController {
    pub fn new(profile_registry: RuntimeProfileRegistry) -> Self {
        Self { profile_registry }
    }

    pub fn admit_shell_request(&self, draft: ShellRequestDraft) -> ShellResult<ShellAdmission> {
        let surface = draft.surface;
        let profile_id = draft
            .profile_id
            .clone()
            .unwrap_or_else(|| default_profile_for_surface(surface).to_owned());
        let policy_profile = self.profile_registry.resolve(&profile_id).map_err(|_| {
            ShellError::IncompatibleProfile {
                surface,
                profile_id: profile_id.clone(),
            }
        })?;
        ensure_profile_surface_compatibility(surface, &policy_profile)?;
        ensure_permission_surface_compatibility(surface, draft.permission_mode)?;
        let adapter_manifest = self.adapter_manifest(surface);
        let normalized_entry = normalize_entry(draft.into_entry_request())?;
        ensure_channel_surface_compatibility(surface, normalized_entry.channel)?;

        let requires_trusted_execution_path = matches!(
            normalized_entry.candidate.risk_level,
            RiskLevel::High | RiskLevel::Critical
        ) || matches!(
            normalized_entry.permission_mode,
            PermissionMode::Networked | PermissionMode::Privileged
        );
        let approval_hint = requires_trusted_execution_path.then(|| ApprovalPrompt {
            approval_ref: None,
            status: RunStatus::AwaitingApproval,
            risk_level: normalized_entry.candidate.risk_level,
            reason: "shell can only submit the request; trusted core must approve execution".into(),
        });

        Ok(ShellAdmission {
            surface,
            command: ShellCommandKind::SubmitEntry,
            normalized_entry,
            policy_profile,
            adapter_manifest,
            trust_boundaries: vec![
                ShellTrustBoundary::SubmitOnly,
                ShellTrustBoundary::ProjectionOnly,
                ShellTrustBoundary::ApprovalDisplayOnly,
            ],
            cannot_execute_directly: true,
            cannot_authorize: true,
            requires_trusted_execution_path,
            approval_hint,
            admitted_at: Utc::now(),
        })
    }

    pub fn project_event_feed(
        &self,
        surface: ShellSurface,
        profile_id: impl AsRef<str>,
        snapshot: RuntimeEventFeedSnapshot,
    ) -> ShellResult<ShellProjection> {
        let profile = self.resolve_compatible_profile(surface, profile_id.as_ref())?;
        Ok(ShellProjection {
            surface,
            profile_id: profile.profile_id,
            graph_id: snapshot.graph_id,
            graph_goal: None,
            runtime_path: None,
            latest_stage: snapshot.latest_stage,
            latest_message: snapshot.latest_message,
            latest_progress: snapshot.latest_progress,
            current_task_id: snapshot.current_task_id,
            blockers: snapshot
                .blockers
                .into_iter()
                .map(|(task_ref, blocker)| ShellBlockerView { task_ref, blocker })
                .collect(),
            graphs: vec![],
            tasks: vec![],
            event_cursor: snapshot.next_cursor,
            is_complete: snapshot.is_complete,
            generated_at: snapshot.generated_at,
        })
    }

    pub fn project_query_snapshot(
        &self,
        surface: ShellSurface,
        snapshot: RuntimeQuerySnapshot,
    ) -> ShellResult<ShellProjection> {
        let profile =
            self.resolve_compatible_profile(surface, &snapshot.policy_profile.profile_id)?;
        let graph = graph_view_from(snapshot.graph);
        let graph_id = graph.graph_id.clone();
        let graph_goal = graph.goal.clone();
        let runtime_path = graph.path;
        Ok(ShellProjection {
            surface,
            profile_id: profile.profile_id,
            graph_id: Some(graph_id),
            graph_goal: Some(graph_goal),
            runtime_path: Some(runtime_path),
            latest_stage: snapshot.events.last().map(|event| event.stage),
            latest_message: snapshot.events.last().map(|event| event.message.clone()),
            latest_progress: snapshot
                .events
                .last()
                .map(|event| event.progress)
                .unwrap_or_else(|| {
                    snapshot
                        .tasks
                        .iter()
                        .map(|task| task.progress)
                        .fold(0.0_f32, f32::max)
                }),
            current_task_id: snapshot
                .tasks
                .iter()
                .find(|task| task.blocker.is_some())
                .map(|task| task.task_id.clone()),
            blockers: snapshot
                .resume_plan
                .blockers
                .into_iter()
                .map(|(task_ref, blocker)| ShellBlockerView { task_ref, blocker })
                .collect(),
            graphs: vec![graph],
            tasks: snapshot.tasks.into_iter().map(task_view_from).collect(),
            event_cursor: snapshot.event_cursor,
            is_complete: snapshot.resume_plan.is_complete,
            generated_at: Utc::now(),
        })
    }

    pub fn adapter_manifest(&self, surface: ShellSurface) -> ShellAdapterManifest {
        adapter_manifest(surface)
    }

    fn resolve_compatible_profile(
        &self,
        surface: ShellSurface,
        profile_id: &str,
    ) -> ShellResult<RuntimePolicyProfile> {
        let profile = self.profile_registry.resolve(profile_id).map_err(|_| {
            ShellError::IncompatibleProfile {
                surface,
                profile_id: profile_id.to_owned(),
            }
        })?;
        ensure_profile_surface_compatibility(surface, &profile)?;
        Ok(profile)
    }
}

pub fn adapter_manifest(surface: ShellSurface) -> ShellAdapterManifest {
    let (
        shell_id,
        entry_channels,
        supported_permission_modes,
        projection_refs,
        approval_surface_ref,
    ) = match surface {
        ShellSurface::Cli => (
            "shell.cli",
            vec!["cli"],
            vec![PermissionMode::ReadOnly],
            vec!["runtime.event_feed", "runtime.query_snapshot"],
            Some("trusted.review"),
        ),
        ShellSurface::Mcp => (
            "shell.mcp",
            vec!["mcp_server"],
            vec![PermissionMode::ReadOnly],
            vec!["runtime.event_feed", "runtime.query_snapshot"],
            Some("trusted.review"),
        ),
        ShellSurface::Api => (
            "shell.api",
            vec!["http_api", "sdk"],
            vec![PermissionMode::ReadOnly, PermissionMode::WorkspaceWrite],
            vec!["runtime.event_feed", "runtime.query_snapshot"],
            Some("trusted.review"),
        ),
        ShellSurface::Ide => (
            "shell.ide",
            vec!["desktop", "sdk"],
            vec![PermissionMode::ReadOnly, PermissionMode::WorkspaceWrite],
            vec!["runtime.event_feed", "runtime.query_snapshot"],
            Some("trusted.review"),
        ),
        ShellSurface::Desktop => (
            "shell.desktop",
            vec!["desktop"],
            vec![PermissionMode::ReadOnly, PermissionMode::WorkspaceWrite],
            vec!["runtime.event_feed", "runtime.query_snapshot"],
            Some("trusted.review"),
        ),
        ShellSurface::Web => (
            "shell.web",
            vec!["web", "http_api"],
            vec![PermissionMode::ReadOnly],
            vec!["runtime.event_feed", "runtime.query_snapshot"],
            Some("trusted.review"),
        ),
        ShellSurface::Mobile => (
            "shell.mobile",
            vec!["web", "http_api"],
            vec![PermissionMode::ReadOnly],
            vec!["runtime.event_feed", "runtime.query_snapshot"],
            Some("mobile.approval"),
        ),
        ShellSurface::DigitalHuman => (
            "shell.digital_human",
            vec!["desktop", "web"],
            vec![PermissionMode::ReadOnly],
            vec!["runtime.event_feed", "runtime.query_snapshot"],
            Some("trusted.review"),
        ),
    };

    ShellAdapterManifest {
        shell_id: shell_id.into(),
        shell_version: env!("CARGO_PKG_VERSION").into(),
        surface,
        entry_channels: entry_channels.into_iter().map(str::to_owned).collect(),
        supported_permission_modes,
        required_capabilities: vec![],
        projection_refs: projection_refs.into_iter().map(str::to_owned).collect(),
        approval_surface_ref: approval_surface_ref.map(str::to_owned),
    }
}

fn default_profile_for_surface(surface: ShellSurface) -> &'static str {
    match surface {
        ShellSurface::Cli => "shell.cli.fast",
        ShellSurface::Ide
        | ShellSurface::Desktop
        | ShellSurface::Web
        | ShellSurface::Mobile
        | ShellSurface::Api
        | ShellSurface::Mcp => "shell.ide.readonly",
        ShellSurface::DigitalHuman => "shell.digital_human.readonly",
    }
}

fn channel_for_surface(surface: ShellSurface) -> EntryChannel {
    match surface {
        ShellSurface::Cli => EntryChannel::Cli,
        ShellSurface::Ide | ShellSurface::Desktop | ShellSurface::DigitalHuman => {
            EntryChannel::Desktop
        }
        ShellSurface::Web | ShellSurface::Mobile => EntryChannel::Web,
        ShellSurface::Api => EntryChannel::HttpApi,
        ShellSurface::Mcp => EntryChannel::McpServer,
    }
}

fn ensure_profile_surface_compatibility(
    surface: ShellSurface,
    profile: &RuntimePolicyProfile,
) -> ShellResult<()> {
    let ok = match surface {
        ShellSurface::Cli => profile.profile_id == "shell.cli.fast",
        ShellSurface::Mcp | ShellSurface::Api => {
            profile.profile_id == "shell.ide.readonly"
                || profile.profile_id == "shell.trusted.review"
        }
        ShellSurface::DigitalHuman => profile.profile_id == "shell.digital_human.readonly",
        ShellSurface::Ide | ShellSurface::Desktop | ShellSurface::Web | ShellSurface::Mobile => {
            profile.profile_id == "shell.ide.readonly"
                || profile.profile_id == "shell.digital_human.readonly"
                || profile.profile_id == "shell.trusted.review"
        }
    };

    if ok {
        Ok(())
    } else {
        Err(ShellError::IncompatibleProfile {
            surface,
            profile_id: profile.profile_id.clone(),
        })
    }
}

fn ensure_channel_surface_compatibility(
    surface: ShellSurface,
    channel: EntryChannel,
) -> ShellResult<()> {
    let ok = matches!(
        (surface, channel),
        (ShellSurface::Cli, EntryChannel::Cli)
            | (ShellSurface::Ide, EntryChannel::Desktop)
            | (ShellSurface::Ide, EntryChannel::Sdk)
            | (ShellSurface::Desktop, EntryChannel::Desktop)
            | (ShellSurface::Web, EntryChannel::Web)
            | (ShellSurface::Web, EntryChannel::HttpApi)
            | (ShellSurface::Mobile, EntryChannel::Web)
            | (ShellSurface::Mobile, EntryChannel::HttpApi)
            | (ShellSurface::Api, EntryChannel::HttpApi)
            | (ShellSurface::Api, EntryChannel::Sdk)
            | (ShellSurface::Mcp, EntryChannel::McpServer)
            | (ShellSurface::DigitalHuman, EntryChannel::Desktop)
            | (ShellSurface::DigitalHuman, EntryChannel::Web)
    );

    if ok {
        Ok(())
    } else {
        Err(ShellError::UnsupportedChannel { surface, channel })
    }
}

fn ensure_permission_surface_compatibility(
    surface: ShellSurface,
    permission_mode: PermissionMode,
) -> ShellResult<()> {
    let manifest = adapter_manifest(surface);
    if manifest
        .supported_permission_modes
        .contains(&permission_mode)
    {
        Ok(())
    } else {
        Err(ShellError::UnsupportedPermissionMode {
            surface,
            permission_mode,
        })
    }
}

fn graph_view_from(graph: RuntimeGraphListItem) -> ShellGraphView {
    ShellGraphView {
        graph_id: graph.graph_id,
        goal: graph.goal,
        path: graph.path,
        task_count: graph.task_count,
        completed_count: graph.completed_count,
        running_count: graph.running_count,
        blocked_count: graph.blocked_count,
        awaiting_approval_count: graph.awaiting_approval_count,
        failed_count: graph.failed_count,
        is_complete: graph.is_complete,
    }
}

fn task_view_from(task: RuntimeTaskView) -> ShellTaskView {
    ShellTaskView {
        task_id: task.task_id,
        skill_id: task.skill_id,
        capability_id: task.capability_id,
        state: format!("{:?}", task.state),
        last_stage: task.last_stage,
        progress: task.progress,
        message: task.message,
        blocker: task.blocker,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use moxi_contracts::{DeltaTarget, ResourceType};
    use moxi_runtime::{
        RunningTaskPolicy, RuntimeEvent, RuntimeResumePlan, RuntimeTaskView, TaskState,
    };
    use std::collections::BTreeMap;

    #[test]
    fn shell_admission_normalizes_entry_without_authorizing_execution() {
        let controller = ShellController::default();
        let mut draft =
            ShellRequestDraft::cli_readonly("tenant_a", "user_a", "/workspace", "  read status  ");
        draft.request_id = Some("request_1".into());
        draft.session_id = Some("session_1".into());
        draft.requested_capabilities = vec![" file.read ".into(), "file.read".into()];

        let admission = controller.admit_shell_request(draft).unwrap();

        assert_eq!(admission.surface, ShellSurface::Cli);
        assert_eq!(admission.normalized_entry.request_id, "request_1");
        assert_eq!(admission.normalized_entry.candidate.goal, "read status");
        assert_eq!(
            admission.normalized_entry.candidate.requested_capabilities,
            vec!["file.read"]
        );
        assert_eq!(admission.policy_profile.profile_id, "shell.cli.fast");
        assert!(admission.cannot_execute_directly);
        assert!(admission.cannot_authorize);
        assert!(!admission.requires_trusted_execution_path);
    }

    #[test]
    fn cli_fast_shell_is_read_only_and_cannot_use_task_path() {
        let controller = ShellController::default();
        let draft =
            ShellRequestDraft::cli_readonly("tenant_a", "user_a", "/workspace", "read README");

        let admission = controller.admit_shell_request(draft).unwrap();

        assert_eq!(
            admission.adapter_manifest.supported_permission_modes[0],
            PermissionMode::ReadOnly
        );
        assert_eq!(
            admission.policy_profile.allowed_capabilities,
            vec!["file.read"]
        );
        assert!(admission.policy_profile.allow_fast_path);
        assert!(!admission.policy_profile.allow_task_path);
        assert!(!admission.policy_profile.allow_trusted_execution_path);
    }

    #[test]
    fn high_risk_shell_request_requires_trusted_path_but_still_does_not_execute() {
        let controller = ShellController::default();
        let mut draft = ShellRequestDraft::cli_readonly(
            "tenant_a",
            "user_a",
            "/workspace",
            "inspect risky change",
        );
        draft.risk_level = RiskLevel::High;

        let admission = controller.admit_shell_request(draft).unwrap();

        assert!(admission.requires_trusted_execution_path);
        assert_eq!(
            admission.approval_hint.as_ref().unwrap().status,
            RunStatus::AwaitingApproval
        );
        assert!(admission.cannot_execute_directly);
        assert!(admission.cannot_authorize);
    }

    #[test]
    fn mcp_shell_rejects_workspace_write_surface() {
        let controller = ShellController::default();
        let mut draft =
            ShellRequestDraft::cli_readonly("tenant_a", "user_a", "/workspace", "write file");
        draft.surface = ShellSurface::Mcp;
        draft.profile_id = Some("shell.ide.readonly".into());
        draft.permission_mode = PermissionMode::WorkspaceWrite;

        assert!(matches!(
            controller.admit_shell_request(draft),
            Err(ShellError::UnsupportedPermissionMode {
                surface: ShellSurface::Mcp,
                permission_mode: PermissionMode::WorkspaceWrite
            })
        ));
    }

    #[test]
    fn shell_projection_summarizes_event_feed_for_status_polling() {
        let controller = ShellController::default();
        let mut blockers = BTreeMap::new();
        blockers.insert("task_1".into(), ResumeBlocker::AwaitingApproval);
        let snapshot = RuntimeEventFeedSnapshot {
            schema_version: 1,
            graph_id: Some("graph_1".into()),
            from_cursor: 0,
            next_cursor: 2,
            event_count: 1,
            events: vec![],
            latest_stage: Some(RuntimeStage::AwaitingApproval),
            latest_message: Some("waiting for approval".into()),
            latest_progress: 0.4,
            current_task_id: Some("task_1".into()),
            blockers,
            is_complete: false,
            generated_at: Utc::now(),
        };

        let projection = controller
            .project_event_feed(ShellSurface::Cli, "shell.cli.fast", snapshot)
            .unwrap();

        assert_eq!(projection.graph_id.as_deref(), Some("graph_1"));
        assert_eq!(
            projection.latest_stage,
            Some(RuntimeStage::AwaitingApproval)
        );
        assert_eq!(projection.current_task_id.as_deref(), Some("task_1"));
        assert_eq!(projection.blockers.len(), 1);
        assert_eq!(projection.event_cursor, 2);
        assert!(!projection.is_complete);
    }

    #[test]
    fn shell_projection_renders_query_snapshot_graph_and_tasks() {
        let controller = ShellController::default();
        let mut blockers = BTreeMap::new();
        blockers.insert("task_1".into(), ResumeBlocker::AwaitingApproval);
        let graph = RuntimeGraphListItem {
            graph_id: "graph_1".into(),
            goal: "read project".into(),
            path: RuntimePath::TaskPath,
            task_count: 1,
            completed_count: 0,
            running_count: 0,
            blocked_count: 1,
            awaiting_approval_count: 1,
            failed_count: 0,
            is_complete: false,
        };
        let task = RuntimeTaskView {
            task_id: "task_1".into(),
            skill_id: Some("skill.file.read".into()),
            capability_id: "file.read".into(),
            target: DeltaTarget {
                resource_type: ResourceType::File,
                resource_ref: "README.md".into(),
            },
            state: TaskState::AwaitingApproval,
            last_stage: Some(RuntimeStage::AwaitingApproval),
            progress: 0.3,
            message: Some("waiting".into()),
            idempotency_key: None,
            retry_safe: None,
            blocker: Some(ResumeBlocker::AwaitingApproval),
            updated_at: Utc::now(),
        };
        let snapshot = RuntimeQuerySnapshot {
            graph,
            planner: None,
            tasks: vec![task],
            attempts: vec![],
            adoption_probes: vec![],
            events: vec![RuntimeEvent {
                event_id: "event_1".into(),
                graph_id: Some("graph_1".into()),
                run_id: Some("run_1".into()),
                task_id: Some("task_1".into()),
                stage: RuntimeStage::AwaitingApproval,
                message: "waiting".into(),
                progress: 0.3,
                timestamp: Utc::now(),
            }],
            resume_plan: RuntimeResumePlan {
                graph_id: "graph_1".into(),
                completed_task_ids: vec![],
                ready_task_ids: vec![],
                blocked_task_ids: vec!["task_1".into()],
                running_task_ids: vec![],
                awaiting_approval_task_ids: vec!["task_1".into()],
                failed_task_ids: vec![],
                blockers,
                adoption_recommendations: BTreeMap::new(),
                running_task_policy: RunningTaskPolicy::RequireInspection,
                is_complete: false,
            },
            event_cursor: 1,
            policy_profile: RuntimePolicyProfile::shell_ide_readonly(),
        };

        let projection = controller
            .project_query_snapshot(ShellSurface::Ide, snapshot)
            .unwrap();

        assert_eq!(projection.graph_id.as_deref(), Some("graph_1"));
        assert_eq!(projection.graphs.len(), 1);
        assert_eq!(projection.tasks.len(), 1);
        assert_eq!(projection.latest_message.as_deref(), Some("waiting"));
        assert_eq!(projection.blockers[0].task_ref, "task_1");
    }

    #[test]
    fn adapter_manifest_roundtrips_as_shell_contract() {
        let manifest = adapter_manifest(ShellSurface::Mcp);
        let serialized = serde_json::to_string(&manifest).unwrap();
        let parsed: ShellAdapterManifest = serde_json::from_str(&serialized).unwrap();

        assert_eq!(parsed.shell_id, "shell.mcp");
        assert_eq!(parsed.surface, ShellSurface::Mcp);
        assert_eq!(parsed.entry_channels, vec!["mcp_server"]);
        assert_eq!(
            parsed.supported_permission_modes,
            vec![PermissionMode::ReadOnly]
        );
    }
}
