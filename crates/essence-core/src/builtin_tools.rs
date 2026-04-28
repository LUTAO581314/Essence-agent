use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::control::{
    ControlError, ControlPlane, CreateTaskRequest, RequestApprovalRequest, SpawnSubagentRequest,
    StartToolCallRequest,
};
use crate::policy::{PolicyDecision, ToolPolicy, ToolPolicyRequest};
use crate::protocol::{
    AgentId, ApprovalDecision, ApprovalRequest, IsolationMode, LifecycleStatus, SessionId,
    SubagentBudget, TaskId, TaskPatch, ToolCallRecord,
};
use crate::registry::{ToolPermission, ToolRegistry, ToolSpec};

pub const BUILTIN_PROVIDER: &str = "essence-builtin";
pub const TOOL_FS_LIST: &str = "essence.fs.list";
pub const TOOL_FS_READ: &str = "essence.fs.read";
pub const TOOL_FS_GREP: &str = "essence.fs.grep";
pub const TOOL_PATCH_APPLY: &str = "essence.patch.apply";
pub const TOOL_SHELL_EXEC: &str = "essence.shell.exec";
pub const TOOL_WEB_FETCH: &str = "essence.web.fetch";
pub const TOOL_TODO_CREATE: &str = "essence.todo.create";
pub const TOOL_TODO_UPDATE: &str = "essence.todo.update";
pub const TOOL_SUBAGENT_SPAWN: &str = "essence.subagent.spawn";
pub const TOOL_GATEWAY_EXEC: &str = "essence.gateway.exec";

const DEFAULT_MAX_READ_BYTES: usize = 64 * 1024;
const MAX_READ_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_ENTRIES: usize = 200;
const MAX_ENTRIES: usize = 1000;
const DEFAULT_MAX_MATCHES: usize = 100;
const MAX_MATCHES: usize = 1000;
const DEFAULT_MAX_WEB_BYTES: usize = 256 * 1024;
const MAX_WEB_BYTES: usize = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum BuiltinToolError {
    #[error(transparent)]
    Control(#[from] ControlError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("tool `{0}` is not a built-in tool")]
    UnknownTool(String),
    #[error("tool `{0}` is not executable by the built-in executor")]
    UnsupportedTool(String),
    #[error("path `{path}` is outside workspace `{workspace}`")]
    PathOutsideWorkspace { path: PathBuf, workspace: PathBuf },
    #[error("path `{0}` is not valid unicode")]
    InvalidUnicodePath(PathBuf),
    #[error("workspace root is missing for session `{0:?}`")]
    MissingWorkspace(SessionId),
    #[error("run context is required for `{0}`")]
    MissingRunContext(String),
    #[error("run `{0}` is not recorded")]
    MissingRun(Uuid),
    #[error("invalid input `{field}`: {message}")]
    InvalidInput { field: String, message: String },
    #[error("patch old text was not found in `{0}`")]
    PatchOldTextNotFound(String),
    #[error("web fetch failed for `{url}`: {message}")]
    WebFetch { url: String, message: String },
}

pub type BuiltinToolResult<T> = Result<T, BuiltinToolError>;

#[derive(Debug, Clone)]
pub struct BuiltinToolExecutor {
    control: ControlPlane,
    policy: ToolPolicy,
}

impl BuiltinToolExecutor {
    pub fn new(control: ControlPlane, policy: ToolPolicy) -> Self {
        Self { control, policy }
    }

    pub fn for_mode(control: ControlPlane, mode: crate::protocol::PermissionMode) -> Self {
        Self::new(control, builtin_tool_registry().to_policy(mode))
    }

    pub fn run_tool(&self, request: BuiltinToolRequest) -> BuiltinToolResult<BuiltinToolOutcome> {
        let tool_call = self.control.start_tool_call(
            StartToolCallRequest::new(
                request.session_id.clone(),
                request.tool_name.clone(),
                request.input.clone(),
            )
            .with_optional_run_context(request.run_id.clone(), request.turn_id.clone()),
        )?;

        let mut policy_request =
            ToolPolicyRequest::new(request.tool_name.clone(), request.input.clone());
        if let Some(cwd) = request.cwd.clone() {
            policy_request = policy_request.with_cwd(cwd);
        }

        match self.policy.decide(&policy_request) {
            PolicyDecision::Allow => self.execute_started_tool(tool_call, &request),
            PolicyDecision::RequireApproval { reason } => {
                if self.has_reusable_grant(&request.session_id, &request.tool_name)? {
                    return self.execute_started_tool(tool_call, &request);
                }

                let approval = self.control.request_approval(
                    RequestApprovalRequest::new(
                        request.session_id,
                        request.tool_name,
                        request.input,
                        reason,
                    )
                    .with_optional_run_id(request.run_id)
                    .for_tool_call(tool_call.tool_call_id.clone())
                    .with_optional_cwd(request.cwd)
                    .with_allowed_decisions(vec![
                        ApprovalDecision::ApproveOnce,
                        ApprovalDecision::ApproveSession,
                        ApprovalDecision::ApproveAlways,
                        ApprovalDecision::Deny,
                    ]),
                )?;
                Ok(BuiltinToolOutcome::RequiresApproval {
                    tool_call,
                    approval,
                })
            }
            PolicyDecision::Deny { reason } => {
                let failed = self.control.fail_tool_call(&tool_call, reason.clone())?;
                Ok(BuiltinToolOutcome::Denied {
                    tool_call: failed,
                    reason,
                })
            }
        }
    }

    pub fn resolve_approval(
        &self,
        approval: &ApprovalRequest,
        decision: ApprovalDecision,
        resolved_by: impl Into<String>,
    ) -> BuiltinToolResult<BuiltinToolApprovalOutcome> {
        let resolved = self
            .control
            .resolve_approval(approval, decision.clone(), resolved_by)?;
        let tool_call_id = approval
            .tool_call_id
            .clone()
            .ok_or_else(|| ControlError::ApprovalMissingToolCall(approval.approval_id.clone()))?;
        let projection = self.control.projection(&approval.session_id)?;
        let tool_call = projection
            .tool_calls
            .get(&tool_call_id)
            .cloned()
            .ok_or_else(|| ControlError::MissingToolCall(tool_call_id.clone()))?;

        if decision == ApprovalDecision::Deny {
            let failed = self.control.fail_tool_call(&tool_call, "approval denied")?;
            return Ok(BuiltinToolApprovalOutcome::Denied {
                approval: resolved,
                tool_call: failed,
                reason: "approval denied".to_string(),
            });
        }

        let request = BuiltinToolRequest {
            session_id: approval.session_id.clone(),
            run_id: tool_call.run_id.clone(),
            turn_id: tool_call.turn_id.clone(),
            tool_name: approval.subject.clone(),
            input: approval.input.clone(),
            cwd: approval.cwd.clone(),
        };
        match self.execute_tool(&request) {
            Ok(output) => {
                let completed = self
                    .control
                    .complete_tool_call(&tool_call, output.clone())?;
                Ok(BuiltinToolApprovalOutcome::Executed {
                    approval: resolved,
                    tool_call: completed,
                    output,
                })
            }
            Err(error) => {
                let reason = error.to_string();
                let failed = self.control.fail_tool_call(&tool_call, reason.clone())?;
                Ok(BuiltinToolApprovalOutcome::Failed {
                    approval: resolved,
                    tool_call: failed,
                    reason,
                })
            }
        }
    }

    fn execute_started_tool(
        &self,
        tool_call: ToolCallRecord,
        request: &BuiltinToolRequest,
    ) -> BuiltinToolResult<BuiltinToolOutcome> {
        match self.execute_tool(request) {
            Ok(output) => {
                let completed = self
                    .control
                    .complete_tool_call(&tool_call, output.clone())?;
                Ok(BuiltinToolOutcome::Executed {
                    tool_call: completed,
                    output,
                })
            }
            Err(error) => {
                let reason = error.to_string();
                let failed = self.control.fail_tool_call(&tool_call, reason.clone())?;
                Ok(BuiltinToolOutcome::Failed {
                    tool_call: failed,
                    reason,
                })
            }
        }
    }

    fn execute_tool(&self, request: &BuiltinToolRequest) -> BuiltinToolResult<Value> {
        match request.tool_name.as_str() {
            TOOL_FS_LIST => self.fs_list(request),
            TOOL_FS_READ => self.fs_read(request),
            TOOL_FS_GREP => self.fs_grep(request),
            TOOL_PATCH_APPLY => self.patch_apply(request),
            TOOL_SHELL_EXEC => self.shell_exec(request),
            TOOL_WEB_FETCH => self.web_fetch(request),
            TOOL_TODO_CREATE => self.todo_create(request),
            TOOL_TODO_UPDATE => self.todo_update(request),
            TOOL_SUBAGENT_SPAWN => self.subagent_spawn(request),
            TOOL_GATEWAY_EXEC => Err(BuiltinToolError::UnsupportedTool(request.tool_name.clone())),
            other => Err(BuiltinToolError::UnknownTool(other.to_string())),
        }
    }

    fn has_reusable_grant(
        &self,
        session_id: &SessionId,
        tool_name: &str,
    ) -> BuiltinToolResult<bool> {
        Ok(self
            .control
            .projection(session_id)?
            .has_approval_grant_for_subject(tool_name)
            || self
                .control
                .has_approval_always_grant_for_subject(tool_name)?)
    }

    fn workspace_root(&self, request: &BuiltinToolRequest) -> BuiltinToolResult<PathBuf> {
        let cwd = match &request.cwd {
            Some(cwd) => PathBuf::from(cwd),
            None => self
                .control
                .projection(&request.session_id)?
                .session
                .map(|session| PathBuf::from(session.cwd))
                .ok_or_else(|| BuiltinToolError::MissingWorkspace(request.session_id.clone()))?,
        };
        canonicalize(&cwd)
    }

    fn resolve_existing_path(
        &self,
        request: &BuiltinToolRequest,
        path: impl AsRef<Path>,
    ) -> BuiltinToolResult<PathBuf> {
        let root = self.workspace_root(request)?;
        let raw = path.as_ref();
        let joined = if raw.is_absolute() {
            raw.to_path_buf()
        } else {
            root.join(raw)
        };
        let canonical = canonicalize(&joined)?;
        ensure_inside(&canonical, &root)?;
        Ok(canonical)
    }

    fn fs_list(&self, request: &BuiltinToolRequest) -> BuiltinToolResult<Value> {
        let input = decode_input::<ListInput>(request)?;
        let path = input.path.unwrap_or_else(|| ".".to_string());
        let dir = self.resolve_existing_path(request, path)?;
        let max_entries = bounded(input.max_entries, DEFAULT_MAX_ENTRIES, MAX_ENTRIES);
        let mut entries = Vec::new();

        for entry in fs::read_dir(&dir).map_err(|source| BuiltinToolError::Io {
            path: dir.clone(),
            source,
        })? {
            if entries.len() >= max_entries {
                break;
            }
            let entry = entry.map_err(|source| BuiltinToolError::Io {
                path: dir.clone(),
                source,
            })?;
            let metadata = entry.metadata().map_err(|source| BuiltinToolError::Io {
                path: entry.path(),
                source,
            })?;
            entries.push(json!({
                "path": display_path(&entry.path())?,
                "kind": if metadata.is_dir() { "dir" } else { "file" },
                "bytes": if metadata.is_file() { Some(metadata.len()) } else { None },
            }));
        }

        Ok(json!({
            "path": display_path(&dir)?,
            "entries": entries,
            "truncated": entries.len() >= max_entries,
        }))
    }

    fn fs_read(&self, request: &BuiltinToolRequest) -> BuiltinToolResult<Value> {
        let input = decode_input::<ReadInput>(request)?;
        let path = self.resolve_existing_path(request, input.path)?;
        let max_bytes = bounded(input.max_bytes, DEFAULT_MAX_READ_BYTES, MAX_READ_BYTES);
        let (text, truncated) = read_limited_utf8_lossy(&path, max_bytes)?;

        Ok(json!({
            "path": display_path(&path)?,
            "text": text,
            "truncated": truncated,
        }))
    }

    fn fs_grep(&self, request: &BuiltinToolRequest) -> BuiltinToolResult<Value> {
        let input = decode_input::<GrepInput>(request)?;
        let root =
            self.resolve_existing_path(request, input.path.unwrap_or_else(|| ".".to_string()))?;
        let max_matches = bounded(input.max_matches, DEFAULT_MAX_MATCHES, MAX_MATCHES);
        let mut matches = Vec::new();
        collect_grep_matches(&root, &input.query, max_matches, &mut matches)?;

        Ok(json!({
            "query": input.query,
            "root": display_path(&root)?,
            "matches": matches,
            "truncated": matches.len() >= max_matches,
        }))
    }

    fn patch_apply(&self, request: &BuiltinToolRequest) -> BuiltinToolResult<Value> {
        let input = decode_input::<PatchApplyInput>(request)?;
        let path = self.resolve_existing_path(request, &input.path)?;
        let current = fs::read_to_string(&path).map_err(|source| BuiltinToolError::Io {
            path: path.clone(),
            source,
        })?;
        if !current.contains(&input.old) {
            return Err(BuiltinToolError::PatchOldTextNotFound(input.path));
        }
        let updated = current.replacen(&input.old, &input.new, 1);
        fs::write(&path, updated).map_err(|source| BuiltinToolError::Io {
            path: path.clone(),
            source,
        })?;

        Ok(json!({
            "path": display_path(&path)?,
            "replacements": 1,
        }))
    }

    fn shell_exec(&self, request: &BuiltinToolRequest) -> BuiltinToolResult<Value> {
        let input = decode_input::<ShellExecInput>(request)?;
        let root = self.workspace_root(request)?;
        let command = shell_command(&input.command);
        let cwd = root
            .to_str()
            .ok_or_else(|| BuiltinToolError::InvalidUnicodePath(root.clone()))?;
        let result =
            command
                .execute_with_cwd(Some(cwd))
                .map_err(|source| BuiltinToolError::Io {
                    path: root.clone(),
                    source: std::io::Error::new(std::io::ErrorKind::Other, source.to_string()),
                })?;
        serde_json::to_value(result).map_err(BuiltinToolError::from)
    }

    fn web_fetch(&self, request: &BuiltinToolRequest) -> BuiltinToolResult<Value> {
        let input = decode_input::<WebFetchInput>(request)?;
        if !(input.url.starts_with("http://") || input.url.starts_with("https://")) {
            return Err(BuiltinToolError::InvalidInput {
                field: "url".to_string(),
                message: "expected http:// or https:// URL".to_string(),
            });
        }
        let max_bytes = bounded(input.max_bytes, DEFAULT_MAX_WEB_BYTES, MAX_WEB_BYTES);
        let response =
            ureq::get(&input.url)
                .call()
                .map_err(|source| BuiltinToolError::WebFetch {
                    url: input.url.clone(),
                    message: source.to_string(),
                })?;
        let status = response.status();
        let content_type = response
            .header("content-type")
            .map(|value| value.to_string());
        let mut bytes = Vec::new();
        response
            .into_reader()
            .take(max_bytes.saturating_add(1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|source| BuiltinToolError::WebFetch {
                url: input.url.clone(),
                message: source.to_string(),
            })?;
        let truncated = bytes.len() > max_bytes;
        bytes.truncate(max_bytes);

        Ok(json!({
            "url": input.url,
            "status": status,
            "content_type": content_type,
            "text": String::from_utf8_lossy(&bytes),
            "truncated": truncated,
        }))
    }

    fn todo_create(&self, request: &BuiltinToolRequest) -> BuiltinToolResult<Value> {
        let input = decode_input::<TodoCreateInput>(request)?;
        let mut create = CreateTaskRequest::new(request.session_id.clone(), input.title);
        if let Some(lane) = input.lane {
            create = create.with_lane(lane);
        }
        if let Some(assignee) = input.assignee {
            create = create.with_assignee(assignee);
        }
        let task = self.control.create_task(create)?;
        serde_json::to_value(task).map_err(BuiltinToolError::from)
    }

    fn todo_update(&self, request: &BuiltinToolRequest) -> BuiltinToolResult<Value> {
        let input = decode_input::<TodoUpdateInput>(request)?;
        let task_id = TaskId(Uuid::parse_str(&input.task_id).map_err(|source| {
            BuiltinToolError::InvalidInput {
                field: "task_id".to_string(),
                message: source.to_string(),
            }
        })?);
        let patch = TaskPatch {
            task_id,
            title: input.title,
            status: input.status,
            updated_at: Some(time::OffsetDateTime::now_utc()),
            assignee: input.assignee.map(AgentId),
            metadata: Default::default(),
        };
        let patch = self.control.update_task(&request.session_id, patch)?;
        serde_json::to_value(patch).map_err(BuiltinToolError::from)
    }

    fn subagent_spawn(&self, request: &BuiltinToolRequest) -> BuiltinToolResult<Value> {
        let input = decode_input::<SubagentSpawnInput>(request)?;
        let run_id = request
            .run_id
            .clone()
            .ok_or_else(|| BuiltinToolError::MissingRunContext(request.tool_name.clone()))?;
        let projection = self.control.projection(&request.session_id)?;
        let run = projection
            .runs
            .get(&run_id)
            .cloned()
            .ok_or_else(|| BuiltinToolError::MissingRun(run_id.0))?;
        let mut spawn =
            SpawnSubagentRequest::native(request.session_id.clone(), &run, input.lane, input.goal);
        if let Some(subagent_id) = input.subagent_id {
            spawn = spawn.with_subagent_id(subagent_id);
        }
        for toolset in input.toolsets {
            spawn = spawn.with_toolset(toolset);
        }
        for context_ref in input.context_refs {
            spawn = spawn.with_context_ref(context_ref);
        }
        if let Some(budget) = input.budget {
            spawn = spawn.with_budget(budget);
        }
        if let Some(isolation) = input.isolation {
            spawn = spawn.with_isolation(isolation);
        }
        let subagent = self.control.spawn_subagent(spawn)?;
        serde_json::to_value(subagent).map_err(BuiltinToolError::from)
    }
}

#[derive(Debug, Clone)]
pub struct BuiltinToolRequest {
    pub session_id: SessionId,
    pub run_id: Option<crate::protocol::RunId>,
    pub turn_id: Option<crate::protocol::TurnId>,
    pub tool_name: String,
    pub input: Value,
    pub cwd: Option<String>,
}

impl BuiltinToolRequest {
    pub fn new(session_id: SessionId, tool_name: impl Into<String>, input: Value) -> Self {
        Self {
            session_id,
            run_id: None,
            turn_id: None,
            tool_name: tool_name.into(),
            input,
            cwd: None,
        }
    }

    pub fn for_run(mut self, run: &crate::protocol::RunMeta) -> Self {
        self.run_id = Some(run.run_id.clone());
        self.turn_id = Some(run.turn_id.clone());
        self
    }

    pub fn with_cwd(mut self, cwd: impl Into<String>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum BuiltinToolOutcome {
    Executed {
        tool_call: ToolCallRecord,
        output: Value,
    },
    RequiresApproval {
        tool_call: ToolCallRecord,
        approval: ApprovalRequest,
    },
    Denied {
        tool_call: ToolCallRecord,
        reason: String,
    },
    Failed {
        tool_call: ToolCallRecord,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum BuiltinToolApprovalOutcome {
    Executed {
        approval: ApprovalRequest,
        tool_call: ToolCallRecord,
        output: Value,
    },
    Denied {
        approval: ApprovalRequest,
        tool_call: ToolCallRecord,
        reason: String,
    },
    Failed {
        approval: ApprovalRequest,
        tool_call: ToolCallRecord,
        reason: String,
    },
}

pub fn builtin_tool_registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    for tool in builtin_tool_specs() {
        registry.register(tool).expect("unique built-in tool names");
    }
    registry
}

pub fn builtin_tool_specs() -> Vec<ToolSpec> {
    vec![
        readonly_tool(
            TOOL_FS_LIST,
            "List files inside the session workspace.",
            schema(&[], &[("path", "string"), ("max_entries", "integer")]),
        )
        .with_capability("filesystem"),
        readonly_tool(
            TOOL_FS_READ,
            "Read a text file inside the session workspace.",
            schema(&["path"], &[("path", "string"), ("max_bytes", "integer")]),
        )
        .with_capability("filesystem"),
        readonly_tool(
            TOOL_FS_GREP,
            "Search text files inside the session workspace.",
            schema(
                &["query"],
                &[
                    ("query", "string"),
                    ("path", "string"),
                    ("max_matches", "integer"),
                ],
            ),
        )
        .with_capability("filesystem"),
        approval_tool(
            TOOL_PATCH_APPLY,
            "Apply a single exact text replacement to a workspace file.",
            schema(
                &["path", "old", "new"],
                &[("path", "string"), ("old", "string"), ("new", "string")],
            ),
        )
        .with_capability("filesystem")
        .with_capability("writes_workspace"),
        approval_tool(
            TOOL_SHELL_EXEC,
            "Run a shell command in the session workspace.",
            schema(&["command"], &[("command", "string")]),
        )
        .with_capability("process")
        .with_capability("writes_workspace"),
        approval_tool(
            TOOL_WEB_FETCH,
            "Fetch a URL over the network.",
            schema(&["url"], &[("url", "string"), ("max_bytes", "integer")]),
        )
        .with_capability("network"),
        allow_tool(
            TOOL_TODO_CREATE,
            "Create a ledger-backed task.",
            schema(
                &["title"],
                &[
                    ("title", "string"),
                    ("lane", "string"),
                    ("assignee", "string"),
                ],
            ),
        )
        .with_capability("todo"),
        allow_tool(
            TOOL_TODO_UPDATE,
            "Update a ledger-backed task.",
            schema(
                &["task_id"],
                &[
                    ("task_id", "string"),
                    ("title", "string"),
                    ("status", "string"),
                    ("assignee", "string"),
                ],
            ),
        )
        .with_capability("todo"),
        allow_tool(
            TOOL_SUBAGENT_SPAWN,
            "Spawn a ledger-backed native subagent sidechain.",
            schema(
                &["lane", "goal"],
                &[
                    ("lane", "string"),
                    ("goal", "string"),
                    ("subagent_id", "string"),
                ],
            ),
        )
        .with_capability("subagent"),
        ToolSpec::new(
            TOOL_GATEWAY_EXEC,
            "OpenClaw-style remote gateway exec boundary; denied by default.",
            ToolPermission::Deny,
        )
        .with_capability("gateway")
        .with_provider(BUILTIN_PROVIDER)
        .with_input_schema(schema(&["command"], &[("command", "string")])),
    ]
}

fn readonly_tool(name: &str, description: &str, schema: Value) -> ToolSpec {
    allow_tool(name, description, schema).with_capability("read_only")
}

fn allow_tool(name: &str, description: &str, schema: Value) -> ToolSpec {
    ToolSpec::new(name, description, ToolPermission::Allow)
        .with_provider(BUILTIN_PROVIDER)
        .with_input_schema(schema)
}

fn approval_tool(name: &str, description: &str, schema: Value) -> ToolSpec {
    ToolSpec::new(name, description, ToolPermission::RequireApproval)
        .with_provider(BUILTIN_PROVIDER)
        .with_input_schema(schema)
}

fn schema(required: &[&str], properties: &[(&str, &str)]) -> Value {
    let mut props = serde_json::Map::new();
    for (name, kind) in properties {
        props.insert((*name).to_string(), json!({ "type": kind }));
    }
    json!({
        "type": "object",
        "required": required,
        "properties": props,
    })
}

#[derive(Debug, Deserialize)]
struct ListInput {
    path: Option<String>,
    max_entries: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct ReadInput {
    path: String,
    max_bytes: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct GrepInput {
    query: String,
    path: Option<String>,
    max_matches: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct PatchApplyInput {
    path: String,
    old: String,
    new: String,
}

#[derive(Debug, Deserialize)]
struct ShellExecInput {
    command: String,
}

#[derive(Debug, Deserialize)]
struct WebFetchInput {
    url: String,
    max_bytes: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct TodoCreateInput {
    title: String,
    lane: Option<String>,
    assignee: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TodoUpdateInput {
    task_id: String,
    title: Option<String>,
    status: Option<LifecycleStatus>,
    assignee: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SubagentSpawnInput {
    lane: String,
    goal: String,
    subagent_id: Option<String>,
    #[serde(default)]
    toolsets: Vec<String>,
    #[serde(default)]
    context_refs: Vec<String>,
    isolation: Option<IsolationMode>,
    budget: Option<SubagentBudget>,
}

fn decode_input<T: for<'de> Deserialize<'de>>(
    request: &BuiltinToolRequest,
) -> BuiltinToolResult<T> {
    serde_json::from_value(request.input.clone()).map_err(BuiltinToolError::from)
}

fn bounded(value: Option<usize>, default: usize, max: usize) -> usize {
    value.unwrap_or(default).min(max)
}

fn canonicalize(path: &Path) -> BuiltinToolResult<PathBuf> {
    path.canonicalize().map_err(|source| BuiltinToolError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn ensure_inside(path: &Path, workspace: &Path) -> BuiltinToolResult<()> {
    if path.starts_with(workspace) {
        Ok(())
    } else {
        Err(BuiltinToolError::PathOutsideWorkspace {
            path: path.to_path_buf(),
            workspace: workspace.to_path_buf(),
        })
    }
}

fn display_path(path: &Path) -> BuiltinToolResult<String> {
    path.to_str()
        .map(|value| value.to_string())
        .ok_or_else(|| BuiltinToolError::InvalidUnicodePath(path.to_path_buf()))
}

fn read_limited_utf8_lossy(path: &Path, max_bytes: usize) -> BuiltinToolResult<(String, bool)> {
    let mut file = fs::File::open(path).map_err(|source| BuiltinToolError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(max_bytes.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| BuiltinToolError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let truncated = bytes.len() > max_bytes;
    bytes.truncate(max_bytes);
    Ok((String::from_utf8_lossy(&bytes).into_owned(), truncated))
}

fn collect_grep_matches(
    path: &Path,
    query: &str,
    max_matches: usize,
    matches: &mut Vec<Value>,
) -> BuiltinToolResult<()> {
    if matches.len() >= max_matches {
        return Ok(());
    }
    if should_skip_path(path) {
        return Ok(());
    }
    if path.is_dir() {
        for entry in fs::read_dir(path).map_err(|source| BuiltinToolError::Io {
            path: path.to_path_buf(),
            source,
        })? {
            if matches.len() >= max_matches {
                break;
            }
            let entry = entry.map_err(|source| BuiltinToolError::Io {
                path: path.to_path_buf(),
                source,
            })?;
            collect_grep_matches(&entry.path(), query, max_matches, matches)?;
        }
        return Ok(());
    }

    let Ok(text) = fs::read_to_string(path) else {
        return Ok(());
    };
    for (index, line) in text.lines().enumerate() {
        if matches.len() >= max_matches {
            break;
        }
        if line.contains(query) {
            matches.push(json!({
                "path": display_path(path)?,
                "line": index + 1,
                "text": line,
            }));
        }
    }
    Ok(())
}

fn should_skip_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| matches!(name, ".git" | "target" | "node_modules"))
}

fn shell_command(command: &str) -> crate::harness::RenderedCliCommand {
    #[cfg(windows)]
    {
        crate::harness::RenderedCliCommand {
            binary: "cmd".to_string(),
            args: vec!["/C".to_string(), command.to_string()],
            writes_workspace: true,
        }
    }
    #[cfg(not(windows))]
    {
        crate::harness::RenderedCliCommand {
            binary: "sh".to_string(),
            args: vec!["-lc".to_string(), command.to_string()],
            writes_workspace: true,
        }
    }
}

trait StartToolCallRequestExt {
    fn with_optional_run_context(
        self,
        run_id: Option<crate::protocol::RunId>,
        turn_id: Option<crate::protocol::TurnId>,
    ) -> Self;
}

impl StartToolCallRequestExt for StartToolCallRequest {
    fn with_optional_run_context(
        mut self,
        run_id: Option<crate::protocol::RunId>,
        turn_id: Option<crate::protocol::TurnId>,
    ) -> Self {
        self.run_id = run_id;
        self.turn_id = turn_id;
        self
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use uuid::Uuid;

    use crate::builtin_tools::{
        builtin_tool_registry, BuiltinToolApprovalOutcome, BuiltinToolExecutor, BuiltinToolOutcome,
        BuiltinToolRequest, TOOL_FS_GREP, TOOL_FS_READ, TOOL_GATEWAY_EXEC, TOOL_PATCH_APPLY,
        TOOL_SHELL_EXEC, TOOL_SUBAGENT_SPAWN, TOOL_TODO_CREATE, TOOL_TODO_UPDATE, TOOL_WEB_FETCH,
    };
    use crate::control::{ControlPlane, CreateSessionRequest, StartRunRequest};
    use crate::policy::ToolPolicyRequest;
    use crate::protocol::{LifecycleStatus, PermissionMode};

    #[test]
    fn builtin_registry_sets_safe_default_policy() {
        let registry = builtin_tool_registry();
        let policy = registry.to_policy(PermissionMode::Default);

        assert!(policy
            .decide(&ToolPolicyRequest::new(
                TOOL_FS_READ,
                json!({"path": "README.md"})
            ))
            .is_allow());
        assert!(policy
            .decide(&ToolPolicyRequest::new(
                TOOL_PATCH_APPLY,
                json!({"path": "README.md", "old": "a", "new": "b"})
            ))
            .requires_approval());
        assert!(policy
            .decide(&ToolPolicyRequest::new(
                TOOL_SHELL_EXEC,
                json!({"command": "echo hi"})
            ))
            .requires_approval());
        assert!(policy
            .decide(&ToolPolicyRequest::new(
                TOOL_WEB_FETCH,
                json!({"url": "https://example.com"})
            ))
            .requires_approval());
        assert!(policy
            .decide(&ToolPolicyRequest::new(
                TOOL_GATEWAY_EXEC,
                json!({"command": "run"})
            ))
            .is_deny());
    }

    #[test]
    fn reads_and_greps_files_inside_workspace() {
        let root = temp_root("builtin-read");
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(workspace.join("notes.txt"), "alpha\nneedle here\n").unwrap();
        let control = ControlPlane::new(root.join(".essence"));
        let session = control
            .create_session(CreateSessionRequest::interactive(path_string(&workspace)))
            .unwrap();
        let executor = BuiltinToolExecutor::for_mode(control.clone(), PermissionMode::Default);

        let read = executor
            .run_tool(BuiltinToolRequest::new(
                session.session_id.clone(),
                TOOL_FS_READ,
                json!({"path": "notes.txt"}),
            ))
            .unwrap();
        let BuiltinToolOutcome::Executed { output, .. } = read else {
            panic!("expected executed read");
        };
        assert!(output["text"].as_str().unwrap().contains("needle here"));

        let grep = executor
            .run_tool(BuiltinToolRequest::new(
                session.session_id.clone(),
                TOOL_FS_GREP,
                json!({"query": "needle"}),
            ))
            .unwrap();
        let BuiltinToolOutcome::Executed { output, .. } = grep else {
            panic!("expected executed grep");
        };
        assert_eq!(output["matches"].as_array().unwrap().len(), 1);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn patch_requires_approval_then_edits_file() {
        let root = temp_root("builtin-patch");
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        let file = workspace.join("notes.txt");
        std::fs::write(&file, "before\n").unwrap();
        let control = ControlPlane::new(root.join(".essence"));
        let session = control
            .create_session(CreateSessionRequest::interactive(path_string(&workspace)))
            .unwrap();
        let executor = BuiltinToolExecutor::for_mode(control.clone(), PermissionMode::Default);

        let pending = executor
            .run_tool(BuiltinToolRequest::new(
                session.session_id.clone(),
                TOOL_PATCH_APPLY,
                json!({"path": "notes.txt", "old": "before", "new": "after"}),
            ))
            .unwrap();
        let BuiltinToolOutcome::RequiresApproval { approval, .. } = pending else {
            panic!("expected patch approval");
        };
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "before\n");

        let resolved = executor
            .resolve_approval(
                &approval,
                crate::protocol::ApprovalDecision::ApproveOnce,
                "test",
            )
            .unwrap();
        let BuiltinToolApprovalOutcome::Executed { output, .. } = resolved else {
            panic!("expected approved patch execution");
        };
        assert_eq!(output["replacements"], 1);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "after\n");

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn shell_requires_approval_then_records_output() {
        let root = temp_root("builtin-shell");
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        let control = ControlPlane::new(root.join(".essence"));
        let session = control
            .create_session(CreateSessionRequest::interactive(path_string(&workspace)))
            .unwrap();
        let executor = BuiltinToolExecutor::for_mode(control.clone(), PermissionMode::Default);

        let pending = executor
            .run_tool(BuiltinToolRequest::new(
                session.session_id.clone(),
                TOOL_SHELL_EXEC,
                json!({"command": "echo essence-shell"}),
            ))
            .unwrap();
        let BuiltinToolOutcome::RequiresApproval { approval, .. } = pending else {
            panic!("expected shell approval");
        };

        let resolved = executor
            .resolve_approval(
                &approval,
                crate::protocol::ApprovalDecision::ApproveOnce,
                "test",
            )
            .unwrap();
        let BuiltinToolApprovalOutcome::Executed { output, .. } = resolved else {
            panic!("expected approved shell execution");
        };
        assert!(output["stdout"].as_str().unwrap().contains("essence-shell"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn todo_and_subagent_tools_record_ledger_state() {
        let root = temp_root("builtin-ledger-tools");
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        let control = ControlPlane::new(root.join(".essence"));
        let session = control
            .create_session(CreateSessionRequest::interactive(path_string(&workspace)))
            .unwrap();
        let run = control
            .start_run(StartRunRequest::user(session.session_id.clone()))
            .unwrap();
        let executor = BuiltinToolExecutor::for_mode(control.clone(), PermissionMode::Default);

        let created = executor
            .run_tool(BuiltinToolRequest::new(
                session.session_id.clone(),
                TOOL_TODO_CREATE,
                json!({"title": "Wire built-ins", "lane": "core"}),
            ))
            .unwrap();
        let BuiltinToolOutcome::Executed { output, .. } = created else {
            panic!("expected todo create");
        };
        let task_id = output["task_id"].as_str().unwrap().to_string();
        let updated = executor
            .run_tool(BuiltinToolRequest::new(
                session.session_id.clone(),
                TOOL_TODO_UPDATE,
                json!({"task_id": task_id, "status": "completed"}),
            ))
            .unwrap();
        assert!(matches!(updated, BuiltinToolOutcome::Executed { .. }));

        let spawned = executor
            .run_tool(
                BuiltinToolRequest::new(
                    session.session_id.clone(),
                    TOOL_SUBAGENT_SPAWN,
                    json!({"lane": "research", "goal": "Map tool references"}),
                )
                .for_run(&run),
            )
            .unwrap();
        assert!(matches!(spawned, BuiltinToolOutcome::Executed { .. }));

        let projection = control.projection(&session.session_id).unwrap();
        assert!(projection
            .tasks
            .values()
            .any(|task| task.status == LifecycleStatus::Completed));
        assert_eq!(projection.subagents.len(), 1);

        let _ = std::fs::remove_dir_all(root);
    }

    fn temp_root(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("essence-{label}-{}", Uuid::new_v4()))
    }

    fn path_string(path: &std::path::Path) -> String {
        path.to_string_lossy().into_owned()
    }
}
