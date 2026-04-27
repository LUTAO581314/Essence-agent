use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::plugin::PluginManifest;
use crate::policy::{PolicyDecision, ToolPolicy, ToolPolicyRequest};

#[derive(Debug, thiserror::Error)]
pub enum HarnessError {
    #[error("command `{command}` references missing tool `{tool}`")]
    MissingToolForCommand { command: String, tool: String },
    #[error("tool `{0}` has no CLI command")]
    MissingCommandForTool(String),
    #[error("command `{0}` is already registered")]
    DuplicateCommand(String),
    #[error("command `{command}` is missing required input `{key}`")]
    MissingInput { command: String, key: String },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type HarnessResult<T> = Result<T, HarnessError>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CliCommandSpec {
    pub name: String,
    pub tool_name: String,
    pub binary: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub writes_workspace: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RenderedCliCommand {
    pub binary: String,
    pub args: Vec<String>,
    pub writes_workspace: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CliExecutionResult {
    pub status_code: Option<i32>,
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub writes_workspace: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CliExecutionLimits {
    pub timeout: Duration,
    pub max_stdout_bytes: usize,
    pub max_stderr_bytes: usize,
}

impl Default for CliExecutionLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_stdout_bytes: 1024 * 1024,
            max_stderr_bytes: 1024 * 1024,
        }
    }
}

impl RenderedCliCommand {
    pub fn execute(&self) -> HarnessResult<CliExecutionResult> {
        self.execute_with_cwd(None)
    }

    pub fn execute_with_cwd(&self, cwd: Option<&str>) -> HarnessResult<CliExecutionResult> {
        self.execute_with_cwd_and_limits(cwd, CliExecutionLimits::default())
    }

    pub fn execute_with_cwd_and_limits(
        &self,
        cwd: Option<&str>,
        limits: CliExecutionLimits,
    ) -> HarnessResult<CliExecutionResult> {
        let mut command = Command::new(&self.binary);
        command.args(&self.args);
        if let Some(cwd) = cwd {
            command.current_dir(cwd);
        }

        let temp_id = Uuid::new_v4();
        let stdout_path = std::env::temp_dir().join(format!("essence-cli-{temp_id}.stdout"));
        let stderr_path = std::env::temp_dir().join(format!("essence-cli-{temp_id}.stderr"));
        let stdout_file = std::fs::File::create(&stdout_path)?;
        let stderr_file = std::fs::File::create(&stderr_path)?;
        command.stdout(Stdio::from(stdout_file));
        command.stderr(Stdio::from(stderr_file));

        let mut child = command.spawn()?;
        let started = Instant::now();
        let (status, timed_out) = loop {
            if let Some(status) = child.try_wait()? {
                break (status, false);
            }
            if started.elapsed() >= limits.timeout {
                child.kill()?;
                let status = child.wait()?;
                break (status, true);
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        let (stdout, stdout_truncated) = read_limited_lossy(&stdout_path, limits.max_stdout_bytes)?;
        let (stderr, stderr_truncated) = read_limited_lossy(&stderr_path, limits.max_stderr_bytes)?;
        let _ = std::fs::remove_file(&stdout_path);
        let _ = std::fs::remove_file(&stderr_path);

        Ok(CliExecutionResult {
            status_code: if timed_out { None } else { status.code() },
            success: !timed_out && status.success(),
            stdout,
            stderr,
            timed_out,
            stdout_truncated,
            stderr_truncated,
            writes_workspace: self.writes_workspace,
        })
    }
}

fn read_limited_lossy(path: &Path, limit: usize) -> HarnessResult<(String, bool)> {
    let mut file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    let take = limit.saturating_add(1) as u64;
    file.by_ref().take(take).read_to_end(&mut bytes)?;
    let truncated = bytes.len() > limit;
    bytes.truncate(limit);
    Ok((String::from_utf8_lossy(&bytes).into_owned(), truncated))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PolicyBoundCliOutcome {
    Executed {
        command: RenderedCliCommand,
        result: CliExecutionResult,
    },
    RequiresApproval {
        command: RenderedCliCommand,
        reason: String,
    },
    Denied {
        command: RenderedCliCommand,
        reason: String,
    },
}

#[derive(Debug, Clone)]
pub struct PolicyBoundCliHarness {
    pub manifest: CliHarnessManifest,
    pub policy: ToolPolicy,
}

impl PolicyBoundCliHarness {
    pub fn new(manifest: CliHarnessManifest, policy: ToolPolicy) -> Self {
        Self { manifest, policy }
    }

    pub fn run_tool(
        &self,
        tool_name: &str,
        input: Value,
        cwd: Option<String>,
    ) -> HarnessResult<PolicyBoundCliOutcome> {
        let command = self.manifest.render_tool_command(tool_name, &input)?;
        let mut request = ToolPolicyRequest::new(tool_name, input);
        if let Some(cwd) = cwd.clone() {
            request = request.with_cwd(cwd);
        }

        Ok(match self.policy.decide(&request) {
            PolicyDecision::Allow => PolicyBoundCliOutcome::Executed {
                result: command.execute_with_cwd(cwd.as_deref())?,
                command,
            },
            PolicyDecision::RequireApproval { reason } => {
                PolicyBoundCliOutcome::RequiresApproval { command, reason }
            }
            PolicyDecision::Deny { reason } => PolicyBoundCliOutcome::Denied { command, reason },
        })
    }
}

impl CliCommandSpec {
    pub fn new(
        name: impl Into<String>,
        tool_name: impl Into<String>,
        binary: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            tool_name: tool_name.into(),
            binary: binary.into(),
            args: Vec::new(),
            writes_workspace: false,
        }
    }

    pub fn with_arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    pub fn writes_workspace(mut self, writes_workspace: bool) -> Self {
        self.writes_workspace = writes_workspace;
        self
    }

    pub fn render(&self, input: &Value) -> HarnessResult<RenderedCliCommand> {
        let args = self
            .args
            .iter()
            .map(|arg| self.render_arg(arg, input))
            .collect::<HarnessResult<Vec<_>>>()?;

        Ok(RenderedCliCommand {
            binary: self.binary.clone(),
            args,
            writes_workspace: self.writes_workspace,
        })
    }

    fn render_arg(&self, arg: &str, input: &Value) -> HarnessResult<String> {
        let Some(key) = placeholder_key(arg) else {
            return Ok(arg.to_string());
        };
        let value = input.get(key).ok_or_else(|| HarnessError::MissingInput {
            command: self.name.clone(),
            key: key.to_string(),
        })?;
        Ok(match value {
            Value::String(value) => value.clone(),
            other => other.to_string(),
        })
    }
}

fn placeholder_key(arg: &str) -> Option<&str> {
    arg.strip_prefix("{{")?.strip_suffix("}}")
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CliHarnessManifest {
    pub plugin: PluginManifest,
    pub commands: BTreeMap<String, CliCommandSpec>,
}

impl CliHarnessManifest {
    pub fn new(plugin: PluginManifest) -> Self {
        Self {
            plugin,
            commands: BTreeMap::new(),
        }
    }

    pub fn with_command(mut self, command: CliCommandSpec) -> HarnessResult<Self> {
        self.register_command(command)?;
        Ok(self)
    }

    pub fn register_command(&mut self, command: CliCommandSpec) -> HarnessResult<()> {
        if self.commands.contains_key(&command.name) {
            return Err(HarnessError::DuplicateCommand(command.name));
        }
        self.commands.insert(command.name.clone(), command);
        Ok(())
    }

    pub fn command_for_tool(&self, tool_name: &str) -> Option<&CliCommandSpec> {
        self.commands
            .values()
            .find(|command| command.tool_name == tool_name)
    }

    pub fn render_tool_command(
        &self,
        tool_name: &str,
        input: &Value,
    ) -> HarnessResult<RenderedCliCommand> {
        self.command_for_tool(tool_name)
            .ok_or_else(|| HarnessError::MissingCommandForTool(tool_name.to_string()))?
            .render(input)
    }

    pub fn execute_tool_command(
        &self,
        tool_name: &str,
        input: &Value,
    ) -> HarnessResult<CliExecutionResult> {
        self.render_tool_command(tool_name, input)?.execute()
    }

    pub fn validate(&self) -> HarnessResult<()> {
        for command in self.commands.values() {
            if !self
                .plugin
                .tools
                .iter()
                .any(|tool| tool.name == command.tool_name)
            {
                return Err(HarnessError::MissingToolForCommand {
                    command: command.name.clone(),
                    tool: command.tool_name.clone(),
                });
            }
        }

        for tool in &self.plugin.tools {
            if self.command_for_tool(&tool.name).is_none() {
                return Err(HarnessError::MissingCommandForTool(tool.name.clone()));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::harness::{
        CliCommandSpec, CliExecutionLimits, CliExecutionResult, CliHarnessManifest, HarnessError,
        PolicyBoundCliHarness, PolicyBoundCliOutcome, RenderedCliCommand,
    };
    use crate::plugin::PluginManifest;
    use crate::policy::ToolPolicy;
    use crate::protocol::PermissionMode;
    use crate::registry::{ToolPermission, ToolSpec};

    #[test]
    fn validates_commands_for_manifest_tools() {
        let plugin = PluginManifest::new("code", "Code", "0.1.0", "Code tools.").with_tool(
            ToolSpec::new("code.query", "Search code.", ToolPermission::Allow),
        );
        let harness = CliHarnessManifest::new(plugin)
            .with_command(
                CliCommandSpec::new("query", "code.query", "code")
                    .with_arg("query")
                    .with_arg("{{query}}"),
            )
            .unwrap();

        assert!(harness.validate().is_ok());
        assert_eq!(
            harness.command_for_tool("code.query").unwrap().args,
            vec!["query".to_string(), "{{query}}".to_string()]
        );
    }

    #[test]
    fn renders_cli_command_templates_from_json_input() {
        let command = CliCommandSpec::new("query", "code.query", "code")
            .with_arg("query")
            .with_arg("{{query}}")
            .with_arg("--limit")
            .with_arg("{{limit}}");

        let rendered = command
            .render(&serde_json::json!({"query": "ControlPlane", "limit": 5}))
            .unwrap();

        assert_eq!(rendered.binary, "code");
        assert_eq!(
            rendered.args,
            vec![
                "query".to_string(),
                "ControlPlane".to_string(),
                "--limit".to_string(),
                "5".to_string()
            ]
        );
        assert!(!rendered.writes_workspace);
    }

    #[test]
    fn rejects_missing_template_inputs() {
        let command = CliCommandSpec::new("query", "code.query", "code").with_arg("{{query}}");

        let error = command.render(&serde_json::json!({})).unwrap_err();

        assert!(matches!(
            error,
            HarnessError::MissingInput { command, key }
                if command == "query" && key == "query"
        ));
    }

    #[test]
    fn renders_tool_commands_from_manifest() {
        let plugin = PluginManifest::new("code", "Code", "0.1.0", "Code tools.").with_tool(
            ToolSpec::new("code.query", "Search code.", ToolPermission::Allow),
        );
        let harness = CliHarnessManifest::new(plugin)
            .with_command(
                CliCommandSpec::new("query", "code.query", "code")
                    .with_arg("query")
                    .with_arg("{{query}}"),
            )
            .unwrap();

        let rendered = harness
            .render_tool_command("code.query", &serde_json::json!({"query": "ControlPlane"}))
            .unwrap();

        assert_eq!(rendered.binary, "code");
        assert_eq!(rendered.args, vec!["query", "ControlPlane"]);
    }

    #[test]
    fn executes_rendered_cli_commands_and_captures_output() {
        let command = RenderedCliCommand {
            binary: std::env::current_exe()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            args: vec!["--list".to_string()],
            writes_workspace: false,
        };

        let result: CliExecutionResult = command.execute().unwrap();

        assert!(result.success);
        assert_eq!(result.status_code, Some(0));
        assert!(result
            .stdout
            .contains("executes_rendered_cli_commands_and_captures_output"));
        assert!(!result.timed_out);
        assert!(!result.stdout_truncated);
        assert!(!result.writes_workspace);
    }

    #[test]
    fn truncates_rendered_cli_command_output_when_limit_is_reached() {
        let command = RenderedCliCommand {
            binary: std::env::current_exe()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            args: vec!["--list".to_string()],
            writes_workspace: false,
        };

        let result = command
            .execute_with_cwd_and_limits(
                None,
                CliExecutionLimits {
                    timeout: std::time::Duration::from_secs(5),
                    max_stdout_bytes: 16,
                    max_stderr_bytes: 16,
                },
            )
            .unwrap();

        assert!(result.success);
        assert_eq!(result.stdout.len(), 16);
        assert!(result.stdout_truncated);
        assert!(!result.stderr_truncated);
    }

    #[test]
    fn times_out_rendered_cli_command_execution() {
        let command = RenderedCliCommand {
            binary: std::env::current_exe()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            args: vec![
                "harness::tests::ignored_helper_sleeps_for_timeout".to_string(),
                "--exact".to_string(),
                "--ignored".to_string(),
            ],
            writes_workspace: false,
        };

        let result = command
            .execute_with_cwd_and_limits(
                None,
                CliExecutionLimits {
                    timeout: std::time::Duration::from_millis(25),
                    max_stdout_bytes: 1024,
                    max_stderr_bytes: 1024,
                },
            )
            .unwrap();

        assert!(!result.success);
        assert!(result.timed_out);
        assert_eq!(result.status_code, None);
    }

    #[test]
    #[ignore]
    fn ignored_helper_sleeps_for_timeout() {
        std::thread::sleep(std::time::Duration::from_secs(5));
    }

    #[test]
    fn policy_bound_harness_executes_allowed_tools() {
        let tool_name = "code.list";
        let harness = test_executable_harness(tool_name, ToolPermission::Allow);
        let policy = harness.plugin.tools.to_vec();
        let mut registry = crate::registry::ToolRegistry::new();
        for spec in policy {
            registry.register(spec).unwrap();
        }
        let runner =
            PolicyBoundCliHarness::new(harness, registry.to_policy(PermissionMode::Default));

        let outcome = runner
            .run_tool(tool_name, serde_json::json!({}), None)
            .unwrap();

        match outcome {
            PolicyBoundCliOutcome::Executed { result, .. } => {
                assert!(result.success);
                assert!(result
                    .stdout
                    .contains("policy_bound_harness_executes_allowed_tools"));
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    #[test]
    fn policy_bound_harness_returns_approval_without_executing() {
        let tool_name = "code.list";
        let harness = test_executable_harness(tool_name, ToolPermission::RequireApproval);
        let policy = ToolPolicy::new(PermissionMode::Default).with_approval_tool(tool_name);
        let runner = PolicyBoundCliHarness::new(harness, policy);

        let outcome = runner
            .run_tool(tool_name, serde_json::json!({}), None)
            .unwrap();

        match outcome {
            PolicyBoundCliOutcome::RequiresApproval { command, reason } => {
                assert_eq!(command.args, vec!["--list"]);
                assert!(reason.contains("require approval"));
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    #[test]
    fn policy_bound_harness_returns_denial_without_executing() {
        let tool_name = "code.list";
        let harness = test_executable_harness(tool_name, ToolPermission::Deny);
        let policy = ToolPolicy::new(PermissionMode::Bypass).with_denied_tool(tool_name);
        let runner = PolicyBoundCliHarness::new(harness, policy);

        let outcome = runner
            .run_tool(tool_name, serde_json::json!({}), None)
            .unwrap();

        match outcome {
            PolicyBoundCliOutcome::Denied { command, reason } => {
                assert_eq!(command.args, vec!["--list"]);
                assert!(reason.contains("explicitly denied"));
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    #[test]
    fn rejects_commands_for_missing_tools() {
        let plugin = PluginManifest::new("code", "Code", "0.1.0", "Code tools.");
        let harness = CliHarnessManifest::new(plugin)
            .with_command(CliCommandSpec::new("query", "code.query", "code"))
            .unwrap();

        let error = harness.validate().unwrap_err();

        assert!(matches!(
            error,
            HarnessError::MissingToolForCommand { command, tool }
                if command == "query" && tool == "code.query"
        ));
    }

    fn test_executable_harness(tool_name: &str, permission: ToolPermission) -> CliHarnessManifest {
        let binary = std::env::current_exe()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let plugin = PluginManifest::new("code", "Code", "0.1.0", "Code tools.")
            .with_tool(ToolSpec::new(tool_name, "List tests.", permission));

        CliHarnessManifest::new(plugin)
            .with_command(CliCommandSpec::new("list", tool_name, binary).with_arg("--list"))
            .unwrap()
    }
}
