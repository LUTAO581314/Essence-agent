use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::plugin::PluginManifest;

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
    use crate::harness::{CliCommandSpec, CliHarnessManifest, HarnessError};
    use crate::plugin::PluginManifest;
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
}
