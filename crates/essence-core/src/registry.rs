use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::policy::ToolPolicy;
use crate::protocol::PermissionMode;

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("tool `{0}` is already registered")]
    DuplicateTool(String),
    #[error("tool `{0}` is not registered")]
    MissingTool(String),
}

pub type RegistryResult<T> = Result<T, RegistryError>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ToolPermission {
    Allow,
    RequireApproval,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    pub permission: ToolPermission,
    #[serde(default)]
    pub capabilities: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
}

impl ToolSpec {
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        permission: ToolPermission,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            permission,
            capabilities: BTreeSet::new(),
            input_schema: None,
            provider: None,
        }
    }

    pub fn with_capability(mut self, capability: impl Into<String>) -> Self {
        self.capabilities.insert(capability.into());
        self
    }

    pub fn with_input_schema(mut self, schema: Value) -> Self {
        self.input_schema = Some(schema);
        self
    }

    pub fn with_provider(mut self, provider: impl Into<String>) -> Self {
        self.provider = Some(provider.into());
        self
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ToolRegistry {
    tools: BTreeMap<String, ToolSpec>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, spec: ToolSpec) -> RegistryResult<()> {
        if self.tools.contains_key(&spec.name) {
            return Err(RegistryError::DuplicateTool(spec.name));
        }
        self.tools.insert(spec.name.clone(), spec);
        Ok(())
    }

    pub fn with_tool(mut self, spec: ToolSpec) -> RegistryResult<Self> {
        self.register(spec)?;
        Ok(self)
    }

    pub fn get(&self, name: &str) -> RegistryResult<&ToolSpec> {
        self.tools
            .get(name)
            .ok_or_else(|| RegistryError::MissingTool(name.to_string()))
    }

    pub fn contains(&self, name: &str) -> bool {
        self.tools.contains_key(name)
    }

    pub fn iter(&self) -> impl Iterator<Item = &ToolSpec> {
        self.tools.values()
    }

    pub fn by_capability<'a>(&'a self, capability: &'a str) -> impl Iterator<Item = &'a ToolSpec> {
        self.tools
            .values()
            .filter(move |spec| spec.capabilities.contains(capability))
    }

    pub fn to_policy(&self, mode: PermissionMode) -> ToolPolicy {
        let mut policy = ToolPolicy::new(mode);
        for spec in self.tools.values() {
            policy = match spec.permission {
                ToolPermission::Allow => policy.with_allowed_tool(spec.name.clone()),
                ToolPermission::RequireApproval => policy.with_approval_tool(spec.name.clone()),
                ToolPermission::Deny => policy.with_denied_tool(spec.name.clone()),
            };
        }
        policy
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::policy::{PolicyDecision, ToolPolicyRequest};
    use crate::protocol::PermissionMode;
    use crate::registry::{RegistryError, ToolPermission, ToolRegistry, ToolSpec};

    #[test]
    fn registers_and_finds_tools() {
        let mut registry = ToolRegistry::new();
        registry
            .register(
                ToolSpec::new("read_file", "Read a workspace file.", ToolPermission::Allow)
                    .with_capability("filesystem")
                    .with_provider("core"),
            )
            .unwrap();

        let spec = registry.get("read_file").unwrap();

        assert_eq!(spec.name, "read_file");
        assert!(spec.capabilities.contains("filesystem"));
        assert_eq!(spec.provider.as_deref(), Some("core"));
    }

    #[test]
    fn rejects_duplicate_tools() {
        let mut registry = ToolRegistry::new();
        registry
            .register(ToolSpec::new(
                "shell",
                "Run a command.",
                ToolPermission::RequireApproval,
            ))
            .unwrap();
        let error = registry
            .register(ToolSpec::new(
                "shell",
                "Run another command.",
                ToolPermission::Deny,
            ))
            .unwrap_err();

        assert!(matches!(error, RegistryError::DuplicateTool(name) if name == "shell"));
    }

    #[test]
    fn filters_by_capability() {
        let mut registry = ToolRegistry::new();
        registry
            .register(
                ToolSpec::new("read_file", "Read a workspace file.", ToolPermission::Allow)
                    .with_capability("filesystem"),
            )
            .unwrap();
        registry
            .register(
                ToolSpec::new(
                    "search_web",
                    "Search the web.",
                    ToolPermission::RequireApproval,
                )
                .with_capability("network"),
            )
            .unwrap();

        let names = registry
            .by_capability("filesystem")
            .map(|spec| spec.name.as_str())
            .collect::<Vec<_>>();

        assert_eq!(names, vec!["read_file"]);
    }

    #[test]
    fn builds_policy_from_registered_permissions() {
        let mut registry = ToolRegistry::new();
        registry
            .register(ToolSpec::new(
                "read_file",
                "Read file.",
                ToolPermission::Allow,
            ))
            .unwrap();
        registry
            .register(ToolSpec::new(
                "shell",
                "Run command.",
                ToolPermission::RequireApproval,
            ))
            .unwrap();
        registry
            .register(ToolSpec::new(
                "delete_file",
                "Delete file.",
                ToolPermission::Deny,
            ))
            .unwrap();
        let policy = registry.to_policy(PermissionMode::Default);

        assert_eq!(
            policy.decide(&ToolPolicyRequest::new("read_file", json!({}))),
            PolicyDecision::Allow
        );
        assert!(policy
            .decide(&ToolPolicyRequest::new("shell", json!({})))
            .requires_approval());
        assert!(policy
            .decide(&ToolPolicyRequest::new("delete_file", json!({})))
            .is_deny());
    }

    #[test]
    fn stores_input_schema_metadata() {
        let spec = ToolSpec::new("shell", "Run command.", ToolPermission::RequireApproval)
            .with_input_schema(json!({
                "type": "object",
                "required": ["command"],
                "properties": {"command": {"type": "string"}}
            }));

        assert!(spec.input_schema.is_some());
    }
}
