use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::protocol::JsonObject;
use crate::registry::{RegistryError, ToolRegistry, ToolSpec};

#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    #[error("plugin `{0}` is already registered")]
    DuplicatePlugin(String),
    #[error("plugin `{0}` is not registered")]
    MissingPlugin(String),
    #[error(transparent)]
    Registry(#[from] RegistryError),
}

pub type PluginResult<T> = Result<T, PluginError>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PluginManifest {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    #[serde(default)]
    pub capabilities: BTreeSet<String>,
    #[serde(default)]
    pub tools: Vec<ToolSpec>,
    #[serde(default)]
    pub metadata: JsonObject,
}

impl PluginManifest {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        version: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            version: version.into(),
            description: description.into(),
            capabilities: BTreeSet::new(),
            tools: Vec::new(),
            metadata: Default::default(),
        }
    }

    pub fn with_capability(mut self, capability: impl Into<String>) -> Self {
        self.capabilities.insert(capability.into());
        self
    }

    pub fn with_tool(mut self, tool: ToolSpec) -> Self {
        self.tools.push(tool);
        self
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct PluginHost {
    plugins: BTreeMap<String, PluginManifest>,
    tools: ToolRegistry,
}

impl PluginHost {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, plugin: PluginManifest) -> PluginResult<()> {
        if self.plugins.contains_key(&plugin.id) {
            return Err(PluginError::DuplicatePlugin(plugin.id));
        }

        for tool in &plugin.tools {
            self.tools.register(tool.clone())?;
        }
        self.plugins.insert(plugin.id.clone(), plugin);
        Ok(())
    }

    pub fn with_plugin(mut self, plugin: PluginManifest) -> PluginResult<Self> {
        self.register(plugin)?;
        Ok(self)
    }

    pub fn plugin(&self, id: &str) -> PluginResult<&PluginManifest> {
        self.plugins
            .get(id)
            .ok_or_else(|| PluginError::MissingPlugin(id.to_string()))
    }

    pub fn plugins(&self) -> impl Iterator<Item = &PluginManifest> {
        self.plugins.values()
    }

    pub fn tools(&self) -> &ToolRegistry {
        &self.tools
    }

    pub fn into_tools(self) -> ToolRegistry {
        self.tools
    }
}

#[cfg(test)]
mod tests {
    use crate::plugin::{PluginError, PluginHost, PluginManifest};
    use crate::registry::{RegistryError, ToolPermission, ToolSpec};

    #[test]
    fn registers_plugin_tools_into_host_registry() {
        let plugin = PluginManifest::new(
            "code-intel",
            "Code Intelligence",
            "0.1.0",
            "Code understanding tools.",
        )
        .with_capability("code_intelligence")
        .with_tool(
            ToolSpec::new("code.query", "Search indexed code.", ToolPermission::Allow)
                .with_provider("code-intel"),
        );
        let mut host = PluginHost::new();

        host.register(plugin).unwrap();

        assert_eq!(host.plugins().count(), 1);
        assert!(host.plugin("code-intel").is_ok());
        assert!(host.tools().contains("code.query"));
        assert_eq!(
            host.tools().get("code.query").unwrap().provider.as_deref(),
            Some("code-intel")
        );
    }

    #[test]
    fn rejects_duplicate_plugins() {
        let plugin = PluginManifest::new("code-intel", "Code Intelligence", "0.1.0", "Tools.");
        let mut host = PluginHost::new();
        host.register(plugin.clone()).unwrap();

        let error = host.register(plugin).unwrap_err();

        assert!(matches!(error, PluginError::DuplicatePlugin(id) if id == "code-intel"));
    }

    #[test]
    fn rejects_duplicate_plugin_tools() {
        let first = PluginManifest::new("one", "One", "0.1.0", "First.").with_tool(ToolSpec::new(
            "code.query",
            "Search indexed code.",
            ToolPermission::Allow,
        ));
        let second =
            PluginManifest::new("two", "Two", "0.1.0", "Second.").with_tool(ToolSpec::new(
                "code.query",
                "Search indexed code again.",
                ToolPermission::Allow,
            ));
        let mut host = PluginHost::new();
        host.register(first).unwrap();

        let error = host.register(second).unwrap_err();

        assert!(matches!(
            error,
            PluginError::Registry(RegistryError::DuplicateTool(name)) if name == "code.query"
        ));
    }
}
