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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PluginKind {
    ToolProvider,
    CliHarness,
    BrowserDaemon,
    ResearchRadar,
    MemoryBackend,
    UiShell,
    RolePack,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginSource {
    pub uri: String,
    pub kind: String,
}

impl PluginSource {
    pub fn bundled(uri: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            kind: "bundled".to_string(),
        }
    }

    pub fn remote(uri: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            kind: "remote".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UiSlotKind {
    WorkspaceShell,
    AgentPanel,
    TaskPanel,
    SettingsPanel,
    ArtifactViewer,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UiSlot {
    pub slot_id: String,
    pub kind: UiSlotKind,
    pub entry_ref: String,
}

impl UiSlot {
    pub fn new(slot_id: impl Into<String>, kind: UiSlotKind, entry_ref: impl Into<String>) -> Self {
        Self {
            slot_id: slot_id.into(),
            kind,
            entry_ref: entry_ref.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PluginManifest {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub kind: PluginKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<PluginSource>,
    #[serde(default)]
    pub capabilities: BTreeSet<String>,
    #[serde(default)]
    pub tools: Vec<ToolSpec>,
    #[serde(default)]
    pub ui_slots: Vec<UiSlot>,
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
            kind: PluginKind::ToolProvider,
            source: None,
            capabilities: BTreeSet::new(),
            tools: Vec::new(),
            ui_slots: Vec::new(),
            metadata: Default::default(),
        }
    }

    pub fn with_kind(mut self, kind: PluginKind) -> Self {
        self.kind = kind;
        self
    }

    pub fn with_source(mut self, source: PluginSource) -> Self {
        self.source = Some(source);
        self
    }

    pub fn with_capability(mut self, capability: impl Into<String>) -> Self {
        self.capabilities.insert(capability.into());
        self
    }

    pub fn with_tool(mut self, tool: ToolSpec) -> Self {
        self.tools.push(tool);
        self
    }

    pub fn with_ui_slot(mut self, ui_slot: UiSlot) -> Self {
        self.ui_slots.push(ui_slot);
        self
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct PluginCatalog {
    plugins: BTreeMap<String, PluginManifest>,
}

impl PluginCatalog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_plugin(mut self, plugin: PluginManifest) -> Self {
        self.plugins.insert(plugin.id.clone(), plugin);
        self
    }

    pub fn plugin(&self, id: &str) -> PluginResult<&PluginManifest> {
        self.plugins
            .get(id)
            .ok_or_else(|| PluginError::MissingPlugin(id.to_string()))
    }

    pub fn plugins(&self) -> impl Iterator<Item = &PluginManifest> {
        self.plugins.values()
    }

    pub fn by_kind(&self, kind: PluginKind) -> impl Iterator<Item = &PluginManifest> {
        self.plugins
            .values()
            .filter(move |plugin| plugin.kind == kind)
    }

    pub fn by_capability<'a>(
        &'a self,
        capability: &'a str,
    ) -> impl Iterator<Item = &'a PluginManifest> {
        self.plugins
            .values()
            .filter(move |plugin| plugin.capabilities.contains(capability))
    }
}

pub fn basic_plugin_catalog() -> PluginCatalog {
    PluginCatalog::new()
        .with_plugin(crate::gitnexus::gitnexus_harness().plugin)
        .with_plugin(crate::workspace::browser_daemon_plugin(
            crate::workspace::BrowserDaemonDescriptor::local(".essence/browser-daemon.json"),
        ))
        .with_plugin(memory_index_plugin())
        .with_plugin(research_radar_plugin())
        .with_plugin(workspace_shell_plugin())
}

pub fn memory_index_plugin() -> PluginManifest {
    PluginManifest::new(
        "memory-index",
        "Local Memory Index",
        "0.1.0",
        "Deterministic local memory search over saved ledger memories.",
    )
    .with_kind(PluginKind::MemoryBackend)
    .with_source(PluginSource::bundled("essence://plugins/memory-index"))
    .with_capability("memory_index")
    .with_capability("local_first")
    .with_tool(
        ToolSpec::new(
            "essence.memory_search",
            "Search saved local memories.",
            crate::registry::ToolPermission::Allow,
        )
        .with_capability("read_only")
        .with_capability("memory_index")
        .with_provider("memory-index"),
    )
}

pub fn research_radar_plugin() -> PluginManifest {
    PluginManifest::new(
        "research-radar",
        "Research Radar",
        "0.1.0",
        "Plugin boundary for scheduled source ingestion and normalized research items.",
    )
    .with_kind(PluginKind::ResearchRadar)
    .with_source(PluginSource::bundled("essence://plugins/research-radar"))
    .with_capability("research_radar")
    .with_capability("source_ingestion")
    .with_metadata("status", serde_json::json!("boundary"))
}

pub fn workspace_shell_plugin() -> PluginManifest {
    PluginManifest::new(
        "workspace-shell",
        "Workspace Shell",
        "0.1.0",
        "Visual multi-agent workspace shell over ledger projections.",
    )
    .with_kind(PluginKind::UiShell)
    .with_source(PluginSource::bundled("essence://plugins/workspace-shell"))
    .with_capability("ui_shell")
    .with_capability("workspace_projection")
    .with_ui_slot(UiSlot::new(
        "workspace.main",
        UiSlotKind::WorkspaceShell,
        "ui://workspace-shell/main",
    ))
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

    pub fn install_from_catalog(&mut self, catalog: &PluginCatalog, id: &str) -> PluginResult<()> {
        self.register(catalog.plugin(id)?.clone())
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

    pub fn ui_slots(&self) -> impl Iterator<Item = &UiSlot> {
        self.plugins
            .values()
            .flat_map(|plugin| plugin.ui_slots.iter())
    }

    pub fn into_tools(self) -> ToolRegistry {
        self.tools
    }
}

#[cfg(test)]
mod tests {
    use crate::plugin::{
        basic_plugin_catalog, PluginError, PluginHost, PluginKind, PluginManifest, UiSlot,
        UiSlotKind,
    };
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

    #[test]
    fn installs_selected_plugins_from_catalog() {
        let catalog = basic_plugin_catalog();
        let mut host = PluginHost::new();

        host.install_from_catalog(&catalog, "memory-index").unwrap();
        host.install_from_catalog(&catalog, "workspace-shell")
            .unwrap();

        assert!(host.plugin("memory-index").is_ok());
        assert!(host.tools().contains("essence.memory_search"));
        assert_eq!(host.ui_slots().count(), 1);
        assert_eq!(
            catalog.by_kind(PluginKind::UiShell).next().unwrap().id,
            "workspace-shell"
        );
        assert!(catalog.by_capability("browser_daemon").next().is_some());
    }

    #[test]
    fn supports_frontend_ui_plugins() {
        let plugin =
            PluginManifest::new("office-ui", "Office UI", "0.1.0", "Agent office dashboard.")
                .with_kind(PluginKind::UiShell)
                .with_capability("ui_shell")
                .with_ui_slot(UiSlot::new(
                    "office.main",
                    UiSlotKind::WorkspaceShell,
                    "ui://office/main",
                ));
        let mut host = PluginHost::new();

        host.register(plugin).unwrap();
        let slots = host.ui_slots().collect::<Vec<_>>();

        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].entry_ref, "ui://office/main");
    }
}
