use serde_json::json;

use crate::harness::{CliCommandSpec, CliHarnessManifest};
use crate::plugin::{PluginKind, PluginManifest, PluginSource};
use crate::registry::{ToolPermission, ToolSpec};

pub const GITNEXUS_PLUGIN_ID: &str = "gitnexus";
pub const GITNEXUS_PROVIDER: &str = "gitnexus";

pub fn gitnexus_harness() -> CliHarnessManifest {
    let plugin = PluginManifest::new(
        GITNEXUS_PLUGIN_ID,
        "GitNexus Code Intelligence",
        "1.6",
        "Graph-powered code indexing, search, context, and impact analysis.",
    )
    .with_capability("code_intelligence")
    .with_capability("code_graph")
    .with_kind(PluginKind::CliHarness)
    .with_source(PluginSource::bundled("essence://plugins/gitnexus"))
    .with_metadata("license", json!("PolyForm-Noncommercial-1.0.0"))
    .with_metadata("integration", json!("external_cli"))
    .with_tool(readonly_tool(
        "gitnexus.query",
        "Search the indexed code graph with hybrid lexical and semantic retrieval.",
        query_schema(),
    ))
    .with_tool(readonly_tool(
        "gitnexus.context",
        "Fetch callers, callees, and process context for a symbol.",
        context_schema(),
    ))
    .with_tool(readonly_tool(
        "gitnexus.impact",
        "Analyze upstream or downstream blast radius for a symbol before editing.",
        impact_schema(),
    ))
    .with_tool(readonly_tool(
        "gitnexus.detect_changes",
        "Map git diffs to affected symbols and processes.",
        detect_changes_schema(),
    ))
    .with_tool(readonly_tool(
        "gitnexus.api_impact",
        "Analyze impact for an API route handler.",
        api_impact_schema(),
    ))
    .with_tool(readonly_tool(
        "gitnexus.tool_map",
        "Map MCP or RPC tool definitions to their handlers.",
        tool_map_schema(),
    ))
    .with_tool(
        ToolSpec::new(
            "gitnexus.analyze",
            "Index or re-index a repository into a local GitNexus graph.",
            ToolPermission::RequireApproval,
        )
        .with_capability("code_intelligence")
        .with_capability("code_indexing")
        .with_provider(GITNEXUS_PROVIDER)
        .with_input_schema(analyze_schema()),
    );

    CliHarnessManifest::new(plugin)
        .with_command(
            command("query", "gitnexus.query")
                .with_arg("query")
                .with_arg("{{query}}"),
        )
        .unwrap()
        .with_command(
            command("context", "gitnexus.context")
                .with_arg("context")
                .with_arg("{{target}}"),
        )
        .unwrap()
        .with_command(
            command("impact", "gitnexus.impact")
                .with_arg("impact")
                .with_arg("{{target}}")
                .with_arg("--direction")
                .with_arg("{{direction}}"),
        )
        .unwrap()
        .with_command(
            command("detect_changes", "gitnexus.detect_changes").with_arg("detect-changes"),
        )
        .unwrap()
        .with_command(
            command("api_impact", "gitnexus.api_impact")
                .with_arg("api-impact")
                .with_arg("{{route}}"),
        )
        .unwrap()
        .with_command(command("tool_map", "gitnexus.tool_map").with_arg("tool-map"))
        .unwrap()
        .with_command(
            command("analyze", "gitnexus.analyze")
                .with_arg("analyze")
                .with_arg("{{path}}")
                .writes_workspace(true),
        )
        .unwrap()
}

fn readonly_tool(name: &str, description: &str, schema: serde_json::Value) -> ToolSpec {
    ToolSpec::new(name, description, ToolPermission::Allow)
        .with_capability("code_intelligence")
        .with_provider(GITNEXUS_PROVIDER)
        .with_input_schema(schema)
}

fn command(name: &str, tool_name: &str) -> CliCommandSpec {
    CliCommandSpec::new(name, tool_name, "gitnexus")
}

fn query_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "required": ["query"],
        "properties": {
            "query": {"type": "string"},
            "repo": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1}
        }
    })
}

fn context_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "required": ["target"],
        "properties": {
            "target": {"type": "string"},
            "repo": {"type": "string"}
        }
    })
}

fn impact_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "required": ["target", "direction"],
        "properties": {
            "target": {"type": "string"},
            "repo": {"type": "string"},
            "direction": {
                "type": "string",
                "enum": ["upstream", "downstream", "both"]
            }
        }
    })
}

fn detect_changes_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "properties": {
            "repo": {"type": "string"},
            "base": {"type": "string"},
            "head": {"type": "string"}
        }
    })
}

fn api_impact_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "required": ["route"],
        "properties": {
            "route": {"type": "string"},
            "repo": {"type": "string"}
        }
    })
}

fn tool_map_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "properties": {
            "repo": {"type": "string"},
            "tool": {"type": "string"}
        }
    })
}

fn analyze_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "required": ["path"],
        "properties": {
            "path": {"type": "string", "default": "."},
            "name": {"type": "string"},
            "skip_git": {"type": "boolean"},
            "embeddings": {"type": "boolean"}
        }
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::gitnexus::{gitnexus_harness, GITNEXUS_PLUGIN_ID};
    use crate::plugin::PluginHost;
    use crate::protocol::PermissionMode;

    #[test]
    fn exposes_gitnexus_tools_as_valid_cli_harness() {
        let harness = gitnexus_harness();

        harness.validate().unwrap();

        assert_eq!(harness.plugin.id, GITNEXUS_PLUGIN_ID);
        assert!(harness.plugin.capabilities.contains("code_graph"));
        assert_eq!(harness.plugin.tools.len(), harness.commands.len());
        assert!(harness.command_for_tool("gitnexus.impact").is_some());
        assert!(
            harness
                .command_for_tool("gitnexus.analyze")
                .unwrap()
                .writes_workspace
        );
    }

    #[test]
    fn registers_gitnexus_tools_with_policy_metadata() {
        let harness = gitnexus_harness();
        let mut host = PluginHost::new();
        host.register(harness.plugin).unwrap();
        let policy = host.tools().to_policy(PermissionMode::Default);

        assert!(host.tools().contains("gitnexus.query"));
        assert!(host.tools().contains("gitnexus.analyze"));
        assert!(policy
            .decide(&crate::policy::ToolPolicyRequest::new(
                "gitnexus.query",
                json!({"query": "ControlPlane"})
            ))
            .is_allow());
        assert!(policy
            .decide(&crate::policy::ToolPolicyRequest::new(
                "gitnexus.analyze",
                json!({"path": "."})
            ))
            .requires_approval());
    }

    #[test]
    fn renders_gitnexus_impact_command() {
        let harness = gitnexus_harness();
        let command = harness
            .command_for_tool("gitnexus.impact")
            .unwrap()
            .render(&json!({"target": "ControlPlane", "direction": "upstream"}))
            .unwrap();

        assert_eq!(command.binary, "gitnexus");
        assert_eq!(
            command.args,
            vec![
                "impact".to_string(),
                "ControlPlane".to_string(),
                "--direction".to_string(),
                "upstream".to_string()
            ]
        );
    }
}
