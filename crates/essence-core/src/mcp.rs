use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::api::{
    ApiEventsAfterRequest, ApiMemorySearchRequest, ApiSwarmTickRequest, ApiVerifyIntegrityRequest,
    ControlApi,
};
use crate::control::ControlError;
use crate::registry::ToolSpec;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct McpToolDescriptor {
    pub name: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<Value>,
    #[serde(default)]
    pub read_only: bool,
}

impl From<&ToolSpec> for McpToolDescriptor {
    fn from(tool: &ToolSpec) -> Self {
        Self {
            name: tool.name.clone(),
            description: tool.description.clone(),
            input_schema: tool.input_schema.clone(),
            read_only: tool.capabilities.contains("read_only"),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct McpAdapterManifest {
    pub server_name: String,
    pub tools: Vec<McpToolDescriptor>,
}

impl McpAdapterManifest {
    pub fn new(server_name: impl Into<String>) -> Self {
        Self {
            server_name: server_name.into(),
            tools: Vec::new(),
        }
    }

    pub fn with_tool(mut self, tool: McpToolDescriptor) -> Self {
        self.tools.push(tool);
        self
    }

    pub fn from_tools<'a>(
        server_name: impl Into<String>,
        tools: impl IntoIterator<Item = &'a ToolSpec>,
    ) -> Self {
        Self {
            server_name: server_name.into(),
            tools: tools.into_iter().map(McpToolDescriptor::from).collect(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum McpError {
    #[error(transparent)]
    Control(#[from] ControlError),
    #[error("unknown MCP tool `{0}`")]
    UnknownTool(String),
    #[error("invalid input for MCP tool `{tool}`: {source}")]
    InvalidInput {
        tool: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("could not encode MCP response for `{tool}`: {source}")]
    Response {
        tool: String,
        #[source]
        source: serde_json::Error,
    },
}

pub type McpResult<T> = Result<T, McpError>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct McpToolCallRequest {
    pub name: String,
    #[serde(default)]
    pub arguments: Value,
}

impl McpToolCallRequest {
    pub fn new(name: impl Into<String>, arguments: Value) -> Self {
        Self {
            name: name.into(),
            arguments,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct McpToolCallResponse {
    #[serde(default)]
    pub structured_content: Value,
    #[serde(default)]
    pub is_error: bool,
}

impl McpToolCallResponse {
    pub fn structured(tool: &str, value: impl Serialize) -> McpResult<Self> {
        Ok(Self {
            structured_content: serde_json::to_value(value).map_err(|source| {
                McpError::Response {
                    tool: tool.to_string(),
                    source,
                }
            })?,
            is_error: false,
        })
    }
}

#[derive(Debug, Clone)]
pub struct EssenceMcpServer {
    api: ControlApi,
}

impl EssenceMcpServer {
    pub fn new(api: ControlApi) -> Self {
        Self { api }
    }

    pub fn manifest(&self) -> McpAdapterManifest {
        self.api.mcp_manifest()
    }

    pub fn call_tool(&self, request: McpToolCallRequest) -> McpResult<McpToolCallResponse> {
        match request.name.as_str() {
            "essence_events_after" => {
                let input =
                    decode_tool_input::<ApiEventsAfterRequest>(&request.name, request.arguments)?;
                McpToolCallResponse::structured(&request.name, self.api.events_after(input)?)
            }
            "essence_verify_integrity" => {
                let input = decode_tool_input::<ApiVerifyIntegrityRequest>(
                    &request.name,
                    request.arguments,
                )?;
                McpToolCallResponse::structured(&request.name, self.api.verify_integrity(input)?)
            }
            "essence_swarm_tick" => {
                let input =
                    decode_tool_input::<ApiSwarmTickRequest>(&request.name, request.arguments)?;
                McpToolCallResponse::structured(&request.name, self.api.swarm_tick(input)?)
            }
            "essence_memory_search" => {
                let input =
                    decode_tool_input::<ApiMemorySearchRequest>(&request.name, request.arguments)?;
                McpToolCallResponse::structured(&request.name, self.api.memory_search(input)?)
            }
            other => Err(McpError::UnknownTool(other.to_string())),
        }
    }
}

fn decode_tool_input<T: for<'de> Deserialize<'de>>(tool: &str, value: Value) -> McpResult<T> {
    serde_json::from_value(value).map_err(|source| McpError::InvalidInput {
        tool: tool.to_string(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use uuid::Uuid;

    use crate::api::{ApiCreateSessionRequest, ControlApi};
    use crate::control::ControlPlane;
    use crate::mcp::McpAdapterManifest;
    use crate::mcp::{EssenceMcpServer, McpError, McpToolCallRequest};
    use crate::registry::{ToolPermission, ToolSpec};

    #[test]
    fn maps_tool_specs_to_mcp_descriptors() {
        let tool = ToolSpec::new(
            "essence_events_after",
            "List ledger events after a cursor.",
            ToolPermission::Allow,
        )
        .with_capability("read_only")
        .with_input_schema(json!({"type": "object"}));

        let manifest = McpAdapterManifest::from_tools("essence", [&tool]);

        assert_eq!(manifest.server_name, "essence");
        assert_eq!(manifest.tools[0].name, "essence_events_after");
        assert!(manifest.tools[0].read_only);
        assert!(manifest.tools[0].input_schema.is_some());
    }

    #[test]
    fn dispatches_core_mcp_tool_calls() {
        let root = std::env::temp_dir().join(format!("essence-mcp-{}", Uuid::new_v4()));
        let api = ControlApi::new(ControlPlane::new(&root));
        let session = api
            .create_session(ApiCreateSessionRequest::interactive("."))
            .unwrap();
        api.send_message(crate::api::ApiSendMessageRequest {
            session_id: session.session_id.clone(),
            text: "hello mcp".to_string(),
        })
        .unwrap();
        let server = EssenceMcpServer::new(api);

        let response = server
            .call_tool(McpToolCallRequest::new(
                "essence_events_after",
                json!({
                    "session_id": session.session_id.clone(),
                    "after_seq": 1
                }),
            ))
            .unwrap();
        let events = response.structured_content.as_array().unwrap();

        assert!(!response.is_error);
        assert_eq!(events.len(), 1);
        let report = server
            .call_tool(McpToolCallRequest::new(
                "essence_verify_integrity",
                json!({
                    "session_id": session.session_id.clone()
                }),
            ))
            .unwrap();
        assert_eq!(
            report.structured_content["findings"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        assert!(server
            .manifest()
            .tools
            .iter()
            .any(|tool| tool.name == "essence_memory_search"));
        assert!(server
            .manifest()
            .tools
            .iter()
            .any(|tool| tool.name == "essence_verify_integrity" && tool.read_only));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn rejects_unknown_mcp_tools() {
        let server = EssenceMcpServer::new(ControlApi::new(ControlPlane::new(".")));
        let error = server
            .call_tool(McpToolCallRequest::new("missing", json!({})))
            .unwrap_err();

        assert!(matches!(error, McpError::UnknownTool(tool) if tool == "missing"));
    }
}
