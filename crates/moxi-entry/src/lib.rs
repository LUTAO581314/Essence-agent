use moxi_contracts::{Budget, PermissionMode, RiskLevel};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EntryError {
    #[error("missing required entry field: {0}")]
    MissingField(&'static str),
    #[error("entry goal cannot be empty")]
    EmptyGoal,
    #[error("entry requested capability cannot be empty")]
    EmptyCapability,
}

pub type EntryResult<T> = Result<T, EntryError>;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EntryChannel {
    Cli,
    Desktop,
    Web,
    HttpApi,
    Sdk,
    McpServer,
    Automation,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct EntryContext {
    pub channel: EntryChannel,
    pub tenant_id: String,
    pub user_id: String,
    pub workspace_root: String,
    pub session_id: Option<String>,
    pub request_id: Option<String>,
    pub source_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct EntryRequest {
    pub context: EntryContext,
    pub goal: String,
    pub requested_capabilities: Vec<String>,
    pub risk_level: RiskLevel,
    pub permission_mode: PermissionMode,
    pub budget: Budget,
}

impl EntryRequest {
    pub fn new(
        channel: EntryChannel,
        tenant_id: impl Into<String>,
        user_id: impl Into<String>,
        workspace_root: impl Into<String>,
        goal: impl Into<String>,
    ) -> Self {
        Self {
            context: EntryContext {
                channel,
                tenant_id: tenant_id.into(),
                user_id: user_id.into(),
                workspace_root: workspace_root.into(),
                session_id: None,
                request_id: None,
                source_ref: None,
            },
            goal: goal.into(),
            requested_capabilities: Vec::new(),
            risk_level: RiskLevel::Low,
            permission_mode: PermissionMode::ReadOnly,
            budget: Budget::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct EntryIntentCandidate {
    pub tenant_id: String,
    pub user_id: String,
    pub goal: String,
    pub requested_capabilities: Vec<String>,
    pub risk_level: RiskLevel,
    pub workspace_root: String,
    pub budget: Budget,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct NormalizedEntry {
    pub channel: EntryChannel,
    pub request_id: String,
    pub session_id: Option<String>,
    pub source_ref: Option<String>,
    pub permission_mode: PermissionMode,
    pub candidate: EntryIntentCandidate,
}

pub struct EntryAdapter;

impl EntryAdapter {
    pub fn normalize(request: EntryRequest) -> EntryResult<NormalizedEntry> {
        require_non_empty("tenant_id", &request.context.tenant_id)?;
        require_non_empty("user_id", &request.context.user_id)?;
        require_non_empty("workspace_root", &request.context.workspace_root)?;

        let goal = trimmed_required_goal(&request.goal)?;
        let requested_capabilities = normalize_capabilities(request.requested_capabilities)?;
        let request_id = request
            .context
            .request_id
            .unwrap_or_else(|| format!("entry_{}", Uuid::new_v4()));

        Ok(NormalizedEntry {
            channel: request.context.channel,
            request_id,
            session_id: request.context.session_id,
            source_ref: request.context.source_ref,
            permission_mode: request.permission_mode,
            candidate: EntryIntentCandidate {
                tenant_id: request.context.tenant_id,
                user_id: request.context.user_id,
                goal,
                requested_capabilities,
                risk_level: request.risk_level,
                workspace_root: request.context.workspace_root,
                budget: request.budget,
            },
        })
    }
}

pub fn normalize_entry(request: EntryRequest) -> EntryResult<NormalizedEntry> {
    EntryAdapter::normalize(request)
}

fn require_non_empty(field: &'static str, value: &str) -> EntryResult<()> {
    if value.trim().is_empty() {
        return Err(EntryError::MissingField(field));
    }
    Ok(())
}

fn trimmed_required_goal(goal: &str) -> EntryResult<String> {
    let trimmed = goal.trim();
    if trimmed.is_empty() {
        return Err(EntryError::EmptyGoal);
    }
    Ok(trimmed.to_owned())
}

fn normalize_capabilities(capabilities: Vec<String>) -> EntryResult<Vec<String>> {
    let mut normalized = Vec::new();
    for capability in capabilities {
        let capability = capability.trim();
        if capability.is_empty() {
            return Err(EntryError::EmptyCapability);
        }
        if !normalized.iter().any(|existing| existing == capability) {
            normalized.push(capability.to_owned());
        }
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_entry_request_into_intent_candidate() {
        let mut request = EntryRequest::new(
            EntryChannel::McpServer,
            "tenant_a",
            "user_a",
            "/workspace",
            "  read project status  ",
        );
        request.context.session_id = Some("session_1".into());
        request.context.request_id = Some("request_1".into());
        request.context.source_ref = Some("mcp://client/request_1".into());
        request.requested_capabilities = vec![
            " file.read ".into(),
            "file.read".into(),
            "memory.read".into(),
        ];

        let normalized = normalize_entry(request).unwrap();

        assert_eq!(normalized.channel, EntryChannel::McpServer);
        assert_eq!(normalized.request_id, "request_1");
        assert_eq!(normalized.session_id.as_deref(), Some("session_1"));
        assert_eq!(
            normalized.source_ref.as_deref(),
            Some("mcp://client/request_1")
        );
        assert_eq!(normalized.permission_mode, PermissionMode::ReadOnly);
        assert_eq!(normalized.candidate.goal, "read project status");
        assert_eq!(
            normalized.candidate.requested_capabilities,
            vec!["file.read", "memory.read"]
        );
        assert_eq!(normalized.candidate.tenant_id, "tenant_a");
        assert_eq!(normalized.candidate.user_id, "user_a");
    }

    #[test]
    fn rejects_empty_boundary_fields() {
        let request = EntryRequest::new(EntryChannel::Cli, "tenant_a", "user_a", "/workspace", " ");

        assert_eq!(normalize_entry(request).unwrap_err(), EntryError::EmptyGoal);
    }

    #[test]
    fn rejects_empty_capability_names() {
        let mut request = EntryRequest::new(
            EntryChannel::Cli,
            "tenant_a",
            "user_a",
            "/workspace",
            "read",
        );
        request.requested_capabilities = vec!["file.read".into(), " ".into()];

        assert_eq!(
            normalize_entry(request).unwrap_err(),
            EntryError::EmptyCapability
        );
    }
}
