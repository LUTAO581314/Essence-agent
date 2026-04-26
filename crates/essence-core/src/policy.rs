use std::collections::BTreeSet;

use serde_json::Value;

use crate::protocol::PermissionMode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    RequireApproval { reason: String },
    Deny { reason: String },
}

impl PolicyDecision {
    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow)
    }

    pub fn requires_approval(&self) -> bool {
        matches!(self, Self::RequireApproval { .. })
    }

    pub fn is_deny(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolPolicy {
    mode: PermissionMode,
    allow_tools: BTreeSet<String>,
    approval_tools: BTreeSet<String>,
    deny_tools: BTreeSet<String>,
}

impl ToolPolicy {
    pub fn new(mode: PermissionMode) -> Self {
        Self {
            mode,
            allow_tools: BTreeSet::new(),
            approval_tools: BTreeSet::new(),
            deny_tools: BTreeSet::new(),
        }
    }

    pub fn with_allowed_tool(mut self, tool_name: impl Into<String>) -> Self {
        self.allow_tools.insert(tool_name.into());
        self
    }

    pub fn with_approval_tool(mut self, tool_name: impl Into<String>) -> Self {
        self.approval_tools.insert(tool_name.into());
        self
    }

    pub fn with_denied_tool(mut self, tool_name: impl Into<String>) -> Self {
        self.deny_tools.insert(tool_name.into());
        self
    }

    pub fn decide(&self, request: &ToolPolicyRequest) -> PolicyDecision {
        if self.deny_tools.contains(&request.tool_name) {
            return PolicyDecision::Deny {
                reason: format!("tool `{}` is explicitly denied", request.tool_name),
            };
        }

        match self.mode {
            PermissionMode::Bypass => PolicyDecision::Allow,
            PermissionMode::Readonly => PolicyDecision::Deny {
                reason: "readonly permission mode denies tool execution".to_string(),
            },
            PermissionMode::Plan => PolicyDecision::RequireApproval {
                reason: "plan permission mode requires approval for tool execution".to_string(),
            },
            PermissionMode::Auto if self.approval_tools.contains(&request.tool_name) => {
                PolicyDecision::RequireApproval {
                    reason: format!(
                        "tool `{}` is configured to require approval",
                        request.tool_name
                    ),
                }
            }
            PermissionMode::Auto => PolicyDecision::Allow,
            PermissionMode::Default if self.allow_tools.contains(&request.tool_name) => {
                PolicyDecision::Allow
            }
            PermissionMode::Default if self.approval_tools.contains(&request.tool_name) => {
                PolicyDecision::RequireApproval {
                    reason: format!(
                        "tool `{}` is configured to require approval",
                        request.tool_name
                    ),
                }
            }
            PermissionMode::Default => PolicyDecision::RequireApproval {
                reason: format!("tool `{}` has no allow rule", request.tool_name),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ToolPolicyRequest {
    pub tool_name: String,
    pub input: Value,
    pub cwd: Option<String>,
}

impl ToolPolicyRequest {
    pub fn new(tool_name: impl Into<String>, input: Value) -> Self {
        Self {
            tool_name: tool_name.into(),
            input,
            cwd: None,
        }
    }

    pub fn with_cwd(mut self, cwd: impl Into<String>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::policy::{PolicyDecision, ToolPolicy, ToolPolicyRequest};
    use crate::protocol::PermissionMode;

    #[test]
    fn default_mode_allows_explicit_tools() {
        let policy = ToolPolicy::new(PermissionMode::Default).with_allowed_tool("read_file");
        let request = ToolPolicyRequest::new("read_file", json!({"path": "README.md"}));

        assert_eq!(policy.decide(&request), PolicyDecision::Allow);
    }

    #[test]
    fn default_mode_requires_approval_without_allow_rule() {
        let policy = ToolPolicy::new(PermissionMode::Default);
        let request = ToolPolicyRequest::new("shell", json!({"command": "cargo test"}));

        assert!(policy.decide(&request).requires_approval());
    }

    #[test]
    fn readonly_mode_denies_tools() {
        let policy = ToolPolicy::new(PermissionMode::Readonly).with_allowed_tool("read_file");
        let request = ToolPolicyRequest::new("read_file", json!({"path": "README.md"}));

        assert!(policy.decide(&request).is_deny());
    }

    #[test]
    fn deny_rules_win_over_bypass_mode() {
        let policy = ToolPolicy::new(PermissionMode::Bypass).with_denied_tool("delete_file");
        let request = ToolPolicyRequest::new("delete_file", json!({"path": "README.md"}));

        assert!(policy.decide(&request).is_deny());
    }

    #[test]
    fn auto_mode_allows_except_approval_tools() {
        let policy = ToolPolicy::new(PermissionMode::Auto).with_approval_tool("shell");
        let request = ToolPolicyRequest::new("shell", json!({"command": "cargo test"}));

        assert!(policy.decide(&request).requires_approval());
    }
}
