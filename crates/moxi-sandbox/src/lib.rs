use chrono::Utc;
use moxi_contracts::{
    ErrorCode, ExecutionTicket, SandboxInput, SandboxResult, Severity, StructuredError,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("unsupported capability: {0}")]
    UnsupportedCapability(String),
    #[error("missing string payload field: {0}")]
    MissingField(&'static str),
    #[error("path is outside workspace root: {0}")]
    OutsideWorkspace(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type SandboxResultType<T> = Result<T, SandboxError>;

pub trait Sandbox {
    fn execute(
        &self,
        ticket: &ExecutionTicket,
        input: SandboxInput,
    ) -> SandboxResultType<SandboxResult>;
}

pub struct FileReadSandbox {
    workspace_root: PathBuf,
}

impl FileReadSandbox {
    pub fn new(workspace_root: impl Into<PathBuf>) -> Self {
        Self {
            workspace_root: workspace_root.into(),
        }
    }

    pub fn resolve_workspace_path(&self, requested_path: &str) -> SandboxResultType<PathBuf> {
        let root = self.workspace_root.canonicalize()?;
        let requested = Path::new(requested_path);
        let candidate = if requested.is_absolute() {
            requested.to_path_buf()
        } else {
            root.join(requested)
        };
        let canonical = candidate.canonicalize()?;

        if !canonical.starts_with(&root) {
            return Err(SandboxError::OutsideWorkspace(
                canonical.to_string_lossy().into_owned(),
            ));
        }

        Ok(canonical)
    }
}

impl Sandbox for FileReadSandbox {
    fn execute(
        &self,
        ticket: &ExecutionTicket,
        input: SandboxInput,
    ) -> SandboxResultType<SandboxResult> {
        if ticket.capability_id != "file.read" || input.capability_id != "file.read" {
            return Err(SandboxError::UnsupportedCapability(
                ticket.capability_id.clone(),
            ));
        }

        let started_at = Utc::now();
        let Some(path) = input.payload.get("path").and_then(|value| value.as_str()) else {
            return Err(SandboxError::MissingField("path"));
        };

        let canonical = self.resolve_workspace_path(path)?;
        let content = fs::read_to_string(&canonical)?;
        let output_hash = sha256_hex(content.as_bytes());
        let finished_at = Utc::now();

        Ok(SandboxResult {
            ticket_id: ticket.ticket_id.clone(),
            run_id: ticket.run_id.clone(),
            capability_id: "file.read".into(),
            success: true,
            output: json!({
                "path": canonical.to_string_lossy(),
                "content": content,
            }),
            error: None,
            started_at,
            finished_at,
            output_hash,
        })
    }
}

pub fn sha256_hex(bytes: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(bytes.as_ref()))
}

pub fn structured_sandbox_error(
    error: &SandboxError,
    internal_ref: impl Into<String>,
) -> StructuredError {
    StructuredError {
        code: match error {
            SandboxError::UnsupportedCapability(_) => ErrorCode::PolicyDenied,
            SandboxError::MissingField(_) => ErrorCode::UserInputError,
            SandboxError::OutsideWorkspace(_) => ErrorCode::SafetyBlocked,
            SandboxError::Io(_) => ErrorCode::ToolError,
        },
        severity: match error {
            SandboxError::OutsideWorkspace(_) => Severity::Critical,
            _ => Severity::Error,
        },
        retryable: false,
        rollback_required: false,
        user_visible_message: error.to_string(),
        internal_ref: internal_ref.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use moxi_contracts::ExecutionTicket;
    use tempfile::tempdir;

    fn ticket() -> ExecutionTicket {
        ExecutionTicket {
            ticket_id: "ticket_1".into(),
            run_id: "run_1".into(),
            delta_id: "delta_1".into(),
            policy_decision_ref: "pd_1".into(),
            capability_contract_ref: "file.read".into(),
            sandbox_profile_ref: "fs-readonly".into(),
            actor_id: "kernel".into(),
            capability_id: "file.read".into(),
            expires_at: Utc::now() + Duration::seconds(60),
        }
    }

    #[test]
    fn reads_file_inside_workspace() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("hello.txt"), "hello").unwrap();
        let sandbox = FileReadSandbox::new(temp.path());

        let result = sandbox
            .execute(
                &ticket(),
                SandboxInput {
                    capability_id: "file.read".into(),
                    payload: json!({ "path": "hello.txt" }),
                },
            )
            .unwrap();

        assert!(result.success);
        assert_eq!(result.output["content"], "hello");
    }

    #[test]
    fn blocks_path_traversal_outside_workspace() {
        let temp = tempdir().unwrap();
        let outside = tempdir().unwrap();
        fs::write(outside.path().join("secret.txt"), "secret").unwrap();
        let sandbox = FileReadSandbox::new(temp.path());

        let err = sandbox
            .resolve_workspace_path(&outside.path().join("secret.txt").to_string_lossy())
            .unwrap_err();

        assert!(matches!(err, SandboxError::OutsideWorkspace(_)));
    }
}
