use chrono::Utc;
use moxi_contracts::{
    ErrorCode, ExecutionTicket, SandboxInput, SandboxResult, Severity, StructuredError,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("unsupported capability: {0}")]
    UnsupportedCapability(String),
    #[error("missing string payload field: {0}")]
    MissingField(&'static str),
    #[error("path is outside workspace root: {0}")]
    OutsideWorkspace(String),
    #[error("process executor timed out after {timeout_ms}ms: {command}")]
    ProcessTimedOut { command: String, timeout_ms: u64 },
    #[error("process executor failed: {command} exited with {status}: {stderr}")]
    ProcessFailed {
        command: String,
        status: String,
        stderr: String,
    },
    #[error("process executor output is invalid: {0}")]
    InvalidProcessOutput(String),
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

pub struct ProcessSandbox {
    command: PathBuf,
    args: Vec<String>,
    current_dir: Option<PathBuf>,
    timeout_ms: u64,
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

impl ProcessSandbox {
    pub fn new(command: impl Into<PathBuf>) -> Self {
        Self {
            command: command.into(),
            args: Vec::new(),
            current_dir: None,
            timeout_ms: 10_000,
        }
    }

    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    pub fn args(mut self, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    pub fn current_dir(mut self, current_dir: impl Into<PathBuf>) -> Self {
        self.current_dir = Some(current_dir.into());
        self
    }

    pub fn timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms.max(1);
        self
    }

    fn command_label(&self) -> String {
        let mut parts = vec![self.command.to_string_lossy().into_owned()];
        parts.extend(self.args.clone());
        parts.join(" ")
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
            policy_decision_ref: String::new(),
            capability_contract_ref: String::new(),
            capability_contract_hash: String::new(),
            executor_ref: String::new(),
            executor_version: String::new(),
            executor_artifact_hash: String::new(),
            executor_signature_ref: String::new(),
            executor_signing_key_ref: String::new(),
            executor_manifest_hash: String::new(),
            gateway_decision_ref: None,
            input_hash: String::new(),
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

impl Sandbox for ProcessSandbox {
    fn execute(
        &self,
        ticket: &ExecutionTicket,
        input: SandboxInput,
    ) -> SandboxResultType<SandboxResult> {
        let started_at = Utc::now();
        let mut command = Command::new(&self.command);
        command
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(current_dir) = &self.current_dir {
            command.current_dir(current_dir);
        }

        let mut child = command.spawn()?;
        let request = serde_json::json!({
            "ticket": ticket,
            "input": input,
        });
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(
                serde_json::to_vec(&request)
                    .expect("process sandbox request serialization cannot fail")
                    .as_slice(),
            )?;
        }

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| SandboxError::InvalidProcessOutput("missing stdout pipe".into()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| SandboxError::InvalidProcessOutput("missing stderr pipe".into()))?;
        let stdout_reader = read_pipe(stdout);
        let stderr_reader = read_pipe(stderr);

        let deadline = Instant::now() + Duration::from_millis(self.timeout_ms);
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(SandboxError::ProcessTimedOut {
                    command: self.command_label(),
                    timeout_ms: self.timeout_ms,
                });
            }
            thread::sleep(Duration::from_millis(10));
        };

        let stdout = join_pipe(stdout_reader)?;
        let stderr = join_pipe(stderr_reader)?;
        let stderr_text = String::from_utf8_lossy(&stderr).trim().to_owned();
        if !status.success() {
            return Err(SandboxError::ProcessFailed {
                command: self.command_label(),
                status: status.to_string(),
                stderr: stderr_text,
            });
        }

        let response: serde_json::Value = serde_json::from_slice(&stdout)
            .map_err(|error| SandboxError::InvalidProcessOutput(error.to_string()))?;
        let success = response
            .get("success")
            .and_then(|value| value.as_bool())
            .unwrap_or(true);
        let output = response
            .get("output")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let error = response
            .get("error")
            .filter(|value| !value.is_null())
            .map(|value| serde_json::from_value(value.clone()))
            .transpose()
            .map_err(|error| SandboxError::InvalidProcessOutput(error.to_string()))?;
        let output_hash = sha256_hex(
            serde_json::to_vec(&output).expect("process output serialization cannot fail"),
        );

        Ok(SandboxResult {
            ticket_id: ticket.ticket_id.clone(),
            run_id: ticket.run_id.clone(),
            capability_id: ticket.capability_id.clone(),
            policy_decision_ref: String::new(),
            capability_contract_ref: String::new(),
            capability_contract_hash: String::new(),
            executor_ref: String::new(),
            executor_version: String::new(),
            executor_artifact_hash: String::new(),
            executor_signature_ref: String::new(),
            executor_signing_key_ref: String::new(),
            executor_manifest_hash: String::new(),
            gateway_decision_ref: None,
            input_hash: String::new(),
            success,
            output,
            error,
            started_at,
            finished_at: Utc::now(),
            output_hash,
        })
    }
}

fn read_pipe(mut pipe: impl Read + Send + 'static) -> thread::JoinHandle<std::io::Result<Vec<u8>>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        pipe.read_to_end(&mut bytes)?;
        Ok(bytes)
    })
}

fn join_pipe(handle: thread::JoinHandle<std::io::Result<Vec<u8>>>) -> SandboxResultType<Vec<u8>> {
    handle
        .join()
        .map_err(|_| SandboxError::InvalidProcessOutput("pipe reader panicked".into()))?
        .map_err(SandboxError::Io)
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
            SandboxError::ProcessTimedOut { .. }
            | SandboxError::ProcessFailed { .. }
            | SandboxError::InvalidProcessOutput(_)
            | SandboxError::Io(_) => ErrorCode::ToolError,
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

    #[cfg(windows)]
    fn json_process() -> ProcessSandbox {
        ProcessSandbox::new("powershell.exe").args([
            "-NoProfile",
            "-Command",
            "$input | Out-Null; Write-Output '{\"success\":true,\"output\":{\"echo\":\"process executor\"}}'",
        ])
    }

    #[cfg(not(windows))]
    fn json_process() -> ProcessSandbox {
        ProcessSandbox::new("/bin/sh").args([
            "-c",
            "cat >/dev/null; printf '%s\n' '{\"success\":true,\"output\":{\"echo\":\"process executor\"}}'",
        ])
    }

    fn ticket() -> ExecutionTicket {
        ExecutionTicket {
            ticket_id: "ticket_1".into(),
            run_id: "run_1".into(),
            delta_id: "delta_1".into(),
            policy_decision_ref: "pd_1".into(),
            capability_contract_ref: "file.read".into(),
            capability_contract_hash: "contract_hash_1".into(),
            executor_ref: "builtin.fs/file.read".into(),
            executor_version: "0.2.0".into(),
            executor_artifact_hash:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            executor_signature_ref: "builtin://moxi/file.read/executor/signature".into(),
            executor_signing_key_ref: "builtin://moxi/signing-key".into(),
            executor_manifest_hash: "executor_manifest_hash_1".into(),
            executor_isolation: moxi_contracts::ExecutorIsolation::InProcessTrusted,
            retry_policy: Default::default(),
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

    #[test]
    fn process_sandbox_executes_json_protocol() {
        let result = json_process()
            .execute(
                &ticket(),
                SandboxInput {
                    capability_id: "file.read".into(),
                    payload: json!({ "path": "ignored.txt" }),
                },
            )
            .unwrap();

        assert!(result.success);
        assert_eq!(result.output["echo"], "process executor");
        assert_eq!(result.ticket_id, "ticket_1");
    }
}
