use std::io::{self, Write};
use std::path::{Path, PathBuf};

use essence_core::{ApprovalId, EventEnvelope, RunId, SessionId, TaskId, UiEvent};
use serde::Serialize;
use uuid::Uuid;

use super::args::CliOutputFormat;

#[derive(Debug, thiserror::Error)]
pub(crate) enum CliError {
    #[error(transparent)]
    Control(#[from] essence_core::ControlError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    ModelLoop(#[from] essence_core::ModelLoopError),
    #[error(transparent)]
    Uuid(#[from] uuid::Error),
    #[error("path is not valid unicode: {0}")]
    InvalidPath(PathBuf),
    #[error("approval `{0}` is not recorded")]
    MissingApproval(String),
    #[error("agent profile `{0}` is not recorded")]
    MissingAgentProfile(String),
    #[error("agent template `{0}` is not available")]
    MissingAgentTemplate(String),
    #[error("invalid agent id `{0}`; use letters, numbers, `-`, or `_`")]
    InvalidAgentId(String),
    #[error("anchor key env var `{0}` is not set")]
    MissingAnchorKeyEnv(String),
    #[error("invalid model configuration: {0}")]
    ModelConfig(String),
    #[error("doctor found {0}")]
    Doctor(String),
    #[error("interactive command cannot run in this environment: {0}")]
    NonInteractive(String),
    #[error("{0}")]
    Usage(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OutputMode {
    pub(crate) format: CliOutputFormat,
    pub(crate) quiet: bool,
    pub(crate) verbose: u8,
    pub(crate) dry_run: bool,
}

impl OutputMode {
    pub(crate) fn new(
        output: CliOutputFormat,
        json: bool,
        quiet: bool,
        verbose: u8,
        dry_run: bool,
    ) -> Self {
        Self {
            format: if json { CliOutputFormat::Json } else { output },
            quiet,
            verbose,
            dry_run,
        }
    }

    pub(crate) fn is_json(self) -> bool {
        self.format == CliOutputFormat::Json
    }

    pub(crate) fn is_jsonl(self) -> bool {
        self.format == CliOutputFormat::Jsonl
    }

    pub(crate) fn is_structured(self) -> bool {
        self.is_json() || self.is_jsonl()
    }
}

pub(crate) fn emit_events(
    writer: &mut impl Write,
    events: &[EventEnvelope],
) -> Result<(), CliError> {
    for event in events {
        write_json_line(writer, event)?;
    }
    Ok(())
}

pub(crate) fn emit_ui_events(writer: &mut impl Write, events: &[UiEvent]) -> Result<(), CliError> {
    for event in events {
        write_json_line(writer, event)?;
    }
    Ok(())
}

pub(crate) fn write_json_pretty(
    writer: &mut impl Write,
    value: &impl Serialize,
) -> Result<(), CliError> {
    serde_json::to_writer_pretty(&mut *writer, value)?;
    writer.write_all(b"\n")?;
    Ok(())
}

pub(crate) fn write_text_line(
    writer: &mut impl Write,
    text: impl AsRef<str>,
) -> Result<(), CliError> {
    writer.write_all(text.as_ref().as_bytes())?;
    writer.write_all(b"\n")?;
    Ok(())
}

pub(crate) fn write_json_line(
    writer: &mut impl Write,
    value: &impl Serialize,
) -> Result<(), CliError> {
    serde_json::to_writer(&mut *writer, value)?;
    writer.write_all(b"\n")?;
    Ok(())
}

pub(crate) fn parse_session_id(raw: &str) -> Result<SessionId, CliError> {
    Ok(SessionId(Uuid::parse_str(raw)?))
}

pub(crate) fn parse_approval_id(raw: &str) -> Result<ApprovalId, CliError> {
    Ok(ApprovalId(Uuid::parse_str(raw)?))
}

pub(crate) fn parse_run_id(raw: &str) -> Result<RunId, CliError> {
    Ok(RunId(Uuid::parse_str(raw)?))
}

pub(crate) fn parse_task_id(raw: &str) -> Result<TaskId, CliError> {
    Ok(TaskId(Uuid::parse_str(raw)?))
}

pub(crate) fn anchor_key_from_env(env_name: &str) -> Result<String, CliError> {
    std::env::var(env_name).map_err(|_| CliError::MissingAnchorKeyEnv(env_name.to_string()))
}

pub(crate) fn path_to_string(path: &Path) -> Result<String, CliError> {
    match path.to_str() {
        Some(value) => Ok(value.to_string()),
        None => Err(CliError::InvalidPath(path.to_path_buf())),
    }
}
