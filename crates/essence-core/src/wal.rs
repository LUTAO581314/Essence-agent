use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use crate::protocol::EventEnvelope;

#[derive(Debug, thiserror::Error)]
pub enum WalError {
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("json error at {path}: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

pub type WalResult<T> = Result<T, WalError>;

#[derive(Debug, Clone)]
pub struct JsonlWal {
    path: PathBuf,
}

impl JsonlWal {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append(&self, event: &EventEnvelope) -> WalResult<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| WalError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|source| WalError::Io {
                path: self.path.clone(),
                source,
            })?;

        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, event).map_err(|source| WalError::Json {
            path: self.path.clone(),
            source,
        })?;
        writer.write_all(b"\n").map_err(|source| WalError::Io {
            path: self.path.clone(),
            source,
        })?;
        writer.flush().map_err(|source| WalError::Io {
            path: self.path.clone(),
            source,
        })
    }

    pub fn replay(&self) -> WalResult<Vec<EventEnvelope>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }

        let file = File::open(&self.path).map_err(|source| WalError::Io {
            path: self.path.clone(),
            source,
        })?;

        let reader = BufReader::new(file);
        let mut events = Vec::new();
        for line in reader.lines() {
            let line = line.map_err(|source| WalError::Io {
                path: self.path.clone(),
                source,
            })?;
            if line.trim().is_empty() {
                continue;
            }
            let event = serde_json::from_str::<EventEnvelope>(&line).map_err(|source| {
                WalError::Json {
                    path: self.path.clone(),
                    source,
                }
            })?;
            events.push(event);
        }
        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use uuid::Uuid;

    use crate::protocol::{
        EventEnvelope, EventSource, EventType, EventVisibility, SessionId,
    };

    use super::JsonlWal;

    #[test]
    fn appends_and_replays_events() {
        let path = std::env::temp_dir().join(format!(
            "essence-wal-test-{}.jsonl",
            Uuid::new_v4()
        ));
        let wal = JsonlWal::new(&path);
        let session_id = SessionId(Uuid::new_v4());

        let first = EventEnvelope::new(
            1,
            session_id.clone(),
            EventType::SessionMeta,
            EventSource::System,
            EventVisibility::Audit,
            json!({"cwd": "."}),
        );
        let second = EventEnvelope::new(
            2,
            session_id,
            EventType::MessageUser,
            EventSource::User,
            EventVisibility::User,
            json!({"role": "user", "content": [{"kind": "text", "text": "hello"}]}),
        );

        wal.append(&first).unwrap();
        wal.append(&second).unwrap();

        let events = wal.replay().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].seq, 1);
        assert_eq!(events[1].event_type, EventType::MessageUser);

        let _ = std::fs::remove_file(path);
    }
}

