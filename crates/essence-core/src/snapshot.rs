use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::projection::{LedgerProjection, ProjectionError};
use crate::protocol::SessionId;

#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
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
    #[error(transparent)]
    Projection(#[from] ProjectionError),
}

pub type SnapshotResult<T> = Result<T, SnapshotError>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProjectionSnapshot {
    pub session_id: SessionId,
    pub latest_seq: u64,
    pub generated_at: OffsetDateTime,
    pub projection: LedgerProjection,
}

impl ProjectionSnapshot {
    pub fn new(session_id: SessionId, projection: LedgerProjection) -> Self {
        Self {
            session_id,
            latest_seq: projection.latest_seq,
            generated_at: OffsetDateTime::now_utc(),
            projection,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SnapshotStore {
    root: PathBuf,
}

impl SnapshotStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn write(&self, snapshot: &ProjectionSnapshot) -> SnapshotResult<PathBuf> {
        let path = self.path_for_session(&snapshot.session_id);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| SnapshotError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let bytes = serde_json::to_vec_pretty(snapshot).map_err(|source| SnapshotError::Json {
            path: path.clone(),
            source,
        })?;
        std::fs::write(&path, bytes).map_err(|source| SnapshotError::Io {
            path: path.clone(),
            source,
        })?;
        Ok(path)
    }

    pub fn read(&self, session_id: &SessionId) -> SnapshotResult<Option<ProjectionSnapshot>> {
        let path = self.path_for_session(session_id);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&path).map_err(|source| SnapshotError::Io {
            path: path.clone(),
            source,
        })?;
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|source| SnapshotError::Json { path, source })
    }

    pub fn path_for_session(&self, session_id: &SessionId) -> PathBuf {
        self.root
            .join("projections")
            .join(format!("{}.json", session_id.0))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use uuid::Uuid;

    use crate::control::{ControlPlane, CreateSessionRequest};
    use crate::snapshot::{ProjectionSnapshot, SnapshotStore};

    #[test]
    fn writes_and_reads_projection_snapshots() {
        let root = std::env::temp_dir().join(format!("essence-snapshot-{}", Uuid::new_v4()));
        let control = ControlPlane::new(&root);
        let session = control
            .create_session(CreateSessionRequest::interactive("."))
            .unwrap();
        control
            .submit_user_message(&session.session_id, "hello snapshot")
            .unwrap();
        let projection = control.projection(&session.session_id).unwrap();
        let snapshot = ProjectionSnapshot::new(session.session_id.clone(), projection);
        let store = SnapshotStore::new(&root);

        let path = store.write(&snapshot).unwrap();
        let read = store.read(&session.session_id).unwrap().unwrap();

        assert!(path.exists());
        assert_eq!(read.session_id, session.session_id);
        assert_eq!(read.latest_seq, 2);
        assert_eq!(read.projection.messages.len(), 1);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn returns_none_for_missing_snapshot() {
        let root = std::env::temp_dir().join(format!("essence-snapshot-{}", Uuid::new_v4()));
        let store = SnapshotStore::new(&root);

        let missing = store
            .read(&crate::protocol::SessionId(Uuid::new_v4()))
            .unwrap();

        assert_eq!(missing, None);
    }

    #[test]
    fn snapshot_serializes_as_json() {
        let root = std::env::temp_dir().join(format!("essence-snapshot-{}", Uuid::new_v4()));
        let control = ControlPlane::new(&root);
        let session = control
            .create_session(CreateSessionRequest::interactive("."))
            .unwrap();
        control
            .create_artifact(crate::control::CreateArtifactRequest::new(
                session.session_id.clone(),
                "artifact://notes.md",
                "markdown",
            ))
            .unwrap();
        let snapshot = ProjectionSnapshot::new(
            session.session_id.clone(),
            control.projection(&session.session_id).unwrap(),
        );

        let value = serde_json::to_value(snapshot).unwrap();

        assert_eq!(value["latest_seq"], json!(2));
        assert_eq!(
            value["projection"]["artifacts"].as_object().unwrap().len(),
            1
        );

        let _ = std::fs::remove_dir_all(root);
    }
}
