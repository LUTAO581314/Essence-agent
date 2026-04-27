use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use time::OffsetDateTime;

use crate::protocol::{EventEnvelope, EventId};

type HmacSha256 = Hmac<Sha256>;

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
    #[error("WAL integrity check failed at {path}: {findings:?}")]
    Integrity {
        path: PathBuf,
        findings: Vec<WalIntegrityFinding>,
    },
    #[error("anchor key must not be empty")]
    EmptyAnchorKey,
    #[error("anchor signature is not valid hex")]
    InvalidAnchorSignature,
}

pub type WalResult<T> = Result<T, WalError>;

const LAST_EVENT_READ_CHUNK_SIZE: u64 = 8192;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalIntegrityReport {
    pub event_count: usize,
    pub latest_seq: Option<u64>,
    pub latest_hash: Option<String>,
    pub findings: Vec<WalIntegrityFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalAnchor {
    pub algorithm: String,
    pub key_id: String,
    pub created_at: OffsetDateTime,
    pub event_count: usize,
    pub latest_seq: Option<u64>,
    pub latest_hash: Option<String>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalAnchorVerification {
    pub anchor: WalAnchor,
    pub report: WalIntegrityReport,
    pub integrity_valid: bool,
    pub latest_seq_matches: bool,
    pub latest_hash_matches: bool,
    pub signature_valid: bool,
}

impl WalAnchorVerification {
    pub fn is_valid(&self) -> bool {
        self.integrity_valid
            && self.latest_seq_matches
            && self.latest_hash_matches
            && self.signature_valid
    }
}

#[derive(Debug, Serialize)]
struct WalAnchorMaterial<'a> {
    algorithm: &'a str,
    key_id: &'a str,
    created_at: OffsetDateTime,
    event_count: usize,
    latest_seq: Option<u64>,
    latest_hash: Option<&'a str>,
}

impl WalIntegrityReport {
    pub fn from_events(events: &[EventEnvelope]) -> Result<Self, serde_json::Error> {
        let mut findings = Vec::new();

        for (index, event) in events.iter().enumerate() {
            let expected_seq = index as u64 + 1;
            if event.seq != expected_seq {
                findings.push(WalIntegrityFinding::SeqMismatch {
                    index,
                    expected: expected_seq,
                    actual: event.seq,
                });
            }

            let computed_hash = event.computed_hash()?;
            match &event.hash {
                Some(hash) if hash == &computed_hash => {}
                Some(hash) => findings.push(WalIntegrityFinding::HashMismatch {
                    seq: event.seq,
                    expected: computed_hash,
                    actual: Some(hash.clone()),
                }),
                None => findings.push(WalIntegrityFinding::MissingHash { seq: event.seq }),
            }

            match index
                .checked_sub(1)
                .and_then(|previous| events.get(previous))
            {
                Some(previous) => {
                    if event.prev_event_id.as_ref() != Some(&previous.event_id) {
                        findings.push(WalIntegrityFinding::PrevEventMismatch {
                            seq: event.seq,
                            expected: Some(previous.event_id.clone()),
                            actual: event.prev_event_id.clone(),
                        });
                    }
                    let previous_hash = previous.stored_or_computed_hash()?;
                    if event.prev_hash.as_deref() != Some(previous_hash.as_str()) {
                        findings.push(WalIntegrityFinding::PrevHashMismatch {
                            seq: event.seq,
                            expected: Some(previous_hash),
                            actual: event.prev_hash.clone(),
                        });
                    }
                }
                None => {
                    if event.prev_event_id.is_some() {
                        findings.push(WalIntegrityFinding::PrevEventMismatch {
                            seq: event.seq,
                            expected: None,
                            actual: event.prev_event_id.clone(),
                        });
                    }
                    if event.prev_hash.is_some() {
                        findings.push(WalIntegrityFinding::PrevHashMismatch {
                            seq: event.seq,
                            expected: None,
                            actual: event.prev_hash.clone(),
                        });
                    }
                }
            }
        }

        Ok(Self {
            event_count: events.len(),
            latest_seq: events.last().map(|event| event.seq),
            latest_hash: events
                .last()
                .map(EventEnvelope::stored_or_computed_hash)
                .transpose()?,
            findings,
        })
    }

    pub fn is_valid(&self) -> bool {
        self.findings.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WalIntegrityFinding {
    SeqMismatch {
        index: usize,
        expected: u64,
        actual: u64,
    },
    PrevEventMismatch {
        seq: u64,
        expected: Option<EventId>,
        actual: Option<EventId>,
    },
    PrevHashMismatch {
        seq: u64,
        expected: Option<String>,
        actual: Option<String>,
    },
    MissingHash {
        seq: u64,
    },
    HashMismatch {
        seq: u64,
        expected: String,
        actual: Option<String>,
    },
}

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

    pub fn anchor_path(&self) -> PathBuf {
        let mut path = self.path.as_os_str().to_os_string();
        path.push(".anchor.json");
        PathBuf::from(path)
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
        self.replay_after(0)
    }

    pub fn last(&self) -> WalResult<Option<EventEnvelope>> {
        if !self.path.exists() {
            return Ok(None);
        }

        let mut file = File::open(&self.path).map_err(|source| WalError::Io {
            path: self.path.clone(),
            source,
        })?;
        let mut position = file
            .metadata()
            .map_err(|source| WalError::Io {
                path: self.path.clone(),
                source,
            })?
            .len();
        if position == 0 {
            return Ok(None);
        }

        let mut suffix = Vec::new();
        while position > 0 {
            let read_len = position.min(LAST_EVENT_READ_CHUNK_SIZE) as usize;
            position -= read_len as u64;
            file.seek(SeekFrom::Start(position))
                .map_err(|source| WalError::Io {
                    path: self.path.clone(),
                    source,
                })?;

            let mut chunk = vec![0; read_len];
            file.read_exact(&mut chunk).map_err(|source| WalError::Io {
                path: self.path.clone(),
                source,
            })?;
            chunk.extend_from_slice(&suffix);

            let trimmed_end = trim_ascii_whitespace_end(&chunk);
            if trimmed_end == 0 {
                suffix = chunk;
                continue;
            }

            if let Some(line_start) = chunk[..trimmed_end]
                .iter()
                .rposition(|byte| *byte == b'\n')
                .map(|index| index + 1)
            {
                return serde_json::from_slice::<EventEnvelope>(&chunk[line_start..trimmed_end])
                    .map(Some)
                    .map_err(|source| WalError::Json {
                        path: self.path.clone(),
                        source,
                    });
            }

            suffix = chunk;
        }

        let trimmed_end = trim_ascii_whitespace_end(&suffix);
        if trimmed_end == 0 {
            Ok(None)
        } else {
            serde_json::from_slice::<EventEnvelope>(&suffix[..trimmed_end])
                .map(Some)
                .map_err(|source| WalError::Json {
                    path: self.path.clone(),
                    source,
                })
        }
    }

    pub fn replay_after(&self, seq: u64) -> WalResult<Vec<EventEnvelope>> {
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
            let event =
                serde_json::from_str::<EventEnvelope>(&line).map_err(|source| WalError::Json {
                    path: self.path.clone(),
                    source,
                })?;
            if event.seq > seq {
                events.push(event);
            }
        }
        Ok(events)
    }

    pub fn verify_integrity(&self) -> WalResult<WalIntegrityReport> {
        let events = self.replay()?;
        WalIntegrityReport::from_events(&events).map_err(|source| WalError::Json {
            path: self.path.clone(),
            source,
        })
    }

    pub fn write_anchor(&self, key_id: impl Into<String>, key: &[u8]) -> WalResult<WalAnchor> {
        let key_id = key_id.into();
        let report = self.verify_integrity()?;
        if !report.is_valid() {
            return Err(WalError::Integrity {
                path: self.path.clone(),
                findings: report.findings,
            });
        }

        let anchor = WalAnchor::new(key_id, &report, key)?;
        let anchor_path = self.anchor_path();
        if let Some(parent) = anchor_path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| WalError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let file = File::create(&anchor_path).map_err(|source| WalError::Io {
            path: anchor_path.clone(),
            source,
        })?;
        let mut writer = BufWriter::new(file);
        serde_json::to_writer_pretty(&mut writer, &anchor).map_err(|source| WalError::Json {
            path: anchor_path.clone(),
            source,
        })?;
        writer.write_all(b"\n").map_err(|source| WalError::Io {
            path: anchor_path.clone(),
            source,
        })?;
        writer.flush().map_err(|source| WalError::Io {
            path: anchor_path,
            source,
        })?;

        Ok(anchor)
    }

    pub fn read_anchor(&self) -> WalResult<WalAnchor> {
        let anchor_path = self.anchor_path();
        let file = File::open(&anchor_path).map_err(|source| WalError::Io {
            path: anchor_path.clone(),
            source,
        })?;
        serde_json::from_reader(file).map_err(|source| WalError::Json {
            path: anchor_path,
            source,
        })
    }

    pub fn verify_anchor(&self, key: &[u8]) -> WalResult<WalAnchorVerification> {
        let anchor = self.read_anchor()?;
        self.verify_anchor_value(anchor, key)
    }

    pub fn verify_anchor_value(
        &self,
        anchor: WalAnchor,
        key: &[u8],
    ) -> WalResult<WalAnchorVerification> {
        let report = self.verify_integrity()?;
        let signature_valid = anchor.verify_signature(key)?;
        let latest_seq_matches = anchor.latest_seq == report.latest_seq;
        let latest_hash_matches = anchor.latest_hash == report.latest_hash;
        let integrity_valid = report.is_valid();

        Ok(WalAnchorVerification {
            anchor,
            report,
            integrity_valid,
            latest_seq_matches,
            latest_hash_matches,
            signature_valid,
        })
    }
}

fn trim_ascii_whitespace_end(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(0, |index| index + 1)
}

impl WalAnchor {
    const ALGORITHM: &'static str = "hmac_sha256";

    fn new(key_id: String, report: &WalIntegrityReport, key: &[u8]) -> WalResult<Self> {
        let mut anchor = Self {
            algorithm: Self::ALGORITHM.to_string(),
            key_id,
            created_at: OffsetDateTime::now_utc(),
            event_count: report.event_count,
            latest_seq: report.latest_seq,
            latest_hash: report.latest_hash.clone(),
            signature: String::new(),
        };
        anchor.signature = anchor.compute_signature(key)?;
        Ok(anchor)
    }

    fn material(&self) -> WalAnchorMaterial<'_> {
        WalAnchorMaterial {
            algorithm: &self.algorithm,
            key_id: &self.key_id,
            created_at: self.created_at,
            event_count: self.event_count,
            latest_seq: self.latest_seq,
            latest_hash: self.latest_hash.as_deref(),
        }
    }

    fn compute_signature(&self, key: &[u8]) -> WalResult<String> {
        Ok(encode_hex(&self.compute_mac(key)?))
    }

    fn verify_signature(&self, key: &[u8]) -> WalResult<bool> {
        let signature = decode_hex(&self.signature)?;
        let mut mac = mac_for_key(key)?;
        mac.update(
            &serde_json::to_vec(&self.material()).map_err(|source| WalError::Json {
                path: PathBuf::from("anchor-material"),
                source,
            })?,
        );
        Ok(mac.verify_slice(&signature).is_ok())
    }

    fn compute_mac(&self, key: &[u8]) -> WalResult<Vec<u8>> {
        let mut mac = mac_for_key(key)?;
        let material = serde_json::to_vec(&self.material()).map_err(|source| WalError::Json {
            path: PathBuf::from("anchor-material"),
            source,
        })?;
        mac.update(&material);
        Ok(mac.finalize().into_bytes().to_vec())
    }
}

fn mac_for_key(key: &[u8]) -> WalResult<HmacSha256> {
    if key.is_empty() {
        return Err(WalError::EmptyAnchorKey);
    }
    HmacSha256::new_from_slice(key).map_err(|_| WalError::EmptyAnchorKey)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn decode_hex(value: &str) -> WalResult<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return Err(WalError::InvalidAnchorSignature);
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for chunk in value.as_bytes().chunks_exact(2) {
        let high = hex_value(chunk[0])?;
        let low = hex_value(chunk[1])?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_value(byte: u8) -> WalResult<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(WalError::InvalidAnchorSignature),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use serde_json::json;
    use uuid::Uuid;

    use crate::protocol::{EventEnvelope, EventSource, EventType, EventVisibility, SessionId};

    use super::{JsonlWal, WalIntegrityFinding};

    #[test]
    fn appends_and_replays_events() {
        let path = std::env::temp_dir().join(format!("essence-wal-test-{}.jsonl", Uuid::new_v4()));
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
        assert_eq!(
            wal.last().unwrap().unwrap().event_type,
            EventType::MessageUser
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn verifies_event_hash_chain_and_detects_tampering() {
        let path =
            std::env::temp_dir().join(format!("essence-wal-verify-{}.jsonl", Uuid::new_v4()));
        let wal = JsonlWal::new(&path);
        let session_id = SessionId(Uuid::new_v4());

        let first = EventEnvelope::new(
            1,
            session_id.clone(),
            EventType::SessionMeta,
            EventSource::System,
            EventVisibility::Audit,
            json!({"cwd": "."}),
        )
        .seal_hash()
        .unwrap();
        let second = EventEnvelope::new(
            2,
            session_id,
            EventType::MessageUser,
            EventSource::User,
            EventVisibility::User,
            json!({"role": "user", "content": [{"kind": "text", "text": "hello"}]}),
        )
        .with_prev_event(&first)
        .unwrap()
        .seal_hash()
        .unwrap();

        wal.append(&first).unwrap();
        wal.append(&second).unwrap();

        let report = wal.verify_integrity().unwrap();
        assert!(report.is_valid());
        assert_eq!(report.event_count, 2);
        assert_eq!(report.latest_seq, Some(2));
        let anchor = wal.write_anchor("test-key", b"anchor-secret").unwrap();
        assert_eq!(anchor.algorithm, "hmac_sha256");
        assert_eq!(anchor.key_id, "test-key");
        assert!(wal.anchor_path().exists());
        let verification = wal.verify_anchor(b"anchor-secret").unwrap();
        assert!(verification.is_valid());
        assert!(!wal.verify_anchor(b"wrong-secret").unwrap().signature_valid);

        let mut tampered = wal.replay().unwrap();
        tampered[1].payload =
            json!({"role": "user", "content": [{"kind": "text", "text": "oops"}]});
        let mut file = std::fs::File::create(&path).unwrap();
        for event in &tampered {
            serde_json::to_writer(&mut file, event).unwrap();
            file.write_all(b"\n").unwrap();
        }

        let report = wal.verify_integrity().unwrap();
        assert!(report
            .findings
            .iter()
            .any(|finding| matches!(finding, WalIntegrityFinding::HashMismatch { seq: 2, .. })));
        let verification = wal.verify_anchor(b"anchor-secret").unwrap();
        assert!(!verification.is_valid());
        assert!(!verification.integrity_valid);

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(wal.anchor_path());
    }
}
