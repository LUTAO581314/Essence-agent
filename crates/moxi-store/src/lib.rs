use chrono::Utc;
use moxi_contracts::{LedgerEvent, RunStatus};
use rusqlite::{params, Connection};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

pub type StoreResult<T> = Result<T, StoreError>;

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: impl AsRef<std::path::Path>) -> StoreResult<Self> {
        let conn = Connection::open(path)?;
        let store = Self { conn };
        store.init()?;
        Ok(store)
    }

    pub fn open_memory() -> StoreResult<Self> {
        let conn = Connection::open_in_memory()?;
        let store = Self { conn };
        store.init()?;
        Ok(store)
    }

    fn init(&self) -> StoreResult<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS run_states (
                run_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ledger_events (
                ledger_event_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                timestamp TEXT NOT NULL
            );

            CREATE TRIGGER IF NOT EXISTS ledger_events_no_update
            BEFORE UPDATE ON ledger_events
            BEGIN
                SELECT RAISE(ABORT, 'ledger_events append only');
            END;

            CREATE TRIGGER IF NOT EXISTS ledger_events_no_delete
            BEFORE DELETE ON ledger_events
            BEGIN
                SELECT RAISE(ABORT, 'ledger_events append only');
            END;
            "#,
        )?;
        Ok(())
    }

    pub fn set_run_status(&self, run_id: &str, status: RunStatus) -> StoreResult<()> {
        let payload_json = serde_json::to_string(&status)?;
        self.conn.execute(
            r#"
            INSERT INTO run_states (run_id, status, payload_json, updated_at)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(run_id) DO UPDATE SET
                status = excluded.status,
                payload_json = excluded.payload_json,
                updated_at = excluded.updated_at
            "#,
            params![
                run_id,
                format!("{status:?}"),
                payload_json,
                Utc::now().to_rfc3339()
            ],
        )?;
        Ok(())
    }

    pub fn get_run_status(&self, run_id: &str) -> StoreResult<Option<RunStatus>> {
        let mut stmt = self
            .conn
            .prepare("SELECT payload_json FROM run_states WHERE run_id = ?1")?;
        let mut rows = stmt.query(params![run_id])?;
        if let Some(row) = rows.next()? {
            let payload: String = row.get(0)?;
            Ok(Some(serde_json::from_str(&payload)?))
        } else {
            Ok(None)
        }
    }

    pub fn append_ledger_event(&self, event: &LedgerEvent) -> StoreResult<()> {
        self.conn.execute(
            r#"
            INSERT INTO ledger_events (ledger_event_id, run_id, event_type, payload_json, timestamp)
            VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
            params![
                event.ledger_event_id,
                event.run_id,
                event.event_type,
                serde_json::to_string(event)?,
                event.timestamp.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn ledger_event(&self, ledger_event_id: &str) -> StoreResult<Option<LedgerEvent>> {
        let mut stmt = self
            .conn
            .prepare("SELECT payload_json FROM ledger_events WHERE ledger_event_id = ?1")?;
        let mut rows = stmt.query(params![ledger_event_id])?;
        if let Some(row) = rows.next()? {
            let payload: String = row.get(0)?;
            Ok(Some(serde_json::from_str(&payload)?))
        } else {
            Ok(None)
        }
    }

    pub fn ledger_events_for_run(&self, run_id: &str) -> StoreResult<Vec<LedgerEvent>> {
        let mut stmt = self.conn.prepare(
            "SELECT payload_json FROM ledger_events WHERE run_id = ?1 ORDER BY timestamp ASC",
        )?;
        let events = stmt
            .query_map(params![run_id], |row| row.get::<_, String>(0))?
            .map(|payload| Ok(serde_json::from_str(&payload?)?))
            .collect::<StoreResult<Vec<_>>>()?;
        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use moxi_contracts::EventResult;

    fn ledger_event() -> LedgerEvent {
        LedgerEvent {
            ledger_event_id: "le_1".into(),
            run_id: "run_1".into(),
            event_type: "tool.executed".into(),
            actor_id: "kernel".into(),
            resource_ref: "file.txt".into(),
            delta_id: "delta_1".into(),
            capability_id: "file.read".into(),
            policy_decision_ref: "pd_1".into(),
            proof_refs: vec!["proof_1".into()],
            input_hash: "in".into(),
            output_hash: "out".into(),
            result: EventResult::Success,
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn ledger_is_append_only() {
        let store = Store::open_memory().unwrap();
        let event = ledger_event();
        store.append_ledger_event(&event).unwrap();

        let update = store.conn.execute(
            "UPDATE ledger_events SET event_type = 'tampered' WHERE ledger_event_id = ?1",
            params![event.ledger_event_id],
        );
        assert!(update.is_err());

        let delete = store.conn.execute(
            "DELETE FROM ledger_events WHERE ledger_event_id = ?1",
            params![event.ledger_event_id],
        );
        assert!(delete.is_err());
    }
}
