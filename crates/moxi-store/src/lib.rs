use chrono::Utc;
use moxi_contracts::{
    ApprovalGrant, Budget, ExecutionTicket, LedgerEvent, Proof, RunStatus, SandboxResult,
};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("invalid run state transition from {from:?} to {to:?}")]
    InvalidTransition {
        from: Option<RunStatus>,
        to: RunStatus,
    },
    #[error("{counter} budget exceeded for run {run_id}: {current}/{max}")]
    BudgetExceeded {
        run_id: String,
        counter: &'static str,
        current: u32,
        max: u32,
    },
    #[error("execution ticket was not issued by this kernel: {0}")]
    TicketUnknown(String),
    #[error("execution ticket already consumed: {0}")]
    TicketConsumed(String),
    #[error("ledger chain broken at {ledger_event_id}: expected previous hash {expected_previous_hash}, got {actual_previous_hash}")]
    LedgerChainBroken {
        ledger_event_id: String,
        expected_previous_hash: String,
        actual_previous_hash: String,
    },
    #[error(
        "ledger hash mismatch at {ledger_event_id}: expected {expected_hash}, got {actual_hash}"
    )]
    LedgerHashMismatch {
        ledger_event_id: String,
        expected_hash: String,
        actual_hash: String,
    },
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

            CREATE TABLE IF NOT EXISTS run_usage (
                run_id TEXT PRIMARY KEY,
                max_steps INTEGER NOT NULL,
                max_heartbeats INTEGER NOT NULL,
                max_tool_calls INTEGER NOT NULL,
                timeout_ms INTEGER NOT NULL,
                steps INTEGER NOT NULL DEFAULT 0,
                heartbeats INTEGER NOT NULL DEFAULT 0,
                tool_calls INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS execution_tickets (
                ticket_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                capability_id TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                consumed_at TEXT,
                payload_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sandbox_results (
                ticket_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                capability_id TEXT NOT NULL,
                policy_decision_ref TEXT NOT NULL,
                capability_contract_ref TEXT NOT NULL,
                capability_contract_hash TEXT NOT NULL,
                executor_ref TEXT NOT NULL,
                executor_version TEXT NOT NULL,
                executor_manifest_hash TEXT NOT NULL,
                gateway_decision_ref TEXT,
                input_hash TEXT NOT NULL,
                output_hash TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                finished_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS proofs (
                proof_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                policy_decision_ref TEXT NOT NULL,
                capability_contract_ref TEXT NOT NULL,
                capability_contract_hash TEXT NOT NULL,
                executor_ref TEXT NOT NULL,
                executor_version TEXT NOT NULL,
                executor_manifest_hash TEXT NOT NULL,
                gateway_decision_ref TEXT,
                input_hash TEXT NOT NULL,
                output_hash TEXT NOT NULL,
                source_ref TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                collected_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS approval_grants (
                grant_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                delta_id TEXT NOT NULL,
                policy_decision_ref TEXT NOT NULL,
                capability_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ledger_events (
                ledger_event_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                event_hash TEXT NOT NULL,
                previous_event_hash TEXT NOT NULL,
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

            CREATE TRIGGER IF NOT EXISTS approval_grants_no_update
            BEFORE UPDATE ON approval_grants
            BEGIN
                SELECT RAISE(ABORT, 'approval_grants append only');
            END;

            CREATE TRIGGER IF NOT EXISTS approval_grants_no_delete
            BEFORE DELETE ON approval_grants
            BEGIN
                SELECT RAISE(ABORT, 'approval_grants append only');
            END;

            CREATE TRIGGER IF NOT EXISTS sandbox_results_no_update
            BEFORE UPDATE ON sandbox_results
            BEGIN
                SELECT RAISE(ABORT, 'sandbox_results append only');
            END;

            CREATE TRIGGER IF NOT EXISTS sandbox_results_no_delete
            BEFORE DELETE ON sandbox_results
            BEGIN
                SELECT RAISE(ABORT, 'sandbox_results append only');
            END;

            CREATE TRIGGER IF NOT EXISTS proofs_no_update
            BEFORE UPDATE ON proofs
            BEGIN
                SELECT RAISE(ABORT, 'proofs append only');
            END;

            CREATE TRIGGER IF NOT EXISTS proofs_no_delete
            BEFORE DELETE ON proofs
            BEGIN
                SELECT RAISE(ABORT, 'proofs append only');
            END;
            "#,
        )?;
        self.ensure_column("execution_tickets", "payload_json", "TEXT")?;
        Ok(())
    }

    fn ensure_column(&self, table: &str, column: &str, definition: &str) -> StoreResult<()> {
        let mut stmt = self.conn.prepare(&format!("PRAGMA table_info({table})"))?;
        let columns = stmt
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<Result<Vec<_>, _>>()?;
        if !columns.iter().any(|existing| existing == column) {
            self.conn.execute(
                &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
                [],
            )?;
        }
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

    pub fn transition_run_status(&self, run_id: &str, to: RunStatus) -> StoreResult<()> {
        let from = self.get_run_status(run_id)?;
        if !is_allowed_transition(from, to) {
            return Err(StoreError::InvalidTransition { from, to });
        }
        self.set_run_status(run_id, to)
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

    pub fn initialize_run_budget(&self, run_id: &str, budget: &Budget) -> StoreResult<()> {
        self.conn.execute(
            r#"
            INSERT INTO run_usage (
                run_id, max_steps, max_heartbeats, max_tool_calls, timeout_ms, steps, heartbeats, tool_calls
            )
            VALUES (?1, ?2, ?3, ?4, ?5, 0, 0, 0)
            ON CONFLICT(run_id) DO NOTHING
            "#,
            params![
                run_id,
                budget.max_steps,
                budget.max_heartbeats,
                budget.max_tool_calls,
                budget.timeout_ms,
            ],
        )?;
        Ok(())
    }

    pub fn record_step(&self, run_id: &str) -> StoreResult<()> {
        self.increment_counter(run_id, "steps", "max_steps", "steps")
    }

    pub fn record_heartbeat(&self, run_id: &str) -> StoreResult<()> {
        self.increment_counter(run_id, "heartbeats", "max_heartbeats", "heartbeats")
    }

    pub fn record_tool_call(&self, run_id: &str) -> StoreResult<()> {
        self.increment_counter(run_id, "tool_calls", "max_tool_calls", "tool_calls")
    }

    pub fn record_ticket(&self, ticket: &ExecutionTicket) -> StoreResult<()> {
        self.conn.execute(
            r#"
            INSERT INTO execution_tickets (
                ticket_id, run_id, capability_id, expires_at, consumed_at, payload_json
            )
            VALUES (?1, ?2, ?3, ?4, NULL, ?5)
            "#,
            params![
                ticket.ticket_id,
                ticket.run_id,
                ticket.capability_id,
                ticket.expires_at.to_rfc3339(),
                serde_json::to_string(ticket)?,
            ],
        )?;
        Ok(())
    }

    pub fn execution_ticket(&self, ticket_id: &str) -> StoreResult<Option<ExecutionTicket>> {
        let payload = self
            .conn
            .query_row(
                "SELECT payload_json FROM execution_tickets WHERE ticket_id = ?1",
                params![ticket_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten();
        payload
            .map(|payload| Ok(serde_json::from_str(&payload)?))
            .transpose()
    }

    pub fn consume_ticket(&self, ticket_id: &str) -> StoreResult<()> {
        let consumed_at: Option<Option<String>> = self
            .conn
            .query_row(
                "SELECT consumed_at FROM execution_tickets WHERE ticket_id = ?1",
                params![ticket_id],
                |row| row.get(0),
            )
            .optional()?;

        match consumed_at {
            None => Err(StoreError::TicketUnknown(ticket_id.into())),
            Some(Some(_)) => Err(StoreError::TicketConsumed(ticket_id.into())),
            Some(None) => {
                self.conn.execute(
                    "UPDATE execution_tickets SET consumed_at = ?1 WHERE ticket_id = ?2",
                    params![Utc::now().to_rfc3339(), ticket_id],
                )?;
                Ok(())
            }
        }
    }

    pub fn record_approval_grant(&self, grant: &ApprovalGrant) -> StoreResult<()> {
        self.conn.execute(
            r#"
            INSERT INTO approval_grants (
                grant_id, run_id, delta_id, policy_decision_ref, capability_id, payload_json, expires_at, created_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                grant.grant_id,
                grant.run_id,
                grant.delta_id,
                grant.policy_decision_ref,
                grant.capability_id,
                serde_json::to_string(grant)?,
                grant.expires_at.to_rfc3339(),
                grant.granted_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn approval_grant(&self, grant_id: &str) -> StoreResult<Option<ApprovalGrant>> {
        let mut stmt = self
            .conn
            .prepare("SELECT payload_json FROM approval_grants WHERE grant_id = ?1")?;
        let mut rows = stmt.query(params![grant_id])?;
        if let Some(row) = rows.next()? {
            let payload: String = row.get(0)?;
            Ok(Some(serde_json::from_str(&payload)?))
        } else {
            Ok(None)
        }
    }

    pub fn record_sandbox_result(&self, result: &SandboxResult) -> StoreResult<()> {
        self.conn.execute(
            r#"
            INSERT INTO sandbox_results (
                ticket_id, run_id, capability_id, policy_decision_ref,
                capability_contract_ref, capability_contract_hash, executor_ref,
                executor_version, executor_manifest_hash, gateway_decision_ref,
                input_hash, output_hash, payload_json, finished_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
            "#,
            params![
                result.ticket_id,
                result.run_id,
                result.capability_id,
                result.policy_decision_ref,
                result.capability_contract_ref,
                result.capability_contract_hash,
                result.executor_ref,
                result.executor_version,
                result.executor_manifest_hash,
                result.gateway_decision_ref,
                result.input_hash,
                result.output_hash,
                serde_json::to_string(result)?,
                result.finished_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn sandbox_result(&self, ticket_id: &str) -> StoreResult<Option<SandboxResult>> {
        let mut stmt = self
            .conn
            .prepare("SELECT payload_json FROM sandbox_results WHERE ticket_id = ?1")?;
        let mut rows = stmt.query(params![ticket_id])?;
        if let Some(row) = rows.next()? {
            let payload: String = row.get(0)?;
            Ok(Some(serde_json::from_str(&payload)?))
        } else {
            Ok(None)
        }
    }

    pub fn record_proof(&self, proof: &Proof) -> StoreResult<()> {
        self.conn.execute(
            r#"
            INSERT INTO proofs (
                proof_id, run_id, policy_decision_ref, capability_contract_ref,
                capability_contract_hash, executor_ref, executor_version,
                executor_manifest_hash, gateway_decision_ref, input_hash,
                output_hash, source_ref, payload_json, collected_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
            "#,
            params![
                proof.proof_id,
                proof.run_id,
                proof.policy_decision_ref,
                proof.capability_contract_ref,
                proof.capability_contract_hash,
                proof.executor_ref,
                proof.executor_version,
                proof.executor_manifest_hash,
                proof.gateway_decision_ref,
                proof.input_hash,
                proof.output_hash,
                proof.source_ref,
                serde_json::to_string(proof)?,
                proof.collected_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn proof(&self, proof_id: &str) -> StoreResult<Option<Proof>> {
        let mut stmt = self
            .conn
            .prepare("SELECT payload_json FROM proofs WHERE proof_id = ?1")?;
        let mut rows = stmt.query(params![proof_id])?;
        if let Some(row) = rows.next()? {
            let payload: String = row.get(0)?;
            Ok(Some(serde_json::from_str(&payload)?))
        } else {
            Ok(None)
        }
    }

    pub fn append_ledger_event(&self, mut event: LedgerEvent) -> StoreResult<LedgerEvent> {
        event.previous_event_hash = self.latest_event_hash()?.unwrap_or_default();
        event.event_hash.clear();
        event.event_hash = hash_event(&event)?;

        self.conn.execute(
            r#"
            INSERT INTO ledger_events (
                ledger_event_id, run_id, event_type, payload_json, event_hash, previous_event_hash, timestamp
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
            params![
                event.ledger_event_id,
                event.run_id,
                event.event_type,
                serde_json::to_string(&event)?,
                event.event_hash,
                event.previous_event_hash,
                event.timestamp.to_rfc3339(),
            ],
        )?;
        Ok(event)
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
            "SELECT payload_json FROM ledger_events WHERE run_id = ?1 ORDER BY rowid ASC",
        )?;
        let events = stmt
            .query_map(params![run_id], |row| row.get::<_, String>(0))?
            .map(|payload| Ok(serde_json::from_str(&payload?)?))
            .collect::<StoreResult<Vec<_>>>()?;
        Ok(events)
    }

    pub fn latest_event_hash(&self) -> StoreResult<Option<String>> {
        let hash = self
            .conn
            .query_row(
                "SELECT event_hash FROM ledger_events ORDER BY rowid DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        Ok(hash)
    }

    pub fn validate_ledger_hash_chain(&self) -> StoreResult<()> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT ledger_event_id, payload_json, event_hash, previous_event_hash
            FROM ledger_events
            ORDER BY rowid ASC
            "#,
        )?;
        let mut rows = stmt.query([])?;
        let mut expected_previous_hash = String::new();

        while let Some(row) = rows.next()? {
            let ledger_event_id: String = row.get(0)?;
            let payload_json: String = row.get(1)?;
            let stored_event_hash: String = row.get(2)?;
            let stored_previous_hash: String = row.get(3)?;
            let mut event: LedgerEvent = serde_json::from_str(&payload_json)?;

            if event.ledger_event_id != ledger_event_id {
                return Err(StoreError::LedgerHashMismatch {
                    ledger_event_id,
                    expected_hash: event.ledger_event_id,
                    actual_hash: "ledger_event_id column mismatch".into(),
                });
            }

            if event.previous_event_hash != stored_previous_hash {
                return Err(StoreError::LedgerChainBroken {
                    ledger_event_id,
                    expected_previous_hash: event.previous_event_hash,
                    actual_previous_hash: stored_previous_hash,
                });
            }

            if event.event_hash != stored_event_hash {
                return Err(StoreError::LedgerHashMismatch {
                    ledger_event_id,
                    expected_hash: event.event_hash,
                    actual_hash: stored_event_hash,
                });
            }

            if event.previous_event_hash != expected_previous_hash {
                return Err(StoreError::LedgerChainBroken {
                    ledger_event_id,
                    expected_previous_hash,
                    actual_previous_hash: event.previous_event_hash,
                });
            }

            let actual_hash = event.event_hash.clone();
            event.event_hash.clear();
            let expected_hash = hash_event(&event)?;
            if actual_hash != expected_hash {
                return Err(StoreError::LedgerHashMismatch {
                    ledger_event_id,
                    expected_hash,
                    actual_hash,
                });
            }

            expected_previous_hash = actual_hash;
        }

        Ok(())
    }

    fn increment_counter(
        &self,
        run_id: &str,
        field: &'static str,
        max_field: &'static str,
        counter: &'static str,
    ) -> StoreResult<()> {
        let sql = format!("SELECT {field}, {max_field} FROM run_usage WHERE run_id = ?1");
        let (current, max): (u32, u32) = self
            .conn
            .query_row(&sql, params![run_id], |row| Ok((row.get(0)?, row.get(1)?)))?;

        if current >= max {
            return Err(StoreError::BudgetExceeded {
                run_id: run_id.into(),
                counter,
                current,
                max,
            });
        }

        let sql = format!("UPDATE run_usage SET {field} = {field} + 1 WHERE run_id = ?1");
        self.conn.execute(&sql, params![run_id])?;
        Ok(())
    }
}

fn hash_event(event: &LedgerEvent) -> StoreResult<String> {
    let bytes = serde_json::to_vec(event)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn is_allowed_transition(from: Option<RunStatus>, to: RunStatus) -> bool {
    use RunStatus::*;
    match (from, to) {
        (None, Admitted) => true,
        (Some(Admitted), RunningHeartbeat | AwaitingApproval | Blocked | Executing | Cancelled) => {
            true
        }
        (Some(RunningHeartbeat), AwaitingApproval | Executing | Blocked | Cancelled | Failed) => {
            true
        }
        (Some(AwaitingApproval), RunningHeartbeat | Blocked | Cancelled) => true,
        (Some(Executing), Observing | Failed | Blocked) => true,
        (Some(Observing), Verifying | Failed | Blocked) => true,
        (Some(Verifying), Persisting | Failed | Blocked) => true,
        (Some(Persisting), Completed | Failed | RolledBack) => true,
        (Some(current), next) if current == next => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use moxi_contracts::{ApprovalGrant, EventResult};
    use serde_json::json;

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
            execution_ticket_ref: "ticket_1".into(),
            capability_contract_ref: "file.read".into(),
            capability_contract_hash: "contract_hash_1".into(),
            executor_ref: "moxi.builtin.fs.file_read".into(),
            executor_version: "0.2.0".into(),
            executor_manifest_hash: "executor_manifest_hash_1".into(),
            gateway_decision_ref: None,
            proof_refs: vec!["proof_1".into()],
            input_hash: "in".into(),
            output_hash: "out".into(),
            previous_event_hash: String::new(),
            event_hash: String::new(),
            result: EventResult::Success,
            timestamp: Utc::now(),
        }
    }

    fn approval_grant() -> ApprovalGrant {
        ApprovalGrant {
            grant_id: "ag_1".into(),
            run_id: "run_1".into(),
            delta_id: "delta_1".into(),
            policy_decision_ref: "pd_1".into(),
            capability_id: "file.read".into(),
            approver_id: "human_1".into(),
            reason: "approved".into(),
            granted_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5),
        }
    }

    fn execution_ticket() -> ExecutionTicket {
        ExecutionTicket {
            ticket_id: "ticket_1".into(),
            run_id: "run_1".into(),
            delta_id: "delta_1".into(),
            policy_decision_ref: "pd_1".into(),
            capability_contract_ref: "file.read".into(),
            capability_contract_hash: "contract_hash_1".into(),
            executor_ref: "moxi.builtin.fs.file_read".into(),
            executor_version: "0.2.0".into(),
            executor_manifest_hash: "executor_manifest_hash_1".into(),
            executor_isolation: moxi_contracts::ExecutorIsolation::InProcessTrusted,
            retry_policy: Default::default(),
            sandbox_profile_ref: "fs-readonly".into(),
            actor_id: "kernel".into(),
            capability_id: "file.read".into(),
            expires_at: Utc::now() + Duration::minutes(5),
        }
    }

    fn proof() -> Proof {
        Proof {
            proof_id: "proof_1".into(),
            run_id: "run_1".into(),
            policy_decision_ref: "pd_1".into(),
            capability_contract_ref: "file.read".into(),
            capability_contract_hash: "contract_hash_1".into(),
            executor_ref: "moxi.builtin.fs.file_read".into(),
            executor_version: "0.2.0".into(),
            executor_manifest_hash: "executor_manifest_hash_1".into(),
            gateway_decision_ref: Some("gd_1".into()),
            input_hash: "input_hash_1".into(),
            output_hash: "output_hash_1".into(),
            source_type: "tool_output".into(),
            source_ref: "ticket_1".into(),
            hash: "proof_hash_1".into(),
            claim: "file.read completed successfully".into(),
            confidence: moxi_contracts::Confidence::High,
            collected_at: Utc::now(),
        }
    }

    fn sandbox_result() -> SandboxResult {
        let output = json!({
            "path": "file.txt",
            "content": "hello",
            "bytes": 5
        });
        SandboxResult {
            ticket_id: "ticket_1".into(),
            run_id: "run_1".into(),
            capability_id: "file.read".into(),
            policy_decision_ref: "pd_1".into(),
            capability_contract_ref: "file.read".into(),
            capability_contract_hash: "contract_hash_1".into(),
            executor_ref: "moxi.builtin.fs.file_read".into(),
            executor_version: "0.2.0".into(),
            executor_manifest_hash: "executor_manifest_hash_1".into(),
            gateway_decision_ref: Some("gd_1".into()),
            input_hash: "input_hash_1".into(),
            success: true,
            output,
            error: None,
            started_at: Utc::now(),
            finished_at: Utc::now(),
            output_hash: "output_hash_1".into(),
        }
    }

    #[test]
    fn ledger_is_append_only() {
        let store = Store::open_memory().unwrap();
        let event = ledger_event();
        let event = store.append_ledger_event(event).unwrap();

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

    #[test]
    fn approval_grants_are_append_only() {
        let store = Store::open_memory().unwrap();
        let grant = approval_grant();
        store.record_approval_grant(&grant).unwrap();

        let update = store.conn.execute(
            "UPDATE approval_grants SET capability_id = 'tampered' WHERE grant_id = ?1",
            params![grant.grant_id],
        );
        assert!(update.is_err());

        let delete = store.conn.execute(
            "DELETE FROM approval_grants WHERE grant_id = ?1",
            params![grant.grant_id],
        );
        assert!(delete.is_err());
    }

    #[test]
    fn execution_ticket_payload_is_persisted() {
        let store = Store::open_memory().unwrap();
        let ticket = execution_ticket();

        store.record_ticket(&ticket).unwrap();

        assert_eq!(
            store.execution_ticket(&ticket.ticket_id).unwrap(),
            Some(ticket)
        );
    }

    #[test]
    fn sandbox_result_payload_is_persisted_and_append_only() {
        let store = Store::open_memory().unwrap();
        let result = sandbox_result();
        store.record_sandbox_result(&result).unwrap();

        assert_eq!(
            store.sandbox_result(&result.ticket_id).unwrap(),
            Some(result.clone())
        );

        let update = store.conn.execute(
            "UPDATE sandbox_results SET output_hash = 'tampered' WHERE ticket_id = ?1",
            params![result.ticket_id],
        );
        assert!(update.is_err());

        let delete = store.conn.execute(
            "DELETE FROM sandbox_results WHERE ticket_id = ?1",
            params![result.ticket_id],
        );
        assert!(delete.is_err());
    }

    #[test]
    fn proof_payload_is_persisted_and_append_only() {
        let store = Store::open_memory().unwrap();
        let proof = proof();
        store.record_proof(&proof).unwrap();

        assert_eq!(store.proof(&proof.proof_id).unwrap(), Some(proof.clone()));

        let update = store.conn.execute(
            "UPDATE proofs SET output_hash = 'tampered' WHERE proof_id = ?1",
            params![proof.proof_id],
        );
        assert!(update.is_err());

        let delete = store.conn.execute(
            "DELETE FROM proofs WHERE proof_id = ?1",
            params![proof.proof_id],
        );
        assert!(delete.is_err());
    }

    #[test]
    fn ledger_events_are_hash_chained() {
        let store = Store::open_memory().unwrap();
        let first = store.append_ledger_event(ledger_event()).unwrap();
        let mut second = ledger_event();
        second.ledger_event_id = "le_2".into();

        let second = store.append_ledger_event(second).unwrap();

        assert!(!first.event_hash.is_empty());
        assert_eq!(second.previous_event_hash, first.event_hash);
    }

    #[test]
    fn ledger_hash_chain_validation_accepts_valid_chain() {
        let store = Store::open_memory().unwrap();
        store.append_ledger_event(ledger_event()).unwrap();
        let mut second = ledger_event();
        second.ledger_event_id = "le_2".into();
        store.append_ledger_event(second).unwrap();

        store.validate_ledger_hash_chain().unwrap();
    }

    #[test]
    fn ledger_hash_chain_validation_detects_broken_previous_hash() {
        let store = Store::open_memory().unwrap();
        store.append_ledger_event(ledger_event()).unwrap();
        let mut tampered = ledger_event();
        tampered.ledger_event_id = "le_tampered".into();
        tampered.previous_event_hash = "not-the-previous-hash".into();
        tampered.event_hash = "not-the-event-hash".into();

        store
            .conn
            .execute(
                r#"
                INSERT INTO ledger_events (
                    ledger_event_id, run_id, event_type, payload_json, event_hash, previous_event_hash, timestamp
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                "#,
                params![
                    tampered.ledger_event_id,
                    tampered.run_id,
                    tampered.event_type,
                    serde_json::to_string(&tampered).unwrap(),
                    tampered.event_hash,
                    tampered.previous_event_hash,
                    tampered.timestamp.to_rfc3339(),
                ],
            )
            .unwrap();

        assert!(matches!(
            store.validate_ledger_hash_chain(),
            Err(StoreError::LedgerChainBroken { .. })
        ));
    }

    #[test]
    fn run_state_transitions_reject_backwards_moves() {
        let store = Store::open_memory().unwrap();
        store
            .transition_run_status("run_1", RunStatus::Admitted)
            .unwrap();
        store
            .transition_run_status("run_1", RunStatus::Executing)
            .unwrap();
        store
            .transition_run_status("run_1", RunStatus::Observing)
            .unwrap();
        store
            .transition_run_status("run_1", RunStatus::Verifying)
            .unwrap();
        store
            .transition_run_status("run_1", RunStatus::Persisting)
            .unwrap();
        store
            .transition_run_status("run_1", RunStatus::Completed)
            .unwrap();

        assert!(matches!(
            store.transition_run_status("run_1", RunStatus::Executing),
            Err(StoreError::InvalidTransition { .. })
        ));
    }
}
