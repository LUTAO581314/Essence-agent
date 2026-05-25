use chrono::Utc;
use moxi_contracts::{
    ApprovalGrant, Budget, CapabilityContract, Decision, EventResult, ExecutionTicket,
    ExecutorManifest, LedgerEvent, PolicyDecision, Proof, RunStatus, SandboxResult,
};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use thiserror::Error;

const CURRENT_SCHEMA_VERSION: u32 = 5;

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
    #[error("ledger audit requires at least one proof for successful event {ledger_event_id}")]
    LedgerAuditProofRequired { ledger_event_id: String },
    #[error("ledger audit missing execution ticket {ticket_id} referenced by {ledger_event_id}")]
    LedgerAuditMissingTicket {
        ledger_event_id: String,
        ticket_id: String,
    },
    #[error("ledger audit missing policy decision {policy_decision_ref} referenced by {ledger_event_id}")]
    LedgerAuditMissingPolicyDecision {
        ledger_event_id: String,
        policy_decision_ref: String,
    },
    #[error(
        "ledger audit missing capability contract {capability_id} referenced by {ledger_event_id}"
    )]
    LedgerAuditMissingCapabilityContract {
        ledger_event_id: String,
        capability_id: String,
    },
    #[error(
        "ledger audit missing executor manifest {executor_id} referenced by {ledger_event_id}"
    )]
    LedgerAuditMissingExecutorManifest {
        ledger_event_id: String,
        executor_id: String,
    },
    #[error(
        "ledger audit denied policy decision {policy_decision_ref} referenced by {ledger_event_id}"
    )]
    LedgerAuditDeniedPolicyDecision {
        ledger_event_id: String,
        policy_decision_ref: String,
    },
    #[error("ledger audit missing approval grant for policy decision {policy_decision_ref} referenced by {ledger_event_id}")]
    LedgerAuditMissingApprovalGrant {
        ledger_event_id: String,
        policy_decision_ref: String,
    },
    #[error("ledger audit missing sandbox result {ticket_id} referenced by {ledger_event_id}")]
    LedgerAuditMissingSandboxResult {
        ledger_event_id: String,
        ticket_id: String,
    },
    #[error("ledger audit missing proof {proof_id} referenced by {ledger_event_id}")]
    LedgerAuditMissingProof {
        ledger_event_id: String,
        proof_id: String,
    },
    #[error("ledger audit binding mismatch at {ledger_event_id}: {field} expected {expected}, got {actual}")]
    LedgerAuditBindingMismatch {
        ledger_event_id: String,
        field: &'static str,
        expected: String,
        actual: String,
    },
    #[error("ledger audit proof hash mismatch at {ledger_event_id}/{proof_id}: expected {expected_hash}, got {actual_hash}")]
    LedgerAuditProofHashMismatch {
        ledger_event_id: String,
        proof_id: String,
        expected_hash: String,
        actual_hash: String,
    },
    #[error("store schema version {found} is newer than supported version {supported}")]
    SchemaVersionTooNew { found: u32, supported: u32 },
}

pub type StoreResult<T> = Result<T, StoreError>;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditReplayReport {
    pub ledger_events: usize,
    pub successful_events: usize,
    pub policy_decisions: usize,
    pub approval_grants: usize,
    pub capability_contracts: usize,
    pub executor_manifests: usize,
    pub execution_tickets: usize,
    pub sandbox_results: usize,
    pub proofs: usize,
    pub last_event_hash: Option<String>,
}

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
            CREATE TABLE IF NOT EXISTS store_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            "#,
        )?;
        let version = self.schema_version()?;
        if version > CURRENT_SCHEMA_VERSION {
            return Err(StoreError::SchemaVersionTooNew {
                found: version,
                supported: CURRENT_SCHEMA_VERSION,
            });
        }
        if version < 1 {
            self.migrate_to_v1()?;
        }
        if version < 2 {
            self.migrate_to_v2()?;
        }
        if version < 3 {
            self.migrate_to_v3()?;
        }
        if version < 4 {
            self.migrate_to_v4()?;
        }
        if version < 5 {
            self.migrate_to_v5()?;
        }
        self.install_append_only_triggers()?;
        Ok(())
    }

    pub fn schema_version(&self) -> StoreResult<u32> {
        let value = self
            .conn
            .query_row(
                "SELECT value FROM store_meta WHERE key = 'schema_version'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        Ok(value
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or_default())
    }

    fn set_schema_version(&self, version: u32) -> StoreResult<()> {
        self.conn.execute(
            r#"
            INSERT INTO store_meta (key, value)
            VALUES ('schema_version', ?1)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            "#,
            params![version.to_string()],
        )?;
        Ok(())
    }

    fn migrate_to_v1(&self) -> StoreResult<()> {
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
                executor_artifact_hash TEXT NOT NULL,
                executor_signature_ref TEXT NOT NULL,
                executor_signing_key_ref TEXT NOT NULL,
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
                executor_artifact_hash TEXT NOT NULL,
                executor_signature_ref TEXT NOT NULL,
                executor_signing_key_ref TEXT NOT NULL,
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
        self.set_schema_version(1)?;
        Ok(())
    }

    fn migrate_to_v2(&self) -> StoreResult<()> {
        self.ensure_column("execution_tickets", "payload_json", "TEXT")?;
        self.set_schema_version(2)?;
        Ok(())
    }

    fn migrate_to_v3(&self) -> StoreResult<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS sandbox_results (
                ticket_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                capability_id TEXT NOT NULL,
                policy_decision_ref TEXT NOT NULL,
                capability_contract_ref TEXT NOT NULL,
                capability_contract_hash TEXT NOT NULL,
                executor_ref TEXT NOT NULL,
                executor_version TEXT NOT NULL,
                executor_artifact_hash TEXT NOT NULL DEFAULT '',
                executor_signature_ref TEXT NOT NULL DEFAULT '',
                executor_signing_key_ref TEXT NOT NULL DEFAULT '',
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
                executor_artifact_hash TEXT NOT NULL DEFAULT '',
                executor_signature_ref TEXT NOT NULL DEFAULT '',
                executor_signing_key_ref TEXT NOT NULL DEFAULT '',
                executor_manifest_hash TEXT NOT NULL,
                gateway_decision_ref TEXT,
                input_hash TEXT NOT NULL,
                output_hash TEXT NOT NULL,
                source_ref TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                collected_at TEXT NOT NULL
            );
            "#,
        )?;
        self.ensure_column(
            "sandbox_results",
            "executor_artifact_hash",
            "TEXT NOT NULL DEFAULT ''",
        )?;
        self.ensure_column(
            "sandbox_results",
            "executor_signature_ref",
            "TEXT NOT NULL DEFAULT ''",
        )?;
        self.ensure_column(
            "sandbox_results",
            "executor_signing_key_ref",
            "TEXT NOT NULL DEFAULT ''",
        )?;
        self.ensure_column(
            "proofs",
            "executor_artifact_hash",
            "TEXT NOT NULL DEFAULT ''",
        )?;
        self.ensure_column(
            "proofs",
            "executor_signature_ref",
            "TEXT NOT NULL DEFAULT ''",
        )?;
        self.ensure_column(
            "proofs",
            "executor_signing_key_ref",
            "TEXT NOT NULL DEFAULT ''",
        )?;
        self.set_schema_version(3)?;
        Ok(())
    }

    fn migrate_to_v4(&self) -> StoreResult<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS policy_decisions (
                decision_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                delta_id TEXT NOT NULL,
                capability_id TEXT NOT NULL,
                decision TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            "#,
        )?;
        self.set_schema_version(4)?;
        Ok(())
    }

    fn migrate_to_v5(&self) -> StoreResult<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS capability_contracts (
                capability_id TEXT PRIMARY KEY,
                capability_contract_hash TEXT NOT NULL,
                provider_identity TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS executor_manifests (
                executor_id TEXT PRIMARY KEY,
                capability_id TEXT NOT NULL,
                executor_manifest_hash TEXT NOT NULL,
                capability_contract_hash TEXT NOT NULL,
                artifact_hash TEXT NOT NULL,
                signature_ref TEXT NOT NULL,
                signing_key_ref TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            "#,
        )?;
        self.set_schema_version(5)?;
        Ok(())
    }

    fn install_append_only_triggers(&self) -> StoreResult<()> {
        self.conn.execute_batch(
            r#"
            CREATE TRIGGER IF NOT EXISTS capability_contracts_no_update
            BEFORE UPDATE ON capability_contracts
            BEGIN
                SELECT RAISE(ABORT, 'capability_contracts append only');
            END;

            CREATE TRIGGER IF NOT EXISTS capability_contracts_no_delete
            BEFORE DELETE ON capability_contracts
            BEGIN
                SELECT RAISE(ABORT, 'capability_contracts append only');
            END;

            CREATE TRIGGER IF NOT EXISTS executor_manifests_no_update
            BEFORE UPDATE ON executor_manifests
            BEGIN
                SELECT RAISE(ABORT, 'executor_manifests append only');
            END;

            CREATE TRIGGER IF NOT EXISTS executor_manifests_no_delete
            BEFORE DELETE ON executor_manifests
            BEGIN
                SELECT RAISE(ABORT, 'executor_manifests append only');
            END;

            CREATE TRIGGER IF NOT EXISTS policy_decisions_no_update
            BEFORE UPDATE ON policy_decisions
            BEGIN
                SELECT RAISE(ABORT, 'policy_decisions append only');
            END;

            CREATE TRIGGER IF NOT EXISTS policy_decisions_no_delete
            BEFORE DELETE ON policy_decisions
            BEGIN
                SELECT RAISE(ABORT, 'policy_decisions append only');
            END;

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

    pub fn record_capability_contract(
        &self,
        contract: &CapabilityContract,
        capability_contract_hash: &str,
    ) -> StoreResult<()> {
        self.conn.execute(
            r#"
            INSERT INTO capability_contracts (
                capability_id, capability_contract_hash, provider_identity, payload_json, created_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
            params![
                contract.capability_id,
                capability_contract_hash,
                contract.provider_identity,
                serde_json::to_string(contract)?,
                Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn capability_contract(
        &self,
        capability_id: &str,
    ) -> StoreResult<Option<CapabilityContract>> {
        let payload = self
            .conn
            .query_row(
                "SELECT payload_json FROM capability_contracts WHERE capability_id = ?1",
                params![capability_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        payload
            .map(|payload| Ok(serde_json::from_str(&payload)?))
            .transpose()
    }

    pub fn record_executor_manifest(
        &self,
        manifest: &ExecutorManifest,
        executor_manifest_hash: &str,
    ) -> StoreResult<()> {
        self.conn.execute(
            r#"
            INSERT INTO executor_manifests (
                executor_id, capability_id, executor_manifest_hash, capability_contract_hash,
                artifact_hash, signature_ref, signing_key_ref, payload_json, created_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            "#,
            params![
                manifest.executor_id,
                manifest.capability_id,
                executor_manifest_hash,
                manifest.capability_contract_hash,
                manifest.artifact_hash,
                manifest.signature_ref.as_deref().unwrap_or_default(),
                manifest.signing_key_ref,
                serde_json::to_string(manifest)?,
                Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn executor_manifest(&self, executor_id: &str) -> StoreResult<Option<ExecutorManifest>> {
        let payload = self
            .conn
            .query_row(
                "SELECT payload_json FROM executor_manifests WHERE executor_id = ?1",
                params![executor_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        payload
            .map(|payload| Ok(serde_json::from_str(&payload)?))
            .transpose()
    }

    pub fn record_policy_decision(&self, policy: &PolicyDecision) -> StoreResult<()> {
        self.conn.execute(
            r#"
            INSERT INTO policy_decisions (
                decision_id, run_id, delta_id, capability_id, decision, payload_json, created_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
            params![
                policy.decision_id,
                policy.run_id,
                policy.delta_id,
                policy.capability_id,
                format!("{:?}", policy.decision),
                serde_json::to_string(policy)?,
                Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn policy_decision(&self, decision_id: &str) -> StoreResult<Option<PolicyDecision>> {
        let payload = self
            .conn
            .query_row(
                "SELECT payload_json FROM policy_decisions WHERE decision_id = ?1",
                params![decision_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        payload
            .map(|payload| Ok(serde_json::from_str(&payload)?))
            .transpose()
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

    pub fn approval_grants_for_policy_decision(
        &self,
        policy_decision_ref: &str,
    ) -> StoreResult<Vec<ApprovalGrant>> {
        let mut stmt = self.conn.prepare(
            "SELECT payload_json FROM approval_grants WHERE policy_decision_ref = ?1 ORDER BY rowid ASC",
        )?;
        let grants = stmt
            .query_map(params![policy_decision_ref], |row| row.get::<_, String>(0))?
            .map(|payload| Ok(serde_json::from_str(&payload?)?))
            .collect::<StoreResult<Vec<_>>>()?;
        Ok(grants)
    }

    pub fn record_sandbox_result(&self, result: &SandboxResult) -> StoreResult<()> {
        self.conn.execute(
            r#"
            INSERT INTO sandbox_results (
                ticket_id, run_id, capability_id, policy_decision_ref,
                capability_contract_ref, capability_contract_hash, executor_ref,
                executor_version, executor_artifact_hash, executor_signature_ref,
                executor_signing_key_ref, executor_manifest_hash, gateway_decision_ref,
                input_hash, output_hash, payload_json, finished_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
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
                result.executor_artifact_hash,
                result.executor_signature_ref,
                result.executor_signing_key_ref,
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
                executor_artifact_hash, executor_signature_ref,
                executor_signing_key_ref, executor_manifest_hash, gateway_decision_ref, input_hash,
                output_hash, source_ref, payload_json, collected_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
            "#,
            params![
                proof.proof_id,
                proof.run_id,
                proof.policy_decision_ref,
                proof.capability_contract_ref,
                proof.capability_contract_hash,
                proof.executor_ref,
                proof.executor_version,
                proof.executor_artifact_hash,
                proof.executor_signature_ref,
                proof.executor_signing_key_ref,
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

    fn ledger_events_ordered(&self) -> StoreResult<Vec<LedgerEvent>> {
        let mut stmt = self
            .conn
            .prepare("SELECT payload_json FROM ledger_events ORDER BY rowid ASC")?;
        let events = stmt
            .query_map([], |row| row.get::<_, String>(0))?
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

    pub fn replay_ledger_audit(&self) -> StoreResult<AuditReplayReport> {
        self.validate_ledger_hash_chain()?;

        let mut report = AuditReplayReport::default();
        for event in self.ledger_events_ordered()? {
            report.ledger_events += 1;
            report.last_event_hash = Some(event.event_hash.clone());

            if event.result == EventResult::Success {
                report.successful_events += 1;
                self.verify_successful_ledger_event(&event, &mut report)?;
            }
        }

        Ok(report)
    }

    fn verify_successful_ledger_event(
        &self,
        event: &LedgerEvent,
        report: &mut AuditReplayReport,
    ) -> StoreResult<()> {
        if event.proof_refs.is_empty() {
            return Err(StoreError::LedgerAuditProofRequired {
                ledger_event_id: event.ledger_event_id.clone(),
            });
        }

        let ticket = self
            .execution_ticket(&event.execution_ticket_ref)?
            .ok_or_else(|| StoreError::LedgerAuditMissingTicket {
                ledger_event_id: event.ledger_event_id.clone(),
                ticket_id: event.execution_ticket_ref.clone(),
            })?;
        report.execution_tickets += 1;
        verify_event_ticket_binding(event, &ticket)?;

        let capability = self
            .capability_contract(&event.capability_id)?
            .ok_or_else(|| StoreError::LedgerAuditMissingCapabilityContract {
                ledger_event_id: event.ledger_event_id.clone(),
                capability_id: event.capability_id.clone(),
            })?;
        report.capability_contracts += 1;
        verify_event_capability_binding(event, &capability)?;

        let manifest = self
            .executor_manifest(&event.executor_ref)?
            .ok_or_else(|| StoreError::LedgerAuditMissingExecutorManifest {
                ledger_event_id: event.ledger_event_id.clone(),
                executor_id: event.executor_ref.clone(),
            })?;
        report.executor_manifests += 1;
        verify_event_executor_binding(event, &manifest)?;

        let policy = self
            .policy_decision(&event.policy_decision_ref)?
            .ok_or_else(|| StoreError::LedgerAuditMissingPolicyDecision {
                ledger_event_id: event.ledger_event_id.clone(),
                policy_decision_ref: event.policy_decision_ref.clone(),
            })?;
        report.policy_decisions += 1;
        verify_event_policy_binding(event, &policy)?;
        if policy.decision == Decision::Deny {
            return Err(StoreError::LedgerAuditDeniedPolicyDecision {
                ledger_event_id: event.ledger_event_id.clone(),
                policy_decision_ref: event.policy_decision_ref.clone(),
            });
        }
        if policy.decision == Decision::RequireApproval {
            let grants = self.approval_grants_for_policy_decision(&policy.decision_id)?;
            let approved = grants
                .iter()
                .any(|grant| approval_grant_matches_event(event, grant));
            if !approved {
                return Err(StoreError::LedgerAuditMissingApprovalGrant {
                    ledger_event_id: event.ledger_event_id.clone(),
                    policy_decision_ref: event.policy_decision_ref.clone(),
                });
            }
            report.approval_grants += 1;
        }

        let result = self
            .sandbox_result(&event.execution_ticket_ref)?
            .ok_or_else(|| StoreError::LedgerAuditMissingSandboxResult {
                ledger_event_id: event.ledger_event_id.clone(),
                ticket_id: event.execution_ticket_ref.clone(),
            })?;
        report.sandbox_results += 1;
        verify_event_result_binding(event, &result)?;

        for proof_ref in &event.proof_refs {
            let proof =
                self.proof(proof_ref)?
                    .ok_or_else(|| StoreError::LedgerAuditMissingProof {
                        ledger_event_id: event.ledger_event_id.clone(),
                        proof_id: proof_ref.clone(),
                    })?;
            report.proofs += 1;
            verify_event_proof_binding(event, &proof)?;
            verify_proof_evidence_hash(event, &result, &proof)?;
        }

        Ok(())
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

fn verify_event_ticket_binding(event: &LedgerEvent, ticket: &ExecutionTicket) -> StoreResult<()> {
    audit_expect_eq(
        event,
        "ticket.ticket_id",
        &event.execution_ticket_ref,
        &ticket.ticket_id,
    )?;
    audit_expect_eq(event, "ticket.run_id", &event.run_id, &ticket.run_id)?;
    audit_expect_eq(event, "ticket.delta_id", &event.delta_id, &ticket.delta_id)?;
    audit_expect_eq(
        event,
        "ticket.policy_decision_ref",
        &event.policy_decision_ref,
        &ticket.policy_decision_ref,
    )?;
    audit_expect_eq(
        event,
        "ticket.capability_id",
        &event.capability_id,
        &ticket.capability_id,
    )?;
    audit_expect_eq(
        event,
        "ticket.capability_contract_ref",
        &event.capability_contract_ref,
        &ticket.capability_contract_ref,
    )?;
    audit_expect_eq(
        event,
        "ticket.capability_contract_hash",
        &event.capability_contract_hash,
        &ticket.capability_contract_hash,
    )?;
    audit_expect_eq(
        event,
        "ticket.executor_ref",
        &event.executor_ref,
        &ticket.executor_ref,
    )?;
    audit_expect_eq(
        event,
        "ticket.executor_version",
        &event.executor_version,
        &ticket.executor_version,
    )?;
    audit_expect_eq(
        event,
        "ticket.executor_artifact_hash",
        &event.executor_artifact_hash,
        &ticket.executor_artifact_hash,
    )?;
    audit_expect_eq(
        event,
        "ticket.executor_signature_ref",
        &event.executor_signature_ref,
        &ticket.executor_signature_ref,
    )?;
    audit_expect_eq(
        event,
        "ticket.executor_signing_key_ref",
        &event.executor_signing_key_ref,
        &ticket.executor_signing_key_ref,
    )?;
    audit_expect_eq(
        event,
        "ticket.executor_manifest_hash",
        &event.executor_manifest_hash,
        &ticket.executor_manifest_hash,
    )?;
    audit_expect_eq(event, "ticket.actor_id", &event.actor_id, &ticket.actor_id)?;
    Ok(())
}

fn verify_event_capability_binding(
    event: &LedgerEvent,
    capability: &CapabilityContract,
) -> StoreResult<()> {
    audit_expect_eq(
        event,
        "capability.capability_id",
        &event.capability_id,
        &capability.capability_id,
    )?;
    audit_expect_eq(
        event,
        "capability.capability_id_ref",
        &event.capability_contract_ref,
        &capability.capability_id,
    )?;
    let expected_hash = hash_capability_contract(capability)?;
    audit_expect_eq(
        event,
        "capability.capability_contract_hash",
        &event.capability_contract_hash,
        &expected_hash,
    )?;
    Ok(())
}

fn verify_event_executor_binding(
    event: &LedgerEvent,
    manifest: &ExecutorManifest,
) -> StoreResult<()> {
    audit_expect_eq(
        event,
        "executor.executor_id",
        &event.executor_ref,
        &manifest.executor_id,
    )?;
    audit_expect_eq(
        event,
        "executor.capability_id",
        &event.capability_id,
        &manifest.capability_id,
    )?;
    audit_expect_eq(
        event,
        "executor.executor_version",
        &event.executor_version,
        &manifest.executor_version,
    )?;
    audit_expect_eq(
        event,
        "executor.artifact_hash",
        &event.executor_artifact_hash,
        &manifest.artifact_hash,
    )?;
    audit_expect_eq(
        event,
        "executor.signing_key_ref",
        &event.executor_signing_key_ref,
        &manifest.signing_key_ref,
    )?;
    let signature_ref = manifest
        .signature_ref
        .as_deref()
        .unwrap_or_default()
        .to_string();
    audit_expect_eq(
        event,
        "executor.signature_ref",
        &event.executor_signature_ref,
        &signature_ref,
    )?;
    audit_expect_eq(
        event,
        "executor.capability_contract_hash",
        &event.capability_contract_hash,
        &manifest.capability_contract_hash,
    )?;
    let expected_hash = hash_executor_manifest(manifest)?;
    audit_expect_eq(
        event,
        "executor.executor_manifest_hash",
        &event.executor_manifest_hash,
        &expected_hash,
    )?;
    Ok(())
}

fn verify_event_policy_binding(event: &LedgerEvent, policy: &PolicyDecision) -> StoreResult<()> {
    audit_expect_eq(
        event,
        "policy_decision.decision_id",
        &event.policy_decision_ref,
        &policy.decision_id,
    )?;
    audit_expect_eq(
        event,
        "policy_decision.run_id",
        &event.run_id,
        &policy.run_id,
    )?;
    audit_expect_eq(
        event,
        "policy_decision.delta_id",
        &event.delta_id,
        &policy.delta_id,
    )?;
    audit_expect_eq(
        event,
        "policy_decision.capability_id",
        &event.capability_id,
        &policy.capability_id,
    )?;
    Ok(())
}

fn approval_grant_matches_event(event: &LedgerEvent, grant: &ApprovalGrant) -> bool {
    grant.run_id == event.run_id
        && grant.delta_id == event.delta_id
        && grant.policy_decision_ref == event.policy_decision_ref
        && grant.capability_id == event.capability_id
        && grant.expires_at >= event.timestamp
}

fn verify_event_result_binding(event: &LedgerEvent, result: &SandboxResult) -> StoreResult<()> {
    audit_expect_eq(
        event,
        "sandbox_result.ticket_id",
        &event.execution_ticket_ref,
        &result.ticket_id,
    )?;
    audit_expect_eq(
        event,
        "sandbox_result.run_id",
        &event.run_id,
        &result.run_id,
    )?;
    audit_expect_eq(
        event,
        "sandbox_result.capability_id",
        &event.capability_id,
        &result.capability_id,
    )?;
    audit_expect_eq(
        event,
        "sandbox_result.policy_decision_ref",
        &event.policy_decision_ref,
        &result.policy_decision_ref,
    )?;
    audit_expect_eq(
        event,
        "sandbox_result.capability_contract_ref",
        &event.capability_contract_ref,
        &result.capability_contract_ref,
    )?;
    audit_expect_eq(
        event,
        "sandbox_result.capability_contract_hash",
        &event.capability_contract_hash,
        &result.capability_contract_hash,
    )?;
    audit_expect_eq(
        event,
        "sandbox_result.executor_ref",
        &event.executor_ref,
        &result.executor_ref,
    )?;
    audit_expect_eq(
        event,
        "sandbox_result.executor_version",
        &event.executor_version,
        &result.executor_version,
    )?;
    audit_expect_eq(
        event,
        "sandbox_result.executor_artifact_hash",
        &event.executor_artifact_hash,
        &result.executor_artifact_hash,
    )?;
    audit_expect_eq(
        event,
        "sandbox_result.executor_signature_ref",
        &event.executor_signature_ref,
        &result.executor_signature_ref,
    )?;
    audit_expect_eq(
        event,
        "sandbox_result.executor_signing_key_ref",
        &event.executor_signing_key_ref,
        &result.executor_signing_key_ref,
    )?;
    audit_expect_eq(
        event,
        "sandbox_result.executor_manifest_hash",
        &event.executor_manifest_hash,
        &result.executor_manifest_hash,
    )?;
    audit_expect_eq(
        event,
        "sandbox_result.gateway_decision_ref",
        &event.gateway_decision_ref,
        &result.gateway_decision_ref,
    )?;
    audit_expect_eq(
        event,
        "sandbox_result.input_hash",
        &event.input_hash,
        &result.input_hash,
    )?;
    audit_expect_eq(
        event,
        "sandbox_result.output_hash",
        &event.output_hash,
        &result.output_hash,
    )?;
    audit_expect_eq(event, "sandbox_result.success", &true, &result.success)?;

    let expected_output_hash = hash_json(&result.output);
    audit_expect_eq(
        event,
        "sandbox_result.output_hash",
        &expected_output_hash,
        &result.output_hash,
    )?;
    Ok(())
}

fn verify_event_proof_binding(event: &LedgerEvent, proof: &Proof) -> StoreResult<()> {
    audit_expect_eq(event, "proof.run_id", &event.run_id, &proof.run_id)?;
    audit_expect_eq(
        event,
        "proof.policy_decision_ref",
        &event.policy_decision_ref,
        &proof.policy_decision_ref,
    )?;
    audit_expect_eq(
        event,
        "proof.source_ref",
        &event.execution_ticket_ref,
        &proof.source_ref,
    )?;
    audit_expect_eq(
        event,
        "proof.capability_contract_ref",
        &event.capability_contract_ref,
        &proof.capability_contract_ref,
    )?;
    audit_expect_eq(
        event,
        "proof.capability_contract_hash",
        &event.capability_contract_hash,
        &proof.capability_contract_hash,
    )?;
    audit_expect_eq(
        event,
        "proof.executor_ref",
        &event.executor_ref,
        &proof.executor_ref,
    )?;
    audit_expect_eq(
        event,
        "proof.executor_version",
        &event.executor_version,
        &proof.executor_version,
    )?;
    audit_expect_eq(
        event,
        "proof.executor_artifact_hash",
        &event.executor_artifact_hash,
        &proof.executor_artifact_hash,
    )?;
    audit_expect_eq(
        event,
        "proof.executor_signature_ref",
        &event.executor_signature_ref,
        &proof.executor_signature_ref,
    )?;
    audit_expect_eq(
        event,
        "proof.executor_signing_key_ref",
        &event.executor_signing_key_ref,
        &proof.executor_signing_key_ref,
    )?;
    audit_expect_eq(
        event,
        "proof.executor_manifest_hash",
        &event.executor_manifest_hash,
        &proof.executor_manifest_hash,
    )?;
    audit_expect_eq(
        event,
        "proof.gateway_decision_ref",
        &event.gateway_decision_ref,
        &proof.gateway_decision_ref,
    )?;
    audit_expect_eq(
        event,
        "proof.input_hash",
        &event.input_hash,
        &proof.input_hash,
    )?;
    audit_expect_eq(
        event,
        "proof.output_hash",
        &event.output_hash,
        &proof.output_hash,
    )?;
    audit_expect_eq(
        event,
        "proof.source_type",
        &String::from("tool_output"),
        &proof.source_type,
    )?;
    Ok(())
}

fn verify_proof_evidence_hash(
    event: &LedgerEvent,
    result: &SandboxResult,
    proof: &Proof,
) -> StoreResult<()> {
    let expected_hash = proof_evidence_hash(result);
    if proof.hash != expected_hash {
        return Err(StoreError::LedgerAuditProofHashMismatch {
            ledger_event_id: event.ledger_event_id.clone(),
            proof_id: proof.proof_id.clone(),
            expected_hash,
            actual_hash: proof.hash.clone(),
        });
    }
    Ok(())
}

fn audit_expect_eq<T>(
    event: &LedgerEvent,
    field: &'static str,
    expected: &T,
    actual: &T,
) -> StoreResult<()>
where
    T: PartialEq + std::fmt::Debug,
{
    if expected != actual {
        return Err(StoreError::LedgerAuditBindingMismatch {
            ledger_event_id: event.ledger_event_id.clone(),
            field,
            expected: format!("{expected:?}"),
            actual: format!("{actual:?}"),
        });
    }
    Ok(())
}

fn proof_evidence_hash(result: &SandboxResult) -> String {
    hash_json(&serde_json::json!({
        "ticket_id": result.ticket_id.clone(),
        "run_id": result.run_id.clone(),
        "capability_id": result.capability_id.clone(),
        "policy_decision_ref": result.policy_decision_ref.clone(),
        "capability_contract_ref": result.capability_contract_ref.clone(),
        "capability_contract_hash": result.capability_contract_hash.clone(),
        "executor_ref": result.executor_ref.clone(),
        "executor_version": result.executor_version.clone(),
        "executor_artifact_hash": result.executor_artifact_hash.clone(),
        "executor_signature_ref": result.executor_signature_ref.clone(),
        "executor_signing_key_ref": result.executor_signing_key_ref.clone(),
        "executor_manifest_hash": result.executor_manifest_hash.clone(),
        "gateway_decision_ref": result.gateway_decision_ref.clone(),
        "input_hash": result.input_hash.clone(),
        "output_hash": result.output_hash.clone(),
    }))
}

fn hash_capability_contract(capability: &CapabilityContract) -> StoreResult<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(capability)?)))
}

fn hash_executor_manifest(manifest: &ExecutorManifest) -> StoreResult<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(manifest)?)))
}

fn hash_json(value: &serde_json::Value) -> String {
    hex::encode(Sha256::digest(
        serde_json::to_vec(value).expect("json serialization cannot fail"),
    ))
}

fn hash_event(event: &LedgerEvent) -> StoreResult<String> {
    let bytes = serde_json::to_vec(event)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn is_allowed_transition(from: Option<RunStatus>, to: RunStatus) -> bool {
    use RunStatus::*;
    match (from, to) {
        (None, Admitted) => true,
        (
            Some(Admitted),
            RunningHeartbeat | AwaitingApproval | Blocked | Executing | Cancelled | TimedOut,
        ) => true,
        (Some(RunningHeartbeat), AwaitingApproval | Executing | Blocked | Cancelled | Failed) => {
            true
        }
        (Some(RunningHeartbeat), TimedOut) => true,
        (Some(AwaitingApproval), RunningHeartbeat | Blocked | Cancelled | TimedOut) => true,
        (Some(Executing), Observing | Failed | Blocked | TimedOut) => true,
        (Some(Observing), Verifying | Failed | Blocked | TimedOut) => true,
        (Some(Verifying), Persisting | Failed | Blocked | TimedOut) => true,
        (Some(Persisting), Completed | Failed | RolledBack | TimedOut) => true,
        (Some(current), next) if current == next => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use moxi_contracts::{
        ApprovalGrant, EventResult, ExecutorIsolation, Permissions, RetryPolicy, RiskLevel,
    };
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
            executor_artifact_hash:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            executor_signature_ref: "builtin://moxi/file.read/executor/signature".into(),
            executor_signing_key_ref: "builtin://moxi/signing-key".into(),
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

    fn policy_decision() -> PolicyDecision {
        PolicyDecision {
            decision_id: "pd_1".into(),
            run_id: "run_1".into(),
            delta_id: "delta_1".into(),
            actor_id: "kernel".into(),
            capability_id: "file.read".into(),
            decision: Decision::Allow,
            risk_level: RiskLevel::Low,
            reasons: vec![],
            required_approval: None,
            expires_at: Utc::now() + Duration::minutes(5),
        }
    }

    fn capability_contract() -> CapabilityContract {
        CapabilityContract {
            capability_id: "file.read".into(),
            capability_version: "0.2.0".into(),
            provider: "moxi.builtin.fs".into(),
            provider_identity: "moxi.builtin.fs".into(),
            manifest_ref: Some("builtin://moxi/file.read".into()),
            signature_ref: Some("builtin://moxi/file.read/capability/signature".into()),
            input_schema: json!({"type": "object"}),
            output_schema: json!({"type": "object"}),
            error_schema: json!({"type": "object"}),
            permissions: Permissions {
                resources: vec!["workspace.read".into()],
                denied: vec!["network".into(), "shell".into()],
            },
            sandbox_profile: "fs-readonly".into(),
            risk_level: RiskLevel::Low,
            timeout_ms: 1_000,
            retry_policy: RetryPolicy::default(),
            audit_required: true,
            proof_required: true,
            rollback_required: false,
        }
    }

    fn executor_manifest() -> ExecutorManifest {
        let capability = capability_contract();
        ExecutorManifest {
            executor_id: "moxi.builtin.fs.file_read".into(),
            capability_id: capability.capability_id.clone(),
            capability_contract_hash: hash_capability_contract(&capability).unwrap(),
            provider_identity: capability.provider_identity.clone(),
            executor_version: "0.2.0".into(),
            artifact_hash:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            signing_key_ref: "builtin://moxi/signing-key".into(),
            isolation: ExecutorIsolation::InProcessTrusted,
            sandbox_profile: capability.sandbox_profile,
            manifest_ref: Some("builtin://moxi/file.read/executor".into()),
            signature_ref: Some("builtin://moxi/file.read/executor/signature".into()),
            attestation_ref: None,
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
            executor_artifact_hash:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            executor_signature_ref: "builtin://moxi/file.read/executor/signature".into(),
            executor_signing_key_ref: "builtin://moxi/signing-key".into(),
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
            executor_artifact_hash:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            executor_signature_ref: "builtin://moxi/file.read/executor/signature".into(),
            executor_signing_key_ref: "builtin://moxi/signing-key".into(),
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

    fn audited_chain() -> (
        PolicyDecision,
        ExecutionTicket,
        SandboxResult,
        Proof,
        LedgerEvent,
    ) {
        let policy = policy_decision();
        let capability = capability_contract();
        let manifest = executor_manifest();
        let mut ticket = execution_ticket();
        ticket.capability_contract_hash = hash_capability_contract(&capability).unwrap();
        ticket.executor_manifest_hash = hash_executor_manifest(&manifest).unwrap();
        let mut result = sandbox_result();
        result.capability_contract_hash = ticket.capability_contract_hash.clone();
        result.executor_manifest_hash = ticket.executor_manifest_hash.clone();
        result.output_hash = hash_json(&result.output);

        let mut proof = proof();
        proof.capability_contract_hash = ticket.capability_contract_hash.clone();
        proof.executor_manifest_hash = ticket.executor_manifest_hash.clone();
        proof.gateway_decision_ref = result.gateway_decision_ref.clone();
        proof.input_hash = result.input_hash.clone();
        proof.output_hash = result.output_hash.clone();
        proof.hash = proof_evidence_hash(&result);

        let event = LedgerEvent {
            ledger_event_id: "le_1".into(),
            run_id: result.run_id.clone(),
            event_type: "tool.executed".into(),
            actor_id: ticket.actor_id.clone(),
            resource_ref: "file.txt".into(),
            delta_id: ticket.delta_id.clone(),
            capability_id: result.capability_id.clone(),
            policy_decision_ref: result.policy_decision_ref.clone(),
            execution_ticket_ref: result.ticket_id.clone(),
            capability_contract_ref: result.capability_contract_ref.clone(),
            capability_contract_hash: result.capability_contract_hash.clone(),
            executor_ref: result.executor_ref.clone(),
            executor_version: result.executor_version.clone(),
            executor_artifact_hash: result.executor_artifact_hash.clone(),
            executor_signature_ref: result.executor_signature_ref.clone(),
            executor_signing_key_ref: result.executor_signing_key_ref.clone(),
            executor_manifest_hash: result.executor_manifest_hash.clone(),
            gateway_decision_ref: result.gateway_decision_ref.clone(),
            proof_refs: vec![proof.proof_id.clone()],
            input_hash: result.input_hash.clone(),
            output_hash: result.output_hash.clone(),
            previous_event_hash: String::new(),
            event_hash: String::new(),
            result: EventResult::Success,
            timestamp: Utc::now(),
        };

        (policy, ticket, result, proof, event)
    }

    fn record_audited_chain(store: &Store) -> LedgerEvent {
        let (policy, ticket, result, proof, event) = audited_chain();
        record_registry_facts(store, &event);
        record_execution_facts(store, &policy, &ticket, &result, &proof);
        store.append_ledger_event(event).unwrap()
    }

    fn record_registry_facts(store: &Store, event: &LedgerEvent) {
        let capability = capability_contract();
        let manifest = executor_manifest();
        store
            .record_capability_contract(&capability, &event.capability_contract_hash)
            .unwrap();
        store
            .record_executor_manifest(&manifest, &event.executor_manifest_hash)
            .unwrap();
    }

    fn record_execution_facts(
        store: &Store,
        policy: &PolicyDecision,
        ticket: &ExecutionTicket,
        result: &SandboxResult,
        proof: &Proof,
    ) {
        store.record_policy_decision(policy).unwrap();
        store.record_ticket(ticket).unwrap();
        store.record_sandbox_result(result).unwrap();
        store.record_proof(proof).unwrap();
    }

    fn column_exists(conn: &Connection, table: &str, column: &str) -> bool {
        let mut stmt = conn
            .prepare(&format!("PRAGMA table_info({table})"))
            .unwrap();
        let columns = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        columns.iter().any(|existing| existing == column)
    }

    fn trigger_exists(conn: &Connection, trigger: &str) -> bool {
        conn.query_row(
            "SELECT name FROM sqlite_master WHERE type = 'trigger' AND name = ?1",
            params![trigger],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .unwrap()
        .is_some()
    }

    #[test]
    fn new_store_records_current_schema_version() {
        let store = Store::open_memory().unwrap();

        assert_eq!(store.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
    }

    #[test]
    fn rejects_newer_schema_version() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE store_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            INSERT INTO store_meta (key, value) VALUES ('schema_version', '999');
            "#,
        )
        .unwrap();
        let store = Store { conn };

        assert!(matches!(
            store.init(),
            Err(StoreError::SchemaVersionTooNew {
                found: 999,
                supported: CURRENT_SCHEMA_VERSION
            })
        ));
    }

    #[test]
    fn migrates_v1_schema_to_current() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE store_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            INSERT INTO store_meta (key, value) VALUES ('schema_version', '1');

            CREATE TABLE execution_tickets (
                ticket_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                capability_id TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                consumed_at TEXT
            );

            CREATE TABLE sandbox_results (
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

            CREATE TABLE proofs (
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

            CREATE TABLE ledger_events (
                ledger_event_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                event_hash TEXT NOT NULL,
                previous_event_hash TEXT NOT NULL,
                timestamp TEXT NOT NULL
            );

            CREATE TABLE approval_grants (
                grant_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                delta_id TEXT NOT NULL,
                policy_decision_ref TEXT NOT NULL,
                capability_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            "#,
        )
        .unwrap();
        let store = Store { conn };

        store.init().unwrap();

        assert_eq!(store.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
        assert!(column_exists(
            &store.conn,
            "execution_tickets",
            "payload_json"
        ));
        for table in ["sandbox_results", "proofs"] {
            assert!(column_exists(&store.conn, table, "executor_artifact_hash"));
            assert!(column_exists(&store.conn, table, "executor_signature_ref"));
            assert!(column_exists(
                &store.conn,
                table,
                "executor_signing_key_ref"
            ));
        }
        assert!(column_exists(
            &store.conn,
            "policy_decisions",
            "payload_json"
        ));
        assert!(column_exists(
            &store.conn,
            "capability_contracts",
            "payload_json"
        ));
        assert!(column_exists(
            &store.conn,
            "executor_manifests",
            "payload_json"
        ));
        assert!(trigger_exists(
            &store.conn,
            "capability_contracts_no_update"
        ));
        assert!(trigger_exists(&store.conn, "executor_manifests_no_update"));
        assert!(trigger_exists(&store.conn, "policy_decisions_no_update"));
        assert!(trigger_exists(&store.conn, "sandbox_results_no_update"));
        assert!(trigger_exists(&store.conn, "proofs_no_update"));
    }

    #[test]
    fn capability_contract_payload_is_persisted_and_append_only() {
        let store = Store::open_memory().unwrap();
        let capability = capability_contract();
        let capability_hash = hash_capability_contract(&capability).unwrap();

        store
            .record_capability_contract(&capability, &capability_hash)
            .unwrap();

        assert_eq!(
            store
                .capability_contract(&capability.capability_id)
                .unwrap(),
            Some(capability.clone())
        );

        let update = store.conn.execute(
            "UPDATE capability_contracts SET capability_contract_hash = 'tampered' WHERE capability_id = ?1",
            params![capability.capability_id],
        );
        assert!(update.is_err());

        let delete = store.conn.execute(
            "DELETE FROM capability_contracts WHERE capability_id = ?1",
            params![capability.capability_id],
        );
        assert!(delete.is_err());
    }

    #[test]
    fn executor_manifest_payload_is_persisted_and_append_only() {
        let store = Store::open_memory().unwrap();
        let manifest = executor_manifest();
        let manifest_hash = hash_executor_manifest(&manifest).unwrap();

        store
            .record_executor_manifest(&manifest, &manifest_hash)
            .unwrap();

        assert_eq!(
            store.executor_manifest(&manifest.executor_id).unwrap(),
            Some(manifest.clone())
        );

        let update = store.conn.execute(
            "UPDATE executor_manifests SET executor_manifest_hash = 'tampered' WHERE executor_id = ?1",
            params![manifest.executor_id],
        );
        assert!(update.is_err());

        let delete = store.conn.execute(
            "DELETE FROM executor_manifests WHERE executor_id = ?1",
            params![manifest.executor_id],
        );
        assert!(delete.is_err());
    }

    #[test]
    fn policy_decision_payload_is_persisted_and_append_only() {
        let store = Store::open_memory().unwrap();
        let policy = policy_decision();
        store.record_policy_decision(&policy).unwrap();

        assert_eq!(
            store.policy_decision(&policy.decision_id).unwrap(),
            Some(policy.clone())
        );

        let update = store.conn.execute(
            "UPDATE policy_decisions SET capability_id = 'tampered' WHERE decision_id = ?1",
            params![policy.decision_id],
        );
        assert!(update.is_err());

        let delete = store.conn.execute(
            "DELETE FROM policy_decisions WHERE decision_id = ?1",
            params![policy.decision_id],
        );
        assert!(delete.is_err());
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
    fn ledger_audit_replay_accepts_recorded_execution_chain() {
        let store = Store::open_memory().unwrap();
        let committed = record_audited_chain(&store);

        let report = store.replay_ledger_audit().unwrap();

        assert_eq!(report.ledger_events, 1);
        assert_eq!(report.successful_events, 1);
        assert_eq!(report.policy_decisions, 1);
        assert_eq!(report.approval_grants, 0);
        assert_eq!(report.capability_contracts, 1);
        assert_eq!(report.executor_manifests, 1);
        assert_eq!(report.execution_tickets, 1);
        assert_eq!(report.sandbox_results, 1);
        assert_eq!(report.proofs, 1);
        assert_eq!(report.last_event_hash, Some(committed.event_hash));
    }

    #[test]
    fn ledger_audit_replay_detects_missing_sandbox_result() {
        let store = Store::open_memory().unwrap();
        let (policy, ticket, _result, proof, event) = audited_chain();
        record_registry_facts(&store, &event);
        store.record_policy_decision(&policy).unwrap();
        store.record_ticket(&ticket).unwrap();
        store.record_proof(&proof).unwrap();
        let event = store.append_ledger_event(event).unwrap();

        assert!(matches!(
            store.replay_ledger_audit(),
            Err(StoreError::LedgerAuditMissingSandboxResult {
                ledger_event_id,
                ticket_id
            }) if ledger_event_id == event.ledger_event_id && ticket_id == ticket.ticket_id
        ));
    }

    #[test]
    fn ledger_audit_replay_detects_missing_capability_contract() {
        let store = Store::open_memory().unwrap();
        let (policy, ticket, result, proof, event) = audited_chain();
        let manifest = executor_manifest();
        store
            .record_executor_manifest(&manifest, &event.executor_manifest_hash)
            .unwrap();
        record_execution_facts(&store, &policy, &ticket, &result, &proof);
        let event = store.append_ledger_event(event).unwrap();

        assert!(matches!(
            store.replay_ledger_audit(),
            Err(StoreError::LedgerAuditMissingCapabilityContract {
                ledger_event_id,
                capability_id
            }) if ledger_event_id == event.ledger_event_id
                && capability_id == event.capability_id
        ));
    }

    #[test]
    fn ledger_audit_replay_detects_missing_executor_manifest() {
        let store = Store::open_memory().unwrap();
        let (policy, ticket, result, proof, event) = audited_chain();
        let capability = capability_contract();
        store
            .record_capability_contract(&capability, &event.capability_contract_hash)
            .unwrap();
        record_execution_facts(&store, &policy, &ticket, &result, &proof);
        let event = store.append_ledger_event(event).unwrap();

        assert!(matches!(
            store.replay_ledger_audit(),
            Err(StoreError::LedgerAuditMissingExecutorManifest {
                ledger_event_id,
                executor_id
            }) if ledger_event_id == event.ledger_event_id
                && executor_id == event.executor_ref
        ));
    }

    #[test]
    fn ledger_audit_replay_detects_capability_contract_hash_drift() {
        let store = Store::open_memory().unwrap();
        let (policy, ticket, result, proof, event) = audited_chain();
        let mut capability = capability_contract();
        capability.timeout_ms = 2_000;
        let manifest = executor_manifest();
        store
            .record_capability_contract(&capability, "ignored-column-hash")
            .unwrap();
        store
            .record_executor_manifest(&manifest, &event.executor_manifest_hash)
            .unwrap();
        record_execution_facts(&store, &policy, &ticket, &result, &proof);
        let event = store.append_ledger_event(event).unwrap();

        assert!(matches!(
            store.replay_ledger_audit(),
            Err(StoreError::LedgerAuditBindingMismatch {
                ledger_event_id,
                field: "capability.capability_contract_hash",
                ..
            }) if ledger_event_id == event.ledger_event_id
        ));
    }

    #[test]
    fn ledger_audit_replay_detects_executor_manifest_hash_drift() {
        let store = Store::open_memory().unwrap();
        let (policy, ticket, result, proof, event) = audited_chain();
        let capability = capability_contract();
        let mut manifest = executor_manifest();
        manifest.executor_version = "0.2.1".into();
        store
            .record_capability_contract(&capability, &event.capability_contract_hash)
            .unwrap();
        store
            .record_executor_manifest(&manifest, "ignored-column-hash")
            .unwrap();
        record_execution_facts(&store, &policy, &ticket, &result, &proof);
        let event = store.append_ledger_event(event).unwrap();

        assert!(matches!(
            store.replay_ledger_audit(),
            Err(StoreError::LedgerAuditBindingMismatch {
                ledger_event_id,
                field: "executor.executor_version",
                ..
            }) if ledger_event_id == event.ledger_event_id
        ));
    }

    #[test]
    fn ledger_audit_replay_detects_missing_policy_decision() {
        let store = Store::open_memory().unwrap();
        let (_policy, ticket, result, proof, event) = audited_chain();
        record_registry_facts(&store, &event);
        store.record_ticket(&ticket).unwrap();
        store.record_sandbox_result(&result).unwrap();
        store.record_proof(&proof).unwrap();
        let event = store.append_ledger_event(event).unwrap();

        assert!(matches!(
            store.replay_ledger_audit(),
            Err(StoreError::LedgerAuditMissingPolicyDecision {
                ledger_event_id,
                policy_decision_ref
            }) if ledger_event_id == event.ledger_event_id
                && policy_decision_ref == event.policy_decision_ref
        ));
    }

    #[test]
    fn ledger_audit_replay_detects_policy_decision_binding_drift() {
        let store = Store::open_memory().unwrap();
        let (mut policy, ticket, result, proof, event) = audited_chain();
        policy.capability_id = "file.write".into();
        record_registry_facts(&store, &event);
        store.record_policy_decision(&policy).unwrap();
        store.record_ticket(&ticket).unwrap();
        store.record_sandbox_result(&result).unwrap();
        store.record_proof(&proof).unwrap();
        let event = store.append_ledger_event(event).unwrap();

        assert!(matches!(
            store.replay_ledger_audit(),
            Err(StoreError::LedgerAuditBindingMismatch {
                ledger_event_id,
                field: "policy_decision.capability_id",
                ..
            }) if ledger_event_id == event.ledger_event_id
        ));
    }

    #[test]
    fn ledger_audit_replay_detects_denied_policy_decision() {
        let store = Store::open_memory().unwrap();
        let (mut policy, ticket, result, proof, event) = audited_chain();
        policy.decision = Decision::Deny;
        record_registry_facts(&store, &event);
        store.record_policy_decision(&policy).unwrap();
        store.record_ticket(&ticket).unwrap();
        store.record_sandbox_result(&result).unwrap();
        store.record_proof(&proof).unwrap();
        let event = store.append_ledger_event(event).unwrap();

        assert!(matches!(
            store.replay_ledger_audit(),
            Err(StoreError::LedgerAuditDeniedPolicyDecision {
                ledger_event_id,
                policy_decision_ref
            }) if ledger_event_id == event.ledger_event_id
                && policy_decision_ref == event.policy_decision_ref
        ));
    }

    #[test]
    fn ledger_audit_replay_requires_grant_for_approval_policy_decision() {
        let store = Store::open_memory().unwrap();
        let (mut policy, ticket, result, proof, event) = audited_chain();
        policy.decision = Decision::RequireApproval;
        record_registry_facts(&store, &event);
        store.record_policy_decision(&policy).unwrap();
        store.record_ticket(&ticket).unwrap();
        store.record_sandbox_result(&result).unwrap();
        store.record_proof(&proof).unwrap();
        let event = store.append_ledger_event(event).unwrap();

        assert!(matches!(
            store.replay_ledger_audit(),
            Err(StoreError::LedgerAuditMissingApprovalGrant {
                ledger_event_id,
                policy_decision_ref
            }) if ledger_event_id == event.ledger_event_id
                && policy_decision_ref == event.policy_decision_ref
        ));
    }

    #[test]
    fn ledger_audit_replay_accepts_grant_for_approval_policy_decision() {
        let store = Store::open_memory().unwrap();
        let (mut policy, ticket, result, proof, event) = audited_chain();
        policy.decision = Decision::RequireApproval;
        let grant = approval_grant();
        record_registry_facts(&store, &event);
        store.record_policy_decision(&policy).unwrap();
        store.record_approval_grant(&grant).unwrap();
        store.record_ticket(&ticket).unwrap();
        store.record_sandbox_result(&result).unwrap();
        store.record_proof(&proof).unwrap();
        store.append_ledger_event(event).unwrap();

        let report = store.replay_ledger_audit().unwrap();

        assert_eq!(report.policy_decisions, 1);
        assert_eq!(report.approval_grants, 1);
        assert_eq!(report.capability_contracts, 1);
        assert_eq!(report.executor_manifests, 1);
    }

    #[test]
    fn ledger_audit_replay_detects_executor_identity_drift() {
        let store = Store::open_memory().unwrap();
        let (policy, ticket, result, mut proof, event) = audited_chain();
        proof.executor_artifact_hash =
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into();
        record_registry_facts(&store, &event);
        store.record_policy_decision(&policy).unwrap();
        store.record_ticket(&ticket).unwrap();
        store.record_sandbox_result(&result).unwrap();
        store.record_proof(&proof).unwrap();
        let event = store.append_ledger_event(event).unwrap();

        assert!(matches!(
            store.replay_ledger_audit(),
            Err(StoreError::LedgerAuditBindingMismatch {
                ledger_event_id,
                field: "proof.executor_artifact_hash",
                ..
            }) if ledger_event_id == event.ledger_event_id
        ));
    }

    #[test]
    fn ledger_audit_replay_detects_proof_hash_drift() {
        let store = Store::open_memory().unwrap();
        let (policy, ticket, result, mut proof, event) = audited_chain();
        proof.hash = "tampered-proof-hash".into();
        record_registry_facts(&store, &event);
        store.record_policy_decision(&policy).unwrap();
        store.record_ticket(&ticket).unwrap();
        store.record_sandbox_result(&result).unwrap();
        store.record_proof(&proof).unwrap();
        let event = store.append_ledger_event(event).unwrap();

        assert!(matches!(
            store.replay_ledger_audit(),
            Err(StoreError::LedgerAuditProofHashMismatch {
                ledger_event_id,
                proof_id,
                ..
            }) if ledger_event_id == event.ledger_event_id && proof_id == proof.proof_id
        ));
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
