use std::collections::BTreeMap;

use crate::projection::LedgerProjection;
use crate::protocol::{LifecycleStatus, MemoryId, MemoryRecord};

#[derive(Debug, Clone, Default, PartialEq)]
pub struct MemoryStore {
    memories: BTreeMap<MemoryId, MemoryRecord>,
}

impl MemoryStore {
    pub fn from_projection(projection: &LedgerProjection) -> Self {
        Self {
            memories: projection.memories.clone(),
        }
    }

    pub fn len(&self) -> usize {
        self.memories.len()
    }

    pub fn is_empty(&self) -> bool {
        self.memories.is_empty()
    }

    pub fn get(&self, memory_id: &MemoryId) -> Option<&MemoryRecord> {
        self.memories.get(memory_id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &MemoryRecord> {
        self.memories.values()
    }

    pub fn saved(&self) -> impl Iterator<Item = &MemoryRecord> {
        self.memories
            .values()
            .filter(|memory| memory.status == LifecycleStatus::Completed)
    }

    pub fn by_kind<'a>(&'a self, kind: &'a str) -> impl Iterator<Item = &'a MemoryRecord> {
        self.saved().filter(move |memory| memory.kind == kind)
    }

    pub fn search_text<'a>(&'a self, query: &'a str) -> impl Iterator<Item = &'a MemoryRecord> {
        let query = query.to_lowercase();
        self.saved()
            .filter(move |memory| memory.text.to_lowercase().contains(&query))
    }
}

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;
    use uuid::Uuid;

    use crate::memory_store::MemoryStore;
    use crate::projection::LedgerProjection;
    use crate::protocol::{LifecycleStatus, MemoryId, MemoryRecord, SessionId};

    #[test]
    fn queries_saved_memories_by_kind_and_text() {
        let session_id = SessionId(Uuid::new_v4());
        let decision_id = MemoryId(Uuid::new_v4());
        let mut projection = LedgerProjection::default();
        projection.memories.insert(
            decision_id.clone(),
            memory(
                decision_id.clone(),
                session_id.clone(),
                "decision",
                "JSONL is the canonical source of truth.",
                LifecycleStatus::Completed,
            ),
        );
        projection.memories.insert(
            MemoryId(Uuid::new_v4()),
            memory(
                MemoryId(Uuid::new_v4()),
                session_id,
                "note",
                "Queued candidate",
                LifecycleStatus::Queued,
            ),
        );

        let store = MemoryStore::from_projection(&projection);

        assert_eq!(store.len(), 2);
        assert_eq!(store.saved().count(), 1);
        assert_eq!(store.by_kind("decision").count(), 1);
        assert_eq!(store.search_text("canonical").count(), 1);
        assert_eq!(store.get(&decision_id).unwrap().kind, "decision");
    }

    fn memory(
        memory_id: MemoryId,
        session_id: SessionId,
        kind: impl Into<String>,
        text: impl Into<String>,
        status: LifecycleStatus,
    ) -> MemoryRecord {
        let now = OffsetDateTime::now_utc();
        MemoryRecord {
            memory_id,
            session_id,
            kind: kind.into(),
            text: text.into(),
            status,
            created_at: now,
            updated_at: now,
            source_event_ids: Vec::new(),
            run_id: None,
            confidence: None,
            metadata: Default::default(),
        }
    }
}
