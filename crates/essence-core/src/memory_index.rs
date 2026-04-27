use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::memory_store::MemoryStore;
use crate::protocol::{MemoryId, MemoryRecord};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MemorySearchHit {
    pub memory: MemoryRecord,
    pub score: f32,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct MemoryIndex {
    vectors: BTreeMap<MemoryId, BTreeMap<String, f32>>,
    memories: BTreeMap<MemoryId, MemoryRecord>,
}

impl MemoryIndex {
    pub fn from_store(store: &MemoryStore) -> Self {
        let mut index = Self::default();
        for memory in store.saved() {
            index.insert(memory.clone());
        }
        index
    }

    pub fn insert(&mut self, memory: MemoryRecord) {
        self.vectors
            .insert(memory.memory_id.clone(), text_vector(&memory.text));
        self.memories.insert(memory.memory_id.clone(), memory);
    }

    pub fn len(&self) -> usize {
        self.memories.len()
    }

    pub fn is_empty(&self) -> bool {
        self.memories.is_empty()
    }

    pub fn search(&self, query: &str, limit: usize) -> Vec<MemorySearchHit> {
        let query = text_vector(query);
        let mut hits = self
            .vectors
            .iter()
            .filter_map(|(memory_id, vector)| {
                let score = cosine_similarity(&query, vector);
                (score > 0.0).then(|| MemorySearchHit {
                    memory: self
                        .memories
                        .get(memory_id)
                        .cloned()
                        .expect("indexed memory"),
                    score,
                })
            })
            .collect::<Vec<_>>();
        hits.sort_by(|left, right| {
            right
                .score
                .partial_cmp(&left.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| left.memory.memory_id.cmp(&right.memory.memory_id))
        });
        hits.truncate(limit);
        hits
    }
}

fn text_vector(text: &str) -> BTreeMap<String, f32> {
    let mut vector = BTreeMap::new();
    for token in tokenize(text) {
        *vector.entry(token).or_insert(0.0) += 1.0;
    }
    vector
}

fn tokenize(text: &str) -> impl Iterator<Item = String> + '_ {
    text.split(|ch: char| !ch.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(|token| token.to_lowercase())
}

fn cosine_similarity(left: &BTreeMap<String, f32>, right: &BTreeMap<String, f32>) -> f32 {
    if left.is_empty() || right.is_empty() {
        return 0.0;
    }

    let terms = left
        .keys()
        .chain(right.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let dot = terms
        .iter()
        .map(|term| left.get(term).unwrap_or(&0.0) * right.get(term).unwrap_or(&0.0))
        .sum::<f32>();
    let left_norm = left.values().map(|value| value * value).sum::<f32>().sqrt();
    let right_norm = right
        .values()
        .map(|value| value * value)
        .sum::<f32>()
        .sqrt();
    dot / (left_norm * right_norm)
}

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;
    use uuid::Uuid;

    use crate::memory_index::MemoryIndex;
    use crate::memory_store::MemoryStore;
    use crate::projection::LedgerProjection;
    use crate::protocol::{LifecycleStatus, MemoryId, MemoryRecord, SessionId};

    #[test]
    fn indexes_saved_memories_by_term_vector_similarity() {
        let session_id = SessionId(Uuid::new_v4());
        let first_id = MemoryId(Uuid::new_v4());
        let second_id = MemoryId(Uuid::new_v4());
        let mut projection = LedgerProjection::default();
        projection.memories.insert(
            first_id.clone(),
            memory(
                first_id,
                session_id.clone(),
                "Use JSONL as the durable ledger.",
            ),
        );
        projection.memories.insert(
            second_id,
            memory(
                MemoryId(Uuid::new_v4()),
                session_id,
                "Browser sessions need isolated tabs.",
            ),
        );
        let store = MemoryStore::from_projection(&projection);

        let index = MemoryIndex::from_store(&store);
        let hits = index.search("durable jsonl ledger", 1);

        assert_eq!(index.len(), 2);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].memory.text.contains("JSONL"));
        assert!(hits[0].score > 0.0);
    }

    fn memory(memory_id: MemoryId, session_id: SessionId, text: impl Into<String>) -> MemoryRecord {
        let now = OffsetDateTime::now_utc();
        MemoryRecord {
            memory_id,
            session_id,
            kind: "note".to_string(),
            text: text.into(),
            status: LifecycleStatus::Completed,
            created_at: now,
            updated_at: now,
            source_event_ids: Vec::new(),
            run_id: None,
            confidence: None,
            metadata: Default::default(),
        }
    }
}
