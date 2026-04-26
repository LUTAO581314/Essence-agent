//! Core protocol and append-only WAL primitives for Essence Agent.
//!
//! The v0 kernel keeps the source of truth as replayable JSONL events.
//! Databases, UI streams, memory indexes, and task views are projections.

pub mod protocol;
pub mod projection;
pub mod wal;

pub use protocol::*;
pub use projection::*;
pub use wal::*;
