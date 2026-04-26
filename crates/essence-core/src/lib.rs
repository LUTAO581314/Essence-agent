//! Core protocol and append-only WAL primitives for Essence Agent.
//!
//! The v0 kernel keeps the source of truth as replayable JSONL events.
//! Databases, UI streams, memory indexes, and task views are projections.

pub mod control;
pub mod policy;
pub mod projection;
pub mod protocol;
pub mod registry;
pub mod stream;
pub mod subagent;
pub mod task_store;
pub mod wal;

pub use control::*;
pub use policy::*;
pub use projection::*;
pub use protocol::*;
pub use registry::*;
pub use stream::*;
pub use subagent::*;
pub use task_store::*;
pub use wal::*;
