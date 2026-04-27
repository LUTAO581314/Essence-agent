//! Core protocol and append-only WAL primitives for Essence Agent.
//!
//! The v0 kernel keeps the source of truth as replayable JSONL events.
//! Databases, UI streams, memory indexes, and task views are projections.

pub mod approval_index;
pub mod control;
pub mod gitnexus;
pub mod harness;
pub mod model_loop;
pub mod plugin;
pub mod policy;
pub mod projection;
pub mod protocol;
pub mod registry;
pub mod scheduler;
pub mod snapshot;
pub mod stream;
pub mod subagent;
pub mod task_store;
pub mod wal;

pub use approval_index::*;
pub use control::*;
pub use gitnexus::*;
pub use harness::*;
pub use model_loop::*;
pub use plugin::*;
pub use policy::*;
pub use projection::*;
pub use protocol::*;
pub use registry::*;
pub use scheduler::*;
pub use snapshot::*;
pub use stream::*;
pub use subagent::*;
pub use task_store::*;
pub use wal::*;
