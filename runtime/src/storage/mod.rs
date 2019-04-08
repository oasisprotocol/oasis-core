//! Runtime storage interfaces and implementations.

pub mod cas;
pub mod context;
pub mod mkvs;

// Re-exports.
pub use self::{cas::CAS, context::StorageContext, mkvs::MKVS};
