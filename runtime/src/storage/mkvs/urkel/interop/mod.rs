//! Urkel interoperability test helpers.
use crate::{
    common::{crypto::hash::Hash, roothash::Namespace},
    storage::mkvs::WriteLog,
};

mod protocol_server;
mod rpc;

/// Urkel interoperability driver.
pub trait Driver {
    /// Apply the given write log to the protocol server.
    fn apply(&self, write_log: &WriteLog, hash: Hash, namespace: Namespace, round: u64);
}

pub use self::protocol_server::ProtocolServer;
