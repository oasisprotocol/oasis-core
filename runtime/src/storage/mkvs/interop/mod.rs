//! MKVS interoperability test helpers.
use crate::{
    common::{crypto::hash::Hash, namespace::Namespace},
    storage::mkvs::WriteLog,
};

mod protocol_server;
mod rpc;

/// MKVS interoperability driver.
pub trait Driver {
    /// Apply the given write log to the protocol server.
    fn apply(&self, write_log: &WriteLog, hash: Hash, namespace: Namespace, version: u64);

    /// Apply the given write log against an existing root on the protocol server.
    fn apply_existing(
        &self,
        write_log: &WriteLog,
        existing_root: Hash,
        root_hash: Hash,
        namespace: Namespace,
        version: u64,
    );
}

pub use self::protocol_server::{Fixture, ProtocolServer};
