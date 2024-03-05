//! Roothash block and header.
//!
//! # Note
//!
//! This **MUST** be kept in sync with go/roothash/api/block.
//!
use crate::common::{crypto::hash::Hash, namespace::Namespace};

/// Runtime block.
///
/// # Note
///
/// This should be kept in sync with go/roothash/api/block/block.go.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct Block {
    /// Header.
    pub header: Header,
}

impl Block {
    /// Creates a new empty genesis block given a runtime id and POSIX timestamp.
    pub fn new_genesis_block(id: Namespace, timestamp: u64) -> Block {
        Block {
            header: Header {
                version: 0,
                round: 0,
                timestamp,
                header_type: HeaderType::Normal,
                namespace: id,
                previous_hash: Hash::empty_hash(),
                io_root: Hash::empty_hash(),
                state_root: Hash::empty_hash(),
                messages_hash: Hash::empty_hash(),
                in_msgs_hash: Hash::empty_hash(),
            },
        }
    }

    /// Creates a new empty block with a specific type.
    pub fn new_empty_block(child: &Block, timestamp: u64, header_type: HeaderType) -> Block {
        Block {
            header: Header {
                version: child.header.version,
                namespace: child.header.namespace,
                round: child.header.round + 1,
                timestamp,
                header_type,
                previous_hash: child.header.encoded_hash(),
                io_root: Hash::empty_hash(),
                // State root is unchanged.
                state_root: child.header.state_root,
                messages_hash: Hash::empty_hash(),
                in_msgs_hash: Hash::empty_hash(),
            },
        }
    }
}

/// Header type.
///
/// # Note
///
/// This should be kept in sync with go/roothash/api/block/header.go.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
#[repr(u8)]
pub enum HeaderType {
    #[default]
    Invalid = 0,
    Normal = 1,
    RoundFailed = 2,
    EpochTransition = 3,
    Suspended = 4,
}

/// Block header.
///
/// # Note
///
/// This should be kept in sync with go/roothash/api/block/header.go.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct Header {
    /// Protocol version number.
    pub version: u16,
    /// Chain namespace.
    pub namespace: Namespace,
    /// Round number.
    pub round: u64,
    /// Timestamp (POSIX time).
    pub timestamp: u64,
    /// Header type.
    pub header_type: HeaderType,
    /// Previous block hash.
    pub previous_hash: Hash,
    /// I/O merkle root.
    pub io_root: Hash,
    /// State merkle root.
    pub state_root: Hash,
    /// Messages hash.
    pub messages_hash: Hash,
    /// Hash of processed incoming messages.
    pub in_msgs_hash: Hash,
}

impl Header {
    /// Returns a hash of an encoded header.
    pub fn encoded_hash(&self) -> Hash {
        Hash::digest_bytes(&cbor::to_vec(self.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consistent_hash_header() {
        // NOTE: These hashes MUST be synced with go/roothash/api/block/header_test.go.
        let empty = Header::default();
        assert_eq!(
            empty.encoded_hash(),
            Hash::from("677ad1a6b9f5e99ed94e5d598b6f92a4641a5f952f2d753b2a6122b6dceeb792")
        );

        let populated = Header {
            version: 42,
            namespace: Namespace::from(Hash::empty_hash().as_ref()),
            round: 1000,
            timestamp: 1560257841,
            header_type: HeaderType::RoundFailed,
            previous_hash: empty.encoded_hash(),
            io_root: Hash::empty_hash(),
            state_root: Hash::empty_hash(),
            messages_hash: Hash::empty_hash(),
            in_msgs_hash: Hash::empty_hash(),
        };
        assert_eq!(
            populated.encoded_hash(),
            Hash::from("b17374d9b36796752a787d0726ef44826bfdb3ece52545e126c8e7592663544d")
        );
    }
}
