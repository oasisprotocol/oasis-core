//! Test runtime types.
use std::io::Cursor;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use oasis_core_runtime::{
    common::key_format::KeyFormat,
    consensus::{registry, staking},
};

/// Test transaction call.
#[derive(Clone, Debug, cbor::Encode, cbor::Decode)]
#[cbor(no_default)]
pub struct Call {
    /// Nonce.
    pub nonce: u64,
    /// Method name.
    pub method: String,
    /// Method arguments.
    pub args: cbor::Value,
}

/// Test transaction call output.
#[derive(Clone, Debug, cbor::Encode, cbor::Decode)]
pub enum CallOutput {
    /// Call invoked successfully.
    Success(cbor::Value),
    /// Call raised an error.
    Error(String),
}

/// Get key-value pair call.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct Get {
    pub key: String,
    pub generation: u64,
    pub churp_id: u8,
}

/// Remove key-value pair call.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct Remove {
    pub key: String,
    pub generation: u64,
    pub churp_id: u8,
}

/// Insert key-value pair call.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct Insert {
    pub key: String,
    pub value: String,
    pub generation: u64,
    pub churp_id: u8,
}

/// Encrypt plaintext call.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct Encrypt {
    pub epoch: u64,
    pub key_pair_id: String,
    pub plaintext: Vec<u8>,
}

/// Decrypt plaintext call.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct Decrypt {
    pub epoch: u64,
    pub key_pair_id: String,
    pub ciphertext: Vec<u8>,
}

/// Withdraw call.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct Withdraw {
    pub withdraw: staking::Withdraw,
}

/// Transfer call.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct Transfer {
    pub transfer: staking::Transfer,
}

/// Add escrow call.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct AddEscrow {
    pub escrow: staking::Escrow,
}

/// Reclaim escrow call.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct ReclaimEscrow {
    pub reclaim_escrow: staking::ReclaimEscrow,
}

/// Update runtime call.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct UpdateRuntime {
    pub update_runtime: registry::Runtime,
}

/// Key format used for transaction artifacts.
#[derive(Debug)]
pub struct PendingMessagesKeyFormat {
    pub index: u32,
}

impl KeyFormat for PendingMessagesKeyFormat {
    fn prefix() -> u8 {
        0x00
    }

    fn size() -> usize {
        4
    }

    fn encode_atoms(self, atoms: &mut Vec<Vec<u8>>) {
        let mut index: Vec<u8> = Vec::with_capacity(4);
        index.write_u32::<BigEndian>(self.index).unwrap();
        atoms.push(index);
    }

    fn decode_atoms(data: &[u8]) -> Self {
        let mut reader = Cursor::new(data);
        Self {
            index: reader.read_u32::<BigEndian>().unwrap(),
        }
    }
}

/// Key format used for transaction nonces.
#[derive(Debug)]
pub struct NonceKeyFormat {
    pub nonce: u64,
}

impl KeyFormat for NonceKeyFormat {
    fn prefix() -> u8 {
        0xFF
    }

    fn size() -> usize {
        8
    }

    fn encode_atoms(self, atoms: &mut Vec<Vec<u8>>) {
        let mut nonce: Vec<u8> = Vec::with_capacity(8);
        nonce.write_u64::<BigEndian>(self.nonce).unwrap();
        atoms.push(nonce);
    }

    fn decode_atoms(data: &[u8]) -> Self {
        let mut reader = Cursor::new(data);
        Self {
            nonce: reader.read_u64::<BigEndian>().unwrap(),
        }
    }
}
