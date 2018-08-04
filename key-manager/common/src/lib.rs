extern crate ekiden_common;
extern crate sodalite;

extern crate serde;
#[macro_use]
extern crate serde_derive;

use ekiden_common::bytes::H256;
use sodalite::*;

/// 256-bit ContractId
pub type ContractId = H256;
/// Type of public input key
pub type PublicKeyType = BoxPublicKey;
/// Type of private input key
pub type PrivateKeyType = BoxSecretKey;
/// Type of state encryption key
pub type StateKeyType = SecretboxKey;

/// Default value of a private input key
pub const EMPTY_PRIVATE_KEY: PrivateKeyType = [0; 32];
/// Default value of a public input key
pub const EMPTY_PUBLIC_KEY: PublicKeyType = [0; 32];
/// Default value of a state encryption key
pub const EMPTY_STATE_KEY: StateKeyType = [0; 32];

/// Keys for a contract
#[derive(Clone, Serialize, Deserialize)]
pub struct ContractKey {
    /// Input key pair (pk, sk)
    pub input_keypair: InputKeyPair,
    /// State encryption key
    pub state_key: StateKeyType,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct InputKeyPair {
    /// Pk
    pk: PublicKeyType,
    /// sk
    sk: PrivateKeyType,
}

impl InputKeyPair {
    pub fn new(pk: PublicKeyType, sk: PrivateKeyType) -> Self {
        Self { pk, sk }
    }

    pub fn get_pk(&self) -> PublicKeyType {
        self.pk
    }

    pub fn get_sk(&self) -> PrivateKeyType {
        self.sk
    }
}

impl ContractKey {
    /// Create a set of `ContractKey`.
    pub fn new(pk: PublicKeyType, sk: PrivateKeyType, k: StateKeyType) -> Self {
        Self {
            input_keypair: InputKeyPair { pk, sk },
            state_key: k,
        }
    }
    /// Create a set of `ContractKey` with only the public key.
    pub fn from_public_key(k: PublicKeyType) -> Self {
        Self {
            input_keypair: InputKeyPair {
                pk: k,
                sk: EMPTY_PRIVATE_KEY,
            },
            state_key: EMPTY_STATE_KEY,
        }
    }
}
