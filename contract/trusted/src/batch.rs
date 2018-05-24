//! Contract call batching.
use std;
#[cfg(target_env = "sgx")]
use std::sync::SgxMutex as Mutex;
#[cfg(target_env = "sgx")]
use std::sync::SgxMutexGuard as MutexGuard;
#[cfg(not(target_env = "sgx"))]
use std::sync::{Mutex, MutexGuard};

use serde_cbor;

use ekiden_common::bytes::H256;
use ekiden_common::hash::EncodedHash;
use ekiden_contract_common::batch::CallBatch;
use ekiden_contract_common::call::{Generic, SignedContractCall};

lazy_static! {
    // Global RPC dispatcher object.
    static ref BATCHER: Mutex<Batcher> = Mutex::new(Batcher::new());
}

/// Contract call batcher.
pub struct Batcher {
    /// Active batch.
    batch: CallBatch,
}

impl Batcher {
    /// Create a new batcher instance.
    pub fn new() -> Self {
        Self {
            batch: CallBatch::default(),
        }
    }

    /// Global batcher instance.
    ///
    /// Calling this method will take a lock on the global instance which
    /// will be released once the value goes out of scope.
    pub fn get<'a>() -> MutexGuard<'a, Self> {
        BATCHER.lock().unwrap()
    }

    /// Add new contract call to the current batch.
    ///
    /// Returns the call identifier of the contract call.
    pub fn add(&mut self, call: SignedContractCall<Generic>) -> H256 {
        // TODO: Actually encrypt call.
        let encrypted_call = serde_cbor::to_vec(&call).unwrap();
        let call_id = encrypted_call.get_encoded_hash();
        self.batch.push(encrypted_call);

        call_id
    }

    /// Take the current batch, leaving an empty batch in its place.
    pub fn take(&mut self) -> CallBatch {
        std::mem::replace(&mut self.batch, CallBatch::default())
    }
}
