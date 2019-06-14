//! Mock key manager client which stores everything locally.
use std::{collections::HashMap, sync::Mutex};

use ekiden_client::BoxFuture;
use ekiden_keymanager_api::*;
use ekiden_runtime::common::crypto::signature::Signature;
use futures::{future, Future};
use io_context::Context;

use super::KeyManagerClient;

/// Mock key manager client which stores everything locally.
pub struct MockClient {
    keys: Mutex<HashMap<ContractId, ContractKey>>,
}

impl MockClient {
    /// Create a new mock key manager client.
    pub fn new() -> Self {
        Self {
            keys: Mutex::new(HashMap::new()),
        }
    }
}

impl KeyManagerClient for MockClient {
    fn clear_cache(&self) {}

    fn get_or_create_keys(&self, _ctx: Context, contract_id: ContractId) -> BoxFuture<ContractKey> {
        let mut keys = self.keys.lock().unwrap();
        let key = match keys.get(&contract_id) {
            Some(key) => key.clone(),
            None => {
                let key = ContractKey::generate_mock();
                keys.insert(contract_id, key.clone());
                key
            }
        };

        Box::new(future::ok(key))
    }

    fn get_public_key(
        &self,
        ctx: Context,
        contract_id: ContractId,
    ) -> BoxFuture<Option<SignedPublicKey>> {
        Box::new(self.get_or_create_keys(ctx, contract_id).map(|ck| {
            Some(SignedPublicKey {
                key: ck.input_keypair.get_pk(),
                checksum: vec![],
                signature: Signature::default(),
            })
        }))
    }

    fn replicate_master_secret(&self, _ctx: Context) -> BoxFuture<Option<MasterSecret>> {
        unimplemented!();
    }
}
