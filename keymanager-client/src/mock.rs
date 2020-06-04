//! Mock key manager client which stores everything locally.
use std::{collections::HashMap, sync::Mutex};

use futures::{future, Future};
use io_context::Context;
use oasis_core_client::BoxFuture;
use oasis_core_keymanager_api_common::*;
use oasis_core_runtime::common::crypto::signature::Signature;

use super::KeyManagerClient;

/// Mock key manager client which stores everything locally.
pub struct MockClient {
    keys: Mutex<HashMap<KeyPairId, KeyPair>>,
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

    fn get_or_create_keys(&self, _ctx: Context, key_pair_id: KeyPairId) -> BoxFuture<KeyPair> {
        let mut keys = self.keys.lock().unwrap();
        let key = match keys.get(&key_pair_id) {
            Some(key) => key.clone(),
            None => {
                let key = KeyPair::generate_mock();
                keys.insert(key_pair_id, key.clone());
                key
            }
        };

        Box::new(future::ok(key))
    }

    fn get_public_key(
        &self,
        ctx: Context,
        key_pair_id: KeyPairId,
    ) -> BoxFuture<Option<SignedPublicKey>> {
        Box::new(self.get_or_create_keys(ctx, key_pair_id).map(|ck| {
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
