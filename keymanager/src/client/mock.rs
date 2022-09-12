//! Mock key manager client which stores everything locally.
use std::{collections::HashMap, sync::Mutex};

use futures::{
    future::{self, BoxFuture},
    TryFutureExt,
};
use io_context::Context;

use oasis_core_runtime::{common::crypto::signature::Signature, consensus::beacon::EpochTime};

use crate::{
    api::KeyManagerError,
    crypto::{KeyPair, KeyPairId, MasterSecret, SignedPublicKey},
};

use super::KeyManagerClient;

/// Mock key manager client which stores everything locally.
#[derive(Default)]
pub struct MockClient {
    keys: Mutex<HashMap<(KeyPairId, Option<EpochTime>), KeyPair>>,
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

    fn get_or_create_keys(
        &self,
        _ctx: Context,
        key_pair_id: KeyPairId,
    ) -> BoxFuture<Result<KeyPair, KeyManagerError>> {
        let mut keys = self.keys.lock().unwrap();
        let key = keys
            .entry((key_pair_id, None))
            .or_insert_with(KeyPair::generate_mock)
            .clone();

        Box::pin(future::ok(key))
    }

    fn get_public_key(
        &self,
        ctx: Context,
        key_pair_id: KeyPairId,
    ) -> BoxFuture<Result<Option<SignedPublicKey>, KeyManagerError>> {
        Box::pin(self.get_or_create_keys(ctx, key_pair_id).and_then(|ck| {
            future::ok(Some(SignedPublicKey {
                key: ck.input_keypair.pk,
                checksum: vec![],
                signature: Signature::default(),
            }))
        }))
    }

    fn get_or_create_ephemeral_keys(
        &self,
        _ctx: Context,
        key_pair_id: KeyPairId,
        epoch: EpochTime,
    ) -> BoxFuture<Result<KeyPair, KeyManagerError>> {
        let mut keys = self.keys.lock().unwrap();
        let key = keys
            .entry((key_pair_id, Some(epoch)))
            .or_insert_with(KeyPair::generate_mock)
            .clone();

        Box::pin(future::ok(key))
    }

    fn get_public_ephemeral_key(
        &self,
        ctx: Context,
        key_pair_id: KeyPairId,
        epoch: EpochTime,
    ) -> BoxFuture<Result<Option<SignedPublicKey>, KeyManagerError>> {
        Box::pin(
            self.get_or_create_ephemeral_keys(ctx, key_pair_id, epoch)
                .and_then(|ck| {
                    future::ok(Some(SignedPublicKey {
                        key: ck.input_keypair.pk,
                        checksum: vec![],
                        signature: Signature::default(),
                    }))
                }),
        )
    }

    fn replicate_master_secret(
        &self,
        _ctx: Context,
    ) -> BoxFuture<Result<Option<MasterSecret>, KeyManagerError>> {
        unimplemented!();
    }
}
