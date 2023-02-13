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
    crypto::{KeyPair, KeyPairId, Secret, SignedPublicKey},
};

use super::KeyManagerClient;

/// Mock key manager client which stores everything locally.
#[derive(Default)]
pub struct MockClient {
    longterm_keys: Mutex<HashMap<(KeyPairId, u64), KeyPair>>,
    ephemeral_keys: Mutex<HashMap<(KeyPairId, EpochTime), KeyPair>>,
}

impl MockClient {
    /// Create a new mock key manager client.
    pub fn new() -> Self {
        Self {
            longterm_keys: Mutex::new(HashMap::new()),
            ephemeral_keys: Mutex::new(HashMap::new()),
        }
    }
}

impl KeyManagerClient for MockClient {
    fn clear_cache(&self) {}

    fn get_or_create_keys(
        &self,
        _ctx: Context,
        key_pair_id: KeyPairId,
        generation: u64,
    ) -> BoxFuture<Result<KeyPair, KeyManagerError>> {
        let mut keys = self.longterm_keys.lock().unwrap();
        let key = keys
            .entry((key_pair_id, generation))
            .or_insert_with(KeyPair::generate_mock)
            .clone();

        Box::pin(future::ok(key))
    }

    fn get_public_key(
        &self,
        ctx: Context,
        key_pair_id: KeyPairId,
        generation: u64,
    ) -> BoxFuture<Result<SignedPublicKey, KeyManagerError>> {
        Box::pin(
            self.get_or_create_keys(ctx, key_pair_id, generation)
                .and_then(|ck| {
                    future::ok(SignedPublicKey {
                        key: ck.input_keypair.pk,
                        checksum: vec![],
                        signature: Signature::default(),
                        expiration: None,
                    })
                }),
        )
    }

    fn get_or_create_ephemeral_keys(
        &self,
        _ctx: Context,
        key_pair_id: KeyPairId,
        epoch: EpochTime,
    ) -> BoxFuture<Result<KeyPair, KeyManagerError>> {
        let mut keys = self.ephemeral_keys.lock().unwrap();
        let key = keys
            .entry((key_pair_id, epoch))
            .or_insert_with(KeyPair::generate_mock)
            .clone();

        Box::pin(future::ok(key))
    }

    fn get_public_ephemeral_key(
        &self,
        ctx: Context,
        key_pair_id: KeyPairId,
        epoch: EpochTime,
    ) -> BoxFuture<Result<SignedPublicKey, KeyManagerError>> {
        Box::pin(
            self.get_or_create_ephemeral_keys(ctx, key_pair_id, epoch)
                .and_then(|ck| {
                    future::ok(SignedPublicKey {
                        key: ck.input_keypair.pk,
                        checksum: vec![],
                        signature: Signature::default(),
                        expiration: None,
                    })
                }),
        )
    }

    fn replicate_master_secret(
        &self,
        _ctx: Context,
        _generation: u64,
    ) -> BoxFuture<Result<Secret, KeyManagerError>> {
        unimplemented!();
    }

    fn replicate_ephemeral_secret(
        &self,
        _ctx: Context,
        _epoch: EpochTime,
    ) -> BoxFuture<Result<Secret, KeyManagerError>> {
        unimplemented!();
    }
}
