//! Key manager client.
use std::sync::Arc;

use futures::future::BoxFuture;
use io_context::Context;

use oasis_core_runtime::consensus::beacon::EpochTime;

use crate::{
    api::KeyManagerError,
    crypto::{KeyPair, KeyPairId, Secret, SignedPublicKey},
};

/// Key manager client interface.
pub trait KeyManagerClient: Send + Sync {
    /// Clear local key cache.
    ///
    /// This will make the client re-fetch the keys from the key manager.
    fn clear_cache(&self);

    /// Get or create named long-term key pair.
    ///
    /// If the key does not yet exist, the key manager will generate one. If
    /// the key has already been cached locally, it will be retrieved from
    /// cache.
    fn get_or_create_keys(
        &self,
        ctx: Context,
        key_pair_id: KeyPairId,
        generation: u64,
    ) -> BoxFuture<Result<KeyPair, KeyManagerError>>;

    /// Get long-term public key for a key pair id.
    fn get_public_key(
        &self,
        ctx: Context,
        key_pair_id: KeyPairId,
        generation: u64,
    ) -> BoxFuture<Result<SignedPublicKey, KeyManagerError>>;

    /// Get or create named ephemeral key pair for given epoch.
    ///
    /// If the key does not yet exist, the key manager will generate one. If
    /// the key has already been cached locally, it will be retrieved from
    /// cache.
    fn get_or_create_ephemeral_keys(
        &self,
        ctx: Context,
        key_pair_id: KeyPairId,
        epoch: EpochTime,
    ) -> BoxFuture<Result<KeyPair, KeyManagerError>>;

    /// Get ephemeral public key for an epoch and a key pair id.
    fn get_public_ephemeral_key(
        &self,
        ctx: Context,
        key_pair_id: KeyPairId,
        epoch: EpochTime,
    ) -> BoxFuture<Result<SignedPublicKey, KeyManagerError>>;

    /// Get a copy of the master secret for replication.
    fn replicate_master_secret(
        &self,
        ctx: Context,
        generation: u64,
    ) -> BoxFuture<Result<Secret, KeyManagerError>>;

    /// Get a copy of the ephemeral secret for replication.
    fn replicate_ephemeral_secret(
        &self,
        ctx: Context,
        epoch: EpochTime,
    ) -> BoxFuture<Result<Secret, KeyManagerError>>;
}

impl<T: ?Sized + KeyManagerClient> KeyManagerClient for Arc<T> {
    fn clear_cache(&self) {
        KeyManagerClient::clear_cache(&**self)
    }

    fn get_or_create_keys(
        &self,
        ctx: Context,
        key_pair_id: KeyPairId,
        generation: u64,
    ) -> BoxFuture<Result<KeyPair, KeyManagerError>> {
        KeyManagerClient::get_or_create_keys(&**self, ctx, key_pair_id, generation)
    }

    fn get_public_key(
        &self,
        ctx: Context,
        key_pair_id: KeyPairId,
        generation: u64,
    ) -> BoxFuture<Result<SignedPublicKey, KeyManagerError>> {
        KeyManagerClient::get_public_key(&**self, ctx, key_pair_id, generation)
    }

    fn get_or_create_ephemeral_keys(
        &self,
        ctx: Context,
        key_pair_id: KeyPairId,
        epoch: EpochTime,
    ) -> BoxFuture<Result<KeyPair, KeyManagerError>> {
        KeyManagerClient::get_or_create_ephemeral_keys(&**self, ctx, key_pair_id, epoch)
    }

    fn get_public_ephemeral_key(
        &self,
        ctx: Context,
        key_pair_id: KeyPairId,
        epoch: EpochTime,
    ) -> BoxFuture<Result<SignedPublicKey, KeyManagerError>> {
        KeyManagerClient::get_public_ephemeral_key(&**self, ctx, key_pair_id, epoch)
    }

    fn replicate_master_secret(
        &self,
        ctx: Context,
        generation: u64,
    ) -> BoxFuture<Result<Secret, KeyManagerError>> {
        KeyManagerClient::replicate_master_secret(&**self, ctx, generation)
    }

    fn replicate_ephemeral_secret(
        &self,
        ctx: Context,
        epoch: EpochTime,
    ) -> BoxFuture<Result<Secret, KeyManagerError>> {
        KeyManagerClient::replicate_ephemeral_secret(&**self, ctx, epoch)
    }
}
