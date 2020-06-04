//! Key manager client.

pub mod client;
pub mod mock;

use std::sync::Arc;

use io_context::Context;
use oasis_core_client::BoxFuture;
use oasis_core_keymanager_api_common;

/// Key manager client interface.
pub trait KeyManagerClient: Send + Sync {
    /// Clear local key cache.
    ///
    /// This will make the client re-fetch the keys from the key manager.
    fn clear_cache(&self);

    /// Get or create named key pair.
    ///
    /// If the key does not yet exist, the key manager will generate one. If
    /// the key has already been cached locally, it will be retrieved from
    /// cache.
    fn get_or_create_keys(&self, ctx: Context, key_pair_id: KeyPairId) -> BoxFuture<KeyPair>;

    /// Get public key for a key pair id.
    fn get_public_key(
        &self,
        ctx: Context,
        key_pair_id: KeyPairId,
    ) -> BoxFuture<Option<SignedPublicKey>>;

    /// Get a copy of the master secret for replication.
    fn replicate_master_secret(&self, ctx: Context) -> BoxFuture<Option<MasterSecret>>;
}

impl<T: ?Sized + KeyManagerClient> KeyManagerClient for Arc<T> {
    fn clear_cache(&self) {
        KeyManagerClient::clear_cache(&**self)
    }

    fn get_or_create_keys(&self, ctx: Context, key_pair_id: KeyPairId) -> BoxFuture<KeyPair> {
        KeyManagerClient::get_or_create_keys(&**self, ctx, key_pair_id)
    }

    fn get_public_key(
        &self,
        ctx: Context,
        key_pair_id: KeyPairId,
    ) -> BoxFuture<Option<SignedPublicKey>> {
        KeyManagerClient::get_public_key(&**self, ctx, key_pair_id)
    }

    fn replicate_master_secret(&self, ctx: Context) -> BoxFuture<Option<MasterSecret>> {
        KeyManagerClient::replicate_master_secret(&**self, ctx)
    }
}

// Re-exports.
pub use self::{client::RemoteClient, oasis_core_keymanager_api_common::*};
