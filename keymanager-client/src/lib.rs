//! Key manager client.
extern crate ekiden_client;
extern crate ekiden_keymanager_api;
extern crate ekiden_runtime;
extern crate failure;
extern crate futures;
#[cfg(not(target_env = "sgx"))]
extern crate grpcio;
extern crate io_context;
extern crate lru;

pub mod client;
pub mod mock;

use std::sync::Arc;

use self::{ekiden_client::BoxFuture, io_context::Context};

/// Key manager client interface.
pub trait KeyManagerClient: Send + Sync {
    /// Clear local key cache.
    ///
    /// This will make the client re-fetch the keys from the key manager.
    fn clear_cache(&self);

    /// Get or create named key.
    ///
    /// If the key does not yet exist, the key manager will generate one. If
    /// the key has already been cached locally, it will be retrieved from
    /// cache.
    fn get_or_create_keys(&self, ctx: Context, contract_id: ContractId) -> BoxFuture<ContractKey>;

    /// Get public key for a contract.
    fn get_public_key(
        &self,
        ctx: Context,
        contract_id: ContractId,
    ) -> BoxFuture<Option<SignedPublicKey>>;

    /// Get long-term public key for a contract.
    fn get_long_term_public_key(
        &self,
        ctx: Context,
        contract_id: ContractId,
    ) -> BoxFuture<Option<SignedPublicKey>>;

    /// Get a copy of the master secret for replication.
    fn replicate_master_secret(&self, ctx: Context) -> BoxFuture<Option<MasterSecret>>;
}

impl<T: ?Sized + KeyManagerClient> KeyManagerClient for Arc<T> {
    fn clear_cache(&self) {
        KeyManagerClient::clear_cache(&**self)
    }

    fn get_or_create_keys(&self, ctx: Context, contract_id: ContractId) -> BoxFuture<ContractKey> {
        KeyManagerClient::get_or_create_keys(&**self, ctx, contract_id)
    }

    fn get_public_key(
        &self,
        ctx: Context,
        contract_id: ContractId,
    ) -> BoxFuture<Option<SignedPublicKey>> {
        KeyManagerClient::get_public_key(&**self, ctx, contract_id)
    }

    fn get_long_term_public_key(
        &self,
        ctx: Context,
        contract_id: ContractId,
    ) -> BoxFuture<Option<SignedPublicKey>> {
        KeyManagerClient::get_long_term_public_key(&**self, ctx, contract_id)
    }

    fn replicate_master_secret(&self, ctx: Context) -> BoxFuture<Option<MasterSecret>> {
        KeyManagerClient::replicate_master_secret(&**self, ctx)
    }
}

// Re-exports.
pub use self::{client::RemoteClient, ekiden_keymanager_api::*};
