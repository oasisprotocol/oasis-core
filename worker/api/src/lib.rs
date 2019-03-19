//! Worker API.
extern crate byteorder;
extern crate bytes;
extern crate serde;
extern crate serde_cbor;
#[macro_use]
extern crate serde_derive;
extern crate log;
extern crate rustracing_jaeger;
extern crate serde_bytes;
extern crate sgx_types;
extern crate tokio_codec;
extern crate tokio_io;

extern crate ekiden_core;
extern crate ekiden_roothash_base;
extern crate ekiden_storage_base;
extern crate ekiden_tracing;
extern crate ekiden_untrusted;

use ekiden_core::{
    bytes::{B256, H256},
    enclave::api as identity_api,
    futures::prelude::*,
    rpc::client::ClientEndpoint,
    runtime::batch::CallBatch,
};
use ekiden_roothash_base::Block;

use rustracing_jaeger::span::SpanContext;

pub mod codec;
pub mod impls;
pub mod protocol;
pub mod types;

pub use self::{impls::*, protocol::Protocol};

use self::types::ComputedBatch;

/// Interface exposed by the worker.
pub trait Worker: Send + Sync {
    /// Shutdown worker.
    fn worker_shutdown(&self) -> BoxFuture<()>;

    /// Request the worker to abort runtime or RPC processing.
    fn worker_abort(&self) -> BoxFuture<()>;

    /// Get EPID group id.
    fn capabilitytee_gid(&self) -> BoxFuture<[u8; 4]>;

    /// Generate an RAK and get a quote for it.
    fn capabilitytee_rak_quote(
        &self,
        quote_type: u32,
        spid: [u8; 16],
        sig_rl: Vec<u8>,
    ) -> BoxFuture<(B256, Vec<u8>)>;

    /// Request the worker to execute an RPC call.
    fn rpc_call(&self, request: Vec<u8>) -> BoxFuture<Vec<u8>>;

    /// Request the worker to execute a runtime call batch.
    fn runtime_call_batch(
        &self,
        ctx: Option<SpanContext>,
        calls: CallBatch,
        block: Block,
    ) -> BoxFuture<ComputedBatch>;
}

/// Interface exposed by the host.
pub trait Host: Send + Sync {
    /// Request the host to relay an RPC call.
    fn rpc_call(&self, endpoint: ClientEndpoint, request: Vec<u8>) -> BoxFuture<Vec<u8>>;

    /// Request IAS SPID from host.
    fn ias_get_spid(&self) -> BoxFuture<sgx_types::sgx_spid_t>;

    /// Request IAS quote type from host.
    fn ias_get_quote_type(&self) -> BoxFuture<sgx_types::sgx_quote_sign_type_t>;

    /// Request IAS revocation list from host.
    fn ias_sigrl(&self, gid: &sgx_types::sgx_epid_group_id_t) -> BoxFuture<Vec<u8>>;

    /// Request host to generate an IAS report for given quote.
    fn ias_report(&self, quote: Vec<u8>) -> BoxFuture<identity_api::AvReport>;

    /// Request host to fetch key from storage.
    fn storage_get(&self, key: H256) -> BoxFuture<Vec<u8>>;

    /// Request host to fetch a batch of keys from storage.
    fn storage_get_batch(&self, keys: Vec<H256>) -> BoxFuture<Vec<Option<Vec<u8>>>>;
}
