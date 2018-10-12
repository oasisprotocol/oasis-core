//! Registry backend interface.
use ekiden_common::bytes::{B256, B64};
use ekiden_common::futures::{BoxFuture, BoxStream};
use ekiden_common::runtime::Runtime;
use ekiden_common::signature::Signed;

/// Signature context used for runtime registration.
pub const REGISTER_RUNTIME_SIGNATURE_CONTEXT: B64 = B64(*b"EkRunReg");

/// Registry backend implementing the Ekiden runtime registry.
pub trait RuntimeRegistryBackend: Send + Sync {
    // Register a runtime in the registry.
    // TODO: who is the runtime signed by? currently itself.
    fn register_runtime(&self, runtime: Signed<Runtime>) -> BoxFuture<()>;

    // Get a runtime and associated data from the registry.
    fn get_runtime(&self, id: B256) -> BoxFuture<Runtime>;

    // Subscribe to updates of newly registered runtimes in the registry.
    // Upon subscription, all runtimes will be sent immediately.
    fn get_runtimes(&self) -> BoxStream<Runtime>;
}
