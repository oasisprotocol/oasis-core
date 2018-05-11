//! Registry backend interface.
use ekiden_common::bytes::{B256, B64};
use ekiden_common::contract::Contract;
use ekiden_common::futures::{BoxFuture, BoxStream};
use ekiden_common::signature::Signed;

/// Signature context used for entity registration
pub const REGISTER_CONTRACT_SIGNATURE_CONTEXT: B64 = B64(*b"EkConReg");

/// Registry backend implementing the Ekiden contract registry.
pub trait ContractRegistryBackend: Send + Sync {
    // Register a contract in the registry.
    // TODO: who is the contract signed by? currently itself.
    fn register_contract(&self, contract: Signed<Contract>) -> BoxFuture<()>;

    // Get a contract and associated data from the registry.
    fn get_contract(&self, id: B256) -> BoxFuture<Contract>;

    // Subscribe to updates of newly registered contracts in the registry.
    // Upon subscription, all contracts will be sent immediately.
    fn get_contracts(&self) -> BoxStream<Contract>;
}
