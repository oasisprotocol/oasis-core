//! Registry backend interface.
use ekiden_common::bytes::{B256, B64};
use ekiden_common::entity::Entity;
use ekiden_common::epochtime::EpochTime;
use ekiden_common::futures::{BoxFuture, BoxStream, Executor};
use ekiden_common::node::Node;
use ekiden_common::signature::Signed;

/// Signature context used for entity registration
pub const REGISTER_ENTITY_SIGNATURE_CONTEXT: B64 = B64(*b"EkEntReg");

/// Signature context used for entity deregistration
pub const DEREGISTER_ENTITY_SIGNATURE_CONTEXT: B64 = B64(*b"EkEDeReg");

/// Signature context used for entity registration
pub const REGISTER_NODE_SIGNATURE_CONTEXT: B64 = B64(*b"EkNodReg");

/// Event subscription to registration and deregistration of entities and nodes.
#[derive(Clone, Copy)]
pub enum RegistryEvent<T> {
    Registered(T),
    Deregistered(T),
}

/// Registry backend implementing the Ekiden registry interface.
pub trait EntityRegistryBackend: Send + Sync {
    /// Start the async event source associated with the beacon;
    fn start(&self, executor: &mut Executor);

    /// Register and or update an entity with the registry.
    ///
    /// The signature should be made using `REGISTER_ENTITY_SIGNATURE_CONTEXT`
    fn register_entity(&self, entity: Signed<Entity>) -> BoxFuture<()>;

    /// Deregister an entity.
    ///
    /// The signature should be made using `DEREGISTER_ENTITY_SIGNATURE_CONTEXT`
    fn deregister_entity(&self, id: Signed<B256>) -> BoxFuture<()>;

    /// Get an entity by id.
    fn get_entity(&self, id: B256) -> BoxFuture<Entity>;

    /// Get a list of all registered entities.
    fn get_entities(&self) -> BoxFuture<Vec<Entity>>;

    /// Watch for changes in entity registration.
    fn watch_entities(&self) -> BoxStream<RegistryEvent<Entity>>;

    /// Register and or update a node with the registry.
    ///
    /// The signature should be made using `REGISTER_NODE_SIGNATURE_CONTEXT`
    fn register_node(&self, node: Signed<Node>) -> BoxFuture<()>;

    /// Get a node by id.
    fn get_node(&self, id: B256) -> BoxFuture<Node>;

    /// Get a list of all registered nodes.
    fn get_nodes(&self, epoch: EpochTime) -> BoxFuture<Vec<Node>>;

    /// Get a list of nodes registered to an entity id.
    fn get_nodes_for_entity(&self, id: B256) -> BoxFuture<Vec<Node>>;

    /// Watch for changes in node registration.
    fn watch_nodes(&self) -> BoxStream<RegistryEvent<Node>>;

    /// Watch for the per-epoch stable node lists.  Upon subscription, the
    /// node list for the current epoch will be sent immediately if available.
    ///
    /// Each node list will be sorted by node ID in lexographically ascending
    /// order.
    fn watch_node_list(&self) -> BoxStream<(EpochTime, Vec<Node>)>;
}
