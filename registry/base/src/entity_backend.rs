//! Registry backend interface.
use ekiden_common::bytes::B256;
use ekiden_common::futures::BoxFuture;
use ekiden_common::node::Node;

/// Registry backend implementing the Ekiden registry interface.
pub trait EntityRegistryBackend: Send + Sync {
    /// Get a node by id.
    fn get_node(&self, id: B256) -> BoxFuture<Node>;
}
