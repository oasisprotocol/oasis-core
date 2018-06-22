//! Talking to a group of nodes.
use std::sync::{Arc, Mutex};

use grpcio;

use super::error::{Error, Result};
use super::futures::{future, BoxFuture, Future};

/// Group of nodes speaking the same API.
pub struct NodeGroup<T, U> {
    /// Active nodes and their metadata.
    nodes: Arc<Mutex<Vec<(T, U)>>>,
}

impl<T, U> NodeGroup<T, U> {
    /// Construct new empty node group.
    pub fn new() -> Self {
        Self {
            nodes: Arc::new(Mutex::new(vec![])),
        }
    }

    /// Remove all nodes.
    pub fn clear(&self) {
        let mut nodes = self.nodes.lock().unwrap();
        nodes.clear();
    }

    /// Add a new node.
    pub fn add_node(&self, client: T, meta: U) {
        let mut nodes = self.nodes.lock().unwrap();
        nodes.push((client, meta));
    }

    /// Call all nodes in the group that match the filter predicate.
    pub fn call_filtered<F, G, Rs>(&self, filter: F, method: G) -> BoxFuture<Vec<Result<Rs>>>
    where
        F: Fn(&T, &U) -> bool,
        G: Fn(&T, &U) -> grpcio::Result<grpcio::ClientUnaryReceiver<Rs>>
            + Clone
            + Send
            + Sync
            + 'static,
        Rs: Send + Sync + 'static,
    {
        let nodes = self.nodes.lock().unwrap();

        let calls: Vec<BoxFuture<Result<Rs>>> = nodes
            .iter()
            .filter(|&&(ref node, ref meta)| filter(&node, &meta))
            .map(|&(ref node, ref meta)| -> BoxFuture<Result<Rs>> {
                match method.clone()(&node, &meta) {
                    Ok(call) => Box::new(call.then(|result| {
                        future::ok(result.map_err(|error| Error::from(error)))
                    })),
                    Err(error) => Box::new(future::ok(Err(Error::from(error)))),
                }
            })
            .collect();

        Box::new(future::join_all(calls))
    }

    /// Call all nodes in the group.
    pub fn call_all<G, Rs>(&self, method: G) -> BoxFuture<Vec<Result<Rs>>>
    where
        G: Fn(&T, &U) -> grpcio::Result<grpcio::ClientUnaryReceiver<Rs>>
            + Clone
            + Send
            + Sync
            + 'static,
        Rs: Send + Sync + 'static,
    {
        self.call_filtered(|_, _| true, method)
    }
}
