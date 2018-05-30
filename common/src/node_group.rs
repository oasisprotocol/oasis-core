//! Talking to a group of nodes.
use std::sync::{Arc, Mutex};

use grpcio;

use super::error::{Error, Result};
use super::futures::{future, BoxFuture, Future};

/// Group of nodes speaking the same API.
pub struct NodeGroup<T> {
    /// Active nodes.
    nodes: Arc<Mutex<Vec<T>>>,
}

impl<T> NodeGroup<T> {
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
    pub fn add_node(&self, client: T) {
        let mut nodes = self.nodes.lock().unwrap();
        nodes.push(client);
    }

    /// Call all nodes in the group.
    pub fn call_all<F, Rs>(&self, method: F) -> BoxFuture<Vec<Result<Rs>>>
    where
        F: Fn(&T) -> grpcio::Result<grpcio::ClientUnaryReceiver<Rs>>
            + Clone
            + Send
            + Sync
            + 'static,
        Rs: Send + Sync + 'static,
    {
        let nodes = self.nodes.lock().unwrap();

        let calls: Vec<BoxFuture<Result<Rs>>> = nodes
            .iter()
            .map(|node| -> BoxFuture<Result<Rs>> {
                match method.clone()(node) {
                    Ok(call) => Box::new(call.then(|result| {
                        future::ok(result.map_err(|error| Error::from(error)))
                    })),
                    Err(error) => Box::new(future::ok(Err(Error::from(error)))),
                }
            })
            .collect();

        Box::new(future::join_all(calls))
    }
}
