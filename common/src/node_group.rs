//! Talking to a group of nodes.
use std::sync::{Arc, Mutex};

use grpcio::{self, RpcStatus, RpcStatusCode};

use super::error::Result;
use super::futures::prelude::*;
use super::futures::retry_until_ok_or_max;

/// Group of nodes speaking the same API.
pub struct NodeGroup<T: Sync + Send, U: Sync + Send> {
    /// Active nodes and their metadata.
    nodes: Arc<Mutex<Vec<(Arc<T>, Arc<U>)>>>,
}

impl<T, U> NodeGroup<T, U>
where
    T: Sync + Send + 'static,
    U: Sync + Send + 'static,
{
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
        nodes.push((Arc::new(client), Arc::new(meta)));
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
                let method = method.clone();
                let node = node.clone();
                let meta = meta.clone();

                retry_until_ok_or_max(
                    move || match method.clone()(&node, &meta) {
                        Ok(call) => call.into_box(),
                        Err(error) => future::err(error.into()).into_box(),
                    },
                    |error| {
                        match error {
                            // If the compute node returns that it is Unavailable, we need to retry.
                            grpcio::Error::RpcFailure(RpcStatus {
                                status: RpcStatusCode::Unavailable,
                                ..
                            }) => false,
                            // Consider all other errors permanent.
                            _ => true,
                        }
                    },
                    3,
                ).map_err(|error| error.into())
                    .then(|result| Ok(result))
                    .into_box()
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
