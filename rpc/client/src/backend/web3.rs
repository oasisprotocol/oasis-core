//! gRPC client backend.
use std::sync::{Arc, Mutex};

use grpc;
use tokio_core;

use futures::future::{self, Future};

use protobuf;
use protobuf::Message;

use ekiden_common::error::{Error, Result};
use ekiden_rpc_common::api;

use ekiden_compute_api::{CallContractRequest, Compute, ComputeClient};

use super::{ContractClientBackend, ContractClientCredentials};
use super::super::future::ClientFuture;

/// Address of a compute node.
pub struct ComputeNodeAddress {
    /// Compute node hostname.
    pub host: String,
    /// Compute node port.
    pub port: u16,
}

struct ComputeNode {
    /// gRPC client for the given node.
    client: ComputeClient,
    /// Failed flag.
    failed: bool,
}

#[derive(Default)]
struct ComputeNodes {
    /// Active nodes.
    nodes: Arc<Mutex<Vec<ComputeNode>>>,
}

impl ComputeNodes {
    /// Construct new pool of compute nodes.
    fn new(nodes: &[ComputeNodeAddress]) -> Result<Self> {
        let instance = ComputeNodes::default();

        for node in nodes {
            instance.add_node(node)?;
        }

        Ok(instance)
    }

    /// Add a new compute node.
    fn add_node(&self, address: &ComputeNodeAddress) -> Result<()> {
        // TODO: Pass specific reactor to the compute client as otherwise it will spawn a new thread.
        let client = match ComputeClient::new_plain(&address.host, address.port, Default::default())
        {
            Ok(client) => client,
            _ => return Err(Error::new("Failed to initialize gRPC client")),
        };

        let mut nodes = self.nodes.lock().unwrap();
        nodes.push(ComputeNode {
            client,
            failed: false,
        });

        Ok(())
    }

    /// Call the first available compute node.
    fn call_available_node(
        &self,
        client_request: Vec<u8>,
        max_retries: usize,
    ) -> ClientFuture<Vec<u8>> {
        let mut rpc_request = CallContractRequest::new();
        rpc_request.set_payload(client_request);

        let shared_nodes = self.nodes.clone();

        let try_times = future::loop_fn(
            max_retries,
            move |retries| -> ClientFuture<future::Loop<Vec<u8>, usize>> {
                // Abort when we have reached the given number of retries.
                if retries == 0 {
                    return Box::new(future::err(Error::new(
                        "No active compute nodes are available",
                    )));
                }

                let cloned_nodes = shared_nodes.clone();
                let rpc_request = rpc_request.clone();

                // Try to find an active node on each iteration.
                let try_node = future::loop_fn(
                    (),
                    move |_| -> ClientFuture<future::Loop<Vec<u8>, ()>> {
                        let nodes = cloned_nodes.lock().unwrap();

                        // Find the first non-failed node and use it to send a request.
                        match nodes.iter().enumerate().find(|&(_, node)| !node.failed) {
                            Some((index, ref node)) => {
                                // Found a non-failed node.
                                let cloned_nodes = cloned_nodes.clone();

                                return Box::new(
                                    node.client
                                        .call_contract(
                                            grpc::RequestOptions::new(),
                                            rpc_request.clone(),
                                        )
                                        .drop_metadata()
                                        .then(move |result| {
                                            match result {
                                                Ok(mut response) => {
                                                    Ok(future::Loop::Break(response.take_payload()))
                                                }
                                                Err(_) => {
                                                    let mut nodes = cloned_nodes.lock().unwrap();
                                                    // Since we never remove or reorder nodes, we can be sure that this
                                                    // index always belongs to the specified node and we can avoid sharing
                                                    // and locking individual node instances.
                                                    nodes[index].failed = true;

                                                    Ok(future::Loop::Continue(()))
                                                }
                                            }
                                        }),
                                );
                            }
                            None => {}
                        }

                        Box::new(future::err(Error::new(
                            "No active compute nodes are available on this retry",
                        )))
                    },
                );

                let cloned_nodes = shared_nodes.clone();

                Box::new(try_node.then(move |result| match result {
                    Ok(response) => Ok(future::Loop::Break(response)),
                    Err(_) => {
                        let mut nodes = cloned_nodes.lock().unwrap();

                        // All nodes seem to be failed. Reset failed status for next retry.
                        for node in nodes.iter_mut() {
                            node.failed = false;
                        }

                        Ok(future::Loop::Continue(retries - 1))
                    }
                }))
            },
        );

        Box::new(try_times)
    }
}

/// gRPC client backend.
pub struct Web3ContractClientBackend {
    /// Handle of the reactor used for running all futures.
    reactor: tokio_core::reactor::Remote,
    /// Pool of compute nodes that the client can use.
    nodes: ComputeNodes,
}

impl Web3ContractClientBackend {
    /// Construct new Web3 contract client backend.
    pub fn new(reactor: tokio_core::reactor::Remote, host: &str, port: u16) -> Result<Self> {
        Self::new_pool(
            reactor,
            &[
                ComputeNodeAddress {
                    host: host.to_string(),
                    port: port,
                },
            ],
        )
    }

    /// Construct new Web3 contract client backend with a pool of nodes.
    pub fn new_pool(
        reactor: tokio_core::reactor::Remote,
        nodes: &[ComputeNodeAddress],
    ) -> Result<Self> {
        Ok(Web3ContractClientBackend {
            reactor: reactor.clone(),
            nodes: ComputeNodes::new(&nodes)?,
        })
    }

    /// Add a new compute node for this client.
    pub fn add_node(&self, address: &ComputeNodeAddress) -> Result<()> {
        self.nodes.add_node(&address)
    }

    /// Perform a raw contract call via gRPC.
    fn call_available_node(&self, client_request: Vec<u8>) -> ClientFuture<Vec<u8>> {
        self.nodes.call_available_node(client_request, 3)
    }
}

impl ContractClientBackend for Web3ContractClientBackend {
    /// Spawn future using an executor.
    fn spawn<F: Future<Item = (), Error = ()> + Send + 'static>(&self, future: F) {
        self.reactor.spawn(move |_| future);
    }

    /// Call contract.
    fn call(&self, client_request: api::ClientRequest) -> ClientFuture<api::ClientResponse> {
        let result = self.call_raw(match client_request.write_to_bytes() {
            Ok(request) => request,
            _ => return Box::new(future::err(Error::new("Failed to serialize request"))),
        }).and_then(|response| {
            let client_response: api::ClientResponse = protobuf::parse_from_bytes(&response)?;

            Ok(client_response)
        });

        Box::new(result)
    }

    /// Call contract with raw data.
    fn call_raw(&self, client_request: Vec<u8>) -> ClientFuture<Vec<u8>> {
        self.call_available_node(client_request)
    }

    /// Get credentials.
    fn get_credentials(&self) -> Option<ContractClientCredentials> {
        None
    }
}
