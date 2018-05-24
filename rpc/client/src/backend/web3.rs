//! gRPC client backend.
use std::sync::{Arc, Mutex};

use grpcio;

use futures::future::{self, Future};

use protobuf;
use protobuf::Message;

use ekiden_common::bytes::H256;
use ekiden_common::error::{Error, Result};
use ekiden_rpc_common::api;

use ekiden_compute_api::{CallContractRequest, WaitContractCallRequest, Web3Client};

use super::super::future::ClientFuture;
use super::{RpcClientBackend, RpcClientCredentials};

/// Address of a compute node.
pub struct ComputeNodeAddress {
    /// Compute node hostname.
    pub host: String,
    /// Compute node port.
    pub port: u16,
}

struct ComputeNode {
    /// gRPC client for the given node.
    client: Web3Client,
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
    fn new(environment: Arc<grpcio::Environment>, nodes: &[ComputeNodeAddress]) -> Result<Self> {
        let instance = ComputeNodes::default();

        for node in nodes {
            instance.add_node(environment.clone(), node)?;
        }

        Ok(instance)
    }

    /// Add a new compute node.
    fn add_node(
        &self,
        environment: Arc<grpcio::Environment>,
        address: &ComputeNodeAddress,
    ) -> Result<()> {
        let channel = grpcio::ChannelBuilder::new(environment)
            .connect(&format!("{}:{}", address.host, address.port));
        let client = Web3Client::new(channel);

        let mut nodes = self.nodes.lock().unwrap();
        nodes.push(ComputeNode {
            client,
            failed: false,
        });

        Ok(())
    }

    /// Call the first available compute node.
    fn call_available_node<F, Rs>(&self, method: F, max_retries: usize) -> ClientFuture<Rs>
    where
        F: Fn(&Web3Client) -> grpcio::Result<grpcio::ClientUnaryReceiver<Rs>>
            + Clone
            + Send
            + Sync
            + 'static,
        Rs: Send + Sync + 'static,
    {
        let shared_nodes = self.nodes.clone();

        let try_times = future::loop_fn(
            max_retries,
            move |retries| -> ClientFuture<future::Loop<Rs, usize>> {
                // Abort when we have reached the given number of retries.
                if retries == 0 {
                    return Box::new(future::err(Error::new(
                        "No active compute nodes are available",
                    )));
                }

                let cloned_nodes = shared_nodes.clone();
                let method = method.clone();

                // Try to find an active node on each iteration.
                let try_node = future::loop_fn(
                    (),
                    move |_| -> ClientFuture<future::Loop<Rs, ()>> {
                        let nodes = cloned_nodes.lock().unwrap();

                        // Find the first non-failed node and use it to send a request.
                        match nodes.iter().enumerate().find(|&(_, node)| !node.failed) {
                            Some((index, ref node)) => {
                                // Found a non-failed node.
                                let cloned_nodes = cloned_nodes.clone();

                                return match method(&node.client) {
                                    Ok(call) => Box::new(call.then(move |result| {
                                        match result {
                                            Ok(response) => Ok(future::Loop::Break(response)),
                                            Err(_) => {
                                                let mut nodes = cloned_nodes.lock().unwrap();
                                                // Since we never remove or reorder nodes, we can be sure that this
                                                // index always belongs to the specified node and we can avoid sharing
                                                // and locking individual node instances.
                                                nodes[index].failed = true;

                                                Ok(future::Loop::Continue(()))
                                            }
                                        }
                                    })),
                                    Err(error) => Box::new(future::err(Error::from(error))),
                                };
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
pub struct Web3RpcClientBackend {
    /// Concurrency environment for gRPC communication.
    environment: Arc<grpcio::Environment>,
    /// Completion queue for executing futures. This is an instance of Client because
    /// the grpcio API for doing this directly using an Executor is not exposed.
    completion_queue: grpcio::Client,
    /// Pool of compute nodes that the client can use.
    nodes: ComputeNodes,
}

impl Web3RpcClientBackend {
    /// Construct new Web3 contract client backend.
    pub fn new(environment: Arc<grpcio::Environment>, host: &str, port: u16) -> Result<Self> {
        Self::new_pool(
            environment,
            &[ComputeNodeAddress {
                host: host.to_string(),
                port: port,
            }],
        )
    }

    /// Construct new Web3 contract client backend with a pool of nodes.
    pub fn new_pool(
        environment: Arc<grpcio::Environment>,
        nodes: &[ComputeNodeAddress],
    ) -> Result<Self> {
        Ok(Web3RpcClientBackend {
            // Create a dummy channel, needed for executing futures. This is required because
            // the API for doing this directly using an Executor is not exposed.
            completion_queue: grpcio::Client::new(
                grpcio::ChannelBuilder::new(environment.clone()).connect(""),
            ),
            nodes: ComputeNodes::new(environment.clone(), &nodes)?,
            environment,
        })
    }

    /// Add a new compute node for this client.
    pub fn add_node(&self, address: &ComputeNodeAddress) -> Result<()> {
        self.nodes.add_node(self.environment.clone(), &address)
    }

    /// Perform a raw contract call via gRPC.
    fn call_available_node<F, Rs>(&self, method: F) -> ClientFuture<Rs>
    where
        F: Fn(&Web3Client) -> grpcio::Result<grpcio::ClientUnaryReceiver<Rs>>
            + Clone
            + Send
            + Sync
            + 'static,
        Rs: Send + Sync + 'static,
    {
        self.nodes.call_available_node(method, 3)
    }
}

impl RpcClientBackend for Web3RpcClientBackend {
    /// Spawn future using an executor.
    fn spawn<F: Future<Item = (), Error = ()> + Send + 'static>(&self, future: F) {
        self.completion_queue.spawn(future)
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
        let mut rpc_request = CallContractRequest::new();
        rpc_request.set_payload(client_request);

        Box::new(
            self.call_available_node(move |client| client.call_contract_async(&rpc_request))
                .map(|mut response| response.take_payload()),
        )
    }

    /// Wait for given contract call outputs to become available.
    fn wait_contract_call(&self, call_id: H256) -> ClientFuture<Vec<u8>> {
        let mut rpc_request = WaitContractCallRequest::new();
        rpc_request.set_call_id(call_id.to_vec());

        Box::new(self.call_available_node(move |client| {
            client.wait_contract_call_async(&rpc_request)
        }).map(|mut response| response.take_output()))
    }

    /// Get credentials.
    fn get_credentials(&self) -> Option<RpcClientCredentials> {
        None
    }
}
