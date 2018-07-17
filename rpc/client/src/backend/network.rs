//! Network enclave RPC client backend.
use std::sync::{Arc, Mutex};
use std::time::Duration;

use grpcio;

use protobuf;
use protobuf::Message;

use ekiden_common::environment::Environment;
use ekiden_common::error::{Error, Result};
use ekiden_common::futures::prelude::*;
use ekiden_common::x509::{Certificate, CERTIFICATE_COMMON_NAME};
use ekiden_rpc_api::{CallEnclaveRequest, EnclaveRpcClient};
use ekiden_rpc_common::api;

use super::{RpcClientBackend, RpcClientCredentials};

/// Address of a remote enclave host.
pub struct Address {
    /// Compute node hostname.
    pub host: String,
    /// Compute node port.
    pub port: u16,
    /// Compute node certificate.
    pub certificate: Certificate,
}

struct Node {
    /// gRPC client for the given node.
    client: EnclaveRpcClient,
    /// Failed flag.
    failed: bool,
}

#[derive(Default)]
struct Nodes {
    /// Active nodes.
    nodes: Arc<Mutex<Vec<Node>>>,
}

impl Nodes {
    /// Construct new pool of compute nodes.
    fn new(environment: Arc<Environment>, nodes: &[Address]) -> Result<Self> {
        let instance = Nodes::default();

        for node in nodes {
            instance.add_node(environment.clone(), node)?;
        }

        Ok(instance)
    }

    /// Add a new compute node.
    fn add_node(&self, environment: Arc<Environment>, address: &Address) -> Result<()> {
        let channel = grpcio::ChannelBuilder::new(environment.grpc())
            .max_receive_message_len(i32::max_value())
            .max_send_message_len(i32::max_value())
            .override_ssl_target(CERTIFICATE_COMMON_NAME)
            .secure_connect(
                &format!("{}:{}", address.host, address.port),
                grpcio::ChannelCredentialsBuilder::new()
                    .root_cert(address.certificate.get_pem()?)
                    .build(),
            );
        let client = EnclaveRpcClient::new(channel);

        let mut nodes = self.nodes.lock().unwrap();
        nodes.push(Node {
            client,
            failed: false,
        });

        Ok(())
    }

    /// Call the first available compute node.
    fn call_available_node<F, Rs>(&self, method: F, max_retries: usize) -> BoxFuture<Rs>
    where
        F: Fn(&EnclaveRpcClient) -> grpcio::Result<grpcio::ClientUnaryReceiver<Rs>>
            + Clone
            + Send
            + Sync
            + 'static,
        Rs: Send + Sync + 'static,
    {
        let shared_nodes = self.nodes.clone();

        let try_times = future::loop_fn(
            max_retries,
            move |retries| -> BoxFuture<future::Loop<Rs, usize>> {
                // Abort when we have reached the given number of retries.
                if retries == 0 {
                    return Box::new(future::err(Error::new(
                        "No active compute nodes are available",
                    )));
                }

                let cloned_nodes = shared_nodes.clone();
                let method = method.clone();

                // Try to find an active node on each iteration.
                let try_node = future::loop_fn((), move |_| -> BoxFuture<future::Loop<Rs, ()>> {
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
                });

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
pub struct NetworkRpcClientBackend {
    /// Concurrency environment for gRPC communication.
    environment: Arc<Environment>,
    /// Time limit for gRPC calls. If a request takes longer than
    /// this, we abort it and mark the node as failing.
    timeout: Option<Duration>,
    /// Pool of compute nodes that the client can use.
    nodes: Nodes,
}

impl NetworkRpcClientBackend {
    /// Construct new network enclave RPC client backend.
    pub fn new(
        environment: Arc<Environment>,
        timeout: Option<Duration>,
        host: &str,
        port: u16,
        certificate: Certificate,
    ) -> Result<Self> {
        Self::new_pool(
            environment,
            timeout,
            &[Address {
                host: host.to_string(),
                port: port,
                certificate,
            }],
        )
    }

    /// Construct new network enclave RPC client backend with a pool of nodes.
    pub fn new_pool(
        environment: Arc<Environment>,
        timeout: Option<Duration>,
        nodes: &[Address],
    ) -> Result<Self> {
        Ok(NetworkRpcClientBackend {
            environment: environment.clone(),
            timeout,
            nodes: Nodes::new(environment.clone(), &nodes)?,
        })
    }

    /// Add a new compute node for this client.
    pub fn add_node(&self, address: &Address) -> Result<()> {
        self.nodes.add_node(self.environment.clone(), &address)
    }

    /// Perform a raw contract call via gRPC.
    fn call_available_node<F, Rs>(&self, method: F) -> BoxFuture<Rs>
    where
        F: Fn(&EnclaveRpcClient) -> grpcio::Result<grpcio::ClientUnaryReceiver<Rs>>
            + Clone
            + Send
            + Sync
            + 'static,
        Rs: Send + Sync + 'static,
    {
        self.nodes.call_available_node(method, 3)
    }
}

/// Create a grpcio::CallOption based on our configuration.
fn create_call_opt(timeout: Option<Duration>) -> grpcio::CallOption {
    let mut opts = grpcio::CallOption::default();
    if let Some(timeout) = timeout {
        opts = opts.timeout(timeout);
    }
    opts
}

impl RpcClientBackend for NetworkRpcClientBackend {
    fn get_environment(&self) -> Arc<Environment> {
        self.environment.clone()
    }

    fn call(&self, client_request: api::ClientRequest) -> BoxFuture<api::ClientResponse> {
        let result = self.call_raw(match client_request.write_to_bytes() {
            Ok(request) => request,
            _ => return Box::new(future::err(Error::new("Failed to serialize request"))),
        }).and_then(|response| {
            let client_response: api::ClientResponse = protobuf::parse_from_bytes(&response)?;

            Ok(client_response)
        });

        Box::new(result)
    }

    fn call_raw(&self, client_request: Vec<u8>) -> BoxFuture<Vec<u8>> {
        let mut rpc_request = CallEnclaveRequest::new();
        rpc_request.set_payload(client_request);
        let timeout = self.timeout;

        Box::new(self.call_available_node(move |client| {
            client.call_enclave_async_opt(&rpc_request, create_call_opt(timeout))
        }).map(|mut response| response.take_payload()))
    }

    fn get_credentials(&self) -> Option<RpcClientCredentials> {
        None
    }
}
