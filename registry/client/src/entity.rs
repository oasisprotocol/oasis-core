//! Entity registry gRPC client.
use std::convert::TryFrom;
use std::error::Error as StdError;

use grpcio::{Channel, ChannelBuilder};

use ekiden_common::address::Address;
use ekiden_common::bytes::B256;
use ekiden_common::environment::Environment;
use ekiden_common::error::{Error, Result};
use ekiden_common::futures::prelude::*;
use ekiden_common::remote_node::RemoteNode;
use ekiden_common::x509::Certificate;
use ekiden_registry_api as api;
use ekiden_registry_base::{EntityRegistryBackend, NodeTransport};

/// Scheduler client implements the Scheduler interface.
pub struct EntityRegistryClient(api::EntityRegistryClient);

impl EntityRegistryClient {
    pub fn new(channel: Channel) -> Self {
        EntityRegistryClient(api::EntityRegistryClient::new(channel))
    }
}

impl EntityRegistryBackend for EntityRegistryClient {
    fn get_node_transport(&self, id: B256) -> BoxFuture<NodeTransport> {
        let mut request = api::NodeRequest::new();
        request.set_id(id.to_vec());
        match self.0.get_node_transport_async(&request) {
            Ok(f) => Box::new(f.map_err(|error| Error::new(error.description())).and_then(
                |mut response| {
                    let certificate = Certificate::try_from(response.get_certificate().clone())?;
                    let mut addresses = response.take_addresses().into_vec();
                    let addresses: Result<_> = addresses
                        .drain(..)
                        .map(|address| Address::try_from(address))
                        .collect();
                    let addresses = addresses?;

                    Ok(NodeTransport {
                        addresses,
                        certificate,
                    })
                },
            )),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }
}

// Register for dependency injection.
create_component!(
    remote,
    "entity-registry-backend",
    EntityRegistryClient,
    EntityRegistryBackend,
    (|container: &mut Container| -> Result<Box<Any>> {
        let environment: Arc<Environment> = container.inject()?;

        // "node-host" and "node-port" arguments.
        let remote_node: Arc<RemoteNode> = container.inject()?;

        let channel = ChannelBuilder::new(environment.grpc()).connect(&format!(
            "{}:{}",
            remote_node.get_node_host(),
            remote_node.get_node_port(),
        ));

        let instance: Arc<EntityRegistryBackend> = Arc::new(EntityRegistryClient::new(channel));
        Ok(Box::new(instance))
    }),
    []
);
