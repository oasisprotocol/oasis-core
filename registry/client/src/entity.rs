//! Entity registry gRPC client.
use std::convert::TryFrom;
use std::error::Error as StdError;
use std::sync::Arc;

use grpcio::{Channel, ChannelBuilder};

use ekiden_common::bytes::B256;
use ekiden_common::entity::Entity;
use ekiden_common::environment::Environment;
use ekiden_common::error::{Error, Result};
use ekiden_common::futures::{future, stream, BoxFuture, BoxStream, Future, Stream};
use ekiden_common::identity::NodeIdentity;
use ekiden_common::node::Node;
use ekiden_common::remote_node::RemoteNode;
use ekiden_common::signature::Signed;
use ekiden_epochtime::interface::EpochTime;
use ekiden_registry_api as api;
use ekiden_registry_base::{EntityRegistryBackend, RegistryEvent};

/// Scheduler client implements the Scheduler interface.
pub struct EntityRegistryClient(api::EntityRegistryClient);

impl EntityRegistryClient {
    pub fn new(channel: Channel) -> Self {
        EntityRegistryClient(api::EntityRegistryClient::new(channel))
    }

    pub fn from_node(
        node: &Node,
        environment: Arc<Environment>,
        identity: Arc<NodeIdentity>,
    ) -> Self {
        EntityRegistryClient::new(node.connect(environment, identity))
    }
}

impl EntityRegistryBackend for EntityRegistryClient {
    fn register_entity(&self, entity: Signed<Entity>) -> BoxFuture<()> {
        let mut request = api::RegisterRequest::new();
        request.set_entity(entity.into());
        match self.0.register_entity_async(&request) {
            Ok(f) => Box::new(
                f.map(|_response| ())
                    .map_err(|error| Error::new(error.description())),
            ),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }

    fn deregister_entity(&self, timestamp: Signed<u64>) -> BoxFuture<()> {
        let mut request = api::DeregisterRequest::new();
        request.set_timestamp(timestamp.into());
        match self.0.deregister_entity_async(&request) {
            Ok(f) => Box::new(
                f.map(|_response| ())
                    .map_err(|error| Error::new(error.description())),
            ),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }

    fn get_entity(&self, id: B256) -> BoxFuture<Entity> {
        let mut request = api::EntityRequest::new();
        request.set_id(id.to_vec());
        match self.0.get_entity_async(&request) {
            Ok(f) => Box::new(
                f.map_err(|error| Error::new(error.description()))
                    .and_then(|mut response| Ok(Entity::try_from(response.take_entity())?)),
            ),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }

    fn get_entities(&self) -> BoxFuture<Vec<Entity>> {
        let request = api::EntitiesRequest::new();
        match self.0.get_entities_async(&request) {
            Ok(f) => Box::new(f.map_err(|error| Error::new(error.description())).and_then(
                |mut response| {
                    let mut response = response.take_entity().into_vec();
                    let result: Result<_> = response
                        .drain(..)
                        .map(|entity| Entity::try_from(entity))
                        .collect();

                    result
                },
            )),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }

    fn watch_entities(&self) -> BoxStream<RegistryEvent<Entity>> {
        let request = api::WatchEntityRequest::new();
        match self.0.watch_entities(&request) {
            Ok(stream) => Box::new(stream.then(|result| match result {
                Ok(mut response) => {
                    let entity = Entity::try_from(response.take_entity())?;

                    match response.get_event_type() {
                        api::WatchEntityResponse_ChangeType::REGISTERED => {
                            Ok(RegistryEvent::Registered(entity))
                        }
                        api::WatchEntityResponse_ChangeType::DEREGISTERED => {
                            Ok(RegistryEvent::Deregistered(entity))
                        }
                    }
                }
                Err(error) => Err(Error::new(error.description())),
            })),
            Err(error) => Box::new(stream::once(Err(Error::new(error.description())))),
        }
    }

    fn register_node(&self, node: Signed<Node>) -> BoxFuture<()> {
        let mut request = api::RegisterNodeRequest::new();
        request.set_node(node.into());
        match self.0.register_node_async(&request) {
            Ok(f) => Box::new(
                f.map(|_response| ())
                    .map_err(|error| Error::new(error.description())),
            ),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }

    fn get_node(&self, id: B256) -> BoxFuture<Node> {
        let mut request = api::NodeRequest::new();
        request.set_id(id.to_vec());
        match self.0.get_node_async(&request) {
            Ok(f) => Box::new(
                f.map_err(|error| Error::new(error.description()))
                    .and_then(|mut response| Ok(Node::try_from(response.take_node())?)),
            ),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }

    fn get_nodes(&self, epoch: EpochTime) -> BoxFuture<Vec<Node>> {
        let mut request = api::NodesRequest::new();
        request.set_epoch(epoch);
        match self.0.get_nodes_async(&request) {
            Ok(f) => Box::new(f.map_err(|error| Error::new(error.description())).and_then(
                |mut response| {
                    let mut response = response.take_node().into_vec();
                    let result: Result<_> = response
                        .drain(..)
                        .map(|node| Node::try_from(node))
                        .collect();

                    result
                },
            )),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }

    fn get_nodes_for_entity(&self, id: B256) -> BoxFuture<Vec<Node>> {
        let mut request = api::EntityNodesRequest::new();
        request.set_id(id.to_vec());
        match self.0.get_nodes_for_entity_async(&request) {
            Ok(f) => Box::new(f.map_err(|error| Error::new(error.description())).and_then(
                |mut response| {
                    let mut response = response.take_node().into_vec();
                    let result: Result<_> = response
                        .drain(..)
                        .map(|node| Node::try_from(node))
                        .collect();

                    result
                },
            )),
            Err(error) => Box::new(future::err(Error::new(error.description()))),
        }
    }

    fn watch_nodes(&self) -> BoxStream<RegistryEvent<Node>> {
        let request = api::WatchNodeRequest::new();
        match self.0.watch_nodes(&request) {
            Ok(stream) => Box::new(stream.then(|result| match result {
                Ok(mut response) => {
                    let node = Node::try_from(response.take_node())?;

                    match response.get_event_type() {
                        api::WatchNodeResponse_ChangeType::REGISTERED => {
                            Ok(RegistryEvent::Registered(node))
                        }
                        api::WatchNodeResponse_ChangeType::DEREGISTERED => {
                            Ok(RegistryEvent::Deregistered(node))
                        }
                    }
                }
                Err(error) => Err(Error::new(error.description())),
            })),
            Err(error) => Box::new(stream::once(Err(Error::new(error.description())))),
        }
    }

    fn watch_node_list(&self) -> BoxStream<(EpochTime, Vec<Node>)> {
        let request = api::WatchNodeListRequest::new();
        match self.0.watch_node_list(&request) {
            Ok(stream) => Box::new(stream.then(|result| match result {
                Ok(mut response) => {
                    let epoch = response.get_epoch();
                    let mut response = response.take_node().into_vec();
                    let mut nodes = vec![];
                    for raw_node in response {
                        let node = Node::try_from(raw_node)?;
                        nodes.push(node);
                    }

                    Ok((epoch, nodes))
                }
                Err(error) => Err(Error::new(error.description())),
            })),
            Err(error) => Box::new(stream::once(Err(Error::new(error.description())))),
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
