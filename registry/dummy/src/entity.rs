//! Ekiden dummy registry backend.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ekiden_common::bytes::B256;
use ekiden_common::entity::Entity;
use ekiden_common::environment::Environment;
use ekiden_common::error::Error;
use ekiden_common::futures::prelude::*;
use ekiden_common::node::Node;
use ekiden_common::signature::Signed;
use ekiden_common::subscribers::StreamSubscribers;
use ekiden_epochtime::interface::{EpochTime, TimeSourceNotifier, EKIDEN_EPOCH_INVALID};
use ekiden_registry_base::*;

struct DummyEntityRegistryBackendInner {
    /// state.
    entities: HashMap<B256, Entity>,
    nodes: HashMap<B256, HashMap<B256, Node>>,
    nodeents: HashMap<B256, B256>,
    node_lists: HashMap<EpochTime, Vec<Node>>,
    current_epoch: EpochTime,
}

impl DummyEntityRegistryBackendInner {
    fn build_node_list(&mut self, epoch: EpochTime) -> (EpochTime, Vec<Node>) {
        assert!(!self.node_lists.contains_key(&epoch));
        let mut nodes: Vec<Node> = self.nodes
            .values()
            .flat_map(|n| n.values())
            .map(|n| n.clone())
            .collect();
        nodes.sort_by(|a, b| a.id.cmp(&b.id));
        self.node_lists.insert(epoch, nodes.clone());
        self.node_lists
            .retain(|&k, _| (epoch == 0 || k >= epoch - 1));

        (epoch, nodes)
    }
}

/// A dummy entity registry backend.
///
/// **This backend should only be used for tests. it is centralized and unsafe.***
pub struct DummyEntityRegistryBackend {
    inner: Arc<Mutex<DummyEntityRegistryBackendInner>>,
    time_notifier: Arc<TimeSourceNotifier>,
    /// Event subscribers.
    entity_subscribers: Arc<StreamSubscribers<RegistryEvent<Entity>>>,
    node_subscribers: Arc<StreamSubscribers<RegistryEvent<Node>>>,
    node_list_subscribers: Arc<StreamSubscribers<(EpochTime, Vec<Node>)>>,
}

impl DummyEntityRegistryBackend {
    pub fn new(time_notifier: Arc<TimeSourceNotifier>, env: Arc<Environment>) -> Self {
        let registry = Self {
            inner: Arc::new(Mutex::new(DummyEntityRegistryBackendInner {
                entities: HashMap::new(),
                nodes: HashMap::new(),
                nodeents: HashMap::new(),
                node_lists: HashMap::new(),
                current_epoch: EKIDEN_EPOCH_INVALID,
            })),
            time_notifier,
            entity_subscribers: Arc::new(StreamSubscribers::new()),
            node_subscribers: Arc::new(StreamSubscribers::new()),
            node_list_subscribers: Arc::new(StreamSubscribers::new()),
        };
        registry.start(env);
        registry
    }

    /// Notify the registry that time has advanced to a new epoch.
    /// This allows for explicit driving of this registry as a
    /// cache when driven by a source other than an external
    /// time source directly.
    pub fn mark_epoch(&self, epoch: EpochTime) {
        let mut inner = self.inner.lock().unwrap();
        self.node_list_subscribers
            .notify(&inner.build_node_list(epoch));
        inner.current_epoch = epoch;
    }

    fn start(&self, env: Arc<Environment>) {
        let node_list_subscribers = self.node_list_subscribers.clone();
        let shared_inner = self.inner.clone();

        env.spawn({
            Box::new(self.time_notifier.watch_epochs().for_each_log_errors(
                module_path!(),
                "Unexpected error while processing entity registry events",
                move |event| {
                    let mut inner = shared_inner.lock().unwrap();
                    node_list_subscribers.notify(&inner.build_node_list(event));
                    inner.current_epoch = event;
                    future::ok(())
                },
            ))
        });
    }
}

impl EntityRegistryBackend for DummyEntityRegistryBackend {
    fn register_entity(&self, entity: Signed<Entity>) -> BoxFuture<()> {
        let inner = self.inner.clone();
        let entity_subscribers = self.entity_subscribers.clone();
        Box::new(future::lazy(move || {
            if entity.signature.public_key != entity.get_value_unsafe()?.id {
                return Err(Error::new("Wrong signature."));
            }
            measure_counter_inc!("entity_registered_count");
            let entity = entity.open(&REGISTER_ENTITY_SIGNATURE_CONTEXT)?;
            let mut inner = inner.lock().unwrap();
            inner.entities.insert(entity.id, entity.clone());
            inner.nodes.insert(entity.id, HashMap::new());

            let notification = RegistryEvent::Registered(entity);
            entity_subscribers.notify(&notification);

            Ok(())
        }))
    }

    fn deregister_entity(&self, id: Signed<B256>) -> BoxFuture<()> {
        let inner = self.inner.clone();
        let entity_subscribers = self.entity_subscribers.clone();
        let node_subscribers = self.node_subscribers.clone();
        Box::new(future::lazy(move || {
            if id.signature.public_key != id.get_value_unsafe()? {
                return Err(Error::new("Wrong signature."));
            }
            measure_counter_inc!("entity_deregistered_count");
            let id = id.open(&DEREGISTER_ENTITY_SIGNATURE_CONTEXT)?;

            let mut inner = inner.lock().unwrap();

            let entity = inner.entities.remove(&id);
            let registered_nodes = inner.nodes.remove(&id);

            match registered_nodes {
                Some(nodes) => for node in nodes.values() {
                    inner.nodeents.remove(&node.id);
                    let notification = RegistryEvent::Deregistered(node.to_owned());
                    node_subscribers.notify(&notification);
                },
                None => (),
            };

            match entity {
                Some(e) => {
                    let notification = RegistryEvent::Deregistered(e);
                    entity_subscribers.notify(&notification);
                }
                None => (),
            };

            Ok(())
        }))
    }

    fn get_entity(&self, id: B256) -> BoxFuture<Entity> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let inner = inner.lock().unwrap();
            let ent = inner.entities[&id].clone();

            Ok(ent)
        }))
    }

    fn get_entities(&self) -> BoxFuture<Vec<Entity>> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let inner = inner.lock().unwrap();
            let ent = inner.entities.values().map(|n| n.clone()).collect();

            Ok(ent)
        }))
    }

    fn watch_entities(&self) -> BoxStream<RegistryEvent<Entity>> {
        self.entity_subscribers.subscribe().1
    }

    fn register_node(&self, node: Signed<Node>) -> BoxFuture<()> {
        let inner = self.inner.clone();
        let node_subscribers = self.node_subscribers.clone();
        Box::new(future::lazy(move || {
            if node.get_value_unsafe()?.entity_id != node.signature.public_key {
                return Err(Error::new("Wrong signature."));
            }
            let node = node.open(&REGISTER_NODE_SIGNATURE_CONTEXT)?;

            let mut inner = inner.lock().unwrap();

            if inner.nodeents.get(&node.id) != None {
                return Err(Error::new("Node already registered."));
            }
            measure_counter_inc!("node_registered_count");

            match inner.nodes.get_mut(&node.entity_id) {
                Some(map) => {
                    map.insert(node.id, node.clone());
                    Ok(())
                }
                None => Err(Error::new("No such entity.")),
            }?;
            inner.nodeents.insert(node.id, node.entity_id);

            let notification = RegistryEvent::Registered(node);
            node_subscribers.notify(&notification);

            Ok(())
        }))
    }

    fn get_node(&self, id: B256) -> BoxFuture<Node> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let inner = inner.lock().unwrap();
            match inner.nodeents.get(&id) {
                Some(ent) => match inner.nodes.get(ent) {
                    Some(entity) => match entity.get(&id) {
                        Some(n) => Ok(n.to_owned()),
                        None => Err(Error::new("Consistency error.")),
                    },
                    None => Err(Error::new("Consistency error.")),
                },
                None => Err(Error::new("Node not found.")),
            }
        }))
    }

    fn get_nodes(&self, epoch: EpochTime) -> BoxFuture<Vec<Node>> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let inner = inner.lock().unwrap();
            match inner.node_lists.get(&epoch) {
                Some(nodes) => Ok(nodes.clone()),
                None => Err(Error::new("No node list for epoch.")),
            }
        }))
    }

    fn get_nodes_for_entity(&self, id: B256) -> BoxFuture<Vec<Node>> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let inner = inner.lock().unwrap();
            match inner.nodes.get(&id) {
                Some(ent) => Ok(ent.values().map(|n| n.clone()).collect()),
                None => Err(Error::new("Entity not found.")),
            }
        }))
    }

    fn watch_nodes(&self) -> BoxStream<RegistryEvent<Node>> {
        self.node_subscribers.subscribe().1
    }

    fn watch_node_list(&self) -> BoxStream<(EpochTime, Vec<Node>)> {
        let inner = self.inner.lock().unwrap();
        let (send, recv) = self.node_list_subscribers.subscribe();

        // Feed the current node list to catch up the subscriber to
        // current time.
        if inner.current_epoch != EKIDEN_EPOCH_INVALID {
            let nodes = match inner.node_lists.get(&inner.current_epoch) {
                Some(nodes) => nodes,
                None => {
                    return recv;
                }
            };
            send.unbounded_send((inner.current_epoch, nodes.clone()))
                .unwrap();
        }

        recv
    }
}

// Register for dependency injection.
create_component!(
    dummy,
    "entity-registry-backend",
    DummyEntityRegistryBackend,
    EntityRegistryBackend,
    [TimeSourceNotifier, Environment]
);
