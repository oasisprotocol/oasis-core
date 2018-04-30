//! Ekiden dummy registry backend.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ekiden_common::bytes::B256;
use ekiden_common::entity::Entity;
use ekiden_common::error::Error;
use ekiden_common::futures::{future, BoxFuture};
use ekiden_common::node::Node;
use ekiden_common::signature::Signed;
use ekiden_registry_base::*;

struct DummyRegistryBackendInner {
    /// state.
    entities: HashMap<B256, Entity>,
    nodes: HashMap<B256, HashMap<B256, Node>>,
    nodeents: HashMap<B256, B256>,
}

/// A dummy registry backend.
///
/// **This backend should only be used for tests. it is centralized and unsafe.***
pub struct DummyRegistryBackend {
    inner: Arc<Mutex<DummyRegistryBackendInner>>,
}

impl DummyRegistryBackend {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(DummyRegistryBackendInner {
                entities: HashMap::new(),
                nodes: HashMap::new(),
                nodeents: HashMap::new(),
            })),
        }
    }
}

impl RegistryBackend for DummyRegistryBackend {
    fn register_entity(&self, entity: Signed<Entity>) -> BoxFuture<()> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            if entity.signature.public_key != entity.get_value_unsafe().id {
                return Err(Error::new("Wrong signature."));
            }
            let entity = entity.open(&REGISTER_ENTITY_SIGNATURE_CONTEXT)?;
            let mut inner = inner.lock().unwrap();
            inner.entities.insert(entity.id, entity.clone());
            inner.nodes.insert(entity.id, HashMap::new());

            Ok(())
        }))
    }

    fn deregister_entity(&self, id: Signed<B256>) -> BoxFuture<()> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            if id.signature.public_key != *id.get_value_unsafe() {
                return Err(Error::new("Wrong signature."));
            }
            let id = id.open(&DEREGISTER_ENTITY_SIGNATURE_CONTEXT)?;

            let mut inner = inner.lock().unwrap();

            inner.entities.remove(&id);
            inner.nodes.remove(&id);
            // TODO: keep nodeents in sync.

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

    fn register_node(&self, node: Signed<Node>) -> BoxFuture<()> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            if node.get_value_unsafe().entity_id != node.signature.public_key {
                return Err(Error::new("Wrong signature."));
            }
            let node = node.open(&REGISTER_NODE_SIGNATURE_CONTEXT)?;

            let mut inner = inner.lock().unwrap();

            if inner.nodeents.get(&node.id) != None {
                return Err(Error::new("Node already registered."));
            }

            match inner.nodes.get_mut(&node.entity_id) {
                Some(map) => {
                    map.insert(node.id, node.clone());
                    Ok(())
                }
                None => Err(Error::new("No such entity.")),
            }?;
            inner.nodeents.insert(node.id, node.entity_id);
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

    fn get_nodes(&self) -> BoxFuture<Vec<Node>> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let inner = inner.lock().unwrap();
            let nodes = inner
                .nodes
                .values()
                .flat_map(|n| n.values())
                .map(|n| n.clone())
                .collect();

            Ok(nodes)
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
}
