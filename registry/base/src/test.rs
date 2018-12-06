//! Utilities for testing registry backends.
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ekiden_common::bytes::B256;
use ekiden_common::entity::Entity;
use ekiden_common::futures::Future;
use ekiden_common::node::{Capabilities, Node};
use ekiden_common::ring::signature::Ed25519KeyPair;
use ekiden_common::signature::{InMemorySigner, Signed};
use ekiden_common::untrusted;
use ekiden_common::x509::Certificate;

use super::{EntityRegistryBackend, REGISTER_ENTITY_SIGNATURE_CONTEXT,
            REGISTER_NODE_SIGNATURE_CONTEXT};

/// Populate an entity registry with mock nodes.
pub fn populate_entity_registry(registry: Arc<EntityRegistryBackend>, public_keys: Vec<B256>) {
    // Fake entity owning the compute nodes.
    let entity_sk =
        Ed25519KeyPair::from_seed_unchecked(untrusted::Input::from(&B256::random())).unwrap();
    let entity_pk = B256::from(entity_sk.public_key_bytes());
    let entity_signer = InMemorySigner::new(entity_sk);
    let signed_entity = Signed::sign(
        &entity_signer,
        &REGISTER_ENTITY_SIGNATURE_CONTEXT,
        Entity::for_local_test(entity_pk),
    );
    registry.register_entity(signed_entity).wait().unwrap();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("unable to get time since UNIX epoch")
        .as_secs() as u64;

    // Fake nodes.
    for public_key in public_keys {
        let node = Node {
            id: public_key,
            eth_address: None,
            entity_id: entity_pk,
            expiration: 0xffffffffffffffff,
            addresses: vec![],
            certificate: Certificate::default(),
            stake: vec![],
            registration_time: now,
            capabilities: Capabilities::default(),
        };

        let signed_node = Signed::sign(&entity_signer, &REGISTER_NODE_SIGNATURE_CONTEXT, node);
        registry.register_node(signed_node).wait().unwrap();
    }
}
