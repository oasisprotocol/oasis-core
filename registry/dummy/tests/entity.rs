extern crate ekiden_common;
extern crate ekiden_registry_base;
extern crate ekiden_registry_dummy;
extern crate grpcio;
extern crate serde_cbor;

use serde_cbor::to_vec;
use std::sync::Arc;

use ekiden_common::bytes::B256;
use ekiden_common::entity::Entity;
use ekiden_common::environment::GrpcEnvironment;
use ekiden_common::epochtime::local::{LocalTimeSourceNotifier, MockTimeSource};
use ekiden_common::futures::{future, BoxFuture, Future};
use ekiden_common::ring::signature::Ed25519KeyPair;
use ekiden_common::signature::{InMemorySigner, Signature, Signed};
use ekiden_common::untrusted;
use ekiden_registry_base::*;
use ekiden_registry_dummy::DummyEntityRegistryBackend;

#[test]
fn test_dummy_entity_backend() {
    let time_source = Arc::new(MockTimeSource::new());
    let time_notifier = Arc::new(LocalTimeSourceNotifier::new(time_source.clone()));

    let grpc_environment = grpcio::EnvBuilder::new().build();
    let env = Arc::new(GrpcEnvironment::new(grpc_environment));

    let backend = Arc::new(DummyEntityRegistryBackend::new(time_notifier, env));

    let mut tasks: Vec<BoxFuture<()>> = Vec::new();

    let key_pair =
        Ed25519KeyPair::from_seed_unchecked(untrusted::Input::from(&B256::random())).unwrap();
    let public_key = B256::from(key_pair.public_key_bytes());
    let signer = InMemorySigner::new(key_pair);

    let ent = Entity::for_local_test(public_key);

    let sig = Signature::sign(
        &signer,
        &REGISTER_ENTITY_SIGNATURE_CONTEXT,
        &to_vec(&ent).unwrap(),
    );

    tasks.push(Box::new(
        backend.register_entity(Signed::from_parts(ent, sig)),
    ));
    let future_key = public_key.clone();
    tasks.push(Box::new(backend.get_entities().and_then(move |n| {
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].id, future_key);
        Ok(())
    })));

    let sig = Signature::sign(
        &signer,
        &DEREGISTER_ENTITY_SIGNATURE_CONTEXT,
        &to_vec(&public_key).unwrap(),
    );
    tasks.push(Box::new(
        backend.deregister_entity(Signed::from_parts(public_key, sig)),
    ));

    tasks.push(Box::new(backend.get_entities().and_then(|n| {
        assert_eq!(n.len(), 0);
        Ok(())
    })));

    // TODO: Also test nodes.

    future::join_all(tasks).wait().unwrap();
}
