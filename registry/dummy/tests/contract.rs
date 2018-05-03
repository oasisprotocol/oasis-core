extern crate ekiden_common;
extern crate ekiden_registry_base;
extern crate ekiden_registry_dummy;
extern crate serde_cbor;

use serde_cbor::to_vec;
use std::sync::Arc;

use ekiden_common::bytes::B256;
use ekiden_common::contract::Contract;
use ekiden_common::futures::{future, BoxFuture, Future};
use ekiden_common::ring::signature::Ed25519KeyPair;
use ekiden_common::signature::{InMemorySigner, Signature, Signed};
use ekiden_common::untrusted;
use ekiden_registry_base::*;
use ekiden_registry_dummy::DummyContractRegistryBackend;

#[test]
fn test_dummy_contract_backend() {
    let backend = Arc::new(DummyContractRegistryBackend::new());

    let mut tasks: Vec<BoxFuture<()>> = Vec::new();

    let key_pair =
        Ed25519KeyPair::from_seed_unchecked(untrusted::Input::from(&B256::random())).unwrap();
    let public_key = B256::from(key_pair.public_key_bytes());
    let signer = InMemorySigner::new(key_pair);

    let mut con = Contract::default();
    con.id = public_key;

    let sig = Signature::sign(
        &signer,
        &REGISTER_CONTRACT_SIGNATURE_CONTEXT,
        &to_vec(&con).unwrap(),
    );

    tasks.push(Box::new(
        backend.register_contract(Signed::from_parts(con, sig)),
    ));
    let future_key = public_key.clone();
    tasks.push(Box::new(backend.get_contract(public_key).and_then(
        move |n| {
            assert_eq!(n.id, future_key);
            Ok(())
        },
    )));

    // TODO: test streaming subscription.

    future::join_all(tasks).wait().unwrap();
}
