extern crate ekiden_common;
extern crate ekiden_ethereum;
extern crate ekiden_registry_base;
extern crate ekiden_storage_dummy;

#[macro_use(defer)]
extern crate scopeguard;
extern crate web3;

use std::sync::Arc;

use ekiden_common::bytes::{B256, H160};
use ekiden_common::entity::Entity;
use ekiden_common::epochtime::local::{LocalTimeSourceNotifier, SystemTimeSource};
use ekiden_common::error::Error;
use ekiden_common::futures::{cpupool, future, Future, Stream};
use ekiden_common::ring::signature::Ed25519KeyPair;
use ekiden_common::signature::{InMemorySigner, Signed};
use ekiden_common::testing;
use ekiden_common::untrusted;
use ekiden_ethereum::truffle::{deploy_truffle, mine, start_truffle, DEVELOPMENT_ADDRESS};
use ekiden_ethereum::EthereumEntityRegistryBackend;
use ekiden_registry_base::entity_backend::{EntityRegistryBackend,
                                           REGISTER_ENTITY_SIGNATURE_CONTEXT};
use ekiden_storage_dummy::DummyStorageBackend;
use web3::api::Web3;
use web3::transports::WebSocket;

#[test]
fn test_registry_ethereum_roundtrip() {
    testing::try_init_logging();

    let mut executor = cpupool::CpuPool::new(4);

    // Spin up truffle.
    let mut truffle = start_truffle(env!("CARGO_MANIFEST_DIR"));
    defer! {{
        let _ = truffle.kill();
    }};

    // Connect to truffle.
    let (handle, transport) = WebSocket::new("ws://localhost:9545").unwrap();
    let client = Web3::new(transport.clone());

    // Make sure our contracts are deployed.
    let addresses = deploy_truffle(env!("CARGO_MANIFEST_DIR"));
    let address = addresses
        .get("EntityRegistryOasis")
        .expect("could not find contract address");

    // Run a driver to make some background transactions such that things confirm.
    let tx_stream = mine(transport);
    let _handle = executor.spawn(tx_stream.fold(0 as u64, |a, _b| future::ok::<u64, Error>(a)));

    // Generate local acct. identity. (eth addr is the one hardcoded in truffle develop)
    let ent_sk =
        Ed25519KeyPair::from_seed_unchecked(untrusted::Input::from(&B256::random())).unwrap();

    let me = Entity {
        id: B256::from(ent_sk.public_key_bytes()),
        eth_address: Some(H160::from_slice(DEVELOPMENT_ADDRESS)),
    };

    // Launch the registry.
    let storage = DummyStorageBackend::new();
    let time_source = Arc::new(SystemTimeSource {});
    let time_notifier = Arc::new(LocalTimeSourceNotifier::new(time_source.clone()));
    let registry = EthereumEntityRegistryBackend::new(
        Arc::new(client),
        Arc::new(me.clone()),
        H160::from_slice(&address),
        Arc::new(storage),
        time_notifier.clone(),
    ).expect("Couldn't initialize registry.");
    registry.start(&mut executor);

    let entity_signer = InMemorySigner::new(ent_sk);
    let signed_me = Signed::sign(
        &entity_signer,
        &REGISTER_ENTITY_SIGNATURE_CONTEXT,
        me.clone(),
    );
    let myaddr = me.eth_address.clone();
    let _task = registry
        .register_entity(signed_me)
        .then(move |r| {
            assert!(r.is_ok());
            registry.get_entity(me.id)
        })
        .then(move |ent| {
            assert!(ent.is_ok());

            let entity = ent.unwrap();
            assert!(entity.eth_address == myaddr);

            drop(handle);
            future::ok::<(), ()>(())
        })
        .wait();
}
