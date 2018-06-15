extern crate ekiden_beacon_base;
extern crate ekiden_common;
extern crate ekiden_ethereum;
extern crate ekiden_registry_base;
extern crate ekiden_storage_dummy;

#[macro_use(defer)]
extern crate scopeguard;
extern crate grpcio;
extern crate web3;

use std::sync::Arc;
use std::{thread, time};

use ekiden_beacon_base::backend::RandomBeacon;
use ekiden_common::bytes::{B256, H160};
use ekiden_common::entity::Entity;
use ekiden_common::environment::GrpcEnvironment;
use ekiden_common::error::Error;
use ekiden_common::futures::{cpupool, future, stream, Future, Stream};
use ekiden_common::ring::signature::Ed25519KeyPair;
use ekiden_common::signature::{InMemorySigner, Signed};
use ekiden_common::testing;
use ekiden_common::untrusted;
use ekiden_ethereum::truffle::{deploy_truffle, mine, start_truffle, DEVELOPMENT_ADDRESS};
use ekiden_ethereum::{EthereumEntityRegistryBackend, EthereumMockTime, EthereumRandomBeacon};
use ekiden_registry_base::entity_backend::{EntityRegistryBackend,
                                           REGISTER_ENTITY_SIGNATURE_CONTEXT};
use ekiden_storage_dummy::DummyStorageBackend;
use web3::api::Web3;
use web3::transports::WebSocket;

#[test]
fn test_registry_ethereum_roundtrip() {
    testing::try_init_logging();

    let mut executor = cpupool::CpuPool::new(4);
    let grpc_environment = grpcio::EnvBuilder::new().build();
    let env = Arc::new(GrpcEnvironment::new(grpc_environment));

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
    let time_address = addresses
        .get("MockEpoch")
        .expect("could not find contract address");
    let beacon_address = addresses
        .get("RandomBeaconMock")
        .expect("could not find contract address");
    let entity_address = addresses
        .get("EntityRegistryMock")
        .expect("could not find contract address");

    // Run a driver to make some background transactions such that things confirm.
    let tx_stream = mine(transport);
    let _handle = executor.spawn(tx_stream.fold(0 as u64, |a, _b| future::ok::<u64, Error>(a)));

    // Generate local acct. identity. (eth addr is the one hardcoded in truffle develop)
    let ent_sk =
        Ed25519KeyPair::from_seed_unchecked(untrusted::Input::from(&B256::random())).unwrap();

    let client = Arc::new(client);
    let orig_me = Entity {
        id: B256::from(ent_sk.public_key_bytes()),
        eth_address: Some(H160::from_slice(DEVELOPMENT_ADDRESS)),
    };
    let me = Arc::new(orig_me.clone());

    // Run a driver to advance time so that things confirm.
    let time_source = Arc::new(
        EthereumMockTime::new(
            client.clone(),
            me.clone(),
            H160::from_slice(&time_address),
            &mut executor,
        ).unwrap(),
    );

    // Run a driver to make some background transactions such that things confirm.
    let local_source = time_source.clone();
    let time_stream = Box::new(stream::unfold(0, move |state| {
        thread::sleep(time::Duration::from_millis(500));
        Some(
            local_source
                .set_mock_time(state, 10)
                .then(move |_r| future::ok::<(u64, u64), Error>((0, state + 1))),
        )
    }));
    let _time_handle =
        executor.spawn(time_stream.fold(0 as u64, |a, _b| future::ok::<u64, Error>(a)));

    // Make a beacon.
    let beacon = EthereumRandomBeacon::new(
        client.clone(),
        me.clone(),
        H160::from_slice(&beacon_address),
        time_source.clone(),
    ).unwrap();
    beacon.start(&mut executor);

    // Launch the registry.
    let storage = DummyStorageBackend::new();
    let registry = EthereumEntityRegistryBackend::new(
        client.clone(),
        me.clone(),
        H160::from_slice(&entity_address),
        Arc::new(storage),
        Arc::new(beacon),
        env.clone(),
    ).expect("Couldn't initialize registry.");

    let entity_signer = InMemorySigner::new(ent_sk);
    let signed_me = Signed::sign(
        &entity_signer,
        &REGISTER_ENTITY_SIGNATURE_CONTEXT,
        orig_me.clone(),
    );
    let myaddr = me.eth_address.clone();
    let time_advance = time_source.clone();
    let _task = registry
        .register_entity(signed_me)
        .then(move |r| {
            assert!(r.is_ok());
            time_advance.set_mock_time(100, 0)
        })
        .then(move |_r| registry.get_entity(me.id))
        .then(move |ent| {
            assert!(ent.is_ok());

            let entity = ent.unwrap();
            assert!(entity.eth_address == myaddr);

            drop(handle);
            future::ok::<(), ()>(())
        })
        .wait();
}
