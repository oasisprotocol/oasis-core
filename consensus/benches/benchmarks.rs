#![feature(test)]

extern crate consensus as lib;
extern crate grpc;
extern crate rand;
extern crate test;

use rand::Rng;
use std::{thread, time};
use test::Bencher;

use lib::generated::consensus;
use lib::generated::consensus_grpc;
use lib::generated::consensus_grpc::Consensus;

fn spawn_client_server() -> consensus_grpc::ConsensusClient {
    let config = lib::Config {
        tendermint_host: String::from("localhost"),
        tendermint_port: 46657,
        tendermint_abci_port: 46658,
        grpc_port: 9002,
        no_tendermint: true,
        artificial_delay: 100,
    };
    let client_port = config.grpc_port;
    let _server_handle = thread::spawn(move || {
        lib::run(&config).unwrap();
    });
    // Give time for Tendermint to connect
    thread::sleep(time::Duration::from_millis(3000));

    consensus_grpc::ConsensusClient::new_plain("localhost", client_port, Default::default())
        .unwrap()
}

#[bench]
fn benchmark_get(b: &mut Bencher) {
    let client = spawn_client_server();

    // Set state to `helloworld`
    let mut req = consensus::ReplaceRequest::new();
    req.set_payload(String::from("helloworld").into_bytes());
    client
        .replace(grpc::RequestOptions::new(), req)
        .wait()
        .unwrap();

    b.iter(move || {
        let req = consensus::GetRequest::new();
        let (_, resp, _) = client.get(grpc::RequestOptions::new(), req).wait().unwrap();
        assert_eq!(
            resp.get_checkpoint().get_payload(),
            String::from("helloworld").as_bytes()
        );
    });

    // See https://github.com/sunblaze-ucb/ekiden/issues/223
    // We can't gracefully shut down the server yet.
    panic!("Test passed, just need to panic to get out");
    //server_handle.join();
}

#[bench]
fn benchmark_replace(b: &mut Bencher) {
    let client = spawn_client_server();
    b.iter(move || {
        let s = rand::thread_rng()
            .gen_ascii_chars()
            .take(10)
            .collect::<String>();
        let mut req = consensus::ReplaceRequest::new();
        req.set_payload(s.into_bytes());
        client
            .replace(grpc::RequestOptions::new(), req)
            .wait()
            .unwrap();
    });

    // See https://github.com/sunblaze-ucb/ekiden/issues/223
    // We can't gracefully shut down the server yet.
    panic!("Test passed, just need to panic to get out");
    //server_handle.join();
}
