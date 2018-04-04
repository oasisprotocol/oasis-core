extern crate consensus as lib;
extern crate grpc;

use std::{thread, time};

use lib::generated::consensus;
use lib::generated::consensus_grpc;
use lib::generated::consensus_grpc::Consensus;

#[test]
fn processes_requests() {
    let config = lib::Config {
        tendermint_host: String::from("127.0.0.1"),
        tendermint_port: 46657,
        tendermint_abci_port: 46658,
        grpc_port: 9002,
        no_tendermint: true,
        artificial_delay: 0,
    };
    let client_port = config.grpc_port;

    let _server_handle = thread::spawn(move || {
        lib::run(&config).unwrap();
    });

    // Give time for Tendermint to connect
    thread::sleep(time::Duration::from_millis(3000));

    let client =
        consensus_grpc::ConsensusClient::new_plain("127.0.0.1", client_port, Default::default())
            .unwrap();

    // Get latest state - should be empty
    let req = consensus::GetRequest::new();
    match client.get(grpc::RequestOptions::new(), req).wait() {
        Ok(_resp) => {
            panic!("First `get` should return an error");
        }
        Err(_err) => {
            assert!(true);
        }
    }

    // Get diffs - should be empty
    let mut req = consensus::GetDiffsRequest::new();
    req.set_since_height(0);
    match client.get_diffs(grpc::RequestOptions::new(), req).wait() {
        Ok(_resp) => {
            panic!("First `get` should return an error");
        }
        Err(_err) => {
            assert!(true);
        }
    }

    // Set state to `helloworld`
    let mut req = consensus::ReplaceRequest::new();
    req.set_payload(String::from("helloworld").into_bytes());
    client
        .replace(grpc::RequestOptions::new(), req)
        .wait()
        .unwrap();

    let req = consensus::GetRequest::new();
    let (_, resp, _) = client.get(grpc::RequestOptions::new(), req).wait().unwrap();
    assert_eq!(
        resp.get_checkpoint().get_payload(),
        String::from("helloworld").as_bytes()
    );

    // Set state to `successor`
    let mut req = consensus::ReplaceRequest::new();
    req.set_payload(String::from("successor").into_bytes());
    client
        .replace(grpc::RequestOptions::new(), req)
        .wait()
        .unwrap();

    // Add `diff1`
    let mut req = consensus::AddDiffRequest::new();
    req.set_payload(String::from("diff1").into_bytes());
    client
        .add_diff(grpc::RequestOptions::new(), req)
        .wait()
        .unwrap();

    // Add `diff2`
    let mut req = consensus::AddDiffRequest::new();
    req.set_payload(String::from("diff2").into_bytes());
    client
        .add_diff(grpc::RequestOptions::new(), req)
        .wait()
        .unwrap();

    // Call get, check checkpoint, diffs
    let req = consensus::GetRequest::new();
    let (_, resp, _) = client.get(grpc::RequestOptions::new(), req).wait().unwrap();
    assert_eq!(
        resp.get_checkpoint().get_payload(),
        String::from("successor").as_bytes()
    );
    assert_eq!(resp.get_checkpoint().get_height(), 2);
    assert_eq!(resp.get_diffs().len(), 2);
    assert_eq!(resp.get_diffs()[0], String::from("diff1").as_bytes());
    assert_eq!(resp.get_diffs()[1], String::from("diff2").as_bytes());

    // Call get_diffs
    let mut req = consensus::GetDiffsRequest::new();
    req.set_since_height(3);
    let (_, resp, _) = client
        .get_diffs(grpc::RequestOptions::new(), req)
        .wait()
        .unwrap();
    assert_eq!(resp.get_diffs().len(), 1);
    assert_eq!(resp.get_diffs()[0], String::from("diff2").as_bytes());

    // Set state to a sequence of all byte values
    let mut scale: Vec<u8> = vec![0; 256];
    for i in 0..256 {
        scale[i] = i as u8;
    }

    let mut req = consensus::ReplaceRequest::new();
    req.set_payload(scale.clone());
    client
        .replace(grpc::RequestOptions::new(), req)
        .wait()
        .unwrap();

    let req = consensus::GetRequest::new();
    let (_, resp, _) = client.get(grpc::RequestOptions::new(), req).wait().unwrap();
    assert_eq!(resp.get_checkpoint().get_payload(), &scale[..]);

    // See https://github.com/sunblaze-ucb/ekiden/issues/223
    // We can't gracefully shut down the server yet.
    panic!("Test passed, just need to panic to get out");
    //server_handle.join();
}
