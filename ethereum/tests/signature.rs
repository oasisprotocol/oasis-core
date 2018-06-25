#![feature(test)]

use std::sync::Arc;

extern crate ekiden_common;
extern crate ekiden_ethereum;
#[macro_use(defer)]
extern crate scopeguard;
extern crate test;
extern crate web3;

use ekiden_common::bytes::{B256, B520, H160, H256};
use ekiden_common::testing;
use ekiden_ethereum::signature::{Signer, Verifier, Web3Signer};
use ekiden_ethereum::truffle::start_truffle;
use test::Bencher;
use web3::api::Web3;
use web3::transports::WebSocket;

// keccak256("This is a test.")
const MESSAGE: &str = "7f2c2677f2df19d42c142aff7305f419c52640f07ef69cd2ceae908bdf48743b";
// Generated with `truffle --develop` + `web3.eth.sign`, with fixed up `v`.
const MESSAGE_SIG: &str = "63a3f14a5caf490faed86a485dca8f023916b69cab88683b95f14ed2f16c486942fc6fac885cf8cdaa12f9637cfcceead149a1b5c228432ea5bec20a15609d041b";

#[test]
fn ethereum_signature() {
    let truffle_addr = "627306090abab3a6e1400e9345bc60c78a8bef57";
    let truffle_sk = "c87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3";
    let truffle_addr = H160::from(truffle_addr);
    let truffle_sk = B256::from(truffle_sk);

    let signer = Signer::new(&truffle_sk).unwrap();
    assert_eq!(signer.get_identity(), truffle_addr);

    let message = H256::from(MESSAGE);
    let message_sig = B520::from(MESSAGE_SIG);
    let mut geth_sig = message_sig.clone();
    geth_sig.0[64] = 0x00;

    let signature = signer.sign(&message);
    assert_eq!(signature, message_sig);

    // Test recovery.
    let recovered_addr = Verifier::recover(&message, &message_sig).unwrap();
    assert_eq!(recovered_addr, truffle_addr);

    // Test verification.
    let verifier = Verifier::new_from_address(&truffle_addr);
    assert!(verifier.verify(&message, &message_sig, None));

    //
    // Test the web3 signer.
    //
    testing::try_init_logging();

    // Spin up truffle.
    let mut truffle = start_truffle(env!("CARGO_MANIFEST_DIR"));
    defer! {{
        drop(truffle.kill());
    }};

    // Connect to truffle.
    let (_handle, transport) = WebSocket::new("ws://localhost:9545").unwrap();
    let client = Web3::new(transport.clone());

    // Instantiate the signer.
    let signer = Web3Signer::new(Arc::new(client.clone()), &truffle_addr);

    let signature = signer.sign(&message);
    assert_eq!(signature, geth_sig);
}

#[bench]
fn bench_ecrecover(b: &mut Bencher) {
    let message = H256::from(MESSAGE);
    let message_sig = B520::from(MESSAGE_SIG);
    b.iter(|| Verifier::recover(&message, &message_sig).unwrap())
}
