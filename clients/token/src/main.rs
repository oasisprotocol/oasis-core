#![feature(use_extern_macros)]

#[macro_use]
extern crate clap;
extern crate futures;
extern crate rand;

#[macro_use]
extern crate client_utils;
extern crate ekiden_contract_client;
extern crate ekiden_core;
#[macro_use]
extern crate ekiden_instrumentation;
extern crate ekiden_rpc_client;

extern crate token_api;

use std::sync::Arc;

use clap::{App, Arg};
use futures::future::Future;
use rand::{thread_rng, Rng};

use ekiden_contract_client::create_contract_client;
use ekiden_core::bytes::B256;
use ekiden_core::ring::signature::Ed25519KeyPair;
use ekiden_core::signature::InMemorySigner;
use ekiden_core::untrusted;
use token_api::with_api;

with_api! {
    create_contract_client!(token, token_api, api);
}

/// Initializes the token scenario.
fn init(client: &mut token::Client, _runs: usize, _threads: usize) {
    // Create new token contract.
    let mut request = token::CreateRequest::new();
    request.set_sender("bank".to_string());
    request.set_token_name("Ekiden Token".to_string());
    request.set_token_symbol("EKI".to_string());
    request.set_initial_supply(8);

    client.create(request).wait().unwrap();

    // Check balances.
    let response = client
        .get_balance({
            let mut request = token::GetBalanceRequest::new();
            request.set_account("bank".to_string());
            request
        })
        .wait()
        .unwrap();
    assert_eq!(response.get_balance(), 8_000_000_000_000_000_000);
}

/// Create a new random token address.
fn create_address() -> String {
    thread_rng().gen_ascii_chars().take(32).collect()
}

/// Runs the token scenario.
fn scenario(client: &mut token::Client) {
    // Generate random addresses.
    let destination = create_address();
    let poor = create_address();

    // Transfer some funds.
    client
        .transfer({
            let mut request = token::TransferRequest::new();
            request.set_sender("bank".to_string());
            request.set_destination(destination.clone());
            request.set_value(3);
            request
        })
        .wait()
        .unwrap();
    measure_counter_inc!("value_transferred", 3);

    // Check balances.
    let response = client
        .get_balance({
            let mut request = token::GetBalanceRequest::new();
            request.set_account(destination.clone());
            request
        })
        .wait()
        .unwrap();
    assert_eq!(response.get_balance(), 3);

    let response = client
        .get_balance({
            let mut request = token::GetBalanceRequest::new();
            request.set_account(poor.clone());
            request
        })
        .wait()
        .unwrap();
    assert_eq!(response.get_balance(), 0);
}

/// Finalize the token scenario.
fn finalize(client: &mut token::Client, runs: usize, threads: usize) {
    // Check final balance.
    let response = client
        .get_balance({
            let mut request = token::GetBalanceRequest::new();
            request.set_account("bank".to_string());
            request
        })
        .wait()
        .unwrap();
    assert_eq!(
        response.get_balance(),
        8_000_000_000_000_000_000 - 3 * runs as u64 * threads as u64
    );
}

/// Generate client key pair.
fn create_key_pair() -> Arc<InMemorySigner> {
    let key_pair =
        Ed25519KeyPair::from_seed_unchecked(untrusted::Input::from(&B256::random())).unwrap();
    Arc::new(InMemorySigner::new(key_pair))
}

#[cfg(feature = "benchmark")]
fn main() {
    let signer = create_key_pair();
    let results = benchmark_client!(signer, token, init, scenario, finalize);
    results.show();
}

#[cfg(not(feature = "benchmark"))]
fn main() {
    let signer = create_key_pair();
    let mut client = contract_client!(signer, token);
    init(&mut client, 1, 1);
    scenario(&mut client);
    finalize(&mut client, 1, 1);
}
