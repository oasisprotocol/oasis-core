#![feature(use_extern_macros)]

#[macro_use]
extern crate clap;
extern crate futures;
extern crate rand;
extern crate tokio_core;

#[macro_use]
extern crate client_utils;
extern crate ekiden_core;
extern crate ekiden_rpc_client;

extern crate token_api;

use clap::{App, Arg};
use futures::future::Future;
use rand::{thread_rng, Rng};

use ekiden_rpc_client::create_client_rpc;
use token_api::with_api;

with_api! {
    create_client_rpc!(token, token_api, api);
}

/// Initializes the token scenario.
fn init<Backend>(client: &mut token::Client<Backend>, _runs: usize, _threads: usize)
where
    Backend: ekiden_rpc_client::backend::ContractClientBackend,
{
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
fn scenario<Backend>(client: &mut token::Client<Backend>)
where
    Backend: ekiden_rpc_client::backend::ContractClientBackend,
{
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
fn finalize<Backend>(client: &mut token::Client<Backend>, runs: usize, threads: usize)
where
    Backend: ekiden_rpc_client::backend::ContractClientBackend,
{
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

#[cfg(feature = "benchmark")]
fn main() {
    let results = benchmark_client!(token, init, scenario, finalize);
    results.show();
}

#[cfg(not(feature = "benchmark"))]
fn main() {
    let mut client = contract_client!(token);
    init(&mut client, 1, 1);
    scenario(&mut client);
    finalize(&mut client, 1, 1);
}
