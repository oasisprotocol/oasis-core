#[macro_use]
extern crate clap;
extern crate rand;

#[macro_use]
extern crate client_utils;
extern crate ekiden_contract_client;
extern crate ekiden_core;
extern crate ekiden_rpc_client;

extern crate token_api;

use std::{thread, time};

use clap::{App, Arg};

use ekiden_contract_client::create_contract_client;
use ekiden_core::futures::Future;
use token_api::with_api;

with_api! {
    create_contract_client!(token, token_api, api);
}

fn main() {
    let client = contract_client!(token);

    // Create new token contract.
    let mut request = token::CreateRequest::new();
    request.set_sender("bank".to_string());
    request.set_token_name("Ekiden Token".to_string());
    request.set_token_symbol("EKI".to_string());
    request.set_initial_supply(8);

    client.create(request).wait().unwrap();

    // Check balance.
    let response = client
        .get_balance({
            let mut request = token::GetBalanceRequest::new();
            request.set_account("bank".to_string());
            request
        })
        .wait()
        .unwrap();
    assert_eq!(response.get_balance(), 8_000_000_000_000_000_000);

    // Sleep for 10 seconds to allow for epoch to advance.
    thread::sleep(time::Duration::from_secs(10));

    // Check balance again.
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
