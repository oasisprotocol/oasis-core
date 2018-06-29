use std::sync::Arc;

extern crate bigint;
extern crate ekiden_stake_base;
extern crate ekiden_common;
extern crate ekiden_epochtime;
extern crate ekiden_ethereum;
#[macro_use(defer)]
extern crate scopeguard;
extern crate grpcio;
extern crate web3;
#[macro_use]
extern crate log;
extern crate itertools;

use ekiden_stake_base::{AmountType, StakeEscrowBackend};
use ekiden_common::bytes::{B256, H160};
use ekiden_common::entity::Entity;
use ekiden_common::futures::prelude::*;
use ekiden_common::uint::U256;
use ekiden_common::testing;
use ekiden_common::error::Error;
use ekiden_ethereum::truffle::{deploy_truffle, start_truffle, DEVELOPMENT_ADDRESS, get_development_address};
use ekiden_ethereum::EthereumStake;
use web3::api::Web3;
use web3::transports::WebSocket;
use itertools::Itertools;

#[test]
fn stake_integration() {
    testing::try_init_logging();

    // Spin up truffle.
    let mut truffle = start_truffle(env!("CARGO_MANIFEST_DIR"));
    defer! {{
        drop(truffle.kill());
    }};

    // Connect to truffle.
    let (handle, transport) = WebSocket::new("ws://localhost:9545").unwrap();
    let client = Web3::new(transport.clone());

    // Make sure our contracts are deployed.
    let addresses = deploy_truffle(env!("CARGO_MANIFEST_DIR"));
    let address = addresses
        .get("Stake")
        .expect("could not find contract address");

    let eth_address = H160::from_slice(DEVELOPMENT_ADDRESS);
    let oasis = B256::from_slice(&eth_address.to_vec());

    let stake = EthereumStake::new(
        Arc::new(client),
        Arc::new(Entity {
            id: B256::zero(),
            eth_address: Some(eth_address),
        }),
        H160::from_slice(&address),
    ).unwrap();

    let name = stake.get_name().wait().unwrap();
    debug!("name = {}", name);
    assert_eq!(name, "EkidenStake");  // see ../migration/2_deploy_contracts.js

    let symbol = stake.get_symbol().wait().unwrap();
    debug!("symbol = {}", symbol);
    assert_eq!(symbol, "E$");

    let decimals = stake.get_decimals().wait().unwrap();
    debug!("decimals = {}", decimals);
    assert_eq!(decimals, 18u8);

    let total_supply = stake.get_total_supply().wait().unwrap();
    debug!("total_supply = {}", total_supply);
    let scale = U256::from(bigint::uint::U256::exp10(decimals as usize));
    let expected_supply = U256::from(1000000000) * scale;
    assert_eq!(total_supply, expected_supply);

    let stake_status = stake.get_stake_status(oasis).wait().unwrap();
    debug!("total_stake = {}", stake_status.total_stake);
    debug!("escrowed = {}", stake_status.escrowed);
    assert_eq!(stake_status.total_stake, total_supply);
    assert_eq!(stake_status.escrowed, AmountType::from(0));

    let oasis_addr = get_development_address(0).expect("should have gotten address 0");
    debug!("oasis_addr          = {:02x}", oasis_addr.iter().format(""));
    debug!("DEVELOPMENT_ADDRESS = {:02x}", DEVELOPMENT_ADDRESS.iter().format(""));
    assert_eq!(oasis_addr, DEVELOPMENT_ADDRESS);

    let alice_addr = get_development_address(1).expect("should have gotten address 1");
    debug!("alice_addr          = {:02x}", alice_addr.iter().format(""));
    let alice = B256::from_slice(&alice_addr);

    let oasis_balance = stake.balance_of(oasis).wait().unwrap();
    debug!("oasis balance = {}", oasis_balance);
    assert_eq!(oasis_balance, total_supply);

    let alice_balance = stake.balance_of(alice).wait().unwrap();
    debug!("alice balance = {}", alice_balance);
    assert_eq!(alice_balance, AmountType::from(0));

    let oasis_to_alice_transfer_amt = AmountType::from(1000);

    // TODO fix this. Temporarily transfer to self.
    let b = stake.transfer(oasis, oasis, oasis_to_alice_transfer_amt).wait().unwrap();
    debug!("transfer to alice: {}", b);
    assert!(b);

    let alice_balance = stake.balance_of(alice).wait().unwrap();
    assert_eq!(alice_balance, oasis_to_alice_transfer_amt);

    let oasis_balance = stake.balance_of(oasis).wait().unwrap();
    assert_eq!(oasis_balance, total_supply - oasis_to_alice_transfer_amt);

    drop(handle);
}
