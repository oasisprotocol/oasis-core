extern crate bigint;
extern crate ekiden_common;
extern crate ekiden_epochtime;
extern crate ekiden_ethereum;
extern crate ekiden_stake_base;
extern crate grpcio;
extern crate web3;
#[macro_use]
extern crate log;
extern crate itertools;
#[macro_use]
extern crate lazy_static;

use std::collections::HashMap;
use std::process::Child;
use std::sync::{Arc, Mutex};
use itertools::Itertools;
use web3::api::Web3;
use web3::transports::WebSocket;

use ekiden_common::bytes::{B256, H160};
use ekiden_common::entity::Entity;
use ekiden_common::environment::{Environment, GrpcEnvironment};
use ekiden_common::error::Error;
use ekiden_common::futures::prelude::*;
use ekiden_common::testing;
use ekiden_common::uint::U256;
use ekiden_ethereum::truffle::{deploy_truffle, mine, start_truffle, DevelopmentAddress};
use ekiden_ethereum::EthereumStake;
use ekiden_stake_base::{AmountType, StakeEscrowBackend};

// A truffle-based test is pretty heavy weight and not really a unittest, since it
// involves starting a blockchain and a miner.  Furthermore, since the blockchain runs at
// a fixed address, the tests cannot be run in parallel.  We create an environment where
// we keep track of the resources, since this is common between all such tests.  We do not
// try to re-use the environment, since per-test state changes to the blockchain would be
// applied to the blockchain in a non-determinstic order (if the tests were run in
// "parallel" but competed for access via a mutex).
pub struct TruffleTestEnv {
    pub truffle: Child,
    pub handle: web3::transports::EventLoopHandle,
    pub client: web3::api::Web3<web3::transports::WebSocket>,
    pub addresses: HashMap<String, Vec<u8>>,
    pub dev_addresses: DevelopmentAddress,
    pub eth_address: H160, // dev_addresses[0] converted to H160
    pub contract_address: Vec<u8>,
}

impl Drop for TruffleTestEnv {
    fn drop(&mut self) {
        drop(self.truffle.kill());
    }
}

impl TruffleTestEnv {
    pub fn new(contract_name: &str) -> Result<Self, Error> {
        testing::try_init_logging();

        let grpc_environment = grpcio::EnvBuilder::new().build();
        let environment = Arc::new(GrpcEnvironment::new(grpc_environment));

        // Spin up truffle.
        let truffle = start_truffle(env!("CARGO_MANIFEST_DIR"));

        // Connect to truffle.
        let (handle, transport) =
            WebSocket::new("ws://localhost:9545").expect("WebSocket creation should work");
        let client = Web3::new(transport.clone());

        // Make sure our contracts are deployed.
        let addresses = deploy_truffle(env!("CARGO_MANIFEST_DIR"));

        // Run a driver to make some background transactions such that things confirm.
        environment.spawn(mine(transport).discard());

        let dev_addresses = DevelopmentAddress::new(&client).unwrap();
        let eth_address = H160::from_slice(&dev_addresses.get_address(0).unwrap().to_vec());

        let contract_addr = match addresses.get(contract_name) {
            Some(v) => v.to_vec(),
            None => return Err(Error::new("contract name not found")),
        };

        Ok(Self {
            truffle: truffle,
            handle: handle,
            client: client,
            addresses: addresses,
            dev_addresses: dev_addresses,
            eth_address: eth_address,
            contract_address: contract_addr,
        })
    }
}

// This is our singleton.
lazy_static! {
    static ref TTEW: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
}

#[test]
fn stake_erc20() {
    let ref mut _guard = TTEW.lock().unwrap(); // Gross.  Should yield a new TruffleTestEnv to use.
    
    let tte = TruffleTestEnv::new("Stake").unwrap();

    let oasis = B256::from_slice(&tte.eth_address.to_vec());

    let stake = EthereumStake::new(
        Arc::new(tte.client.clone()),
        Arc::new(Entity {
            id: B256::zero(),
            eth_address: Some(tte.eth_address.clone()),
        }),
        H160::from_slice(&tte.contract_address),
    ).unwrap();

    let name = stake.get_name().wait().expect("name should work");
    debug!("name = {}", name);
    assert_eq!(name, "EkidenStake"); // see ../migration/2_deploy_contracts.js

    let symbol = stake.get_symbol().wait().expect("symbol should work");
    debug!("symbol = {}", symbol);
    assert_eq!(symbol, "E$");

    let decimals = stake.get_decimals().wait().expect("decimals should work");
    debug!("decimals = {}", decimals);
    assert_eq!(decimals, 18u8);

    let total_supply = stake
        .get_total_supply()
        .wait()
        .expect("totalSupply should work");
    debug!("total_supply = {}", total_supply);
    let scale = U256::from(bigint::uint::U256::exp10(decimals as usize));
    let expected_supply = U256::from(1_000_000_000) * scale;
    assert_eq!(total_supply, expected_supply, "initial supply wrong");

    let alice_addr = tte.dev_addresses
        .get_address(1)
        .expect("should have gotten address 1")
        .to_vec();
    debug!("alice_addr          = {:02x}", alice_addr.iter().format(""));
    let alice = B256::from_slice(&alice_addr);

    let bob_addr = tte.dev_addresses
        .get_address(2)
        .expect("should have gotten address 2")
        .to_vec();
    debug!("bob_addr          = {:02x}", bob_addr.iter().format(""));
    let bob = B256::from_slice(&bob_addr);

    let carol_addr = tte.dev_addresses
        .get_address(3)
        .expect("should have gotten address 3")
        .to_vec();
    debug!("carol_addr          = {:02x}", carol_addr.iter().format(""));
    let carol = B256::from_slice(&carol_addr);

    let oasis_balance = stake
        .balance_of(oasis)
        .wait()
        .expect("balanceOf should go through");
    debug!("oasis balance = {}", oasis_balance);
    assert_eq!(oasis_balance, total_supply);

    let alice_balance = stake
        .balance_of(alice)
        .wait()
        .expect("balanceOf should go through");
    debug!("alice balance = {}", alice_balance);
    assert_eq!(alice_balance, AmountType::from(0));

    let oasis_to_alice_transfer_amt = AmountType::from(1000);

    let b = stake
        .transfer(oasis, alice, oasis_to_alice_transfer_amt)
        .wait()
        .expect("transfer from Oasis to Alice should work");
    debug!("transfer to alice: {}", b);
    assert!(b);

    let alice_balance = stake
        .balance_of(alice)
        .wait()
        .expect("balanceOf(alice) should work");
    assert_eq!(
        alice_balance, oasis_to_alice_transfer_amt,
        "post-transfer Alice balance wrong"
    );

    let expected_oasis_balance = oasis_balance - oasis_to_alice_transfer_amt;
    let oasis_balance = stake
        .balance_of(oasis)
        .wait()
        .expect("balanceOf(oasis) should work");
    assert_eq!(
        oasis_balance, expected_oasis_balance,
        "post-transfer Oasis balance wrong"
    );

    let alice_approval = AmountType::from(100);
    let b = stake
        .approve(oasis, alice, alice_approval)
        .wait()
        .expect("approval should go through");
    assert!(b, "approve should have returned true");

    let oasis_to_bob_transfer_amt = AmountType::from(10);
    let b = stake
        .transfer_from(alice, oasis, bob, oasis_to_bob_transfer_amt)
        .wait()
        .expect("transfer_from oasis to bob should work");
    assert!(b, "approved transfer should return true");

    let bob_balance = stake
        .balance_of(bob)
        .wait()
        .expect("balanceOf(bob) should work");
    assert_eq!(bob_balance, oasis_to_bob_transfer_amt);

    let expected_oasis_balance = oasis_balance - oasis_to_bob_transfer_amt;
    let oasis_balance = stake
        .balance_of(oasis)
        .wait()
        .expect("balanceOf(oasis) should work");
    assert_eq!(
        oasis_balance, expected_oasis_balance,
        "post-approved-transfer oasis balance wrong"
    );

    let expected_remaining_allowance = alice_approval - oasis_to_bob_transfer_amt;
    let remaining_allowance = stake
        .allowance(oasis, alice)
        .wait()
        .expect("allowance(oasis, alice) should work");
    assert_eq!(
        remaining_allowance, expected_remaining_allowance,
        "post-approved-transfer allowance wrong"
    );

    let excessive_transfer_amount = remaining_allowance + AmountType::from(1);
    match stake
        .transfer_from(alice, oasis, bob, excessive_transfer_amount)
        .wait()
    {
        Ok(b) => {
            assert!(
                !b,
                "excessive transfer_from did not revert, and returned TRUE"
            );
        }
        Err(e) => {
            debug!(
                "excessive transfer_from aborted correctly: {}",
                e.description()
            );
        }
    }

    let burn_quantity = AmountType::from(10_000);
    let b = stake
        .burn(oasis, burn_quantity)
        .wait()
        .expect("burn(oasis, 10_000) should work");
    assert!(b, "burn(oasis, 10_000) should succeed and return true");

    let expected_oasis_balance = oasis_balance - burn_quantity;
    let oasis_balance = stake
        .balance_of(oasis)
        .wait()
        .expect("balanceOf(oasis) should continue to work");
    assert_eq!(
        oasis_balance, expected_oasis_balance,
        "post-burn oasis balance wrong"
    );

    let expected_total_supply = total_supply - burn_quantity;
    let total_supply = stake
        .get_total_supply()
        .wait()
        .expect("total_supply after burn should work");
    assert_eq!(total_supply, expected_total_supply);

    let carol_burn_approve_amount = AmountType::from(total_supply) + AmountType::from(10);
    let b = stake
        .approve(oasis, carol, carol_burn_approve_amount)
        .wait()
        .expect("carol burn approval should work");
    assert!(
        b,
        "carol approval should return true, even when exceeds total supply"
    );

    let carol_balance = stake
        .balance_of(carol)
        .wait()
        .expect("balanceOf(carol) should work");
    assert_eq!(carol_balance, AmountType::from(0));

    let carol_burns_oasis_amount = AmountType::from(20_000);
    let b = stake
        .burn_from(carol, oasis, carol_burns_oasis_amount)
        .wait()
        .expect("burn_from should work");
    assert!(b, "burn_from(carol, oasis, 20_000) should return true");

    let expected_oasis_balance = oasis_balance - carol_burns_oasis_amount;
    let oasis_balance = stake.balance_of(oasis).wait().unwrap();
    assert_eq!(
        oasis_balance, expected_oasis_balance,
        "post-burn_from oasis balance wrong"
    );

    let expected_total_supply = total_supply - carol_burns_oasis_amount;
    let total_supply = stake
        .get_total_supply()
        .wait()
        .expect("total_supply after burn_from should work");
    assert_eq!(total_supply, expected_total_supply);
}

// #[test]
fn stake_escrow() {
    let ref mut guard = TTEW.lock().unwrap();
    let tte = TruffleTestEnv::new("Stake").unwrap();

    let oasis = B256::from_slice(&tte.eth_address.to_vec());

    let oasis_addr = tte.dev_addresses
        .get_address(0)
        .expect("should have gotten address 0")
        .to_vec();
    debug!("oasis_addr          = {:02x}", oasis_addr.iter().format(""));

    let alice_addr = tte.dev_addresses
        .get_address(1)
        .expect("should have gotten address 1")
        .to_vec();
    debug!("alice_addr          = {:02x}", alice_addr.iter().format(""));
    let alice = B256::from_slice(&alice_addr);

    let bob_addr = tte.dev_addresses
        .get_address(2)
        .expect("should have gotten address 2")
        .to_vec();
    debug!("bob_addr          = {:02x}", bob_addr.iter().format(""));
    let bob = B256::from_slice(&bob_addr);

    let carol_addr = tte.dev_addresses
        .get_address(3)
        .expect("should have gotten address 3")
        .to_vec();
    debug!("carol_addr          = {:02x}", carol_addr.iter().format(""));
    let carol = B256::from_slice(&carol_addr);

    let stake = EthereumStake::new(
        Arc::new(tte.client.clone()),
        Arc::new(Entity {
            id: B256::zero(),
            eth_address: Some(tte.eth_address.clone()),
        }),
        H160::from_slice(&tte.contract_address),
    ).unwrap();

    let total_supply = stake
        .get_total_supply()
        .wait()
        .expect("totalSupply should work");

    let stake_status = stake
        .get_stake_status(oasis)
        .wait()
        .expect("getStakeStatus should work");
    debug!("total_stake = {}", stake_status.total_stake);
    debug!("escrowed = {}", stake_status.escrowed);
    assert_eq!(
        stake_status.total_stake, total_supply,
        "initial total_stake should be total supply"
    );
    assert_eq!(
        stake_status.escrowed,
        AmountType::from(0),
        "initial amount escrowed should be zero"
    );

    let alice_to_bob_escrow_amount = AmountType::from(17);
    let alice_to_bob_aux = B256::from_slice(&[4u8; 32]);
    let alice_to_carol_escrow_amount = AmountType::from(23);
    let alice_to_carol_aux = B256::from_slice(&[5u8; 32]);

    let alice_balance = stake
        .balance_of(alice)
        .wait()
        .expect("balanceOf(alice) should work");
    debug!("alice account balance = {}", alice_balance);
    let bob_balance = stake
        .balance_of(bob)
        .wait()
        .expect("balanceOf(bob) should work");
    match stake
        .allocate_escrow(alice, bob, alice_to_bob_escrow_amount, alice_to_bob_aux)
        .wait() {
            Ok(id) => {
                debug!("allocate escrow returned {}", id);
                assert!(false, "should not be able to allocate escrow when balance is zero");
            },
            Err(e) => {
                debug!("allocate escrow failed: {}", e.description());
            }
        }

    let oasis_to_alice_transfer_amt = AmountType::from(1000);

    let b = stake
        .transfer(oasis, alice, oasis_to_alice_transfer_amt)
        .wait()
        .expect("transfer from Oasis to Alice should work");
    debug!("transfer to alice: {}", b);
    assert!(b);

    let alice_balance = stake
        .balance_of(alice)
        .wait()
        .expect("balanceOf(alice) should work");
    assert_eq!(
        alice_balance, oasis_to_alice_transfer_amt,
        "post-transfer Alice balance wrong"
    );

    let alice_to_bob_escrow_id = stake
        .allocate_escrow(alice, bob, alice_to_bob_escrow_amount, alice_to_bob_aux)
        .wait()
        .expect("allocate_escrow(alice, bob, ...) should work");
    let alice_to_carol_escrow_id = stake
        .allocate_escrow(
            alice,
            carol,
            alice_to_carol_escrow_amount,
            alice_to_carol_aux,
        )
        .wait()
        .expect("allocate_escrow(alice, carol, ...) should work");

    debug!("alice->bob escrow: {}", alice_to_bob_escrow_id);
    debug!("alice->carol escrow: {}", alice_to_carol_escrow_id);

    let alice_bob_status = stake
        .fetch_escrow_by_id(alice_to_bob_escrow_id)
        .wait()
        .expect("fetch_escrow_by_id should work");
    debug!("id {}", alice_bob_status.id);
    debug!("target {}", alice_bob_status.target);
    debug!("amount {}", alice_bob_status.amount);
    debug!("aux {}", alice_bob_status.aux);
    assert_eq!(alice_bob_status.id, alice_to_bob_escrow_id);
    assert_eq!(alice_bob_status.target, bob);
    assert_eq!(alice_bob_status.amount, alice_to_bob_escrow_amount);
    assert_eq!(alice_bob_status.aux, alice_to_bob_aux);

    let it = stake
        .list_active_escrows_iterator(alice)
        .wait()
        .expect("list_active_escrows_iterator(alice) should work");
    debug!("it.has_next {}", it.has_next);
    debug!("it.owner {}", it.owner);
    debug!("it.state {}", it.state);

    let alice_bob_escrow_take = AmountType::from(7);
    let taken = stake
        .take_and_release_escrow(bob, alice_to_bob_escrow_id, alice_bob_escrow_take)
        .wait()
        .expect("take_and_release_escrow should work");
    assert_eq!(taken, alice_bob_escrow_take);
    let expected_bob_balance = bob_balance + alice_bob_escrow_take;
    let bob_balance = stake
        .balance_of(bob)
        .wait()
        .expect("balanceOf(bob) should work");
    assert_eq!(
        bob_balance, expected_bob_balance,
        "post-take Bob balance wrong"
    );
    let expected_alice_balance = alice_balance - alice_to_carol_escrow_amount - taken;
    let alice_balance = stake
        .balance_of(alice)
        .wait()
        .expect("balanceOf(alice) should work");
    assert_eq!(
        alice_balance, expected_alice_balance,
        "post-take Alice balance wrong"
    );
}
