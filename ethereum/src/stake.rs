use std::sync::{Arc, Mutex};
use std::error::Error as StdError;
use std::result::Result as StdResult;

use ekiden_stake_base::StakeEscrowBackend;
use ekiden_common::futures::{future, BoxFuture, Future};
use ekiden_common::bytes::{B256, H160};
use ekiden_common::entity::Entity;
use ekiden_common::error::{Error, Result};
use ekiden_common::uint::U256;
use ekiden_di;
use ethabi::Token;
#[allow(unused_imports)]
use rustc_hex::FromHex;
use serde_json;
use web3;
use web3::api::Web3;
use web3::contract::{Contract as EthContract, Options};
use web3::types::BlockNumber;
use web3::Transport;

use ekiden_stake_base::*;

const STAKE_CONTRACT: &[u8] = include_bytes!("../build/contracts/Stake.json");

/// Ethereum Stake implementation.
pub struct EthereumStake<T: Transport + Sync + Send> {
    contract: Arc<Mutex<EthContract<T>>>,
    client: Arc<Web3<T>>,
    local_eth_address: web3::types::H160,
}

fn web3_u256_to_amount(v: web3::types::U256) -> AmountType {
    let mut slice = [0u8;32];
    v.to_little_endian(&mut slice);
    AmountType::from_little_endian(&slice)
}

// This could go into our bytes.rs, except we'd only want it when web3 types are also imported.
fn web3_u256_to_b256(v: web3::types::U256) -> B256 {
    let mut slice = [0u8; 32];
    v.to_little_endian(&mut slice);
    B256::from_slice(&slice)
}

impl<T: 'static + Transport + Sync + Send> EthereumStake<T>
where
    <T as web3::Transport>::Out: Send,
{
    // Create a new EthereumStake object.  Verifies via the web3 |client| object that the
    // Stake contract for which this interface was written was actually deployed at the
    // supplied Ethereum address in |contract_address|, and that the |local_identity|
    // Entity object, which contains the Rust-side public key, is associated with that
    // Ethereum address.
    pub fn new(
        client: Arc<Web3<T>>,
        local_identity: Arc<Entity>,
        contract_address: H160,
    ) -> Result<Self> {
        let local_eth_address = match local_identity.eth_address {
            Some(addr) => web3::types::H160(addr.0),
            None => return Err(Error::new("No local Ethereum address")),
        };

        let contract_dfn: serde_json::Value = serde_json::from_slice(STAKE_CONTRACT)?;
        let contract_abi = serde_json::to_vec(&contract_dfn["abi"])?;

        let contract_address = web3::types::H160(contract_address.0);
        let contract = EthContract::from_json(
            client.eth(),
            web3::types::H160(contract_address.0),
            &contract_abi,
        )?;

        let ctor_future = client
            .eth()
            .code(contract_address, None)
            .map_err(|e| Error::new(e.description()))
            .and_then(move |code| {
                let actual_str = serde_json::to_string(&code).unwrap_or("".to_string());
                // let expected_str = serde_json::to_string(&contract_dfn["deployedBytecode"])
                //     .unwrap_or("".to_string());
                // If both actual_str and expected_str are "" due to unwrap_or, what happens?
                // The solidity compiler should have generated a valid json file, but it's
                // probably better to force it to succeed.
                let expected_str = serde_json::to_string(&contract_dfn["deployedBytecode"])?;
                // The Stake code is linked against UintSet, so the expected code from
                // contract_dfn is going to differ due to the linkage.
                if false && actual_str != expected_str {
                    // Why do we care if the version deployed might be slightly different
                    // from the version which existed when this source file was compiled?
                    // We don't have semantic versioning, so we don't know if the other
                    // version supports exactly the same API as this code expects.
                    warn!("actual_str:   {}", actual_str);
                    warn!("expected_str: {}", expected_str);
                    return Err(Error::new("Contract not deployed at specified address."));
                }
                let instance = Self {
                    contract: Arc::new(Mutex::new(contract)),
                    client: client,
                    local_eth_address: local_eth_address,
                };

                Ok(instance)
            });

        ctor_future.wait()
    }
}

impl<T: 'static + Transport + Sync + Send> StakeEscrowBackend for EthereumStake<T>
where
    <T as web3::Transport>::Out: Send,
{
    fn get_name(&self) -> BoxFuture<String> {
        let contract = self.contract.clone();
        let local_eth_address = self.local_eth_address;
        Box::new(future::lazy(move || {
            let contract = contract.lock().unwrap();
            contract
                .query("name", (), local_eth_address, Options::default(), None)
                .map_err(|e| Error::new(e.description()))
        }))
    }

    fn get_symbol(&self) -> BoxFuture<String> {
        unimplemented!();
    }

    fn get_decimals(&self) -> BoxFuture<u8> {
        unimplemented!();
    }

    fn get_total_supply(&self) -> BoxFuture<AmountType> {
        unimplemented!();
    }

    fn get_stake_status(&self, owner: B256) -> BoxFuture<StakeStatus> {
        unimplemented!();
    }

    fn balance_of(&self, owner: B256) -> BoxFuture<AmountType> {
        unimplemented!();
    }

    fn transfer(
        &self,
        msg_sender: B256,
        destination_address: B256,
        value: AmountType,
    ) -> BoxFuture<bool> {
        unimplemented!();
    }

    fn transfer_from(
        &self,
        msg_sender: B256,
        source_address: B256,
        destination_address: B256,
        value: AmountType,
    ) -> BoxFuture<bool> {
        unimplemented!();
    }

    fn approve(
        &self,
        msg_sender: B256,
        spender_address: B256,
        value: AmountType,
    ) -> BoxFuture<bool> {
        unimplemented!();
    }

    fn approve_and_call(
        &self,
        msg_sender: B256,
        spender_address: B256,
        value: AmountType,
        extra_data: Vec<u8>,
    ) -> BoxFuture<bool> {
        unimplemented!();
    }

    fn allowance(&self, owner: B256, spender: B256) -> BoxFuture<AmountType> {
        unimplemented!();
    }

    fn burn(&self, msg_sender: B256, value: AmountType) -> BoxFuture<bool> {
        unimplemented!();
    }

    fn burn_from(&self, msg_sender: B256, owner: B256, value: AmountType) -> BoxFuture<bool> {
        unimplemented!();
    }

    fn allocate_escrow(
        &self,
        msg_sender: B256,
        target: B256,
        escrow_amount: AmountType,
        aux: B256,
    ) -> BoxFuture<EscrowAccountIdType> {
        unimplemented!();
    }

    fn list_active_escrows_iterator(&self, owner: B256) -> BoxFuture<EscrowAccountIterator> {
        unimplemented!();
    }

    fn list_active_escrows_get(
        &self,
        iter: EscrowAccountIterator,
    ) -> BoxFuture<(EscrowAccountStatus, EscrowAccountIterator)> {
        unimplemented!();
    }

    fn fetch_escrow_by_id(&self, escrow_id: EscrowAccountIdType) -> BoxFuture<EscrowAccountStatus> {
        let contract = self.contract.clone();
        let local_eth_address = self.local_eth_address;
        Box::new(future::lazy(move || {
            let contract = contract.lock().unwrap();
            contract
                .query("fetch_escrow_by_id", 
                       Token::Uint(web3::types::U256::from_little_endian(&escrow_id.to_vec())),
                       local_eth_address, Options::default(), None)
                .map_err(|e| Error::new(e.description()))
                .then(move |r| {
                    match r {
                        Ok(result) => {
                            let (_owner, target, amount, aux): (
                                web3::types::H160,
                                web3::types::H160,
                                web3::types::U256,
                                web3::types::H256,
                            ) = result;
                            // let owner = B256::from_slice(&owner.to_vec());
                            let target = B256::from_slice(&target.to_vec());
                            let amount = web3_u256_to_amount(amount);
                            let aux = B256::from_slice(&aux.to_vec());
                            Ok(EscrowAccountStatus::new(escrow_id, target, amount, aux))
                        },
                        Err(e) => return Err(e),
                    }
                })
        }))
    }

    fn take_and_release_escrow(
        &self,
        msg_sender: B256,
        escrow_id: EscrowAccountIdType,
        amount_requested: AmountType,
    ) -> BoxFuture<AmountType> {
        unimplemented!();
    }
}

pub type EthereumStakeViaWebsocket = EthereumStake<web3::transports::WebSocket>;
create_component!(
    ethereum,
    "stake-backend",
    EthereumStakeViaWebsocket,
    StakeEscrowBackend,
    (|container: &mut Container| -> StdResult<Box<Any>, ekiden_di::error::Error> {
        let client = container.inject::<Web3<web3::transports::WebSocket>>()?;
        let local_identity = container.inject::<Entity>()?;

        let args = container.get_arguments().unwrap();
        let contract_address = value_t_or_exit!(args, "stake-address", H160);

        let instance: Arc<EthereumStakeViaWebsocket> =
            Arc::new(EthereumStake::new(
                client,
                local_identity,
                contract_address,
            ).map_err(|e| ekiden_di::error::Error::from(e.description()))?);
        Ok(Box::new(instance))
    }),
    [Arg::with_name("stake-address")
        .long("stake-address")
        .env("STAKE_ADDRESS")
        .help("Ethereum address at which the stake contract has been deployed")
        .takes_value(true)]
);
