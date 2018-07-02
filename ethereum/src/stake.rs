use std::error::Error as StdError;
use std::result::Result as StdResult;
use std::sync::{Arc, Mutex};

use ekiden_common::bytes::{B256, H160};
use ekiden_common::entity::Entity;
use ekiden_common::error::{Error, Result};
use ekiden_common::futures::{future, BoxFuture, Future};
use ekiden_di;
use ethabi::Token;
#[allow(unused_imports)]
use rustc_hex::FromHex;
use serde_json;
use web3;
use web3::api::Web3;
use web3::contract::{Contract as EthContract, Options};
use web3::Transport;

use ekiden_stake_base::*;

const STAKE_CONTRACT: &[u8] = include_bytes!("../build/contracts/Stake.json");
const NUM_CONFIRMATIONS: usize = 2; // Why 2 and not 6?  The Rust gRPC interface does not
                                    // have the ability to specify confirmations. Nor yield the block number of the most
                                    // recent block.

/// Ethereum Stake implementation.
#[allow(dead_code)] // client currently unused
pub struct EthereumStake<T: Transport + Sync + Send> {
    contract: Arc<Mutex<EthContract<T>>>,
    client: Arc<Web3<T>>,
    local_eth_address: web3::types::H160,
}

// These probably should return Result<...> in case the web3/JSON glue comes unstuck.  Do
// we trust this interface?  Could an adversary cause the JSON strings to be malformed?
// TODO(bsy): harden this interface, once the API etc settles down.

fn web3_u256_to_amount(v: web3::types::U256) -> AmountType {
    let mut slice = [0u8; 32];
    v.to_little_endian(&mut slice);
    AmountType::from_little_endian(&slice)
}

fn amount_to_web3_u256(v: AmountType) -> web3::types::U256 {
    web3::types::U256::from_little_endian(&v.to_vec())
}

fn web3_u256_to_escrow_account_id(v: web3::types::U256) -> EscrowAccountIdType {
    let mut slice = [0u8; 32];
    v.to_little_endian(&mut slice);
    EscrowAccountIdType::from_slice(&slice).unwrap()
}

fn escrow_account_id_to_web_u256(v: EscrowAccountIdType) -> web3::types::U256 {
    web3::types::U256::from_little_endian(&v.to_vec())
}

fn b256_to_web3_address(v: B256) -> web3::types::H160 {
    web3::types::H160::from_slice(&v.to_vec())
}

fn web3_address_to_b256(v: web3::types::H160) -> B256 {
    B256::from_slice(&v.to_vec())
}

fn b256_to_web3_bytes32(v: B256) -> web3::types::H256 {
    web3::types::H256::from_slice(&v.to_vec())
}

fn web3_bytes32_to_b256(b: web3::types::H256) -> B256 {
    B256::from_slice(&b.to_vec())
}

// fn b256_to_web3_bytes32(v: B256) -> Vec<u8> {
//     v.to_vec()
// }

// fn web3_bytes32_to_b256(b: Vec<u8>) -> B256 {
//     B256::from_slice(&b)
// }

fn web3_u256_to_b256(v: web3::types::U256) -> B256 {
    let mut slice = [0u8; 32];
    v.to_little_endian(&mut slice);
    B256::from_slice(&slice)
}

fn b256_to_web3_u256(v: B256) -> web3::types::U256 {
    web3::types::U256::from_little_endian(&v.to_vec())
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
        let contract = self.contract.clone();
        let local_eth_address = self.local_eth_address;
        Box::new(future::lazy(move || {
            let contract = contract.lock().unwrap();
            contract
                .query("symbol", (), local_eth_address, Options::default(), None)
                .map_err(|e| Error::new(e.description()))
        }))
    }

    fn get_decimals(&self) -> BoxFuture<u8> {
        let contract = self.contract.clone();
        let local_eth_address = self.local_eth_address;
        Box::new(future::lazy(move || {
            let contract = contract.lock().unwrap();
            // web3 parses JSON dictionaries, and there is no type information, so even
            // though the return type is u8, we can (and have to) use u64 to get the
            // value.  The u64 type is the smallest integral type for which
            // web3::contract::tokens::Tokenizable is implemented (as of this writing), so
            // we use that.  TODO: verify that the web3 interfaces are secure, and that
            // bad actors cannot have injected in bad values; we drop the high-order bits
            // here, and we may want to verify that they are all zeros and panic
            // otherwise.
            contract
                .query("decimals", (), local_eth_address, Options::default(), None)
                .map(|v: u64| v as u8)
                .map_err(|e| Error::new(e.description()))
        }))
    }

    fn get_total_supply(&self) -> BoxFuture<AmountType> {
        let contract = self.contract.clone();
        let local_eth_address = self.local_eth_address;
        Box::new(future::lazy(move || {
            let contract = contract.lock().unwrap();
            contract
                .query(
                    "totalSupply",
                    (),
                    local_eth_address,
                    Options::default(),
                    None,
                )
                .map(|v| web3_u256_to_amount(v))
                .map_err(|e| Error::new(e.description()))
        }))
    }

    fn get_stake_status(&self, owner: B256) -> BoxFuture<StakeStatus> {
        let contract = self.contract.clone();
        let local_eth_address = self.local_eth_address;
        Box::new(future::lazy(move || {
            let contract = contract.lock().unwrap();
            let w3_owner = b256_to_web3_address(owner);
            contract
                .query(
                    "getStakeStatus",
                    w3_owner,
                    local_eth_address,
                    Options::default(),
                    None,
                )
                .map(|r| {
                    let (w3_total_stake, w3_escrowed) = r;
                    let total_stake = web3_u256_to_amount(w3_total_stake);
                    let escrowed = web3_u256_to_amount(w3_escrowed);
                    StakeStatus::new(total_stake, escrowed)
                })
                .map_err(|e| Error::new(e.description()))
        }))
    }

    fn balance_of(&self, owner: B256) -> BoxFuture<AmountType> {
        let contract = self.contract.clone();
        let local_eth_address = self.local_eth_address;
        Box::new(future::lazy(move || {
            let contract = contract.lock().unwrap();
            let w3_owner = b256_to_web3_address(owner);
            contract
                .query(
                    "balanceOf",
                    w3_owner,
                    local_eth_address,
                    Options::default(),
                    None,
                )
                .map(|v| web3_u256_to_amount(v))
                .map_err(|e| Error::new(e.description()))
        }))
    }

    fn transfer(
        &self,
        msg_sender: B256,
        destination_address: B256,
        value: AmountType,
    ) -> BoxFuture<bool> {
        let contract = self.contract.clone();
        Box::new(future::lazy(move || {
            let contract_inner = contract.clone();
            let contract = contract.lock().unwrap();
            let w3_msg_sender = b256_to_web3_address(msg_sender);
            let w3_destination_address = b256_to_web3_address(destination_address);
            let w3_value = amount_to_web3_u256(value);
            contract
                .query(
                    "transfer",
                    (w3_destination_address.clone(), w3_value.clone()),
                    w3_msg_sender.clone(),
                    Options::default(),
                    None,
                )
                .map_err(|e| Error::new(e.description()))
                .and_then(move |b: bool| {
                    if !b {
                        return future::ok(false);
                    }
                    let contract = contract_inner.lock().unwrap();
                    contract
                        .call_with_confirmations(
                            "transfer",
                            (w3_destination_address, w3_value),
                            w3_msg_sender,
                            Options::with(|v| v.gas = Some(1_000_000.into())),
                            NUM_CONFIRMATIONS,
                        )
                        .map_err(|e| Error::new(e.description()))
                        .map(
                            move |_tr| // TODO: do something with the TransactionReceipt object
                             future::ok(b),
                        )
                        .wait()
                        .unwrap()
                })
        }))
    }

    fn transfer_from(
        &self,
        msg_sender: B256,
        source_address: B256,
        destination_address: B256,
        value: AmountType,
    ) -> BoxFuture<bool> {
        let contract = self.contract.clone();
        Box::new(future::lazy(move || {
            let contract_inner = contract.clone();
            let contract = contract.lock().unwrap();
            let w3_msg_sender = b256_to_web3_address(msg_sender);
            let w3_source_address = b256_to_web3_address(source_address);
            let w3_destination_address = b256_to_web3_address(destination_address);
            let w3_value = amount_to_web3_u256(value);
            contract
                .query(
                    "transferFrom",
                    (w3_source_address, w3_destination_address, w3_value),
                    w3_msg_sender,
                    Options::default(),
                    None,
                )
                .map_err(|e| Error::new(e.description()))
                .and_then(move |b: bool| {
                    if !b {
                        return future::ok(false);
                    }
                    let contract = contract_inner.lock().unwrap();
                    contract
                        .call_with_confirmations(
                            "transferFrom",
                            (w3_source_address, w3_destination_address, w3_value),
                            w3_msg_sender,
                            Options::with(|v| v.gas = Some(1_000_000.into())),
                            NUM_CONFIRMATIONS,
                        )
                        .map_err(|e| Error::new(e.description()))
                        .map(
                            move |_tr| // TODO: do something with the TransactionReceipt object
                             future::ok(b),
                        )
                        .wait()
                        .unwrap()
                })
        }))
    }

    fn approve(
        &self,
        msg_sender: B256,
        spender_address: B256,
        value: AmountType,
    ) -> BoxFuture<bool> {
        let contract = self.contract.clone();
        Box::new(future::lazy(move || {
            let contract_inner = contract.clone();
            let contract = contract.lock().unwrap();
            let w3_msg_sender = b256_to_web3_address(msg_sender);
            let w3_spender_address = b256_to_web3_address(spender_address);
            let w3_value = amount_to_web3_u256(value);
            contract
                .query(
                    "approve",
                    (w3_spender_address, w3_value),
                    w3_msg_sender,
                    Options::default(),
                    None,
                )
                .map_err(|e| Error::new(e.description()))
                .and_then(move |b: bool| {
                    if !b {
                        return future::ok(false);
                    }
                    let contract = contract_inner.lock().unwrap();
                    contract
                        .call_with_confirmations(
                            "approve",
                            (w3_spender_address, w3_value),
                            w3_msg_sender,
                            Options::with(|v| v.gas = Some(1_000_000.into())),
                            NUM_CONFIRMATIONS,
                        )
                        .map_err(|e| Error::new(e.description()))
                        .map(
                            move |_tr| // TODO: do something with the TransactionReceipt object
                             future::ok(b),
                        )
                        .wait()
                        .unwrap()
                })
        }))
    }

    fn approve_and_call(
        &self,
        msg_sender: B256,
        spender_address: B256,
        value: AmountType,
        extra_data: Vec<u8>,
    ) -> BoxFuture<bool> {
        let contract = self.contract.clone();
        Box::new(future::lazy(move || {
            let contract_inner = contract.clone();
            let contract = contract.lock().unwrap();
            let w3_msg_sender = b256_to_web3_address(msg_sender);
            let w3_spender_address = b256_to_web3_address(spender_address);
            let w3_value = amount_to_web3_u256(value);
            // let w3_extra_data = web3::types::Bytes::from(extra_data);
            contract
                .query(
                    "approveAndCall",
                    (w3_spender_address, w3_value, extra_data.clone()),
                    w3_msg_sender,
                    Options::default(),
                    None,
                )
                .map_err(|e| Error::new(e.description()))
                .and_then(move |b: bool| {
                    if !b {
                        return future::ok(false);
                    }
                    let contract = contract_inner.lock().unwrap();
                    contract
                        .call_with_confirmations(
                            "approveAndCall",
                            (w3_spender_address, w3_value, extra_data),
                            w3_msg_sender,
                            Options::with(|v| v.gas = Some(1_000_000.into())),
                            NUM_CONFIRMATIONS,
                        )
                        .map_err(|e| Error::new(e.description()))
                        .map(
                            move |_tr| // TODO: do something with the TransactionReceipt object
                             future::ok(b),
                        )
                        .wait()
                        .unwrap()
                })
        }))
    }

    fn allowance(&self, owner: B256, spender: B256) -> BoxFuture<AmountType> {
        let contract = self.contract.clone();
        let local_eth_address = self.local_eth_address;
        Box::new(future::lazy(move || {
            let contract = contract.lock().unwrap();
            let w3_owner = b256_to_web3_address(owner);
            let w3_spender = b256_to_web3_address(spender);
            contract
                .query(
                    "allowance",
                    (w3_owner, w3_spender),
                    local_eth_address,
                    Options::default(),
                    None,
                )
                .map(|v| web3_u256_to_amount(v))
                .map_err(|e| Error::new(e.description()))
        }))
    }

    fn burn(&self, msg_sender: B256, value: AmountType) -> BoxFuture<bool> {
        let contract = self.contract.clone();
        Box::new(future::lazy(move || {
            let contract_inner = contract.clone();
            let contract = contract.lock().unwrap();
            let w3_msg_sender = b256_to_web3_address(msg_sender);
            let w3_value = amount_to_web3_u256(value);
            contract
                .query("burn", w3_value, w3_msg_sender, Options::default(), None)
                .map_err(|e| Error::new(e.description()))
                .and_then(move |b: bool| {
                    if !b {
                        return future::ok(false);
                    }
                    let contract = contract_inner.lock().unwrap();
                    contract
                        .call_with_confirmations(
                            "burn",
                            w3_value,
                            w3_msg_sender,
                            Options::with(|v| v.gas = Some(1_000_000.into())),
                            NUM_CONFIRMATIONS,
                        )
                        .map_err(|e| Error::new(e.description()))
                        .map(
                            move |_tr| // TODO: do something with the TransactionReceipt object
                             future::ok(b),
                        )
                        .wait()
                        .unwrap()
                })
        }))
    }

    fn burn_from(&self, msg_sender: B256, owner: B256, value: AmountType) -> BoxFuture<bool> {
        let contract = self.contract.clone();
        Box::new(future::lazy(move || {
            let contract_inner = contract.clone();
            let contract = contract.lock().unwrap();
            let w3_msg_sender = b256_to_web3_address(msg_sender);
            let w3_owner = b256_to_web3_address(owner);
            let w3_value = amount_to_web3_u256(value);
            contract
                .query(
                    "burnFrom",
                    (w3_owner, w3_value),
                    w3_msg_sender,
                    Options::default(),
                    None,
                )
                .map_err(|e| Error::new(e.description()))
                .and_then(move |b: bool| {
                    if !b {
                        return future::ok(false);
                    }
                    let contract = contract_inner.lock().unwrap();
                    contract
                        .call_with_confirmations(
                            "burnFrom",
                            (w3_owner, w3_value),
                            w3_msg_sender,
                            Options::with(|v| v.gas = Some(1_000_000.into())),
                            NUM_CONFIRMATIONS,
                        )
                        .map_err(|e| Error::new(e.description()))
                        .map(
                            move |_tr| // TODO: do something with the TransactionReceipt object
                             future::ok(b),
                        )
                        .wait()
                        .unwrap()
                })
        }))
    }

    fn allocate_escrow(
        &self,
        msg_sender: B256,
        target: B256,
        escrow_amount: AmountType,
        aux: B256,
    ) -> BoxFuture<EscrowAccountIdType> {
        let contract = self.contract.clone();
        Box::new(future::lazy(move || {
            let contract_inner = contract.clone();
            let contract = contract.lock().unwrap();
            let w3_msg_sender = b256_to_web3_address(msg_sender);
            let w3_target = b256_to_web3_address(target);
            let w3_escrow_amount = amount_to_web3_u256(escrow_amount);
            let w3_aux = b256_to_web3_bytes32(aux);
            debug!("w3_msg_sender {}", w3_msg_sender);
            debug!("w3_target {}", w3_target);
            debug!("w3_escrow_amount {}", w3_escrow_amount);
            debug!("w3_aux {:?}", w3_aux);
            contract
                .query(
                    "allocateEscrow",
                    (w3_target, w3_escrow_amount, w3_aux.clone()),
                    w3_msg_sender,
                    Options::default(),
                    None,
                )
                .map_err(|e| Error::new(e.description()))
                .and_then(move |id: web3::types::U256| {
                    let contract = contract_inner.lock().unwrap();
                    debug!("w3_msg_sender {}", w3_msg_sender);
                    debug!("w3_target {}", w3_target);
                    debug!("w3_escrow_amount {}", w3_escrow_amount);
                    debug!("w3_aux {:?}", w3_aux);
                    contract
                        .call_with_confirmations(
                            "allocateEscrow",
                            (w3_target, w3_escrow_amount, w3_aux),
                            w3_msg_sender,
                            Options::with(|v| v.gas = Some(1_000_000.into())),
                            NUM_CONFIRMATIONS,
                        )
                        .map_err(|e| Error::new(e.description()))
                        .map(
                            move |_tr| // TODO: do something with the TransactionReceipt object
                             future::ok(web3_u256_to_escrow_account_id(id)),
                        )
                        .wait()
                        .unwrap()
                })
        }))
    }

    fn list_active_escrows_iterator(&self, owner: B256) -> BoxFuture<EscrowAccountIterator> {
        let contract = self.contract.clone();
        let local_eth_address = self.local_eth_address;
        Box::new(future::lazy(move || {
            let contract = contract.lock().unwrap();
            let w3_owner = b256_to_web3_address(owner);
            contract
                .query(
                    "listActiveEscrowsIterator",
                    w3_owner,
                    local_eth_address,
                    Options::default(),
                    None,
                )
                .map_err(|e| Error::new(e.description()))
                .map(move |result| {
                    let (has_next, state): (bool, web3::types::U256) = result;
                    EscrowAccountIterator::new(has_next, owner, web3_u256_to_b256(state))
                })
        }))
    }

    fn list_active_escrows_get(
        &self,
        iter: EscrowAccountIterator,
    ) -> BoxFuture<(EscrowAccountStatus, EscrowAccountIterator)> {
        // web3 can only decode up to 5 contract call results
        unimplemented!();
    }

    fn fetch_escrow_by_id(&self, escrow_id: EscrowAccountIdType) -> BoxFuture<EscrowAccountStatus> {
        let contract = self.contract.clone();
        let local_eth_address = self.local_eth_address;
        Box::new(future::lazy(move || {
            let contract = contract.lock().unwrap();
            contract
                .query(
                    "fetchEscrowById",
                    escrow_account_id_to_web_u256(escrow_id),
                    local_eth_address,
                    Options::default(),
                    None,
                )
                .map_err(|e| Error::new(e.description()))
                .then(move |r| {
                    match r {
                        Ok(result) => {
                            let (_owner, target, amount, aux): (
                                web3::types::H160, // address
                                web3::types::H160, // address
                                web3::types::U256,
                                web3::types::H256, // bytes32
                            ) = result;
                            // let owner = B256::from_slice(&owner.to_vec());
                            let target = web3_address_to_b256(target);
                            let amount = web3_u256_to_amount(amount);
                            let aux = web3_bytes32_to_b256(aux);
                            Ok(EscrowAccountStatus::new(escrow_id, target, amount, aux))
                        }
                        Err(e) => return Err(e),
                    }
                })
        }))
    }

    fn take_and_release_escrow(
        &self,
        _msg_sender: B256,
        _escrow_id: EscrowAccountIdType,
        _amount_requested: AmountType,
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
            Arc::new(EthereumStake::new(client, local_identity, contract_address)
                .map_err(|e| ekiden_di::error::Error::from(e.description()))?);
        Ok(Box::new(instance))
    }),
    [Arg::with_name("stake-address")
        .long("stake-address")
        .env("STAKE_ADDRESS")
        .help("Ethereum address at which the stake contract has been deployed")
        .takes_value(true)]
);
