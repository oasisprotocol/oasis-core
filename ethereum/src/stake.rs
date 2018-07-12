use std::error::Error as StdError;
use std::result::Result as StdResult;
use std::sync::{Arc, Mutex};

use ekiden_common::bytes::{B256, H160};
use ekiden_common::entity::Entity;
use ekiden_common::error::{Error, Result};
use ekiden_common::futures::{future, BoxFuture, Future};
use ekiden_di;
#[allow(unused_imports)]
use rustc_hex::FromHex;
use serde_json;
use web3;
use web3::api::Web3;
use web3::contract::{Contract as EthContract, Options};
use web3::Transport;

use ekiden_stake_base::*;

const STAKE_CONTRACT: &[u8] = include_bytes!("../build/contracts/Stake.json");
const NUM_CONFIRMATIONS: usize = 2;
// This value is arbitrary. Could be exposed as part of the call interfaces.
const DEFAULT_GAS: u64 = 1_000_000;

/// Ethereum Stake implementation.
pub struct EthereumStake<T: Transport + Sync + Send> {
    contract: Arc<Mutex<EthContract<T>>>,
    local_eth_address: web3::types::H160,
}

// The web3 code uses the loopback interface to talk to the blockchain implementation, so
// the (string) values in the JSON RPC should be well-formatted, except if/when there are
// bugs in the blockchain or web3 code.
fn web3_u256_to_amount(v: web3::types::U256) -> AmountType {
    let mut slice = [0u8; 32];
    v.to_little_endian(&mut slice);
    AmountType::from_little_endian(&slice)
}

fn amount_to_web3_u256(v: AmountType) -> web3::types::U256 {
    web3::types::U256::from_little_endian(&v.to_vec())
}

fn b256_to_web3_address(v: B256) -> web3::types::H160 {
    web3::types::H160::from_slice(&v.to_vec())
}

// We will need this once we get web3 to decode 6 outputs
#[allow(dead_code)]
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

        let instance = Self {
            contract: Arc::new(Mutex::new(contract)),
            local_eth_address: local_eth_address,
        };

        Ok(instance)
    }
}

impl<T: 'static + Transport + Sync + Send> StakeEscrowBackend for EthereumStake<T>
where
    <T as web3::Transport>::Out: Send,
{
    fn link_to_dispute_resolution(&self, address: B256) -> BoxFuture<bool> {
        let contract = self.contract.clone();
        let local_eth_address = self.local_eth_address;
        Box::new(future::lazy(move || {
            let contract_inner = contract.clone();
            let contract = contract.lock().unwrap();
            let w3_address = b256_to_web3_address(address);
            contract
                .query(
                    "linkToDisputeResolution",
                    w3_address.clone(),
                    local_eth_address.clone(),
                    Options::default(),
                    None,
                )
                .map_err(|e| Error::new(e.description()))
                .and_then(move |b: bool| -> BoxFuture<bool> {
                    if !b {
                        return Box::new(future::ok(b));
                    }
                    let contract = contract_inner.lock().unwrap();
                    Box::new(
                        contract
                            .call_with_confirmations(
                                "linkToDisputeResolution",
                                w3_address,
                                local_eth_address,
                                Options::with(|v| v.gas = Some(DEFAULT_GAS.into())),
                                NUM_CONFIRMATIONS,
                            )
                            .map_err(|e| Error::new(e.description()))
                            .map(move |_tr| b),
                    ) // TODO: do something with the TransactionReceipt object
                })
        }))
    }

    fn link_to_entity_registry(&self, address: B256) -> BoxFuture<bool> {
        let contract = self.contract.clone();
        let local_eth_address = self.local_eth_address;
        Box::new(future::lazy(move || {
            let contract_inner = contract.clone();
            let contract = contract.lock().unwrap();
            let w3_address = b256_to_web3_address(address);
            contract
                .query(
                    "linkToEntityRegistry",
                    w3_address.clone(),
                    local_eth_address.clone(),
                    Options::default(),
                    None,
                )
                .map_err(|e| Error::new(e.description()))
                .and_then(move |b: bool| -> BoxFuture<bool> {
                    if !b {
                        return Box::new(future::ok(b));
                    }
                    let contract = contract_inner.lock().unwrap();
                    Box::new(
                        contract
                            .call_with_confirmations(
                                "linkToEntityRegistry",
                                w3_address,
                                local_eth_address,
                                Options::with(|v| v.gas = Some(DEFAULT_GAS.into())),
                                NUM_CONFIRMATIONS,
                            )
                            .map_err(|e| Error::new(e.description()))
                            .map(move |_tr| b),
                    ) // TODO: do something with the TransactionReceipt object
                })
        }))
    }

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
                .and_then(move |b: bool| -> BoxFuture<bool> {
                    if !b {
                        return Box::new(future::ok(b));
                    }
                    let contract = contract_inner.lock().unwrap();
                    Box::new(
                        contract
                            .call_with_confirmations(
                                "transfer",
                                (w3_destination_address, w3_value),
                                w3_msg_sender,
                                Options::with(|v| v.gas = Some(DEFAULT_GAS.into())),
                                NUM_CONFIRMATIONS,
                            )
                            .map_err(|e| Error::new(e.description()))
                            .map(move |_tr| b),
                    ) // TODO: do something with the TransactionReceipt object
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
                .and_then(move |b: bool| -> BoxFuture<bool> {
                    if !b {
                        return Box::new(future::ok(false));
                    }
                    let contract = contract_inner.lock().unwrap();
                    Box::new(
                        contract
                            .call_with_confirmations(
                                "transferFrom",
                                (w3_source_address, w3_destination_address, w3_value),
                                w3_msg_sender,
                                Options::with(|v| v.gas = Some(DEFAULT_GAS.into())),
                                NUM_CONFIRMATIONS,
                            )
                            .map_err(|e| Error::new(e.description()))
                            .map(move |_tr| b),
                    ) // TODO: do something with the TransactionReceipt object
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
                .and_then(move |b: bool| -> BoxFuture<bool> {
                    if !b {
                        return Box::new(future::ok(false));
                    }
                    let contract = contract_inner.lock().unwrap();
                    Box::new(
                        contract
                            .call_with_confirmations(
                                "approve",
                                (w3_spender_address, w3_value),
                                w3_msg_sender,
                                Options::with(|v| v.gas = Some(DEFAULT_GAS.into())),
                                NUM_CONFIRMATIONS,
                            )
                            .map_err(|e| Error::new(e.description()))
                            .map(move |_tr| b),
                    ) // TODO: do something with the TransactionReceipt object
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
                .and_then(move |b: bool| -> BoxFuture<bool> {
                    if !b {
                        return Box::new(future::ok(false));
                    }
                    let contract = contract_inner.lock().unwrap();
                    Box::new(
                        contract
                            .call_with_confirmations(
                                "approveAndCall",
                                (w3_spender_address, w3_value, extra_data),
                                w3_msg_sender,
                                Options::with(|v| v.gas = Some(DEFAULT_GAS.into())),
                                NUM_CONFIRMATIONS,
                            )
                            .map_err(|e| Error::new(e.description()))
                            .map(move |_tr| b),
                    ) // TODO: do something with the TransactionReceipt object
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
                .and_then(move |b: bool| -> BoxFuture<bool> {
                    if !b {
                        return Box::new(future::ok(false));
                    }
                    let contract = contract_inner.lock().unwrap();
                    Box::new(
                        contract
                            .call_with_confirmations(
                                "burn",
                                w3_value,
                                w3_msg_sender,
                                Options::with(|v| v.gas = Some(DEFAULT_GAS.into())),
                                NUM_CONFIRMATIONS,
                            )
                            .map_err(|e| Error::new(e.description()))
                            .map(move |_tr| b),
                    ) // TODO: do something with the TransactionReceipt object
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
                .and_then(move |b: bool| -> BoxFuture<bool> {
                    if !b {
                        return Box::new(future::ok(false));
                    }
                    let contract = contract_inner.lock().unwrap();
                    Box::new(
                        contract
                            .call_with_confirmations(
                                "burnFrom",
                                (w3_owner, w3_value),
                                w3_msg_sender,
                                Options::with(|v| v.gas = Some(DEFAULT_GAS.into())),
                                NUM_CONFIRMATIONS,
                            )
                            .map_err(|e| Error::new(e.description()))
                            .map(move |_tr| b),
                    ) // TODO: do something with the TransactionReceipt object
                })
        }))
    }

    fn add_escrow(&self, msg_sender: B256, escrow_amount: AmountType) -> BoxFuture<AmountType> {
        let contract = self.contract.clone();
        Box::new(future::lazy(move || {
            let contract_inner = contract.clone();
            let contract = contract.lock().unwrap();
            let w3_msg_sender = b256_to_web3_address(msg_sender);
            let w3_escrow_amount = amount_to_web3_u256(escrow_amount);
            debug!("w3_msg_sender {}", w3_msg_sender);
            debug!("w3_escrow_amount {}", w3_escrow_amount);
            contract
                .query(
                    "addEscrow",
                    w3_escrow_amount,
                    w3_msg_sender,
                    Options::default(),
                    None,
                )
                .map_err(|e| Error::new(e.description()))
                .and_then(
                    move |total_escrow_so_far: web3::types::U256| -> BoxFuture<AmountType> {
                        let contract = contract_inner.lock().unwrap();
                        debug!("w3_msg_sender {}", w3_msg_sender);
                        debug!("w3_escrow_amount {}", w3_escrow_amount);
                        Box::new(
                            contract
                                .call_with_confirmations(
                                    "addEscrow",
                                    w3_escrow_amount,
                                    w3_msg_sender,
                                    Options::with(|v| v.gas = Some(DEFAULT_GAS.into())),
                                    NUM_CONFIRMATIONS,
                                )
                                .map_err(|e| Error::new(e.description()))
                                .map(move |_tr| web3_u256_to_amount(total_escrow_so_far)),
                        )
                        // TODO: do something with the TransactionReceipt object
                    },
                )
        }))
    }

    fn fetch_escrow_amount(&self, owner: B256) -> BoxFuture<AmountType> {
        let contract = self.contract.clone();
        let local_eth_address = self.local_eth_address;
        Box::new(future::lazy(move || {
            let contract = contract.lock().unwrap();
            contract
                .query(
                    "fetchEscrowAmount",
                    b256_to_web3_address(owner),
                    local_eth_address,
                    Options::default(),
                    None,
                )
                .map_err(|e| Error::new(e.description()))
                .then(move |r| match r {
                    Ok(result) => {
                        let amount: web3::types::U256 = result;
                        let amount = web3_u256_to_amount(amount);
                        Ok(amount)
                    }
                    Err(e) => return Err(e),
                })
        }))
    }

    fn take_escrow(
        &self,
        msg_sender: B256,
        owner: B256,
        amount_requested: AmountType,
    ) -> BoxFuture<AmountType> {
        let contract = self.contract.clone();
        Box::new(future::lazy(move || {
            let contract_inner = contract.clone();
            let contract = contract.lock().unwrap();
            let w3_msg_sender = b256_to_web3_address(msg_sender);
            let w3_owner = b256_to_web3_address(owner);
            let w3_amount = amount_to_web3_u256(amount_requested);
            contract
                .query(
                    "takeEscrow",
                    (w3_owner, w3_amount),
                    w3_msg_sender,
                    Options::default(),
                    None,
                )
                .map_err(|e| Error::new(e.description()))
                .and_then(
                    move |amount_taken: web3::types::U256| -> BoxFuture<AmountType> {
                        let contract = contract_inner.lock().unwrap();
                        Box::new(
                            contract
                                .call_with_confirmations(
                                    "takeEscrow",
                                    (w3_owner, w3_amount),
                                    w3_msg_sender,
                                    Options::with(|v| v.gas = Some(DEFAULT_GAS.into())),
                                    NUM_CONFIRMATIONS,
                                )
                                .map_err(|e| Error::new(e.description()))
                                .map(move |_tr| web3_u256_to_amount(amount_taken)),
                        )
                        // TODO: do something with the TransactionReceipt object
                    },
                )
        }))
    }

    fn release_escrow(&self, msg_sender: B256, owner: B256) -> BoxFuture<AmountType> {
        let contract = self.contract.clone();
        Box::new(future::lazy(move || {
            let contract_inner = contract.clone();
            let contract = contract.lock().unwrap();
            let w3_msg_sender = b256_to_web3_address(msg_sender);
            let w3_owner = b256_to_web3_address(owner);
            contract
                .query(
                    "releaseEscrow",
                    w3_owner,
                    w3_msg_sender,
                    Options::default(),
                    None,
                )
                .map_err(|e| Error::new(e.description()))
                .and_then(
                    move |amount_returned: web3::types::U256| -> BoxFuture<AmountType> {
                        let contract = contract_inner.lock().unwrap();
                        Box::new(
                            contract
                                .call_with_confirmations(
                                    "releaseEscrow",
                                    w3_owner,
                                    w3_msg_sender,
                                    Options::with(|v| v.gas = Some(DEFAULT_GAS.into())),
                                    NUM_CONFIRMATIONS,
                                )
                                .map_err(|e| Error::new(e.description()))
                                .map(move |_tr| web3_u256_to_amount(amount_returned)),
                        )
                        // TODO: do something with the TransactionReceipt object
                    },
                )
        }))
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
        .env("ENV_Stake")
        .help("Ethereum address at which the stake contract has been deployed")
        .takes_value(true)]
);
