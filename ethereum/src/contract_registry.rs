//! Ekiden ethereum contract registry backend.
use std::error::Error as StdError;
use std::mem;
use std::sync::{Arc, Mutex};

use ekiden_beacon_base::RandomBeacon;
use ekiden_common::bytes::{self, B256, H160};
use ekiden_common::contract::Contract as EkContract;
use ekiden_common::entity::Entity;
use ekiden_common::environment::Environment;
use ekiden_common::error::{Error, Result};
use ekiden_common::futures::prelude::*;
use ekiden_common::futures::sync::oneshot;
use ekiden_common::signature::Signed;
use ekiden_registry_base::*;
use ekiden_registry_dummy::DummyContractRegistryBackend;
use ekiden_storage_base::{self, StorageBackend};
use ethabi::Token;
use web3;
use web3::api::Web3;
use web3::contract::{Contract as EthContract, Options};
use web3::types::BlockNumber;
use web3::Transport;

use serde_json;

// TODO: Handle storage expiry.
const STORAGE_EXPIRY_TIME: u64 = u64::max_value();

const CONTRACT_CONTRACT: &[u8] = include_bytes!("../build/contracts/ContractRegistry.json");

const CONTRACT_EVENT_HASH: &str = //keccak("Contract(bytes32,uint64)")
    "0xeeac550fcccadfa80b03136ae0ced2245491aa3f53262fbc74a401f2b82458d5";

/// An ethereum-backed contract registry.
pub struct EthereumContractRegistryBackend<T: Transport + Sync + Send> {
    eth_contract: Arc<Mutex<EthContract<T>>>,
    client: Arc<Web3<T>>,
    storage: Arc<StorageBackend>,
    local_identity: Arc<Entity>,
    /// Local cache of state.
    cache: Arc<DummyContractRegistryBackend>,
}

impl<T: 'static + Transport + Sync + Send> EthereumContractRegistryBackend<T>
where
    <T as web3::Transport>::Out: Send,
{
    pub fn new(
        client: Arc<Web3<T>>,
        local_identity: Arc<Entity>,
        contract_address: bytes::H160,
        storage: Arc<StorageBackend>,
        beacon: Arc<RandomBeacon>,
        environment: Arc<Environment>,
    ) -> Result<Self> {
        let contract_dfn: serde_json::Value = match serde_json::from_slice(CONTRACT_CONTRACT) {
            Ok(c) => c,
            Err(e) => return Err(Error::new(e.description())),
        };
        let contract_abi = match serde_json::to_vec(&contract_dfn["abi"]) {
            Ok(abi) => abi,
            Err(e) => return Err(Error::new(e.description())),
        };

        let contract_address = web3::types::H160(contract_address.0);
        let contract = match EthContract::from_json(client.eth(), contract_address, &contract_abi) {
            Ok(c) => c,
            Err(e) => return Err(Error::new(e.description())),
        };

        let ctor_future = client
            .eth()
            .code(contract_address, None)
            .map_err(|e| Error::new(e.description()))
            .and_then(move |code| {
                let actual_str = serde_json::to_string(&code).unwrap_or("".to_string());
                let expected_str = serde_json::to_string(&contract_dfn["deployedBytecode"])
                    .unwrap_or("".to_string());
                if actual_str != expected_str {
                    return Err(Error::new("Contract not deployed at specified address."));
                } else {
                    Ok(Self {
                        eth_contract: Arc::new(Mutex::new(contract)),
                        client: client.clone(),
                        storage: storage,
                        local_identity: local_identity,
                        cache: Arc::new(DummyContractRegistryBackend::new()),
                    })
                }
            });
        let result = ctor_future.wait();
        if result.is_ok() {
            let result = result.unwrap();
            let _ = result.start(beacon, environment);
            Ok(result)
        } else {
            result
        }
    }

    fn on_log(
        cache: Arc<DummyContractRegistryBackend>,
        storage: Arc<StorageBackend>,
        log: &web3::types::Log,
    ) -> BoxFuture<()> {
        if log.topics.len() < 2 {
            return future::err(Error::new("Invalid Log")).into_box();
        }

        debug!("Log Received: {:?}", log);
        match format!("0x{:#x}", log.topics[0]).as_str() {
            CONTRACT_EVENT_HASH => {
                let storage_hash = log.topics[1];
                storage
                    .get(bytes::H256(storage_hash.0))
                    .and_then(
                        move |contract_bytes| match serde_json::from_slice(&contract_bytes) {
                            Ok(contract) => {
                                trace!("registering contract.");
                                cache.register_contract(contract)
                            }
                            Err(e) => future::err(Error::new(e.description())).into_box(),
                        },
                    )
                    .into_box()
            }
            _ => future::err(Error::new("Unexpected log topic")).into_box(),
        }
    }

    fn start(&self, beacon: Arc<RandomBeacon>, environment: Arc<Environment>) -> Result<()> {
        let contract = self.eth_contract.clone();
        let contract = contract.lock().unwrap();
        let contract_address = contract.address();

        let client = self.client.clone();
        let cache = self.cache.clone();
        let storage = self.storage.clone();

        let (sender, receiver): (
            oneshot::Sender<Result<()>>,
            oneshot::Receiver<Result<()>>,
        ) = oneshot::channel();
        let sender = Arc::new(Mutex::new(Some(sender)));

        let triggers = beacon.watch_beacons().fold(0, move |last_block, notify| {
            info!("Beacon triggered. playing log blocks in registry.");
            let eth_filter = client.eth_filter();
            let cache = cache.clone();
            let storage = storage.clone();
            let sender = sender.clone();
            let (epoch, _) = notify;
            let current_block = beacon.get_block_for_epoch(epoch).unwrap();
            let filter = web3::types::FilterBuilder::default()
                .from_block(BlockNumber::Number(last_block))
                .to_block(BlockNumber::Number(current_block - 1))
                .address(vec![contract_address])
                .build();
            let task = eth_filter
                .create_logs_filter(filter)
                .or_else(|e| future::err(Error::new(format!("{:?}", e))))
                .and_then(move |filter| {
                    filter.logs().then(move |r| match r {
                        Err(e) => future::err(Error::new(format!("{:?}", e))).into_box(),
                        Ok(logs) => future::join_all(logs.into_iter().map(move |log| {
                            trace!("Log replay: {:?}", log);
                            EthereumContractRegistryBackend::<T>::on_log(
                                cache.clone(),
                                storage.clone(),
                                &log,
                            )
                        })).into_box(),
                    })
                })
                .and_then(move |_r| {
                    if last_block == 0 {
                        // Caught up.
                        let mut sender = sender.lock().unwrap();
                        match mem::replace(&mut *sender, None) {
                            Some(sender) => sender.send(Ok(())).unwrap(),
                            None => warn!("tried to re-trigger caught-up notification"),
                        }
                    }
                    future::ok(current_block)
                })
                .or_else(|e| {
                    error!("{:?}", e);
                    future::err(e)
                });
            task
        });
        environment.spawn(triggers.discard());

        receiver.wait().unwrap() // Block till filter is installed.
    }
}

impl<T: 'static + Transport + Sync + Send> ContractRegistryBackend
    for EthereumContractRegistryBackend<T>
where
    <T as web3::Transport>::Out: Send,
{
    fn register_contract(&self, reg_contract: Signed<EkContract>) -> BoxFuture<()> {
        let backing_contract = self.eth_contract.clone();
        let local_ident = self.local_identity.clone();

        // Fail fast.
        match reg_contract
            .clone()
            .open(&REGISTER_CONTRACT_SIGNATURE_CONTEXT)
        {
            Ok(_) => (),
            Err(e) => return Box::new(future::err(e)),
        };

        // Store the signed contract, so others replaying the log also re-validate.
        let reg_bytes = serde_json::to_vec(&reg_contract).unwrap();
        Box::new(
            self.storage
                .insert(reg_bytes.clone(), STORAGE_EXPIRY_TIME)
                .and_then(move |_r| {
                    let c_hash = ekiden_storage_base::hash_storage_key(&reg_bytes);
                    // TODO: call confirmations may need to be setable for safety
                    let backing_contract = backing_contract.lock().unwrap();
                    debug!("Registering Contract with smart contract");
                    backing_contract
                        .call_with_confirmations(
                            "register",
                            Token::FixedBytes(c_hash.to_vec()),
                            web3::types::H160(local_ident.eth_address.unwrap_or(H160::default()).0),
                            Options::default(),
                            2,
                        )
                        .map_err(|e| {
                            warn!("register failed. {:?}", e);
                            Error::new(e.description())
                        })
                })
                .and_then(move |_r| {
                    debug!("Contract registered with smart contract");
                    future::ok(())
                }),
        )
    }

    fn get_contract(&self, id: B256) -> BoxFuture<EkContract> {
        let cache = self.cache.clone();
        cache.get_contract(id)
    }

    fn get_contracts(&self) -> BoxStream<EkContract> {
        let cache = self.cache.clone();
        cache.get_contracts()
    }
}
