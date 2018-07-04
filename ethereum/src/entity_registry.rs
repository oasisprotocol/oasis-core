//! Ekiden ethereum registry backend.
use std::error::Error as StdError;
use std::mem;
use std::sync::{Arc, Mutex};

use ekiden_beacon_base::RandomBeacon;
use ekiden_common::bytes::{self, B256, H160};
use ekiden_common::entity::Entity;
use ekiden_common::environment::Environment;
use ekiden_common::error::{Error, Result};
use ekiden_common::futures::sync::oneshot;
use ekiden_common::futures::{future, BoxFuture, BoxStream, Future, FutureExt, Stream};
use ekiden_common::node::Node;
use ekiden_common::signature::Signed;
use ekiden_epochtime::interface::EpochTime;
use ekiden_epochtime::local::{LocalTimeSourceNotifier, SystemTimeSource};
use ekiden_registry_base::*;
use ekiden_registry_dummy::DummyEntityRegistryBackend;
use ekiden_storage_base::{self, StorageBackend};
use ethabi::Token;
use web3;
use web3::api::Web3;
use web3::contract::{Contract as EthContract, Options};
use web3::types::BlockNumber;
use web3::Transport;

use serde_json;

// TODO: Handle storage expiry.
const STORAGE_EXPIRY_TIME: u64 = 90;

const ENTITY_CONTRACT: &[u8] = include_bytes!("../build/contracts/EntityRegistry.json");

const ENTITY_EVENT_HASH: &str = //keccak("Entity(address,bytes32,uint64)")
    "0x26ef326f5bd7e981515a9f6b5c1deb897a2508954e4844cf86285d0b114516ef";
const DEREG_EVENT_HASH: &str = //keccak("Dereg(address,bytes32,uint64)")
    "0xc42c74f23e325011f741fc6090dc36b92e41701ef87fc58139737e2ab466a3ef";
const NODE_EVENT_HASH: &str = //keccak("Node(address,bytes32,uint64)")
    "0x63fdac5d85a0554c1ec78ea77a9f98ebff4d3a7468e8f93bfd02d18dd90151b4";

/// An ethereum-backed entity registry.
pub struct EthereumEntityRegistryBackend<T: Transport + Sync + Send> {
    contract: Arc<Mutex<EthContract<T>>>,
    client: Arc<Web3<T>>,
    storage: Arc<StorageBackend>,
    local_identity: Arc<Entity>,
    /// Local cache of state.
    cache: Arc<DummyEntityRegistryBackend>,
}

impl<T: 'static + Transport + Sync + Send> EthereumEntityRegistryBackend<T>
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
        let contract_dfn: serde_json::Value = match serde_json::from_slice(ENTITY_CONTRACT) {
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

        let beacon_env = environment.clone();
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
                    // Disconnect notifications from the time source, so that it's
                    // the responsibility of this object to call `mark_epoch` on the
                    // cache to advance epochs there.
                    let never_notifying_notifier =
                        LocalTimeSourceNotifier::new(Arc::new(SystemTimeSource {}));
                    Ok(Self {
                        contract: Arc::new(Mutex::new(contract)),
                        client: client.clone(),
                        storage: storage,
                        local_identity: local_identity,
                        cache: Arc::new(DummyEntityRegistryBackend::new(
                            Arc::new(never_notifying_notifier),
                            beacon_env,
                        )),
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

    fn start(&self, beacon: Arc<RandomBeacon>, environment: Arc<Environment>) -> Result<()> {
        let contract = self.contract.clone();
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
            let update_cache = cache.clone();
            let storage = storage.clone();
            let sender = sender.clone();
            let (epoch, _) = notify;
            let current_block = beacon.get_block_for_epoch(epoch).unwrap();
            // TODO: replace catchup of all blocks with state of contract.
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
                            EthereumEntityRegistryBackend::<T>::on_log(
                                cache.clone(),
                                storage.clone(),
                                &log,
                            )
                        })).into_box(),
                    })
                })
                .and_then(move |_r| {
                    update_cache.mark_epoch(current_block);
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
        environment.spawn(Box::new(triggers.then(|_r| future::ok(()))));

        receiver.wait().unwrap() // Block till filter is installed.
    }

    fn on_log(
        cache: Arc<DummyEntityRegistryBackend>,
        storage: Arc<StorageBackend>,
        log: &web3::types::Log,
    ) -> BoxFuture<()> {
        if log.topics.len() < 3 {
            return future::err(Error::new("Invalid Log")).into_box();
        }

        debug!("Log Received: {:?}", log);
        match format!("0x{:#x}", log.topics[0]).as_str() {
            ENTITY_EVENT_HASH => {
                measure_counter_inc!("entity_registry_entity_log", 1);
                //let eth_address = log.topics[1];
                let storage_hash = log.topics[2];
                storage
                    .get(bytes::H256(storage_hash.0))
                    .and_then(
                        move |entity_bytes| match serde_json::from_slice(&entity_bytes) {
                            Ok(entity) => {
                                trace!("registering entity.");
                                cache.register_entity(entity)
                            }
                            Err(e) => future::err(Error::new(e.description())).into_box(),
                        },
                    )
                    .into_box()
            }
            DEREG_EVENT_HASH => {
                measure_counter_inc!("entity_registry_entity_log", -1);
                let storage_hash = log.topics[2];
                storage
                    .get(bytes::H256(storage_hash.0))
                    .and_then(move |id_bytes| match serde_json::from_slice(&id_bytes) {
                        Ok(id) => {
                            trace!("deregistering entity.");
                            cache.deregister_entity(id)
                        }
                        Err(e) => future::err(Error::new(e.description())).into_box(),
                    })
                    .into_box()
            }
            NODE_EVENT_HASH => {
                measure_counter_inc!("entity_registry_node_log", 1);
                let storage_hash = log.topics[2];
                storage
                    .get(bytes::H256(storage_hash.0))
                    .and_then(
                        move |node_bytes| match serde_json::from_slice(&node_bytes) {
                            Ok(node) => {
                                trace!("deregistering node.");
                                cache.register_node(node)
                            }
                            Err(e) => future::err(Error::new(e.description())).into_box(),
                        },
                    )
                    .into_box()
            }
            _ => future::err(Error::new("Unexpected log topic")).into_box(),
        }
    }
}

impl<T: 'static + Transport + Sync + Send> EntityRegistryBackend
    for EthereumEntityRegistryBackend<T>
where
    <T as web3::Transport>::Out: Send,
{
    fn register_entity(&self, entity: Signed<Entity>) -> BoxFuture<()> {
        let contract = self.contract.clone();
        let local_ident = self.local_identity.clone();

        // Fail fast.
        match entity.clone().open(&REGISTER_ENTITY_SIGNATURE_CONTEXT) {
            Ok(_) => (),
            Err(e) => return Box::new(future::err(e)),
        };

        // Store the signed entity, so others replaying the contract log also re-validate.
        let entity_bytes = serde_json::to_vec(&entity).unwrap();
        Box::new(
            self.storage
                .insert(entity_bytes.clone(), STORAGE_EXPIRY_TIME)
                .and_then(move |_r| {
                    let e_hash = ekiden_storage_base::hash_storage_key(&entity_bytes);
                    // TODO: call confirmations may need to be setable for safety
                    let contract = contract.lock().unwrap();
                    debug!("Registering Entity with smart contract");
                    contract
                        .call_with_confirmations(
                            "register",
                            Token::FixedBytes(e_hash.to_vec()),
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
                    debug!("Entity registered with smart contract");
                    future::ok(())
                }),
        )
    }

    fn deregister_entity(&self, id: Signed<B256>) -> BoxFuture<()> {
        let contract = self.contract.clone();
        let local_ident = self.local_identity.clone();

        match id.open(&DEREGISTER_ENTITY_SIGNATURE_CONTEXT) {
            Ok(_) => (),
            Err(e) => return Box::new(future::err(e)),
        };

        // Store the signed dereg, so others replaying the contract log also re-validate.
        let bytes = serde_json::to_vec(&id).unwrap();
        Box::new(
            self.storage
                .insert(bytes.clone(), STORAGE_EXPIRY_TIME)
                .and_then(move |_r| {
                    let e_hash = ekiden_storage_base::hash_storage_key(&bytes);
                    // TODO: call confirmations may need to be setable for safety
                    let contract = contract.lock().unwrap();
                    contract
                        .call_with_confirmations(
                            "deregister",
                            Token::FixedBytes(e_hash.to_vec()),
                            web3::types::H160(local_ident.eth_address.unwrap_or(H160::default()).0),
                            Options::default(),
                            2,
                        )
                        .map_err(|e| {
                            println!("deregister failed. {:?}", e);
                            Error::new(e.description())
                        })
                })
                .and_then(move |_r| future::ok(())),
        )
    }

    fn get_entity(&self, id: B256) -> BoxFuture<Entity> {
        let cache = self.cache.clone();
        cache.get_entity(id)
    }

    fn get_entities(&self) -> BoxFuture<Vec<Entity>> {
        let cache = self.cache.clone();
        cache.get_entities()
    }

    fn watch_entities(&self) -> BoxStream<RegistryEvent<Entity>> {
        let cache = self.cache.clone();
        cache.watch_entities()
    }

    fn register_node(&self, node: Signed<Node>) -> BoxFuture<()> {
        let contract = self.contract.clone();
        let local_ident = self.local_identity.clone();

        // Fail fast.
        match node.clone().open(&REGISTER_NODE_SIGNATURE_CONTEXT) {
            Ok(_) => (),
            Err(e) => return Box::new(future::err(e)),
        };

        let node_bytes = serde_json::to_vec(&node).unwrap();
        Box::new(
            self.storage
                .insert(node_bytes.clone(), STORAGE_EXPIRY_TIME)
                .and_then(move |_r| {
                    let n_hash = ekiden_storage_base::hash_storage_key(&node_bytes);
                    // TODO: call confirmations may need to be setable for safety
                    let contract = contract.lock().unwrap();
                    contract
                        .call_with_confirmations(
                            "registerNode",
                            Token::FixedBytes(n_hash.to_vec()),
                            web3::types::H160(local_ident.eth_address.unwrap_or(H160::default()).0),
                            Options::default(),
                            2,
                        )
                        .map_err(|e| {
                            println!("registerNode failed. {:?}", e);
                            Error::new(e.description())
                        })
                })
                .and_then(move |_r| future::ok(())),
        )
    }

    fn get_node(&self, id: B256) -> BoxFuture<Node> {
        let cache = self.cache.clone();
        cache.get_node(id)
    }

    fn get_nodes(&self, epoch: EpochTime) -> BoxFuture<Vec<Node>> {
        let cache = self.cache.clone();
        cache.get_nodes(epoch)
    }

    fn get_nodes_for_entity(&self, id: B256) -> BoxFuture<Vec<Node>> {
        let cache = self.cache.clone();
        cache.get_nodes_for_entity(id)
    }

    fn watch_nodes(&self) -> BoxStream<RegistryEvent<Node>> {
        let cache = self.cache.clone();
        cache.watch_nodes()
    }

    fn watch_node_list(&self) -> BoxStream<(EpochTime, Vec<Node>)> {
        let cache = self.cache.clone();
        cache.watch_node_list()
    }
}
