use std::collections::HashMap;
use std::error::Error as StdError;
use std::result::Result as StdResult;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::Utc;
use ekiden_beacon_base::RandomBeacon;
use ekiden_common::bytes::{B256, H160};
use ekiden_common::entity::Entity;
use ekiden_common::epochtime::{EpochTime, TimeSourceNotifier, EKIDEN_EPOCH_INVALID};
use ekiden_common::error::{Error, Result};
use ekiden_common::futures::sync::{mpsc, oneshot};
use ekiden_common::futures::{future, BoxFuture, BoxStream, Executor, Future, FutureExt, Stream,
                             StreamExt};
use ekiden_common::subscribers::StreamSubscribers;
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

const BEACON_CONTRACT: &[u8] = include_bytes!("../build/contracts/RandomBeacon.json");
const ON_GENERATE_EVENT: &str = // keccak("OnGenerate(uint64,bytes32)")
    "0xd5d707d83256213ad7cdddd1d7ba293c5127ada1c3ebe564f17ee01eca8e5bc4";

/// Ethereum RandomBeacon implementation.
pub struct EthereumRandomBeacon<T: Transport + Sync + Send> {
    inner: Arc<EthereumRandomBeaconCache<T>>,
}

impl<T: 'static + Transport + Sync + Send> EthereumRandomBeacon<T>
where
    <T as web3::Transport>::Out: Send,
{
    // Create a new Ethereum random beacon.
    pub fn new(
        client: Arc<Web3<T>>,
        local_identity: Arc<Entity>,
        contract_address: H160,
        time_notifier: Arc<TimeSourceNotifier>,
    ) -> Result<Self> {
        let local_eth_address = match local_identity.eth_address {
            Some(addr) => web3::types::H160(addr.0),
            None => return Err(Error::new("No local Ethereum address")),
        };

        let contract_dfn: serde_json::Value = serde_json::from_slice(BEACON_CONTRACT)?;
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
                let expected_str = serde_json::to_string(&contract_dfn["deployedBytecode"])
                    .unwrap_or("".to_string());
                if actual_str != expected_str {
                    return Err(Error::new("Contract not deployed at specified address."));
                } else {
                    Ok(Self {
                        inner: Arc::new(EthereumRandomBeaconCache::new(
                            client,
                            contract,
                            local_eth_address,
                            time_notifier,
                        )),
                    })
                }
            });

        ctor_future.wait()
    }

    // Return the block number at which the beacon value for an epoch was
    // generated if any.
    pub fn get_block_for_epoch(&self, epoch: EpochTime) -> Option<u64> {
        let block_number = match self.inner.get_beacon(epoch) {
            Some(ent) => ent.1,
            None => return None,
        };
        Some(block_number)
    }
}

impl<T: 'static + Transport + Sync + Send> RandomBeacon for EthereumRandomBeacon<T>
where
    <T as web3::Transport>::Out: Send,
{
    fn start(&self, executor: &mut Executor) {
        // Start the log watcher.
        let inner = self.inner.clone();
        executor.spawn({
            let (contract, contract_address) = inner.contract();
            let client = inner.client.clone();
            let shared_inner = inner.clone();

            // The initial bootstrapping process is somewhat involved, and
            // works like thus:
            //
            //  1. Get the current block number.
            //  2. RandomBeacon::get_beacon(now), at the block number from 1.
            //  3. Install a log filter starting at the block number from 1.
            //
            // This avoids the need to replay historical logs just to get the
            // current beacon value, and is race-condition free.  The worst
            // that can happen is that the epoch transition happens mid-query
            // resulting in a failure, however the log filter will return
            // events starting at the point of the query, and resolve the
            // problem.

            client
                .eth()
                .block_number()
                .map_err(|e| {
                    error!("start: Failed to query block_number(): {:?}", e);
                    Error::new(e.description())
                })
                .and_then(move |block_number| {
                    let block_number = block_number.low_u64();
                    let now = Utc::now().timestamp();

                    let inner = shared_inner.clone();
                    contract
                        .query(
                            "get_beacon",
                            Token::Uint(web3::types::U256::from(now)),
                            inner.local_eth_address(),
                            Options::default(),
                            BlockNumber::from(block_number),
                        )
                        .then(move |r| {
                            let inner = shared_inner.clone();

                            match r {
                                Ok(result) => {
                                    let (entropy, epoch, block_number): (
                                        web3::types::H256,
                                        u64,
                                        web3::types::U256,
                                    ) = result;
                                    let entropy = B256::from(entropy.0);
                                    let block_number = block_number.low_u64();
                                    let _ = inner.on_beacon(epoch, entropy, block_number);
                                }
                                Err(e) => warn!("start: Failed to query current beacon: {:?}", e),
                            }

                            let filter = web3::types::FilterBuilder::default()
                                .from_block(BlockNumber::from(block_number))
                                .to_block(BlockNumber::Latest)
                                .topics(Some(vec![ON_GENERATE_EVENT.into()]), None, None, None)
                                .address(vec![contract_address])
                                .build();

                            let client = inner.client.clone();
                            let eth_filter = client.eth_filter();

                            eth_filter
                                .create_logs_filter(filter)
                                .or_else(|e| {
                                    warn!("Failed to create log filter stream: {:?}", e);
                                    future::err(Error::new(e.description()))
                                })
                                .and_then(move |filter| {
                                    shared_inner.on_init_done(Ok(()));

                                    filter
                                        .stream(Duration::from_millis(1000))
                                        .map_err(|e| Error::new(e.description()))
                                        .map(move |log| {
                                            trace!("Streamed log: {:?}", log);
                                            shared_inner.on_log(&log)
                                        })
                                        .fold(0, |acc, _x| future::ok::<_, Error>(acc))
                                        .or_else(|e| future::err(Error::new(e.description())))
                                })
                                .and_then(|_r| future::ok(()))
                        })
                })
                .or_else(|e| {
                    error!("Log watcher terminating: {:?}", e);
                    future::ok(())
                })
                .into_box()
        });

        self.inner.start(executor);
    }

    fn get_beacon(&self, epoch: EpochTime) -> BoxFuture<B256> {
        let f = match self.inner.get_beacon(epoch) {
            Some(ent) => future::ok(ent.0),
            None => future::err(Error::new("Beacon not available")),
        };
        f.into_box()
    }

    fn watch_beacons(&self) -> BoxStream<(EpochTime, B256)> {
        self.inner.watch_beacons()
    }
}

enum Command {
    Catchup((mpsc::UnboundedSender<(EpochTime, B256)>, EpochTime)),
}

struct EthereumRandomBeaconCache<T: Transport + Sync + Send> {
    client: Arc<Web3<T>>,
    inner: Arc<Mutex<EthereumRandomBeaconCacheInner<T>>>,
}

struct EthereumRandomBeaconCacheInner<T: Transport + Sync + Send> {
    contract: Arc<EthContract<T>>,
    local_eth_address: web3::types::H160,
    cache: HashMap<EpochTime, (B256, u64)>,
    subscribers: StreamSubscribers<(EpochTime, B256)>,
    command_sender: mpsc::UnboundedSender<Command>,
    command_receiver: Option<mpsc::UnboundedReceiver<Command>>,
    init_sender: Option<oneshot::Sender<Result<()>>>,
    init_receiver: Option<oneshot::Receiver<Result<()>>>,
    time_notifier: Arc<TimeSourceNotifier>,
    last_notify: (EpochTime, B256),
    current_epoch: EpochTime,
}

impl<T: 'static + Transport + Sync + Send> EthereumRandomBeaconCache<T>
where
    <T as web3::Transport>::Out: Send,
{
    pub fn new(
        client: Arc<Web3<T>>,
        contract: EthContract<T>,
        local_eth_address: web3::types::H160,
        time_notifier: Arc<TimeSourceNotifier>,
    ) -> Self {
        Self {
            client,
            inner: Arc::new(Mutex::new(EthereumRandomBeaconCacheInner::new(
                contract,
                local_eth_address,
                time_notifier,
            ))),
        }
    }

    fn start(&self, executor: &mut Executor) {
        let inner = self.inner.clone();
        executor.spawn({
            let mut inner = inner.lock().unwrap();
            let shared_inner = self.inner.clone();

            trace!("Starting epoch watcher.");

            let time_notifier = inner.time_notifier.clone();
            let init_receiver = inner.init_receiver.take().expect("start already called");
            Box::new(
                init_receiver
                    .map_err(|e| Error::new(e.description()))
                    .and_then(move |_r| {
                        trace!("Log filter installed, starting to watch epochs.");

                        time_notifier
                            .watch_epochs()
                            .for_each(move |now| {
                                trace!("On Epoch: {}", now);
                                let mut inner = shared_inner.lock().unwrap();
                                inner.current_epoch = now;
                                if !inner.maybe_notify(now) {
                                    warn!("No beacon for epoch {}, generating.", now);
                                    return inner.set_beacon();
                                }

                                future::ok(()).into_box()
                            })
                            .then(|_| future::ok(()))
                    })
                    .then(|_| future::ok(())),
            )
        });

        // Start the catchup mechanism.
        let inner = self.inner.clone();
        executor.spawn({
            let mut inner = inner.lock().unwrap();
            let shared_inner = self.inner.clone();
            let command_receiver = inner.command_receiver.take().expect("start already called");

            trace!("Starting catchup command receiver.");

            command_receiver
                .map_err(|_| Error::new("command channel closed"))
                .for_each_log_errors(
                    module_path!(),
                    "Unexpected error catching up beacon subscriber",
                    move |command| match command {
                        Command::Catchup((sender, pre_notify_time)) => {
                            if pre_notify_time != EKIDEN_EPOCH_INVALID {
                                let inner = shared_inner.clone();
                                let inner = inner.lock().unwrap();
                                if pre_notify_time == inner.last_notify.0 {
                                    trace!(
                                        "Command::Catchup(): Catch up: Epoch: {} Beacon: {:?}",
                                        inner.last_notify.0,
                                        inner.last_notify.1,
                                    );
                                    sender.unbounded_send(inner.last_notify).unwrap();
                                }
                            }

                            future::ok(())
                        }
                    },
                )
        });
    }

    fn contract(&self) -> (Arc<EthContract<T>>, web3::types::H160) {
        let inner = self.inner.lock().unwrap();
        (inner.contract.clone(), inner.contract.address())
    }

    fn local_eth_address(&self) -> web3::types::H160 {
        let inner = self.inner.lock().unwrap();
        inner.local_eth_address
    }

    fn get_beacon(&self, epoch: EpochTime) -> Option<(B256, u64)> {
        let inner = self.inner.lock().unwrap();
        match inner.cache.get(&epoch) {
            Some(ent) => Some(ent.clone()),
            None => None,
        }
    }

    fn on_beacon(&self, epoch: EpochTime, entropy: B256, block_number: u64) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();

        trace!(
            "OnBeacon: Epoch: {}, Entropy: {:?} BlockNumber: {}.",
            epoch,
            entropy,
            block_number
        );

        match inner.cache.get(&epoch) {
            Some(ent) => {
                // Be tolerant of exact duplicate events.
                if (*ent).0 != entropy {
                    return Err(Error::new("Beacon already cached for epoch"));
                }
                return Ok(());
            }
            None => {}
        }

        inner.cache.insert(epoch, (entropy, block_number));
        let _ = inner.maybe_notify(epoch);

        Ok(())
    }

    fn watch_beacons(&self) -> BoxStream<(EpochTime, B256)> {
        let inner = self.inner.lock().unwrap();
        let (send, recv) = inner.subscribers.subscribe();

        // Add the task for maybe catching up the new subscriber to the queue.
        inner
            .command_sender
            .unbounded_send(Command::Catchup((send, inner.last_notify.0)))
            .unwrap();

        recv
    }

    fn on_log(&self, log: &web3::types::Log) -> BoxFuture<()> {
        if log.topics.len() < 2 {
            return future::err(Error::new("Invalid Log, unexpected topics")).into_box();
        }
        let data = match B256::try_from(&log.data.0) {
            Ok(data) => data,
            Err(e) => return future::err(Error::new(e.description())).into_box(),
        };
        let block_number = match log.block_number {
            Some(block_number) => block_number,
            None => return future::err(Error::new("Invalid Log, no block number")).into_box(),
        };

        match format!("0x{:#x}", log.topics[0]).as_str() {
            ON_GENERATE_EVENT => {
                let epoch = log.topics[1].low_u64();
                let entropy = data;
                let block_number = block_number.low_u64();

                match self.on_beacon(epoch, entropy, block_number) {
                    Ok(_) => future::ok(()).into_box(),
                    Err(e) => future::err(Error::new(e.description())).into_box(),
                }
            }
            _ => future::err(Error::new("Unexpected log topic")).into_box(),
        }
    }

    fn on_init_done(&self, result: Result<()>) {
        let mut inner = self.inner.lock().unwrap();
        let init_sender = inner.init_sender.take().expect("start already called");

        trace!("Notifying epoch watcher of start() progress: {:?}", result);

        init_sender.send(result).unwrap();
    }
}

impl<T: 'static + Transport + Sync + Send> EthereumRandomBeaconCacheInner<T>
where
    <T as web3::Transport>::Out: Send,
{
    fn new(
        contract: EthContract<T>,
        local_eth_address: web3::types::H160,
        time_notifier: Arc<TimeSourceNotifier>,
    ) -> Self {
        let (init_sender, init_receiver) = oneshot::channel();
        let (command_sender, command_receiver) = mpsc::unbounded();

        Self {
            contract: Arc::new(contract),
            local_eth_address,
            cache: HashMap::new(),
            subscribers: StreamSubscribers::new(),
            command_sender,
            command_receiver: Some(command_receiver),
            init_sender: Some(init_sender),
            init_receiver: Some(init_receiver),
            time_notifier: time_notifier,
            last_notify: (EKIDEN_EPOCH_INVALID, B256::zero()),
            current_epoch: EKIDEN_EPOCH_INVALID,
        }
    }

    fn maybe_notify(&mut self, epoch: EpochTime) -> bool {
        // Don't notify if the current time is unknown, or if the attempt
        // was triggered by a past log entry.
        let now = self.current_epoch;
        if now == EKIDEN_EPOCH_INVALID || now != epoch {
            return false;
        }

        // Don't notify if the beacon is unknown.
        let (beacon, _) = match self.cache.get(&epoch) {
            Some(ent) => ent.clone(),
            None => return false,
        };
        self.last_notify = (now, beacon.clone());

        trace!("Epoch: {} Beacon: {:?}", now, beacon);

        // Batch notify to all current subscribers.
        let to_send = (now, beacon);
        self.subscribers.notify(&to_send);

        true
    }

    // Drive the beacon forward.  Note that this costs money, regardless of
    // if a beacon is generated or not.
    fn set_beacon(&self) -> BoxFuture<()> {
        self.contract
            .call_with_confirmations(
                "set_beacon",
                (),
                self.local_eth_address,
                Options::default(),
                2,
            )
            .map_err(|e| {
                error!("set_beacon failed: {:?}", e);
                Error::new(e.description())
            })
            .and_then(move |_r| {
                trace!("set_beacon issued, and was confirmed");
                future::ok(())
            })
            .into_box()
    }
}

type EthereumRandomBeaconViaWebsocket = EthereumRandomBeacon<web3::transports::WebSocket>;
create_component!(
    ethereum,
    "random-beacon-backend",
    EthereumRandomBeaconViaWebsocket,
    RandomBeacon,
    (|container: &mut Container| -> StdResult<Box<Any>, ekiden_di::error::Error> {
        let client = container.inject::<Web3<web3::transports::WebSocket>>()?;
        let local_identity = container.inject::<Entity>()?;
        let time_notifier = container.inject::<TimeSourceNotifier>()?;

        let args = container.get_arguments().unwrap();
        let contract_address = value_t_or_exit!(args, "beacon-address", H160);

        let instance: Arc<EthereumRandomBeaconViaWebsocket> =
            Arc::new(EthereumRandomBeacon::new(
                client,
                local_identity,
                contract_address,
                time_notifier,
            ).map_err(|e| ekiden_di::error::Error::from(e.description()))?);
        Ok(Box::new(instance))
    }),
    [Arg::with_name("beacon-address")
        .long("beacon-address")
        .help("Ethereum address at which the random beacon has been deployed")
        .takes_value(true)]
);
