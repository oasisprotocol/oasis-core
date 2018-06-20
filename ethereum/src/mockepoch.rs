use std::error::Error as StdError;
use std::result::Result as StdResult;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
use ekiden_common::bytes::H160;
use ekiden_common::entity::Entity;
use ekiden_common::environment::Environment;
use ekiden_common::error::{Error, Result};
use ekiden_common::futures::sync::oneshot;
use ekiden_common::futures::{future, BoxFuture, BoxStream, Future, FutureExt, Stream};
use ekiden_di;
use ekiden_epochtime::interface::{EpochTime, TimeSource, TimeSourceNotifier};
use ekiden_epochtime::local::{LocalTimeSourceNotifier, MockTimeSource};
use ethabi::Token;
use serde_json;
use web3;
use web3::api::Web3;
use web3::contract::{Contract as EthContract, Options};
use web3::types::BlockNumber;
use web3::Transport;

const EPOCH_CONTRACT: &[u8] = include_bytes!("../build/contracts/MockEpoch.json");
const ON_EPOCH_EVENT: &str = // keccak("OnEpoch(uint64,uint64)")
    "0x10f899e134637bf04e36695d5e2b456c2ea1d7427b02ee52cf7de97cd271a619";

/// Ethereum Mock TimeSource/TimeSourceNotifier implementation.
pub struct EthereumMockTime<T: Transport + Sync + Send> {
    inner: Arc<EthereumMockTimeInner<T>>,
}

impl<T: 'static + Transport + Sync + Send> EthereumMockTime<T>
where
    <T as web3::Transport>::Out: Send,
{
    /// Create a new Ethereum mock time source/notifier.
    pub fn new(
        client: Arc<Web3<T>>,
        local_identity: Arc<Entity>,
        contract_address: H160,
        environment: Arc<Environment>,
    ) -> Result<Self> {
        let local_eth_address = match local_identity.eth_address {
            Some(addr) => web3::types::H160(addr.0),
            None => return Err(Error::new("No local Ethereum address")),
        };

        let contract_dfn: serde_json::Value = serde_json::from_slice(EPOCH_CONTRACT)?;
        let contract_abi = serde_json::to_vec(&contract_dfn["abi"])?;

        let contract_address = web3::types::H160(contract_address.0);
        let contract = EthContract::from_json(
            client.eth(),
            web3::types::H160(contract_address.0),
            &contract_abi,
        )?;

        // Ensure the contract is deployed, and retreive the current value.
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
                }

                let source = Arc::new(MockTimeSource::new());
                let notifier = Arc::new(LocalTimeSourceNotifier::new(source.clone()));

                Ok(Self {
                    inner: Arc::new(EthereumMockTimeInner {
                        client,
                        contract: Arc::new(contract),
                        local_eth_address,
                        contract_address,
                        cache: Arc::new(Mutex::new(EthereumMockTimeCache { source, notifier })),
                    }),
                })
            });
        let this = ctor_future.wait()?;

        // Initialize the cache and start the notifier.  Done here because
        // neither trait includes start(), this is only used for testing,
        // and doing so ensures all other calls are race free.
        let _ = this.start(environment)?;

        Ok(this)
    }

    /// Set the mock epoch and offset, and publish the new moch epoch/offset
    /// to the Ethereum MockEpoch contract.
    pub fn set_mock_time(&self, epoch: EpochTime, till: u64) -> BoxFuture<()> {
        // Publish the new mock epoch/offset.
        let epoch = Token::Uint(web3::types::U256::from(epoch));
        let till = Token::Uint(web3::types::U256::from(till));

        self.inner
            .contract
            .call_with_confirmations(
                "set_epoch",
                (epoch, till),
                self.inner.local_eth_address,
                Options::default(),
                2,
            )
            .map_err(|e| {
                error!("set_epoch failed: {:?}", e);
                Error::new(e.description())
            })
            .and_then(move |_r| {
                trace!("set_epoch issued, and was confirmed");
                // XXX: Should this update the cache?  The log watcher will
                // handle it eventually.
                future::ok(())
            })
            .into_box()
    }

    fn start(&self, environment: Arc<Environment>) -> Result<()> {
        let client = self.inner.client.clone();
        let shared_inner = self.inner.clone();

        let (sender, receiver): (
            oneshot::Sender<Result<()>>,
            oneshot::Receiver<Result<()>>,
        ) = oneshot::channel();

        environment.spawn({
            client
                .eth()
                .block_number()
                .map_err(|e| Error::new(e.description()))
                .and_then(move |block_number| {
                    let block_number = block_number.low_u64();
                    shared_inner
                        .contract
                        .query(
                            "get_epoch",
                            Token::Uint(web3::types::U256::zero()),
                            shared_inner.local_eth_address,
                            Options::default(),
                            BlockNumber::from(block_number),
                        )
                        .map_err(|e| Error::new(e.description()))
                        .and_then(move |r| {
                            let inner = shared_inner.clone();

                            let cache = inner.cache.lock().unwrap();
                            let (epoch, _since, till): (u64, u64, u64) = r;
                            let _ = cache.source.set_mock_time(epoch, till).unwrap();

                            let filter = web3::types::FilterBuilder::default()
                                .from_block(BlockNumber::from(block_number))
                                .to_block(BlockNumber::Latest)
                                .topics(Some(vec![ON_EPOCH_EVENT.into()]), None, None, None)
                                .address(vec![inner.contract_address])
                                .build();

                            let eth_filter = client.eth_filter();

                            eth_filter
                                .create_logs_filter(filter)
                                .or_else(|e| {
                                    error!("Failed to create log filter stream: {:?}", e);
                                    // XXX: Probably need to send to the
                                    // channel.
                                    future::err(Error::new(e.description()))
                                })
                                .and_then(move |filter| {
                                    sender.send(Ok(())).unwrap();

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
        receiver.wait().unwrap() // Block till filter is installed.
    }
}

impl<T: 'static + Transport + Sync + Send> TimeSource for EthereumMockTime<T>
where
    <T as web3::Transport>::Out: Send,
{
    fn get_epoch(&self) -> Result<(EpochTime, u64)> {
        let cache = self.inner.cache.lock()?;
        cache.source.get_epoch()
    }

    fn get_epoch_at(&self, at: &DateTime<Utc>) -> Result<(EpochTime, u64)> {
        // The results from this are sort of totally meaningless and unlikely
        // to be what the user wants, but MockTimeSource does this, so match
        // the behavior.
        let cache = self.inner.cache.lock()?;
        cache.source.get_epoch_at(at)
    }
}

impl<T: 'static + Transport + Sync + Send> TimeSourceNotifier for EthereumMockTime<T>
where
    <T as web3::Transport>::Out: Send,
{
    fn get_epoch(&self) -> BoxFuture<EpochTime> {
        match TimeSource::get_epoch(self) {
            Ok((epoch, _)) => Box::new(future::ok(epoch)),
            Err(e) => Box::new(future::err(e)),
        }
    }

    fn watch_epochs(&self) -> BoxStream<EpochTime> {
        let cache = self.inner.cache.lock().unwrap();
        cache.notifier.watch_epochs()
    }
}

struct EthereumMockTimeInner<T: Transport + Sync + Send> {
    client: Arc<Web3<T>>,
    contract: Arc<EthContract<T>>,
    local_eth_address: web3::types::H160,
    contract_address: web3::types::H160,
    cache: Arc<Mutex<EthereumMockTimeCache>>,
}

impl<T: 'static + Transport + Sync + Send> EthereumMockTimeInner<T>
where
    <T as web3::Transport>::Out: Send,
{
    fn on_log(&self, log: &web3::types::Log) -> BoxFuture<()> {
        if log.topics.len() < 2 {
            return future::err(Error::new("Invalid Log, unexpected topics")).into_box();
        }
        if log.data.0.len() != 256 / 8 {
            return future::err(Error::new("Invalid data, unexpected length")).into_box();
        }
        let data = web3::types::U256::from(log.data.0.as_slice());

        match format!("0x{:#x}", log.topics[0]).as_str() {
            ON_EPOCH_EVENT => {
                let epoch = log.topics[1].low_u64();
                let till = data.low_u64();

                trace!("OnEpoch: epoch: {}, till: {}.", epoch, till);

                let cache = self.cache.lock().unwrap();
                match cache.source.set_mock_time(epoch, till) {
                    Ok(_) => {}
                    Err(e) => return future::err(Error::new(e.description())).into_box(),
                };
                match cache.notifier.notify_subscribers() {
                    Ok(_) => future::ok(()).into_box(),
                    Err(e) => return future::err(Error::new(e.description())).into_box(),
                }
            }
            _ => future::err(Error::new("Unexpected log topic")).into_box(),
        }
    }
}

struct EthereumMockTimeCache {
    source: Arc<MockTimeSource>,
    notifier: Arc<LocalTimeSourceNotifier>,
}

pub type EthereumMockTimeViaWebsocket = EthereumMockTime<web3::transports::WebSocket>;
create_component!(
    ethereum,
    "time-source-notifier",
    EthereumMockTimeViaWebsocket,
    TimeSourceNotifier,
    (|container: &mut Container| -> StdResult<Box<Any>, ekiden_di::error::Error> {
        let client = container.inject::<Web3<web3::transports::WebSocket>>()?;
        let local_identity = container.inject::<Entity>()?;
        let environment = container.inject::<Environment>()?;

        let args = container.get_arguments().unwrap();
        let contract_address = value_t_or_exit!(args, "time-address", H160);

        let instance: Arc<EthereumMockTimeViaWebsocket> =
            Arc::new(
                EthereumMockTime::new(client, local_identity, contract_address, environment)
                    .map_err(|e| ekiden_di::error::Error::from(e.description()))?,
            );
        Ok(Box::new(instance))
    }),
    [Arg::with_name("time-address")
        .long("time-address")
        .env("TIME_ADDRESS")
        .help("Ethereum address at which the time source has been deployed")
        .takes_value(true)]
);
