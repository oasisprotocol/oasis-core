//! Ethereum DisputeResolution contract interface.
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ekiden_common::bytes::{B256, H160};
use ekiden_common::environment::Environment;
use ekiden_common::error::{Error, Result};
use ekiden_common::futures::prelude::*;
use ekiden_common::futures::sync::oneshot;
use ekiden_common::node::Node;
use serde_json;
use web3;
use web3::contract::{Contract as EthContract, Options};
use web3::types::BlockNumber;

const DISPUTE_CONTRACT: &[u8] = include_bytes!("../build/contracts/DisputeResolution.json");
const ON_DISPUTE_EVENT: &str = // keccak("OnDispute(bytes32)")
	"0xf7993fadaed9ae0ed62d472e154d76ef8242b6aa0493fdd2507ee692879581b2";
const ON_DISPUTE_RESOLUTION_EVENT: &str = // keccak("OnDisputeResolution(bytes32,bytes32)")
	"0xd0be6bdeaca3675a19757b8c0be7a3bcadfcef3c9ee2443662d4c8f9d0cca47d";
const ON_TRANSITION_EVENT: &str = // keccak("OnTransition(uint64,bytes32")
	"0x81e4a3c0b24d01efe80f77ec9d1ae4cca67578adf77dacf84ac33aa220fc7558";

/// Ethereum DisputeResolution implementation.
pub struct EthereumDisputeResolution<T: web3::Transport + Sync + Send> {
    inner: Arc<EthereumDisputeResolutionInner<T>>,
}

impl<T: 'static + web3::Transport + Sync + Send> EthereumDisputeResolution<T>
where
    <T as web3::Transport>::Out: Send,
{
    // Create a new Ethereum dispute resolution instance.
    pub fn new(
        environment: Arc<Environment>,
        client: Arc<web3::api::Web3<T>>,
        local_identity: Arc<Node>,
        contract_address: H160,
    ) -> Result<Self> {
        let local_eth_address = match local_identity.eth_address {
            Some(addr) => web3::types::H160(addr.0),
            None => return Err(Error::new("No local Ethereum address")),
        };

        let contract_dfn: serde_json::Value = serde_json::from_slice(DISPUTE_CONTRACT)?;
        let contract_abi = serde_json::to_vec(&contract_dfn["abi"])?;

        let contract_address = web3::types::H160(contract_address.0);
        let contract =
            EthContract::from_json(client.eth(), contract_address.clone(), &contract_abi)?;

        let ctor_future = client
            .eth()
            .code(contract_address, None)
            .map_err(|e| Error::new(e.description()))
            .and_then(move |code| {
                let actual_str = serde_json::to_string(&code).unwrap_or("".to_string());
                let expected_str = serde_json::to_string(&contract_dfn["deployedBytecode"])
                    .unwrap_or("".to_string());
                if actual_str != expected_str {
                    return Err(Error::new("Contract not deployed at specified address"));
                } else {
                    let instance = Self {
                        inner: Arc::new(EthereumDisputeResolutionInner {
                            client,
                            contract: Arc::new(contract),
                            local_eth_address,
                            contract_state: Mutex::new(DisputeResolutionState {
                                committee_serial: 0,
                                state: State::Invalid,
                                dispute_batch_hash: B256::zero(),
                            }),
                        }),
                    };
                    instance.start(environment);

                    Ok(instance)
                }
            });

        ctor_future.wait()
    }

    fn start(&self, environment: Arc<Environment>) {
        let inner = self.inner.clone();

        let (sender, receiver): (
            oneshot::Sender<Result<()>>,
            oneshot::Receiver<Result<()>>,
        ) = oneshot::channel();

        environment.spawn({
            let (contract, contract_address) = inner.contract();
            let client = inner.client.clone();
            let shared_inner = inner.clone();

            client
                .eth()
                .block_number()
                .map_err(|e| {
                    error!("start: Failed to query block_number(): {:?}", e);
                    Error::new(e.description())
                })
                .and_then(move |block_number| {
                    let block_number = BlockNumber::from(block_number.low_u64());

                    let inner = shared_inner.clone();
                    contract
                        .query(
                            "contract_state",
                            (),
                            inner.local_eth_address,
                            Options::default(),
                            block_number,
                        )
                        .map_err(|e| Error::new(e.description()))
                        .and_then(move |r| {
                            let inner = shared_inner.clone();
                            let (serial, state, dispute_batch_hash): (
                                u64,
                                u64, // Can't be a u8, Rust web3 limitation.
                                web3::types::H256,
                            ) = r;

                            let mut contract_state = inner.contract_state.lock().unwrap();
                            (*contract_state).committee_serial = serial;
                            (*contract_state).state = State::from(state);
                            (*contract_state).dispute_batch_hash = B256::from(dispute_batch_hash.0);

                            let filter = web3::types::FilterBuilder::default()
                                .from_block(block_number)
                                .to_block(BlockNumber::Latest)
                                .topics(
                                    Some(vec![ON_DISPUTE_EVENT.into()]),
                                    Some(vec![ON_DISPUTE_RESOLUTION_EVENT.into()]),
                                    Some(vec![ON_TRANSITION_EVENT.into()]),
                                    None,
                                )
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
                                    sender.send(Ok(())).unwrap();

                                    filter
                                        .stream(Duration::from_millis(1000)) // XXX: Reduce?
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
        drop(receiver.wait().unwrap()); // Block till filter is intalled.
    }
}

struct EthereumDisputeResolutionInner<T: web3::Transport + Sync + Send> {
    client: Arc<web3::api::Web3<T>>,
    contract: Arc<EthContract<T>>,
    local_eth_address: web3::types::H160,

    contract_state: Mutex<DisputeResolutionState>,
}

impl<T: 'static + web3::Transport + Sync + Send> EthereumDisputeResolutionInner<T>
where
    <T as web3::Transport>::Out: Send,
{
    fn contract(&self) -> (Arc<EthContract<T>>, web3::types::H160) {
        (self.contract.clone(), self.contract.address())
    }

    fn on_log(&self, log: &web3::types::Log) -> BoxFuture<()> {
        // TODO: Do something clever with the logs here.
        unimplemented!();
    }
}

enum State {
    Invalid,
    Optimistic,
    Dispute,
}

impl From<u64> for State {
    fn from(state: u64) -> Self {
        match state {
            0 => State::Invalid,
            1 => State::Optimistic,
            2 => State::Dispute,
            _ => panic!("Invalid state for conversion: {}", state),
        }
    }
}

struct DisputeResolutionState {
    committee_serial: u64,
    state: State,
    dispute_batch_hash: B256,
}
