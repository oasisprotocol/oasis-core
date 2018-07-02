use std::error::Error as StdError;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ekiden_common::bytes::{B256, B520, H160};
use ekiden_common::environment::Environment;
use ekiden_common::error::{Error, Result};
use ekiden_common::futures::prelude::*;
use ekiden_common::futures::sync::mpsc;
use ekiden_common::node::Node;
use ekiden_consensus_base::{Block, Commitment, ConsensusBackend, ConsensusSigner, Event, Header,
                            Nonce, Reveal};
use ekiden_epochtime::interface::EpochTime;
use ekiden_registry_base::EntityRegistryBackend;
use ekiden_scheduler_base::{Committee, Scheduler};
use ethabi::{FixedBytes, Token};
use serde_json;
use web3;
use web3::api::Web3;
use web3::contract::{Contract as EthContract, Options};
use web3::types::BlockNumber;
use web3::Transport;

use super::signature::SIGNATURE_SIZE;

const CONSENSUS_CONTRACT: &[u8] = include_bytes!("../build/contracts/Consensus.json");
const COMMIT_REVEAL_SIZE: usize = SIGNATURE_SIZE + 256 / 8;
const ON_WAITING_COMMITMENTS: &str = // keccak256("OnWaitingCommitments(uint64,uint64,bool)")
    "302e9e107212d0d3b4f43c20c97771cb0c08b6fc83395552e3492a433f7cc5f2";
const ON_WAITING_REVEALS: &str = // keccak256("OnWaitingReveals(uint64,uint64,bool)")
    "a584eaa0c329f521e34de1f6dc8034e67fb0354f5cbe7638c18a5f948c1771a1";
const ON_FINALIZED: &str = // keccak256("OnFinalized(uint64,uint64,bytes32")
    "cb3ef41db96b2224491211ccab2c72456423fcf3e0a38778f2268bcb12010438";
const ON_DISCREPANCY_FAILED: &str = // keccak256("OnDiscrepancyFailed(uint64,uint64)")
    "787b16e9994f29425fb2d1215644e2a16a2625ec5239c2d765cce80c5ecc98b8";

enum State {
    Invalid,
    WaitingCommitments,
    WaitingReveals,
    DiscrepancyWaitingCommitments,
    DiscrepancyWaitingReveals,
    DiscrepancyFailed,
}

impl From<u64> for State {
    fn from(state: u64) -> Self {
        match state {
            0 => State::Invalid,
            1 => State::WaitingCommitments,
            2 => State::WaitingReveals,
            3 => State::DiscrepancyWaitingCommitments,
            4 => State::DiscrepancyWaitingReveals,
            5 => State::DiscrepancyFailed,
            _ => panic!("invalid state for conversion: {}", state),
        }
    }
}

enum AsyncEvent {
    Committee(Committee),
    NodeList((EpochTime, Vec<Node>)),
    Log(web3::types::Log),
}

/// Ethereum Consensus backend implementation.
pub struct EthereumConsensusBackend<T: Transport + Sync + Send> {
    contract_id: B256,
    inner: Arc<EthereumConsensusBackendInner<T>>,
}

impl<T: 'static + Transport + Sync + Send> EthereumConsensusBackend<T>
where
    <T as web3::Transport>::Out: Send,
{
    /// Create a new Ethereum consensus backend.
    pub fn new(
        client: Arc<Web3<T>>,
        local_node: Arc<Node>,
        contract_id: B256,
        eth_contract_address: H160,
        entity_registry: Arc<EntityRegistryBackend>,
        scheduler: Arc<Scheduler>,
        environment: Arc<Environment>,
    ) -> Result<Self> {
        let local_node_address = match local_node.eth_address {
            Some(addr) => web3::types::H160(addr.0),
            None => return Err(Error::new("No local ethereum address")),
        };

        let contract_dfn: serde_json::Value = serde_json::from_slice(CONSENSUS_CONTRACT)?;
        let contract_abi = serde_json::to_vec(&contract_dfn["abi"])?;

        let eth_contract_address = web3::types::H160(eth_contract_address.0);
        let contract = EthContract::from_json(
            client.eth(),
            web3::types::H160(eth_contract_address.0),
            &contract_abi,
        )?;

        // Ensure the contract is deployed.
        let ctor_future = client
            .eth()
            .code(eth_contract_address, None)
            .map_err(|e| Error::new(e.description()))
            .and_then(move |code| {
                let actual_str = serde_json::to_string(&code).unwrap_or("".to_string());
                let expected_str = serde_json::to_string(&contract_dfn["deployedBytecode"])
                    .unwrap_or("".to_string());
                if actual_str != expected_str {
                    return Err(Error::new("Contract not deployed at specified address"));
                }

                Ok(Self {
                    contract_id,
                    inner: Arc::new(EthereumConsensusBackendInner {
                        client,
                        contract: Arc::new(contract),
                        local_node_address,
                        entity_registry,
                        scheduler,
                        contract_state: Arc::new(Mutex::new(ContractState {
                            state: State::Invalid,
                            committee: None,
                        })),
                    }),
                })
            });
        let this = ctor_future.wait()?;

        // Start the worker.  The ConsensusBackend trait does not have a start
        // method, so all initialization needs to happen in the ctor.
        let _ = this.start(environment)?;

        Ok(this)
    }

    fn start(&self, environment: Arc<Environment>) -> Result<()> {
        let inner = self.inner.clone();

        let (log_sender, log_receiver) = mpsc::unbounded();
        let on_log = move |log: web3::types::Log| -> BoxFuture<()> {
            match log_sender.unbounded_send(log) {
                Ok(_) => future::ok(()).into_box(),
                Err(e) => future::err(Error::new(e.description())).into_box(),
            }
        };

        environment.spawn({
            let client = inner.client.clone();
            let shared_inner = inner.clone();
            let contract = inner.contract.clone();
            let contract_addr = contract.address();

            // Query enough of the contract state, to establish sanity, then
            // start watching events.
            client
                .eth()
                .block_number()
                .map_err(|e| {
                    error!("start: Failed to query block_number(): {:?}", e);
                    Error::new(e.description())
                })
                .and_then(move |block_number| {
                    let block_number = block_number.low_u64();
                    let inner = shared_inner.clone();

                    contract
                        .query(
                            "get_compact_state",
                            (),
                            shared_inner.local_node_address,
                            Options::default(),
                            BlockNumber::from(block_number),
                        )
                        .map_err(|e| Error::new(e.description()))
                        .and_then(move |r| {
                            let (state, epoch, leader): (
                                u64,
                                u64,
                                web3::types::H160,
                            ) = r;
                            let state = State::from(state);

                            // XXX: Do something with `state`.

                            // Subscribe to state change events.
                            let filter = web3::types::FilterBuilder::default()
                                .from_block(BlockNumber::from(block_number))
                                .to_block(BlockNumber::Latest)
                                .topics(
                                    Some(vec![ON_WAITING_COMMITMENTS.into()]),
                                    Some(vec![ON_WAITING_REVEALS.into()]),
                                    Some(vec![ON_FINALIZED.into()]),
                                    Some(vec![ON_DISCREPANCY_FAILED.into()]),
                                )
                                .address(vec![contract_addr])
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
                                    // XXX: Notify that the filter is installed.

                                    filter
                                        .stream(Duration::from_millis(1000)) // XXX: Reduce?
                                        .map_err(|e| Error::new(e.description()))
                                        .map(move |log| {
                                            trace!("Streamed log: {:?}", log);
                                            on_log(log)
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

        // Start the event handler.
        environment.spawn({
            // Subscribe to the relevant event feeds.
            let committee_stream = self.inner
                .scheduler
                .watch_committees()
                .map(AsyncEvent::Committee);
            let node_list_stream = self.inner
                .entity_registry
                .watch_node_list()
                .map(AsyncEvent::NodeList);
            let log_stream = log_receiver
                .map(AsyncEvent::Log)
                .map_err(|e| Error::new("having this shuts the compiler up"));

            let event_stream = committee_stream.select(log_stream).select(node_list_stream);

            Box::new(
                event_stream
                    .for_each(move |event| {
                        // XXX: Do something.
                        Ok(())
                    })
                    .then(|_| future::ok(())),
            )
        });

        Ok(())
    }

    fn check_contract_id(&self, contract_id: B256) -> Result<()> {
        if contract_id != self.contract_id {
            return Err(Error::new("Unexpected contract ID"));
        }
        Ok(())
    }
}

impl<T: 'static + Transport + Sync + Send> ConsensusBackend for EthereumConsensusBackend<T>
where
    <T as web3::Transport>::Out: Send,
{
    fn get_blocks(&self, contract_id: B256) -> BoxStream<Block> {
        let _ = self.check_contract_id(contract_id).unwrap();
        unimplemented!();
    }

    fn get_events(&self, contract_id: B256) -> BoxStream<Event> {
        let _ = self.check_contract_id(contract_id).unwrap();
        unimplemented!();
    }

    fn commit(&self, contract_id: B256, _commitment: Commitment) -> BoxFuture<()> {
        let _ = match self.check_contract_id(contract_id) {
            Ok(_) => (),
            Err(e) => return Box::new(future::err(e)),
        };

        // Ensure that the contract is in the appropriate state, and that
        // the current node is the correct kind of member of the current
        // comittee.
        let contract_state = self.inner.contract_state.lock().unwrap();
        match contract_state.state {
            State::WaitingCommitments => {}
            State::DiscrepancyWaitingCommitments => {}
            _ => return Box::new(future::err(Error::new("Invalid contract state for commit"))),
        }

        unimplemented!();
    }

    fn reveal(&self, contract_id: B256, _reveal: Reveal) -> BoxFuture<()> {
        let _ = match self.check_contract_id(contract_id) {
            Ok(_) => (),
            Err(e) => return Box::new(future::err(e)),
        };

        // Ensure that the contract is in the appropriate state, and that
        // the current node is the correct kind of member of the current
        // comittee.
        let contract_state = self.inner.contract_state.lock().unwrap();
        match contract_state.state {
            State::WaitingReveals => {}
            State::DiscrepancyWaitingReveals => {}
            _ => return Box::new(future::err(Error::new("Invalid contract state for reveal"))),
        }

        unimplemented!();
    }

    fn commit_many(&self, contract_id: B256, commitments: Vec<Commitment>) -> BoxFuture<()> {
        let _ = match self.check_contract_id(contract_id) {
            Ok(_) => (),
            Err(e) => return Box::new(future::err(e)),
        };

        // Ensure that the contract is in the appropriate state, and that
        // the current node is the leader of the current comittee.
        let contract_state = self.inner.contract_state.lock().unwrap();
        match contract_state.state {
            State::WaitingCommitments | State::DiscrepancyWaitingCommitments => {}
            _ => {
                return Box::new(future::err(Error::new(
                    "Invalid contract state for aggregate commit",
                )))
            }
        }

        // Convert `commitments` to the format needed.
        let mut r_vec = vec![];
        let mut s_vec = vec![];
        let mut v_vec = vec![];
        let mut com_vec = vec![];
        for commit in commitments {
            // XXX: Should this take it as a matter of faith that the commits are
            // from nodes actually in the committee?  If not, it's a trivial recover operation.

            let (r, s, v, com) = match fmt_for_contract(&commit.data) {
                Ok(tuple) => tuple,
                Err(e) => return Box::new(future::err(e)),
            };

            r_vec.push(Token::FixedBytes(r));
            s_vec.push(Token::FixedBytes(s));
            v_vec.push(v);
            com_vec.push(Token::FixedBytes(com));
        }

        // Call the contract.
        self.inner
            .contract
            .call_with_confirmations(
                "add_commitments",
                (
                    Token::Array(r_vec),
                    Token::Array(s_vec),
                    Token::Bytes(v_vec),
                    Token::Array(com_vec),
                ),
                self.inner.local_node_address,
                Options::default(),
                2,
            )
            .map_err(|e| {
                error!("add_commitments failed: {:?}", e);
                Error::new(e.description())
            })
            .and_then(move |_r| {
                trace!("add_commitments issued, and was confirmed");
                future::ok(())
            })
            .into_box()
    }

    fn reveal_many(&self, contract_id: B256, reveals: Vec<Reveal>) -> BoxFuture<()> {
        let _ = match self.check_contract_id(contract_id) {
            Ok(_) => (),
            Err(e) => return Box::new(future::err(e)),
        };

        // Ensure that the contract is in the appropriate state, and that
        // the current node is the leader of the current comittee.
        let contract_state = self.inner.contract_state.lock().unwrap();
        match contract_state.state {
            State::WaitingReveals | State::DiscrepancyWaitingReveals => {}
            _ => {
                return Box::new(future::err(Error::new(
                    "Invalid contract state for aggregate reveal",
                )))
            }
        }

        // Convert `reveals` to the format needed.
        let mut r_vec = vec![];
        let mut s_vec = vec![];
        let mut v_vec = vec![];
        let mut rev_vec = vec![];
        for reveal in reveals {
            // XXX: Should this take it as a matter of faith that the reveals are
            // from nodes actually in the committee?  If not, it's a trivial recover operation.

            let (r, s, v, rev) = match fmt_for_contract(&reveal.data) {
                Ok(tuple) => tuple,
                Err(e) => return Box::new(future::err(e)),
            };

            r_vec.push(Token::FixedBytes(r));
            s_vec.push(Token::FixedBytes(s));
            v_vec.push(v);
            rev_vec.push(Token::FixedBytes(rev));
        }

        // Call the contract.
        self.inner
            .contract
            .call_with_confirmations(
                "add_reveals",
                (
                    Token::Array(r_vec),
                    Token::Array(s_vec),
                    Token::Bytes(v_vec),
                    Token::Array(rev_vec),
                ),
                self.inner.local_node_address,
                Options::default(),
                2,
            )
            .map_err(|e| {
                error!("add_reveals failed: {:?}", e);
                Error::new(e.description())
            })
            .and_then(move |_r| {
                trace!("add_reveals issued, and was confirmed");
                future::ok(())
            })
            .into_box()
    }
}

impl<T: 'static + Transport + Sync + Send> ConsensusSigner for EthereumConsensusBackend<T>
where
    <T as web3::Transport>::Out: Send,
{
    fn sign_commitment(&self, header: &Header) -> Result<(Commitment, Nonce)> {
        unimplemented!();
    }

    fn sign_reveal(&self, header: &Header, nonce: &Nonce) -> Result<Reveal> {
        unimplemented!();
    }
}

struct EthereumConsensusBackendInner<T: Transport + Sync + Send> {
    client: Arc<Web3<T>>,
    contract: Arc<EthContract<T>>,
    local_node_address: web3::types::H160,
    entity_registry: Arc<EntityRegistryBackend>,
    scheduler: Arc<Scheduler>,
    contract_state: Arc<Mutex<ContractState>>,
}

impl<T: 'static + Transport + Sync + Send> EthereumConsensusBackendInner<T>
where
    <T as web3::Transport>::Out: Send,
{
}

struct ContractState {
    state: State,
    committee: Option<Committee>,
}

/// Convert a commitment or reveal into discrete components, to save having
/// to do this in the contract.
fn fmt_for_contract(data: &[u8]) -> Result<(FixedBytes, FixedBytes, u8, FixedBytes)> {
    if data.len() != COMMIT_REVEAL_SIZE {
        return Err(Error::new("Invalid commit/reveal, unexpected length"));
    }

    let signature = B520::from(&data[..64]);
    let r = signature.0[..32].to_vec();
    let s = signature.0[32..64].to_vec();
    let v = signature.0[64];
    let digest = data[64..].to_vec();

    Ok((r, s, v, digest))
}

// TODO:
//  * Oasis identity <-> Ethereum identity.
//  * Oasis commits/reveals/rounds <-> Ethereum commits/reveals/rounds.
//    * How the fuck do I go from a bytes32 to a Block?
//  * Wire in the aggregate interface.
//    * It's not immediately obvious how much of the non-aggregate interface
//      is required.
//  * Figure out bootstrapping and persistence.  A leader restarting in the
//    middle of the round should not be irrecoverable.
