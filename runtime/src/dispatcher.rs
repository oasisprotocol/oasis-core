//! Runtime call dispatcher.
use std::{
    convert::TryInto,
    sync::{Arc, Condvar, Mutex},
    thread,
};

use anyhow::Result as AnyResult;
use slog::{debug, error, info, warn, Logger};
use tokio::sync::mpsc;

use crate::{
    attestation, cache,
    common::{
        crypto::{hash::Hash, signature::Signer},
        logger::get_logger,
        process,
        sgx::QuotePolicy,
    },
    consensus::{
        beacon::EpochTime,
        roothash::{self, ComputeResultsHeader, Header, COMPUTE_RESULTS_HEADER_SIGNATURE_CONTEXT},
        state::keymanager::Status as KeyManagerStatus,
        verifier::Verifier,
        LightBlock,
    },
    enclave_rpc::{
        demux::Demux as RpcDemux,
        dispatcher::Dispatcher as RpcDispatcher,
        session::SessionInfo,
        types::{
            Kind as RpcKind, Message as RpcMessage, Request as RpcRequest, Response as RpcResponse,
        },
        Context as RpcContext,
    },
    future::block_on,
    identity::Identity,
    policy::PolicyVerifier,
    protocol::{Protocol, ProtocolUntrustedLocalStorage},
    storage::mkvs::{sync::NoopReadSyncer, OverlayTree, Root, RootType},
    transaction::{
        dispatcher::{Dispatcher as TxnDispatcher, NoopDispatcher as TxnNoopDispatcher},
        tree::Tree as TxnTree,
        types::TxnBatch,
        Context as TxnContext,
    },
    types::{Body, ComputedBatch, Error, ExecutionMode},
};

/// Maximum amount of requests that can be in the dispatcher queue.
const BACKLOG_SIZE: usize = 1000;

/// Interface for dispatcher initializers.
pub trait Initializer: Send + Sync {
    /// Initializes the dispatcher(s).
    fn init(&self, state: PreInitState<'_>) -> PostInitState;
}

impl<F> Initializer for F
where
    F: Fn(PreInitState<'_>) -> PostInitState + Send + Sync,
{
    fn init(&self, state: PreInitState<'_>) -> PostInitState {
        (*self)(state)
    }
}

/// State available before initialization.
pub struct PreInitState<'a> {
    /// Protocol instance.
    pub protocol: &'a Arc<Protocol>,
    /// Runtime Attestation Key instance.
    pub identity: &'a Arc<Identity>,
    /// RPC demultiplexer instance.
    pub rpc_demux: &'a mut RpcDemux,
    /// RPC dispatcher instance.
    pub rpc_dispatcher: &'a mut RpcDispatcher,
    /// Consensus verifier instance.
    pub consensus_verifier: &'a Arc<dyn Verifier>,
}

/// State returned by the initializer.
#[derive(Default)]
pub struct PostInitState {
    /// Optional transaction dispatcher that should be used.
    pub txn_dispatcher: Option<Box<dyn TxnDispatcher>>,
}

/// A guard that will abort the process if dropped while panicking.
///
/// This is to ensure that the runtime will terminate in case there is
/// a panic encountered during dispatch and the runtime is built with
/// a non-abort panic handler.
struct AbortOnPanic;

impl Drop for AbortOnPanic {
    fn drop(&mut self) {
        if thread::panicking() {
            process::abort();
        }
    }
}

impl From<tokio::task::JoinError> for Error {
    fn from(e: tokio::task::JoinError) -> Self {
        Error::new(
            "dispatcher",
            1,
            &format!("error while processing request: {e}"),
        )
    }
}

/// State related to dispatching a runtime transaction.
struct TxDispatchState {
    mode: ExecutionMode,
    consensus_block: LightBlock,
    consensus_verifier: Arc<dyn Verifier>,
    header: Header,
    epoch: EpochTime,
    round_results: roothash::RoundResults,
    max_messages: u32,
    check_only: bool,
}

/// State provided by the protocol upon successful initialization.
struct ProtocolState {
    protocol: Arc<Protocol>,
    consensus_verifier: Arc<dyn Verifier>,
}

/// State held by the dispatcher, shared between all async tasks.
#[derive(Clone)]
struct State {
    protocol: Arc<Protocol>,
    consensus_verifier: Arc<dyn Verifier>,
    dispatcher: Arc<Dispatcher>,
    rpc_demux: Arc<RpcDemux>,
    rpc_dispatcher: Arc<RpcDispatcher>,
    txn_dispatcher: Arc<dyn TxnDispatcher>,
    #[cfg_attr(not(target_env = "sgx"), allow(unused))]
    attestation_handler: attestation::Handler,
    policy_verifier: Arc<PolicyVerifier>,
    cache_set: cache::CacheSet,
}

#[derive(Debug)]
enum Command {
    Request(u64, Body),
}

/// Runtime call dispatcher.
pub struct Dispatcher {
    logger: Logger,
    queue_tx: mpsc::Sender<Command>,
    identity: Arc<Identity>,

    state: Mutex<Option<ProtocolState>>,
    state_cond: Condvar,

    tokio_runtime: tokio::runtime::Handle,
}

impl Dispatcher {
    /// Create a new runtime call dispatcher.
    pub fn new(
        tokio_runtime: tokio::runtime::Handle,
        initializer: Box<dyn Initializer>,
        identity: Arc<Identity>,
    ) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(BACKLOG_SIZE);

        let dispatcher = Arc::new(Dispatcher {
            logger: get_logger("runtime/dispatcher"),
            queue_tx: tx,
            identity,
            state: Mutex::new(None),
            state_cond: Condvar::new(),
            tokio_runtime,
        });

        // Spawn the dispatcher processing thread.
        let d = dispatcher.clone();
        thread::spawn(move || {
            let _guard = AbortOnPanic;
            d.run(initializer, rx);
        });

        dispatcher
    }

    /// Start the dispatcher.
    pub fn start(&self, protocol: Arc<Protocol>, consensus_verifier: Box<dyn Verifier>) {
        let consensus_verifier = Arc::from(consensus_verifier);
        let mut s = self.state.lock().unwrap();
        *s = Some(ProtocolState {
            protocol,
            consensus_verifier,
        });
        self.state_cond.notify_one();
    }

    /// Queue a new request to be dispatched.
    pub fn queue_request(&self, id: u64, body: Body) -> AnyResult<()> {
        self.queue_tx.blocking_send(Command::Request(id, body))?;
        Ok(())
    }

    fn run(self: &Arc<Self>, initializer: Box<dyn Initializer>, mut rx: mpsc::Receiver<Command>) {
        // Wait for the state to be available.
        let ProtocolState {
            protocol,
            consensus_verifier,
        } = {
            let mut guard = self.state.lock().unwrap();
            while guard.is_none() {
                guard = self.state_cond.wait(guard).unwrap();
            }

            guard.take().unwrap()
        };

        // Create actual dispatchers for RPCs and transactions.
        info!(self.logger, "Starting the runtime dispatcher");
        let mut rpc_demux = RpcDemux::new(self.identity.clone());
        let mut rpc_dispatcher = RpcDispatcher::default();
        let pre_init_state = PreInitState {
            protocol: &protocol,
            identity: &self.identity,
            rpc_demux: &mut rpc_demux,
            rpc_dispatcher: &mut rpc_dispatcher,
            consensus_verifier: &consensus_verifier,
        };
        let post_init_state = initializer.init(pre_init_state);
        let txn_dispatcher = post_init_state
            .txn_dispatcher
            .unwrap_or_else(|| Box::<TxnNoopDispatcher>::default());

        let state = State {
            protocol: protocol.clone(),
            consensus_verifier: consensus_verifier.clone(),
            dispatcher: self.clone(),
            rpc_demux: Arc::new(rpc_demux),
            rpc_dispatcher: Arc::new(rpc_dispatcher),
            txn_dispatcher: Arc::from(txn_dispatcher),
            attestation_handler: attestation::Handler::new(
                self.identity.clone(),
                protocol.clone(),
                consensus_verifier.clone(),
                protocol.get_runtime_id(),
                protocol.get_config().version,
            ),
            policy_verifier: Arc::new(PolicyVerifier::new(consensus_verifier)),
            cache_set: cache::CacheSet::new(protocol.clone()),
        };

        // Start the async message processing task.
        self.tokio_runtime.block_on(async move {
            while let Some(cmd) = rx.recv().await {
                // Process received command.
                match cmd {
                    Command::Request(id, request) => {
                        // Process request in its own task.
                        let state = state.clone();

                        tokio::spawn(async move {
                            let protocol = state.protocol.clone();
                            let dispatcher = state.dispatcher.clone();
                            let result = dispatcher.handle_request(state, request).await;

                            // Send response.
                            let response = match result {
                                Ok(body) => body,
                                Err(error) => Body::Error(error),
                            };
                            protocol.send_response(id, response).unwrap();
                        });
                    }
                }
            }
        });

        info!(self.logger, "Runtime call dispatcher is terminating");
    }

    async fn handle_request(self: &Arc<Self>, state: State, request: Body) -> Result<Body, Error> {
        match request {
            // Attestation-related requests.
            #[cfg(target_env = "sgx")]
            Body::RuntimeCapabilityTEERakInitRequest { .. }
            | Body::RuntimeCapabilityTEERakReportRequest {}
            | Body::RuntimeCapabilityTEERakAvrRequest { .. }
            | Body::RuntimeCapabilityTEERakQuoteRequest { .. } => {
                Ok(state.attestation_handler.handle(request).await?)
            }

            // RPC and transaction requests.
            Body::RuntimeRPCCallRequest { request, kind } => {
                debug!(self.logger, "Received RPC call request";
                    "kind" => ?kind,
                );

                match kind {
                    RpcKind::NoiseSession => self.dispatch_secure_rpc(state, request).await,
                    RpcKind::InsecureQuery => self.dispatch_insecure_rpc(state, request).await,
                    RpcKind::LocalQuery => self.dispatch_local_rpc(state, request).await,
                }
            }
            Body::RuntimeLocalRPCCallRequest { request } => {
                debug!(self.logger, "Received RPC call request";
                    "kind" => ?RpcKind::LocalQuery,
                );

                self.dispatch_local_rpc(state, request).await
            }
            Body::RuntimeExecuteTxBatchRequest {
                mode,
                consensus_block,
                round_results,
                io_root,
                inputs,
                in_msgs,
                block,
                epoch,
                max_messages,
            } => {
                // Transaction execution.
                self.dispatch_txn(
                    state.cache_set,
                    &state.txn_dispatcher,
                    &state.protocol,
                    io_root,
                    inputs.unwrap_or_default(),
                    in_msgs,
                    TxDispatchState {
                        mode,
                        consensus_block,
                        consensus_verifier: state.consensus_verifier,
                        header: block.header,
                        epoch,
                        round_results,
                        max_messages,
                        check_only: false,
                    },
                )
                .await
            }
            Body::RuntimeCheckTxBatchRequest {
                consensus_block,
                inputs,
                block,
                epoch,
                max_messages,
            } => {
                // Transaction check.
                self.dispatch_txn(
                    state.cache_set,
                    &state.txn_dispatcher,
                    &state.protocol,
                    Hash::default(),
                    inputs,
                    vec![],
                    TxDispatchState {
                        mode: ExecutionMode::Execute,
                        consensus_block,
                        consensus_verifier: state.consensus_verifier,
                        header: block.header,
                        epoch,
                        round_results: Default::default(),
                        max_messages,
                        check_only: true,
                    },
                )
                .await
            }
            Body::RuntimeQueryRequest {
                consensus_block,
                header,
                epoch,
                max_messages,
                method,
                args,
            } => {
                // Query.
                self.dispatch_query(
                    state.cache_set,
                    &state.txn_dispatcher,
                    &state.protocol,
                    method,
                    args,
                    TxDispatchState {
                        mode: ExecutionMode::Execute,
                        consensus_block,
                        consensus_verifier: state.consensus_verifier,
                        header,
                        epoch,
                        round_results: Default::default(),
                        max_messages,
                        check_only: true,
                    },
                )
                .await
            }

            // Other requests.
            Body::RuntimeKeyManagerStatusUpdateRequest { status } => {
                // Key manager status update local RPC call.
                self.handle_km_status_update(state, status).await
            }
            Body::RuntimeKeyManagerQuotePolicyUpdateRequest {
                policy: quote_policy,
            } => {
                // Key manager quote policy update local RPC call.
                self.handle_km_quote_policy_update(state, quote_policy)
                    .await
            }
            Body::RuntimeConsensusSyncRequest { height } => state
                .consensus_verifier
                .sync(height)
                .await
                .map_err(Into::into)
                .map(|_| Body::RuntimeConsensusSyncResponse {}),

            _ => {
                error!(self.logger, "Unsupported request type");
                Err(Error::new("dispatcher", 1, "Unsupported request type"))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn dispatch_query(
        &self,
        cache_set: cache::CacheSet,
        txn_dispatcher: &Arc<dyn TxnDispatcher>,
        protocol: &Arc<Protocol>,
        method: String,
        args: Vec<u8>,
        state: TxDispatchState,
    ) -> Result<Body, Error> {
        debug!(self.logger, "Received query request";
            "method" => &method,
            "state_root" => ?state.header.state_root,
            "round" => ?state.header.round,
        );

        // Verify that the runtime ID matches the block's namespace. This is a protocol violation
        // as the compute node should never change the runtime ID.
        if state.header.namespace != protocol.get_runtime_id() {
            return Err(Error::new(
                "dispatcher",
                1,
                &format!(
                    "block namespace does not match runtime id (namespace: {:?} runtime ID: {:?})",
                    state.header.namespace,
                    protocol.get_runtime_id(),
                ),
            ));
        }

        let protocol = protocol.clone();
        let txn_dispatcher = txn_dispatcher.clone();

        // For queries we don't do any consensus layer integrity verification by default and it
        // is up to the runtime to decide whether this is critical on a query-by-query basis.
        let consensus_state = state
            .consensus_verifier
            .unverified_state(state.consensus_block.clone())
            .await?;

        tokio::task::spawn_blocking(move || {
            let cache = cache_set.query(Root {
                namespace: state.header.namespace,
                version: state.header.round,
                root_type: RootType::State,
                hash: state.header.state_root,
            });
            let mut cache = cache.borrow_mut();
            let mut overlay = OverlayTree::new(cache.tree_mut());

            let txn_ctx = TxnContext::new(
                protocol,
                &state.consensus_block,
                consensus_state,
                &mut overlay,
                &state.header,
                state.epoch,
                &state.round_results,
                state.max_messages,
                state.check_only,
            );

            txn_dispatcher
                .query(txn_ctx, &method, args)
                .map(|data| Body::RuntimeQueryResponse { data })
        })
        .await?
    }

    fn txn_check_batch(
        &self,
        protocol: Arc<Protocol>,
        cache_set: cache::CacheSet,
        txn_dispatcher: &dyn TxnDispatcher,
        inputs: TxnBatch,
        state: TxDispatchState,
    ) -> Result<Body, Error> {
        // For check-only we don't do any consensus layer integrity verification.
        // TODO: Make this async.
        let consensus_state = block_on(
            state
                .consensus_verifier
                .unverified_state(state.consensus_block.clone()),
        )?;

        let mut cache = cache_set.check(Root {
            namespace: state.header.namespace,
            version: state.header.round,
            root_type: RootType::State,
            hash: state.header.state_root,
        });
        let mut overlay = OverlayTree::new(cache.tree_mut());

        let txn_ctx = TxnContext::new(
            protocol.clone(),
            &state.consensus_block,
            consensus_state,
            &mut overlay,
            &state.header,
            state.epoch,
            &state.round_results,
            state.max_messages,
            state.check_only,
        );
        let results = txn_dispatcher.check_batch(txn_ctx, &inputs);

        if protocol.get_config().persist_check_tx_state {
            // Commit results to in-memory tree so they persist for subsequent batches that are
            // based on the same block.
            let _ = overlay.commit().unwrap();
        }

        debug!(self.logger, "Transaction batch check complete");

        results.map(|results| Body::RuntimeCheckTxBatchResponse { results })
    }

    #[allow(clippy::too_many_arguments)]
    fn txn_execute_batch(
        &self,
        protocol: Arc<Protocol>,
        cache_set: cache::CacheSet,
        txn_dispatcher: &dyn TxnDispatcher,
        mut inputs: TxnBatch,
        in_msgs: Vec<roothash::IncomingMessage>,
        io_root: Hash,
        state: TxDispatchState,
    ) -> Result<Body, Error> {
        // Verify consensus state and runtime state root integrity before execution.
        // TODO: Make this async.
        let consensus_state = block_on(state.consensus_verifier.verify(
            state.consensus_block.clone(),
            state.header.clone(),
            state.epoch,
        ))?;
        // Ensure the runtime is still ready to process requests.
        protocol.ensure_initialized()?;

        let header = &state.header;

        let mut cache = cache_set.execute(Root {
            namespace: state.header.namespace,
            version: state.header.round,
            root_type: RootType::State,
            hash: state.header.state_root,
        });
        let mut overlay = OverlayTree::new(cache.tree_mut());

        let txn_ctx = TxnContext::new(
            protocol,
            &state.consensus_block,
            consensus_state,
            &mut overlay,
            header,
            state.epoch,
            &state.round_results,
            state.max_messages,
            state.check_only,
        );

        // Perform execution based on the passed mode.
        let mut results = match state.mode {
            ExecutionMode::Execute => {
                // Just execute the batch.
                txn_dispatcher.execute_batch(txn_ctx, &inputs, &in_msgs)?
            }
            ExecutionMode::Schedule => {
                // Allow the runtime to arbitrarily update the batch.
                txn_dispatcher.schedule_and_execute_batch(txn_ctx, &mut inputs, &in_msgs)?
            }
        };

        // Finalize state.
        let (state_write_log, new_state_root) = overlay
            .commit_both(header.namespace, header.round + 1)
            .expect("state commit must succeed");

        txn_dispatcher.finalize(new_state_root);
        cache.commit(header.round + 1, new_state_root);

        // Generate I/O root. Since we already fetched the inputs we avoid the need
        // to fetch them again by generating the previous I/O tree (generated by the
        // transaction scheduler) from the inputs.
        let mut txn_tree = TxnTree::new(
            Box::new(NoopReadSyncer),
            Root {
                namespace: header.namespace,
                version: header.round + 1,
                root_type: RootType::IO,
                hash: Hash::empty_hash(),
            },
        );
        let mut hashes = Vec::new();
        for (batch_order, input) in inputs.drain(..).enumerate() {
            hashes.push(Hash::digest_bytes(&input));
            txn_tree
                .add_input(input, batch_order.try_into().unwrap())
                .expect("add transaction must succeed");
        }

        let (input_write_log, input_io_root) = txn_tree.commit().expect("io commit must succeed");

        assert!(
            state.mode != ExecutionMode::Execute || input_io_root == io_root,
            "dispatcher: I/O root inconsistent with inputs (expected: {:?} got: {:?})",
            io_root,
            input_io_root
        );

        for (tx_hash, result) in hashes.iter().zip(results.results.drain(..)) {
            txn_tree
                .add_output(*tx_hash, result.output, result.tags)
                .expect("add transaction must succeed");
        }

        txn_tree
            .add_block_tags(results.block_tags)
            .expect("adding block tags must succeed");

        let (io_write_log, io_root) = txn_tree.commit().expect("io commit must succeed");

        let header = ComputeResultsHeader {
            round: header.round + 1,
            previous_hash: header.encoded_hash(),
            io_root: Some(io_root),
            state_root: Some(new_state_root),
            messages_hash: Some(roothash::Message::messages_hash(&results.messages)),
            in_msgs_hash: Some(roothash::IncomingMessage::in_messages_hash(
                &in_msgs[..results.in_msgs_count],
            )),
            in_msgs_count: results.in_msgs_count.try_into().unwrap(),
        };

        debug!(self.logger, "Transaction batch execution complete";
            "previous_hash" => ?header.previous_hash,
            "io_root" => ?header.io_root,
            "state_root" => ?header.state_root,
            "messages_hash" => ?header.messages_hash,
            "in_msgs_hash" => ?header.in_msgs_hash,
        );

        let rak_sig = self
            .identity
            .sign(
                COMPUTE_RESULTS_HEADER_SIGNATURE_CONTEXT,
                &cbor::to_vec(header.clone()),
            )
            .unwrap();

        Ok(Body::RuntimeExecuteTxBatchResponse {
            batch: ComputedBatch {
                header,
                io_write_log,
                state_write_log,
                rak_sig,
                messages: results.messages,
            },
            tx_hashes: hashes,
            tx_reject_hashes: results.tx_reject_hashes,
            tx_input_root: input_io_root,
            tx_input_write_log: input_write_log,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn dispatch_txn(
        self: &Arc<Self>,
        cache_set: cache::CacheSet,
        txn_dispatcher: &Arc<dyn TxnDispatcher>,
        protocol: &Arc<Protocol>,
        io_root: Hash,
        inputs: TxnBatch,
        in_msgs: Vec<roothash::IncomingMessage>,
        state: TxDispatchState,
    ) -> Result<Body, Error> {
        // Make sure to abort the process on panic during transaction processing as that indicates
        // a serious problem and should make sure to clean up the process.
        let _guard = AbortOnPanic;

        debug!(self.logger, "Received transaction batch request";
            "state_root" => ?state.header.state_root,
            "round" => state.header.round + 1,
            "round_results" => ?state.round_results,
            "tx_count" => inputs.len(),
            "in_msg_count" => in_msgs.len(),
            "check_only" => state.check_only,
        );

        // Verify that the runtime ID matches the block's namespace. This is a protocol violation
        // as the compute node should never change the runtime ID.
        assert!(
            state.header.namespace == protocol.get_runtime_id(),
            "block namespace does not match runtime id (namespace: {:?} runtime ID: {:?})",
            state.header.namespace,
            protocol.get_runtime_id(),
        );

        let protocol = protocol.clone();
        let dispatcher = self.clone();
        let txn_dispatcher = txn_dispatcher.clone();

        tokio::task::spawn_blocking(move || {
            if state.check_only {
                dispatcher.txn_check_batch(protocol, cache_set, &txn_dispatcher, inputs, state)
            } else {
                dispatcher.txn_execute_batch(
                    protocol,
                    cache_set,
                    &txn_dispatcher,
                    inputs,
                    in_msgs,
                    io_root,
                    state,
                )
            }
        })
        .await
        .unwrap() // Propagate panics during transaction dispatch.
    }

    async fn dispatch_secure_rpc(&self, state: State, request: Vec<u8>) -> Result<Body, Error> {
        // Make sure to abort the process on panic during RPC processing as that indicates a
        // serious problem and should make sure to clean up the process.
        let _guard = AbortOnPanic;

        // Process frame.
        let mut buffer = vec![];
        let (mut session, message) = state.rpc_demux.process_frame(request, &mut buffer).await?;

        if let Some(message) = message {
            // Dispatch request.
            assert!(
                buffer.is_empty(),
                "must have no handshake data in transport mode"
            );

            match message {
                RpcMessage::Request(req) => {
                    // Request, dispatch.
                    let response = self
                        .dispatch_rpc(req, RpcKind::NoiseSession, session.info(), &state)
                        .await?;
                    let response = RpcMessage::Response(response);

                    // Note: MKVS commit is omitted, this MUST be global side-effect free.

                    debug!(self.logger, "RPC call dispatch complete";
                        "kind" => ?RpcKind::NoiseSession,
                    );

                    let mut buffer = vec![];
                    session
                        .write_message(response, &mut buffer)
                        .map_err(|err| {
                            error!(self.logger, "Error while writing response"; "err" => %err);
                            Error::new("rhp/dispatcher", 1, &format!("{err}"))
                        })
                        .map(|_| Body::RuntimeRPCCallResponse { response: buffer })
                }
                RpcMessage::Close => {
                    // Session close.
                    let mut buffer = vec![];
                    state
                        .rpc_demux
                        .close(session, &mut buffer)
                        .map_err(|err| {
                            error!(self.logger, "Error while closing session"; "err" => %err);
                            Error::new("rhp/dispatcher", 1, &format!("{err}"))
                        })
                        .map(|_| Body::RuntimeRPCCallResponse { response: buffer })
                }
                msg => {
                    warn!(self.logger, "Ignoring invalid RPC message type"; "msg" => ?msg);
                    Err(Error::new("rhp/dispatcher", 1, "invalid RPC message type"))
                }
            }
        } else {
            // Send back any handshake frames.
            Ok(Body::RuntimeRPCCallResponse { response: buffer })
        }
    }

    async fn dispatch_insecure_rpc(&self, state: State, request: Vec<u8>) -> Result<Body, Error> {
        // Make sure to abort the process on panic during RPC processing as that indicates a
        // serious problem and should make sure to clean up the process.
        let _guard = AbortOnPanic;

        let request: RpcRequest = cbor::from_slice(&request)
            .map_err(|_| Error::new("rhp/dispatcher", 1, "malformed request"))?;

        // Request, dispatch.
        let response = self
            .dispatch_rpc(request, RpcKind::InsecureQuery, None, &state)
            .await?;
        let response = cbor::to_vec(response);

        // Note: MKVS commit is omitted, this MUST be global side-effect free.

        debug!(self.logger, "RPC call dispatch complete";
            "kind" => ?RpcKind::InsecureQuery,
        );

        Ok(Body::RuntimeRPCCallResponse { response })
    }

    async fn dispatch_local_rpc(&self, state: State, request: Vec<u8>) -> Result<Body, Error> {
        // Make sure to abort the process on panic during local RPC processing as that indicates a
        // serious problem and should make sure to clean up the process.
        let _guard = AbortOnPanic;

        let request = cbor::from_slice(&request)
            .map_err(|_| Error::new("rhp/dispatcher", 1, "malformed request"))?;

        // Request, dispatch.
        let response = self
            .dispatch_rpc(request, RpcKind::LocalQuery, None, &state)
            .await?;
        let response = RpcMessage::Response(response);
        let response = cbor::to_vec(response);

        debug!(self.logger, "RPC call dispatch complete";
            "kind" => ?RpcKind::LocalQuery,
        );

        Ok(Body::RuntimeLocalRPCCallResponse { response })
    }

    async fn dispatch_rpc(
        &self,
        request: RpcRequest,
        kind: RpcKind,
        session_info: Option<Arc<SessionInfo>>,
        state: &State,
    ) -> Result<RpcResponse, Error> {
        let identity = self.identity.clone();
        let protocol = state.protocol.clone();
        let consensus_verifier = state.consensus_verifier.clone();
        let rpc_dispatcher = state.rpc_dispatcher.clone();
        let is_secure = kind == RpcKind::NoiseSession;

        let response = tokio::task::spawn_blocking(move || {
            let untrusted_local = Arc::new(ProtocolUntrustedLocalStorage::new(protocol.clone()));
            let rpc_ctx = RpcContext::new(
                identity,
                is_secure,
                session_info,
                consensus_verifier,
                &untrusted_local,
            );

            rpc_dispatcher.dispatch(rpc_ctx, request, kind)
        })
        .await?;

        Ok(response)
    }

    async fn handle_km_status_update(
        &self,
        state: State,
        status: KeyManagerStatus,
    ) -> Result<Body, Error> {
        // Make sure to abort the process on panic during policy processing as that indicates a
        // serious problem and should make sure to clean up the process.
        let _guard = AbortOnPanic;

        debug!(self.logger, "Received km status update request");

        // Verify and decode the status.
        let runtime_id = state.protocol.get_host_info().runtime_id;

        tokio::task::spawn_blocking(move || -> Result<(), Error> {
            let key_manager = state.policy_verifier.key_manager(&runtime_id)?;
            let published_status = state
                .policy_verifier
                .verify_key_manager_status(status, key_manager)?;

            // Dispatch the local RPC call.
            state
                .rpc_dispatcher
                .handle_km_status_update(published_status);

            Ok(())
        })
        .await??;

        debug!(self.logger, "KM status update request complete");

        Ok(Body::RuntimeKeyManagerStatusUpdateResponse {})
    }

    async fn handle_km_quote_policy_update(
        &self,
        state: State,
        quote_policy: QuotePolicy,
    ) -> Result<Body, Error> {
        // Make sure to abort the process on panic during quote policy processing as that indicates
        // a serious problem and should make sure to clean up the process.
        let _guard = AbortOnPanic;

        debug!(self.logger, "Received km quote policy update request");

        // Verify and decode the policy.
        let runtime_id = state.protocol.get_host_info().runtime_id;

        tokio::task::spawn_blocking(move || -> Result<(), Error> {
            let key_manager = state.policy_verifier.key_manager(&runtime_id)?;
            let policy =
                state
                    .policy_verifier
                    .verify_quote_policy(quote_policy, &key_manager, None)?;

            // Dispatch the local RPC call.
            state.rpc_dispatcher.handle_km_quote_policy_update(policy);

            Ok(())
        })
        .await??;

        debug!(self.logger, "KM quote policy update request complete");

        Ok(Body::RuntimeKeyManagerQuotePolicyUpdateResponse {})
    }
}
