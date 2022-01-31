//! Runtime call dispatcher.
use std::{
    convert::TryInto,
    process,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Condvar, Mutex,
    },
    thread,
};

use anyhow::Result as AnyResult;
use io_context::Context;
use slog::{debug, error, info, warn, Logger};
use tokio::sync::mpsc;

use crate::{
    cache,
    common::{
        crypto::{
            hash::Hash,
            signature::{Signature, Signer},
        },
        logger::get_logger,
    },
    consensus::{
        beacon::EpochTime,
        roothash::{self, ComputeResultsHeader, Header, COMPUTE_RESULTS_HEADER_CONTEXT},
        verifier::Verifier,
        LightBlock,
    },
    enclave_rpc::{
        demux::Demux as RpcDemux,
        dispatcher::Dispatcher as RpcDispatcher,
        types::{Message as RpcMessage, Request as RpcRequest},
        Context as RpcContext,
    },
    protocol::{Protocol, ProtocolUntrustedLocalStorage},
    rak::RAK,
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
    fn init(
        &self,
        protocol: &Arc<Protocol>,
        rak: &Arc<RAK>,
        rpc_demux: &mut RpcDemux,
        rpc_dispatcher: &mut RpcDispatcher,
    ) -> Option<Box<dyn TxnDispatcher>>;
}

impl<F> Initializer for F
where
    F: Fn(
            &Arc<Protocol>,
            &Arc<RAK>,
            &mut RpcDemux,
            &mut RpcDispatcher,
        ) -> Option<Box<dyn TxnDispatcher>>
        + Send
        + Sync,
{
    fn init(
        &self,
        protocol: &Arc<Protocol>,
        rak: &Arc<RAK>,
        rpc_demux: &mut RpcDemux,
        rpc_dispatcher: &mut RpcDispatcher,
    ) -> Option<Box<dyn TxnDispatcher>> {
        (*self)(protocol, rak, rpc_demux, rpc_dispatcher)
    }
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
            &format!("error while processing request: {}", e),
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
    consensus_verifier: Box<dyn Verifier>,
}

/// State held by the dispatcher, shared between all async tasks.
#[derive(Clone)]
struct State {
    protocol: Arc<Protocol>,
    consensus_verifier: Arc<dyn Verifier>,
    dispatcher: Arc<Dispatcher>,
    rpc_demux: Arc<Mutex<RpcDemux>>,
    rpc_dispatcher: Arc<RpcDispatcher>,
    txn_dispatcher: Arc<dyn TxnDispatcher>,
    cache_set: cache::CacheSet,
}

#[derive(Debug)]
enum Command {
    Request(Context, u64, Body),
    Abort(mpsc::Sender<()>),
}

/// Runtime call dispatcher.
pub struct Dispatcher {
    logger: Logger,
    queue_tx: mpsc::Sender<Command>,
    rak: Arc<RAK>,
    abort_batch: Arc<AtomicBool>,

    state: Mutex<Option<ProtocolState>>,
    state_cond: Condvar,

    tokio_runtime: tokio::runtime::Runtime,
}

impl Dispatcher {
    #[cfg(target_env = "sgx")]
    fn new_tokio_runtime() -> tokio::runtime::Runtime {
        // In an SGX environment we use a single-threaded Tokio runtime.
        tokio::runtime::Builder::new_current_thread()
            .max_blocking_threads(2) // Limited in SGX.
            .thread_keep_alive(std::time::Duration::from_secs(120))
            .build()
            .unwrap()
    }

    #[cfg(not(target_env = "sgx"))]
    fn new_tokio_runtime() -> tokio::runtime::Runtime {
        // Otherwise we use a fully-fledged Tokio runtime.
        tokio::runtime::Runtime::new().unwrap()
    }

    /// Create a new runtime call dispatcher.
    pub fn new(initializer: Box<dyn Initializer>, rak: Arc<RAK>) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(BACKLOG_SIZE);

        let dispatcher = Arc::new(Dispatcher {
            logger: get_logger("runtime/dispatcher"),
            queue_tx: tx,
            rak,
            abort_batch: Arc::new(AtomicBool::new(false)),
            state: Mutex::new(None),
            state_cond: Condvar::new(),
            tokio_runtime: Self::new_tokio_runtime(),
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
        let mut s = self.state.lock().unwrap();
        *s = Some(ProtocolState {
            protocol,
            consensus_verifier,
        });
        self.state_cond.notify_one();
    }

    /// Queue a new request to be dispatched.
    pub fn queue_request(&self, ctx: Context, id: u64, body: Body) -> AnyResult<()> {
        self.queue_tx
            .blocking_send(Command::Request(ctx, id, body))?;
        Ok(())
    }

    /// Signals to dispatcher that it should abort and waits for the abort to
    /// complete.
    pub fn abort_and_wait(&self) -> AnyResult<()> {
        self.abort_batch.store(true, Ordering::SeqCst);
        // Queue an abort command and wait for it to be processed.
        let (tx, mut rx) = mpsc::channel(1);
        self.queue_tx.blocking_send(Command::Abort(tx))?;
        rx.blocking_recv();
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
        let mut rpc_demux = RpcDemux::new(self.rak.clone());
        let mut rpc_dispatcher = RpcDispatcher::new();
        let mut txn_dispatcher: Box<dyn TxnDispatcher> = if let Some(txn) =
            initializer.init(&protocol, &self.rak, &mut rpc_demux, &mut rpc_dispatcher)
        {
            txn
        } else {
            Box::new(TxnNoopDispatcher::new())
        };
        txn_dispatcher.set_abort_batch_flag(self.abort_batch.clone());

        let state = State {
            protocol: protocol.clone(),
            consensus_verifier: Arc::from(consensus_verifier),
            dispatcher: self.clone(),
            rpc_demux: Arc::new(Mutex::new(rpc_demux)),
            rpc_dispatcher: Arc::new(rpc_dispatcher),
            txn_dispatcher: Arc::from(txn_dispatcher),
            cache_set: cache::CacheSet::new(protocol.clone()),
        };

        // Start the async message processing task.
        self.tokio_runtime.block_on(async move {
            while let Some(cmd) = rx.recv().await {
                // Process received command.
                match cmd {
                    Command::Request(ctx, id, request) => {
                        // Process request in its own task.
                        let state = state.clone();

                        tokio::spawn(async move {
                            let protocol = state.protocol.clone();
                            let dispatcher = state.dispatcher.clone();
                            let result = dispatcher.handle_request(state, ctx, request).await;

                            // Send response.
                            let response = match result {
                                Ok(body) => body,
                                Err(error) => Body::Error(error),
                            };
                            protocol.send_response(id, response).unwrap();
                        });
                    }
                    Command::Abort(tx) => {
                        // Request to abort processing.
                        tx.send(()).await.unwrap();
                    }
                }
            }
        });

        info!(self.logger, "Runtime call dispatcher is terminating");
    }

    async fn handle_request(
        self: &Arc<Self>,
        state: State,
        ctx: Context,
        request: Body,
    ) -> Result<Body, Error> {
        match request {
            Body::RuntimeRPCCallRequest { request } => {
                // RPC call.
                self.dispatch_rpc(
                    &state.rpc_demux,
                    &state.rpc_dispatcher,
                    &state.protocol,
                    ctx,
                    request,
                )
                .await
            }
            Body::RuntimeLocalRPCCallRequest { request } => {
                // Local RPC call.
                self.dispatch_local_rpc(&state.rpc_dispatcher, &state.protocol, ctx, request)
                    .await
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
                    ctx,
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
                    ctx,
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
                    ctx,
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
            Body::RuntimeKeyManagerPolicyUpdateRequest { signed_policy_raw } => {
                // KeyManager policy update local RPC call.
                self.handle_km_policy_update(&state.rpc_dispatcher, ctx, signed_policy_raw)
            }
            Body::RuntimeConsensusSyncRequest { height } => state
                .consensus_verifier
                .sync(height)
                .map_err(Into::into)
                .map(|_| Body::RuntimeConsensusSyncResponse {}),
            _ => {
                error!(self.logger, "Unsupported request type");
                Err(Error::new("dispatcher", 1, "Unsupported request type"))
            }
        }
    }

    async fn dispatch_query(
        &self,
        ctx: Context,
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

        tokio::task::spawn_blocking(move || {
            // For queries we don't do any consensus layer integrity verification.
            let consensus_state = state
                .consensus_verifier
                .unverified_state(state.consensus_block)
                .unwrap();

            let cache = cache_set.query(Root {
                namespace: state.header.namespace,
                version: state.header.round,
                root_type: RootType::State,
                hash: state.header.state_root,
            });
            let mut cache = cache.borrow_mut();
            let mut overlay = OverlayTree::new(cache.tree_mut());

            let txn_ctx = TxnContext::new(
                ctx.freeze(),
                protocol,
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
        ctx: Arc<Context>,
        protocol: Arc<Protocol>,
        cache_set: cache::CacheSet,
        txn_dispatcher: &dyn TxnDispatcher,
        inputs: TxnBatch,
        state: TxDispatchState,
    ) -> Result<Body, Error> {
        // For check-only we don't do any consensus layer integrity verification.
        let consensus_state = state
            .consensus_verifier
            .unverified_state(state.consensus_block)?;

        let mut cache = cache_set.check(Root {
            namespace: state.header.namespace,
            version: state.header.round,
            root_type: RootType::State,
            hash: state.header.state_root,
        });
        let mut overlay = OverlayTree::new(cache.tree_mut());

        let txn_ctx = TxnContext::new(
            ctx.clone(),
            protocol,
            consensus_state,
            &mut overlay,
            &state.header,
            state.epoch,
            &state.round_results,
            state.max_messages,
            state.check_only,
        );
        let results = txn_dispatcher.check_batch(txn_ctx, &inputs);

        debug!(self.logger, "Transaction batch check complete");

        results.map(|results| Body::RuntimeCheckTxBatchResponse { results })
    }

    fn txn_execute_batch(
        &self,
        ctx: Arc<Context>,
        protocol: Arc<Protocol>,
        cache_set: cache::CacheSet,
        txn_dispatcher: &dyn TxnDispatcher,
        mut inputs: TxnBatch,
        in_msgs: Vec<roothash::IncomingMessage>,
        io_root: Hash,
        state: TxDispatchState,
    ) -> Result<Body, Error> {
        // Verify consensus state and runtime state root integrity before execution.
        let consensus_state = state
            .consensus_verifier
            .verify(state.consensus_block, state.header.clone())?;

        let header = &state.header;

        let mut cache = cache_set.execute(Root {
            namespace: state.header.namespace,
            version: state.header.round,
            root_type: RootType::State,
            hash: state.header.state_root,
        });
        let mut overlay = OverlayTree::new(cache.tree_mut());

        let txn_ctx = TxnContext::new(
            ctx.clone(),
            protocol,
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
            .commit_both(
                Context::create_child(&ctx),
                header.namespace,
                header.round + 1,
            )
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
                .add_input(
                    Context::create_child(&ctx),
                    input,
                    batch_order.try_into().unwrap(),
                )
                .expect("add transaction must succeed");
        }

        let (input_write_log, input_io_root) = txn_tree
            .commit(Context::create_child(&ctx))
            .expect("io commit must succeed");
        if state.mode == ExecutionMode::Execute && input_io_root != io_root {
            panic!(
                "dispatcher: I/O root inconsistent with inputs (expected: {:?} got: {:?})",
                io_root, input_io_root
            );
        }

        for (tx_hash, result) in hashes.iter().zip(results.results.drain(..)) {
            txn_tree
                .add_output(
                    Context::create_child(&ctx),
                    *tx_hash,
                    result.output,
                    result.tags,
                )
                .expect("add transaction must succeed");
        }

        txn_tree
            .add_block_tags(Context::create_child(&ctx), results.block_tags)
            .expect("adding block tags must succeed");

        let (io_write_log, io_root) = txn_tree
            .commit(Context::create_child(&ctx))
            .expect("io commit must succeed");

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

        // Since we've computed the batch, we can trust it.
        state
            .consensus_verifier
            .trust(&header)
            .expect("trusting a computed header must succeed");

        debug!(self.logger, "Transaction batch execution complete";
            "previous_hash" => ?header.previous_hash,
            "io_root" => ?header.io_root,
            "state_root" => ?header.state_root,
            "messages_hash" => ?header.messages_hash,
            "in_msgs_hash" => ?header.in_msgs_hash,
        );

        let rak_sig = if self.rak.public_key().is_some() {
            self.rak
                .sign(
                    &COMPUTE_RESULTS_HEADER_CONTEXT,
                    &cbor::to_vec(header.clone()),
                )
                .unwrap()
        } else {
            Signature::default()
        };

        Ok(Body::RuntimeExecuteTxBatchResponse {
            batch: ComputedBatch {
                header,
                io_write_log,
                state_write_log,
                rak_sig,
                messages: results.messages,
            },
            batch_weight_limits: results.batch_weight_limits,
            tx_hashes: hashes,
            tx_reject_hashes: results.tx_reject_hashes,
            tx_input_root: input_io_root,
            tx_input_write_log: input_write_log,
        })
    }

    async fn dispatch_txn(
        self: &Arc<Self>,
        ctx: Context,
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
        if state.header.namespace != protocol.get_runtime_id() {
            panic!(
                "block namespace does not match runtime id (namespace: {:?} runtime ID: {:?})",
                state.header.namespace,
                protocol.get_runtime_id(),
            );
        }

        let ctx = ctx.freeze();
        let protocol = protocol.clone();
        let dispatcher = self.clone();
        let txn_dispatcher = txn_dispatcher.clone();

        tokio::task::spawn_blocking(move || {
            if state.check_only {
                dispatcher.txn_check_batch(ctx, protocol, cache_set, &txn_dispatcher, inputs, state)
            } else {
                dispatcher.txn_execute_batch(
                    ctx,
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

    async fn dispatch_rpc(
        &self,
        rpc_demux: &Arc<Mutex<RpcDemux>>,
        rpc_dispatcher: &Arc<RpcDispatcher>,
        protocol: &Arc<Protocol>,
        ctx: Context,
        request: Vec<u8>,
    ) -> Result<Body, Error> {
        debug!(self.logger, "Received RPC call request");

        // Process frame.
        let mut buffer = vec![];
        let result = match rpc_demux
            .lock()
            .unwrap()
            .process_frame(request, &mut buffer)
        {
            Ok(result) => result,
            Err(error) => {
                error!(self.logger, "Error while processing frame"; "err" => %error);
                return Err(Error::new("rhp/dispatcher", 1, &format!("{}", error)));
            }
        };

        if let Some((session_id, session_info, message, untrusted_plaintext)) = result {
            // Dispatch request.
            assert!(
                buffer.is_empty(),
                "must have no handshake data in transport mode"
            );

            match message {
                RpcMessage::Request(req) => {
                    // First make sure that the untrusted_plaintext matches
                    // the request's method!
                    if untrusted_plaintext != req.method {
                        error!(self.logger, "Request methods don't match!";
                            "untrusted_plaintext" => ?untrusted_plaintext,
                            "method" => ?req.method
                        );
                        return Err(Error::new(
                            "rhp/dispatcher",
                            1,
                            "Request's method doesn't match untrusted_plaintext copy.",
                        ));
                    }

                    // Request, dispatch.
                    let ctx = ctx.freeze();
                    let rak = self.rak.clone();
                    let protocol = protocol.clone();
                    let rpc_dispatcher = rpc_dispatcher.clone();

                    let response = tokio::task::spawn_blocking(move || {
                        let untrusted_local = Arc::new(ProtocolUntrustedLocalStorage::new(
                            Context::create_child(&ctx),
                            protocol.clone(),
                        ));
                        let rpc_ctx =
                            RpcContext::new(ctx.clone(), rak, session_info, &untrusted_local);
                        let response = rpc_dispatcher.dispatch(req, rpc_ctx);
                        RpcMessage::Response(response)
                    })
                    .await?;

                    // Note: MKVS commit is omitted, this MUST be global side-effect free.

                    debug!(self.logger, "RPC call dispatch complete");

                    let mut buffer = vec![];
                    match rpc_demux
                        .lock()
                        .unwrap()
                        .write_message(session_id, response, &mut buffer)
                    {
                        Ok(_) => {
                            // Transmit response.
                            Ok(Body::RuntimeRPCCallResponse { response: buffer })
                        }
                        Err(error) => {
                            error!(self.logger, "Error while writing response"; "err" => %error);
                            Err(Error::new("rhp/dispatcher", 1, &format!("{}", error)))
                        }
                    }
                }
                RpcMessage::Close => {
                    // Session close.
                    let mut buffer = vec![];
                    match rpc_demux.lock().unwrap().close(session_id, &mut buffer) {
                        Ok(_) => {
                            // Transmit response.
                            Ok(Body::RuntimeRPCCallResponse { response: buffer })
                        }
                        Err(error) => {
                            error!(self.logger, "Error while closing session"; "err" => %error);
                            Err(Error::new("rhp/dispatcher", 1, &format!("{}", error)))
                        }
                    }
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

    async fn dispatch_local_rpc(
        self: &Arc<Self>,
        rpc_dispatcher: &Arc<RpcDispatcher>,
        protocol: &Arc<Protocol>,
        ctx: Context,
        request: Vec<u8>,
    ) -> Result<Body, Error> {
        // Make sure to abort the process on panic during local RPC processing as that indicates a
        // serious problem and should make sure to clean up the process.
        let _guard = AbortOnPanic;

        debug!(self.logger, "Received local RPC call request");

        let req: RpcRequest = cbor::from_slice(&request)
            .map_err(|_| Error::new("rhp/dispatcher", 1, "malformed request"))?;

        // Request, dispatch.
        let ctx = ctx.freeze();
        let protocol = protocol.clone();
        let dispatcher = self.clone();
        let rpc_dispatcher = rpc_dispatcher.clone();

        tokio::task::spawn_blocking(move || {
            let untrusted_local = Arc::new(ProtocolUntrustedLocalStorage::new(
                Context::create_child(&ctx),
                protocol.clone(),
            ));
            let rpc_ctx =
                RpcContext::new(ctx.clone(), dispatcher.rak.clone(), None, &untrusted_local);
            let response = rpc_dispatcher.dispatch_local(req, rpc_ctx);
            let response = RpcMessage::Response(response);

            // Note: MKVS commit is omitted, this MUST be global side-effect free.

            debug!(dispatcher.logger, "Local RPC call dispatch complete");

            let response = cbor::to_vec(response);
            Ok(Body::RuntimeLocalRPCCallResponse { response })
        })
        .await
        .unwrap() // Propagate panics during local RPC dispatch.
    }

    fn handle_km_policy_update(
        &self,
        rpc_dispatcher: &RpcDispatcher,
        _ctx: Context,
        signed_policy_raw: Vec<u8>,
    ) -> Result<Body, Error> {
        // Make sure to abort the process on panic during policy processing as that indicates a
        // serious problem and should make sure to clean up the process.
        let _guard = AbortOnPanic;

        debug!(self.logger, "Received km policy update request");
        rpc_dispatcher.handle_km_policy_update(signed_policy_raw);
        debug!(self.logger, "KM policy update request complete");

        Ok(Body::RuntimeKeyManagerPolicyUpdateResponse {})
    }
}
