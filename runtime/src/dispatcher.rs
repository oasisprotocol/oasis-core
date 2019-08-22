//! Runtime call dispatcher.
use std::{
    convert::TryInto,
    sync::{Arc, Condvar, Mutex},
    thread,
};

use crossbeam::channel;
use failure::Fallible;
use io_context::Context;
use slog::Logger;

use crate::{
    common::{
        cbor,
        crypto::{
            hash::Hash,
            signature::{Signature, Signer},
        },
        logger::get_logger,
        roothash::{Block, ComputeResultsHeader, COMPUTE_RESULTS_HEADER_CONTEXT},
    },
    protocol::{Protocol, ProtocolUntrustedLocalStorage},
    rak::RAK,
    rpc::{
        demux::Demux as RpcDemux,
        dispatcher::Dispatcher as RpcDispatcher,
        types::{Message as RpcMessage, Request as RpcRequest},
        Context as RpcContext,
    },
    storage::{
        mkvs::{
            urkel::sync::{HostReadSyncer, NoopReadSyncer, Root},
            UrkelTree,
        },
        StorageContext,
    },
    transaction::{
        dispatcher::Dispatcher as TxnDispatcher, tree::Tree as TxnTree, types::TxnBatch,
        Context as TxnContext,
    },
    types::{Body, ComputedBatch},
};

/// Maximum amount of requests that can be in the dispatcher queue.
const BACKLOG_SIZE: usize = 10;

/// Interface for dispatcher initializers.
pub trait Initializer: Send + Sync {
    /// Initializes the dispatcher(s).
    fn init(
        &self,
        protocol: &Arc<Protocol>,
        rak: &Arc<RAK>,
        rpc_demux: &mut RpcDemux,
        rpc_dispatcher: &mut RpcDispatcher,
        txn_dispatcher: &mut TxnDispatcher,
    );
}

impl<F> Initializer for F
where
    F: Fn(&Arc<Protocol>, &Arc<RAK>, &mut RpcDemux, &mut RpcDispatcher, &mut TxnDispatcher)
        + Send
        + Sync,
{
    fn init(
        &self,
        protocol: &Arc<Protocol>,
        rak: &Arc<RAK>,
        rpc_demux: &mut RpcDemux,
        rpc_dispatcher: &mut RpcDispatcher,
        txn_dispatcher: &mut TxnDispatcher,
    ) {
        (*self)(protocol, rak, rpc_demux, rpc_dispatcher, txn_dispatcher)
    }
}

type QueueItem = (Context, u64, Body);

/// Runtime call dispatcher.
pub struct Dispatcher {
    logger: Logger,
    queue_tx: channel::Sender<QueueItem>,
    protocol: Mutex<Option<Arc<Protocol>>>,
    protocol_cond: Condvar,
    rak: Arc<RAK>,
}

impl Dispatcher {
    /// Create a new runtime call dispatcher.
    pub fn new(initializer: Option<Box<dyn Initializer>>, rak: Arc<RAK>) -> Arc<Self> {
        let (tx, rx) = channel::bounded(BACKLOG_SIZE);
        let dispatcher = Arc::new(Dispatcher {
            logger: get_logger("runtime/dispatcher"),
            queue_tx: tx,
            protocol: Mutex::new(None),
            protocol_cond: Condvar::new(),
            rak,
        });

        let d = dispatcher.clone();
        thread::spawn(move || d.run(initializer, rx));

        dispatcher
    }

    /// Start the dispatcher.
    pub fn start(&self, protocol: Arc<Protocol>) {
        let mut p = self.protocol.lock().unwrap();
        *p = Some(protocol);
        self.protocol_cond.notify_one();
    }

    /// Queue a new request to be dispatched.
    pub fn queue_request(&self, ctx: Context, id: u64, body: Body) -> Fallible<()> {
        self.queue_tx.try_send((ctx, id, body))?;
        Ok(())
    }

    fn run(&self, initializer: Option<Box<dyn Initializer>>, rx: channel::Receiver<QueueItem>) {
        // Wait for the protocol instance to be available.
        let protocol = {
            let mut guard = self.protocol.lock().unwrap();
            while guard.is_none() {
                guard = self.protocol_cond.wait(guard).unwrap();
            }

            guard.take().unwrap()
        };

        // Create actual dispatchers for RPCs and transactions.
        info!(self.logger, "Starting the runtime dispatcher");
        let mut rpc_demux = RpcDemux::new(self.rak.clone());
        let mut rpc_dispatcher = RpcDispatcher::new();
        let mut txn_dispatcher = TxnDispatcher::new();
        if let Some(initializer) = initializer {
            initializer.init(
                &protocol,
                &self.rak,
                &mut rpc_demux,
                &mut rpc_dispatcher,
                &mut txn_dispatcher,
            );
        }

        // Create common MKVS to use as a cache as long as the root stays the same.
        let mut cache = Cache::new(
            &Context::background().freeze(),
            &protocol,
            Default::default(),
        );

        'dispatch: loop {
            match rx.recv() {
                Ok((
                    ctx,
                    id,
                    Body::WorkerRPCCallRequest {
                        request,
                        state_root,
                    },
                )) => {
                    // RPC call.
                    self.dispatch_rpc(
                        &mut rpc_demux,
                        &mut rpc_dispatcher,
                        &protocol,
                        ctx,
                        id,
                        request,
                        state_root,
                    );
                }
                Ok((
                    ctx,
                    id,
                    Body::WorkerLocalRPCCallRequest {
                        request,
                        state_root,
                    },
                )) => {
                    // Local RPC call.
                    self.dispatch_local_rpc(
                        &mut rpc_dispatcher,
                        &protocol,
                        ctx,
                        id,
                        request,
                        state_root,
                    );
                }
                Ok((
                    ctx,
                    id,
                    Body::WorkerExecuteTxBatchRequest {
                        io_root,
                        inputs,
                        block,
                    },
                )) => {
                    // Transaction execution.
                    self.dispatch_txn(
                        &mut cache,
                        &mut txn_dispatcher,
                        &protocol,
                        ctx,
                        id,
                        io_root,
                        inputs,
                        block,
                        false,
                    );
                }
                Ok((ctx, id, Body::WorkerCheckTxBatchRequest { inputs, block })) => {
                    // Transaction check.
                    self.dispatch_txn(
                        &mut cache,
                        &mut txn_dispatcher,
                        &protocol,
                        ctx,
                        id,
                        Hash::default(),
                        inputs,
                        block,
                        true,
                    );
                }
                Ok(_) => {
                    error!(self.logger, "Unsupported request type");
                    break 'dispatch;
                }
                Err(error) => {
                    error!(self.logger, "Error while waiting for request"; "err" => %error);
                    break 'dispatch;
                }
            }
        }

        info!(self.logger, "Runtime call dispatcher is terminating");
    }

    fn dispatch_txn(
        &self,
        cache: &mut Cache,
        txn_dispatcher: &mut TxnDispatcher,
        protocol: &Arc<Protocol>,
        ctx: Context,
        id: u64,
        io_root: Hash,
        mut inputs: TxnBatch,
        block: Block,
        check_only: bool,
    ) {
        debug!(self.logger, "Received transaction batch request";
            "state_root" => ?block.header.state_root,
            "check_only" => check_only,
        );

        // Create a new context and dispatch the batch.
        let ctx = ctx.freeze();
        cache.maybe_replace(
            &ctx,
            protocol,
            Root {
                namespace: block.header.namespace,
                round: block.header.round,
                hash: block.header.state_root,
            },
        );

        let untrusted_local = Arc::new(ProtocolUntrustedLocalStorage::new(
            Context::create_child(&ctx),
            protocol.clone(),
        ));
        let txn_ctx = TxnContext::new(ctx.clone(), &block.header, check_only);
        let (mut outputs, mut tags) =
            StorageContext::enter(&mut cache.mkvs, untrusted_local.clone(), || {
                txn_dispatcher.dispatch_batch(&inputs, txn_ctx)
            });

        if check_only {
            debug!(self.logger, "Transaction batch check complete");

            // Send the result back.
            protocol
                .send_response(id, Body::WorkerCheckTxBatchResponse { results: outputs })
                .unwrap();
        } else {
            // Finalize state.
            let (state_write_log, new_state_root) = cache
                .mkvs
                .commit(
                    Context::create_child(&ctx),
                    block.header.namespace,
                    block.header.round + 1,
                )
                .expect("state commit must succeed");
            txn_dispatcher.finalize(new_state_root);
            cache.root.round = block.header.round + 1;
            cache.root.hash = new_state_root;

            // Generate I/O root. Since we already fetched the inputs we avoid the need
            // to fetch them again by generating the previous I/O tree (generated by the
            // transaction scheduler) from the inputs.
            let mut txn_tree = TxnTree::new(
                Context::create_child(&ctx),
                Box::new(NoopReadSyncer {}),
                Root {
                    namespace: block.header.namespace,
                    round: block.header.round + 1,
                    hash: Hash::empty_hash(),
                },
            )
            .unwrap();
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

            let (_, old_io_root) = txn_tree
                .commit(Context::create_child(&ctx))
                .expect("io commit must succeed");
            if old_io_root != io_root {
                panic!(
                    "dispatcher: I/O root inconsistent with inputs (expected: {:?} got: {:?})",
                    io_root, old_io_root
                );
            }

            for (tx_hash, (output, tags)) in
                hashes.drain(..).zip(outputs.drain(..).zip(tags.drain(..)))
            {
                txn_tree
                    .add_output(Context::create_child(&ctx), tx_hash, output, tags)
                    .expect("add transaction must succeed");
            }

            let (io_write_log, io_root) = txn_tree
                .commit(Context::create_child(&ctx))
                .expect("io commit must succeed");

            let header = ComputeResultsHeader {
                previous_hash: block.header.encoded_hash(),
                io_root,
                state_root: new_state_root,
            };

            debug!(self.logger, "Transaction batch execution complete";
                "previous_hash" => ?header.previous_hash,
                "io_root" => ?header.io_root,
                "state_root" => ?header.state_root
            );

            let rak_sig = if self.rak.public_key().is_some() {
                self.rak
                    .sign(&COMPUTE_RESULTS_HEADER_CONTEXT, &cbor::to_vec(&header))
                    .unwrap()
            } else {
                Signature::default()
            };

            let result = ComputedBatch {
                header,
                io_write_log,
                state_write_log,
                rak_sig,
            };

            // Send the result back.
            protocol
                .send_response(id, Body::WorkerExecuteTxBatchResponse { batch: result })
                .unwrap();
        }
    }

    fn dispatch_rpc(
        &self,
        rpc_demux: &mut RpcDemux,
        rpc_dispatcher: &mut RpcDispatcher,
        protocol: &Arc<Protocol>,
        ctx: Context,
        id: u64,
        request: Vec<u8>,
        state_root: Hash,
    ) {
        debug!(self.logger, "Received RPC call request"; "state_root" => ?state_root);

        // Process frame.
        let mut buffer = vec![];
        let result = match rpc_demux.process_frame(request, &mut buffer) {
            Ok(result) => result,
            Err(error) => {
                error!(self.logger, "Error while processing frame"; "err" => %error);

                protocol
                    .send_response(
                        id,
                        Body::Error {
                            message: format!("{}", error),
                        },
                    )
                    .unwrap();
                return;
            }
        };

        let protocol_response;
        if let Some((session_id, session_info, message)) = result {
            // Dispatch request.
            assert!(
                buffer.is_empty(),
                "must have no handshake data in transport mode"
            );

            match message {
                RpcMessage::Request(req) => {
                    // Request, dispatch.
                    let ctx = ctx.freeze();
                    let read_syncer = HostReadSyncer::new(protocol.clone());
                    let mut mkvs = UrkelTree::make()
                        .with_root(Root {
                            hash: state_root,
                            ..Default::default()
                        })
                        .new(Context::create_child(&ctx), Box::new(read_syncer))
                        .unwrap();
                    let untrusted_local = Arc::new(ProtocolUntrustedLocalStorage::new(
                        Context::create_child(&ctx),
                        protocol.clone(),
                    ));
                    let rpc_ctx = RpcContext::new(ctx.clone(), self.rak.clone(), session_info);
                    let response =
                        StorageContext::enter(&mut mkvs, untrusted_local.clone(), || {
                            rpc_dispatcher.dispatch(req, rpc_ctx)
                        });
                    let response = RpcMessage::Response(response);

                    let (write_log, new_state_root) = mkvs
                        .commit(Context::create_child(&ctx), Default::default(), 0)
                        .expect("mkvs commit must succeed");

                    debug!(self.logger, "RPC call dispatch complete"; "new_state_root" => ?new_state_root);

                    let mut buffer = vec![];
                    match rpc_demux.write_message(session_id, response, &mut buffer) {
                        Ok(_) => {
                            // Transmit response.
                            protocol_response = Body::WorkerRPCCallResponse {
                                response: buffer,
                                write_log: write_log,
                                new_state_root,
                            };
                        }
                        Err(error) => {
                            error!(self.logger, "Error while writing response"; "err" => %error);
                            protocol_response = Body::Error {
                                message: format!("{}", error),
                            };
                        }
                    }
                }
                RpcMessage::Close => {
                    // Session close.
                    let mut buffer = vec![];
                    match rpc_demux.close(session_id, &mut buffer) {
                        Ok(_) => {
                            // Transmit response.
                            protocol_response = Body::WorkerRPCCallResponse {
                                response: buffer,
                                write_log: vec![],
                                new_state_root: state_root,
                            };
                        }
                        Err(error) => {
                            error!(self.logger, "Error while closing session"; "err" => %error);
                            protocol_response = Body::Error {
                                message: format!("{}", error),
                            };
                        }
                    }
                }
                msg => {
                    warn!(self.logger, "Ignoring invalid RPC message type"; "msg" => ?msg);
                    protocol_response = Body::Error {
                        message: "invalid RPC message type".to_owned(),
                    };
                }
            }
        } else {
            // Send back any handshake frames.
            protocol_response = Body::WorkerRPCCallResponse {
                response: buffer,
                write_log: vec![],
                new_state_root: state_root,
            };
        }

        protocol.send_response(id, protocol_response).unwrap();
    }

    fn dispatch_local_rpc(
        &self,
        rpc_dispatcher: &mut RpcDispatcher,
        protocol: &Arc<Protocol>,
        ctx: Context,
        id: u64,
        request: Vec<u8>,
        state_root: Hash,
    ) {
        debug!(self.logger, "Received local RPC call request"; "state_root" => ?state_root);

        let req: RpcRequest = cbor::from_slice(&request).unwrap();

        // Request, dispatch.
        let ctx = ctx.freeze();
        let read_syncer = HostReadSyncer::new(protocol.clone());
        let mut mkvs = UrkelTree::make()
            .with_root(Root {
                hash: state_root,
                ..Default::default()
            })
            .new(Context::create_child(&ctx), Box::new(read_syncer))
            .unwrap();
        let untrusted_local = Arc::new(ProtocolUntrustedLocalStorage::new(
            Context::create_child(&ctx),
            protocol.clone(),
        ));
        let rpc_ctx = RpcContext::new(ctx.clone(), self.rak.clone(), None);
        let response = StorageContext::enter(&mut mkvs, untrusted_local.clone(), || {
            rpc_dispatcher.dispatch_local(req, rpc_ctx)
        });
        let response = RpcMessage::Response(response);

        // Note: MKVS commit is omitted, this MUST be global side-effect free.

        debug!(self.logger, "Local RPC call dispatch complete");

        let response = cbor::to_vec(&response);
        let protocol_response = Body::WorkerLocalRPCCallResponse { response };

        protocol.send_response(id, protocol_response).unwrap();
    }
}

struct Cache {
    mkvs: UrkelTree,
    root: Root,
}

impl Cache {
    fn new(ctx: &Arc<Context>, protocol: &Arc<Protocol>, root: Root) -> Self {
        let read_syncer = HostReadSyncer::new(protocol.clone());
        let mkvs = UrkelTree::make()
            .with_capacity(100_000, 10_000_000)
            .with_root(root)
            .new(Context::create_child(ctx), Box::new(read_syncer))
            .unwrap();

        Self { mkvs, root }
    }

    fn maybe_replace(&mut self, ctx: &Arc<Context>, protocol: &Arc<Protocol>, root: Root) {
        if self.root == root {
            return;
        }

        *self = Self::new(ctx, protocol, root);
    }
}
