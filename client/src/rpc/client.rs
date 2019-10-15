//! Enclave RPC client.
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

use failure::Fallible;
use futures::{
    future,
    prelude::*,
    sync::{mpsc, oneshot},
};
#[cfg(not(target_env = "sgx"))]
use grpcio::Channel;
use io_context::Context;
use serde::{de::DeserializeOwned, Serialize};
use tokio_executor::spawn;

use oasis_core_runtime::{
    common::cbor,
    protocol::Protocol,
    rpc::{
        session::{Builder, Session},
        types,
    },
    types::Body,
};

#[cfg(not(target_env = "sgx"))]
use super::api::{CallEnclaveRequest, EnclaveRpcClient};
use crate::BoxFuture;

/// Internal send queue backlog.
const SENDQ_BACKLOG: usize = 10;

/// RPC client error.
#[derive(Debug, Fail)]
enum RpcClientError {
    #[fail(display = "call failed: {}", 0)]
    CallFailed(String),
    #[fail(display = "expected response message, received: {:?}", 0)]
    ExpectedResponseMessage(types::Message),
    #[fail(display = "expected close message, received: {:?}", 0)]
    ExpectedCloseMessage(types::Message),
    #[fail(display = "transport error")]
    Transport,
    #[fail(display = "client dropped")]
    Dropped,
}

trait Transport: Send + Sync {
    fn write_message(
        &self,
        ctx: Context,
        session_id: types::SessionID,
        data: Vec<u8>,
        untrusted_plaintext: String,
    ) -> BoxFuture<Vec<u8>> {
        // Frame message.
        let frame = types::Frame {
            session: session_id,
            untrusted_plaintext: untrusted_plaintext,
            payload: data,
        };

        self.write_message_impl(ctx, cbor::to_vec(&frame))
    }

    fn write_message_impl(&self, ctx: Context, data: Vec<u8>) -> BoxFuture<Vec<u8>>;
}

struct RuntimeTransport {
    protocol: Arc<Protocol>,
    endpoint: String,
}

impl Transport for RuntimeTransport {
    fn write_message_impl(&self, ctx: Context, data: Vec<u8>) -> BoxFuture<Vec<u8>> {
        // NOTE: This is not actually async in SGX, but futures should be
        //       dispatched on the current thread anyway.
        let rsp = self.protocol.make_request(
            ctx,
            Body::HostRPCCallRequest {
                endpoint: self.endpoint.clone(),
                request: data,
            },
        );

        let rsp = match rsp {
            Ok(rsp) => rsp,
            Err(error) => return Box::new(future::err(error)),
        };

        match rsp {
            Body::HostRPCCallResponse { response } => Box::new(future::ok(response)),
            _ => Box::new(future::err(RpcClientError::Transport.into())),
        }
    }
}

#[cfg(not(target_env = "sgx"))]
struct GrpcTransport {
    grpc_client: EnclaveRpcClient,
    endpoint: String,
}

#[cfg(not(target_env = "sgx"))]
impl Transport for GrpcTransport {
    fn write_message_impl(&self, _ctx: Context, data: Vec<u8>) -> BoxFuture<Vec<u8>> {
        let mut req = CallEnclaveRequest::new();
        req.set_payload(data);
        req.set_endpoint(self.endpoint.clone());

        match self.grpc_client.call_enclave_async(&req) {
            Ok(rsp) => Box::new(rsp.map(|r| r.payload).map_err(|error| error.into())),
            Err(error) => Box::new(future::err(error.into())),
        }
    }
}

type SendqRequest = (
    Arc<Context>,
    types::Request,
    oneshot::Sender<Fallible<types::Response>>,
    usize,
);

struct Inner {
    /// Session builder for resetting sessions.
    builder: Builder,
    /// Underlying protocol session.
    session: Mutex<Session>,
    /// Unique session identifier.
    session_id: types::SessionID,
    /// Used transport.
    transport: Box<dyn Transport>,
    /// Internal send queue receiver, only available until the controller
    /// is spawned (is None later).
    recvq: Mutex<Option<mpsc::Receiver<SendqRequest>>>,
    /// Internal send queue sender for serializing all requests.
    sendq: mpsc::Sender<SendqRequest>,
    /// Flag indicating whether the controller has been spawned.
    has_controller: AtomicBool,
    /// Maximum number of call retries.
    max_retries: usize,
}

/// RPC client.
pub struct RpcClient {
    inner: Arc<Inner>,
}

impl RpcClient {
    fn new(transport: Box<dyn Transport>, builder: Builder) -> Self {
        let (tx, rx) = mpsc::channel(SENDQ_BACKLOG);

        Self {
            inner: Arc::new(Inner {
                builder: builder.clone(),
                session: Mutex::new(builder.build_initiator()),
                session_id: types::SessionID::random(),
                transport,
                recvq: Mutex::new(Some(rx)),
                sendq: tx,
                has_controller: AtomicBool::new(false),
                max_retries: 3,
            }),
        }
    }

    /// Construct an unconnected RPC client with runtime-internal transport.
    pub fn new_runtime(builder: Builder, protocol: Arc<Protocol>, endpoint: &str) -> Self {
        Self::new(
            Box::new(RuntimeTransport {
                protocol,
                endpoint: endpoint.to_owned(),
            }),
            builder,
        )
    }

    /// Construct an unconnected RPC client with gRPC transport.
    #[cfg(not(target_env = "sgx"))]
    pub fn new_grpc(builder: Builder, channel: Channel, endpoint: &str) -> Self {
        Self::new(
            Box::new(GrpcTransport {
                grpc_client: EnclaveRpcClient::new(channel),
                endpoint: endpoint.to_owned(),
            }),
            builder,
        )
    }

    /// Call a remote method.
    pub fn call<C, O>(&self, ctx: Context, method: &'static str, args: C) -> BoxFuture<O>
    where
        C: Serialize,
        O: DeserializeOwned + Send + 'static,
    {
        let request = types::Request {
            method: method.to_owned(),
            args: cbor::to_value(args),
        };

        Box::new(
            self.execute_call(ctx, request)
                .and_then(|response| match response.body {
                    types::Body::Success(value) => Ok(cbor::from_value(value)?),
                    types::Body::Error(error) => Err(RpcClientError::CallFailed(error).into()),
                }),
        )
    }

    fn execute_call(&self, ctx: Context, request: types::Request) -> BoxFuture<types::Response> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            // Spawn a new controller if we haven't spawned one yet.
            if !inner
                .has_controller
                .compare_and_swap(false, true, Ordering::SeqCst)
            {
                let rx = inner
                    .recvq
                    .lock()
                    .unwrap()
                    .take()
                    .expect("has_controller was false");

                let inner = inner.clone();
                let inner2 = inner.clone();
                spawn(
                    rx.for_each(move |(ctx, request, rsp_tx, retries)| {
                        let inner = inner.clone();
                        let inner2 = inner.clone();
                        let request2 = request.clone();
                        let ctx2 = ctx.clone();

                        Self::connect(inner.clone(), Context::create_child(&ctx))
                            .and_then(move |_| {
                                Self::call_raw(inner.clone(), Context::create_child(&ctx), request)
                            })
                            .then(
                                move |result| -> Box<dyn Future<Item = (), Error = ()> + Send> {
                                    match result {
                                        ref r if r.is_ok() || retries >= inner2.max_retries => {
                                            drop(rsp_tx.send(result));
                                            Box::new(future::ok(()))
                                        }
                                        _ => {
                                            // Attempt retry if number of retries is not exceeded.
                                            Box::new(
                                                inner2
                                                    .sendq
                                                    .clone()
                                                    .send((ctx2, request2, rsp_tx, retries + 1))
                                                    .map(|_| ())
                                                    .or_else(|err| {
                                                        let (_, _, rsp_tx, _) = err.into_inner();
                                                        rsp_tx
                                                            .send(Err(
                                                                RpcClientError::Dropped.into()
                                                            ))
                                                            .map_err(|_err| ())
                                                    })
                                                    .map_err(|_err| ()),
                                            )
                                        }
                                    }
                                },
                            )
                    })
                    .then(move |_| {
                        // Close stream after the client is dropped.
                        Self::close(inner2).map_err(|_err| ())
                    }),
                );
            }

            // Send request to controller.
            let (rsp_tx, rsp_rx) = oneshot::channel();
            inner
                .sendq
                .clone()
                .send((ctx.freeze(), request, rsp_tx, 0))
                .map_err(|err| err.into())
                .and_then(move |_| rsp_rx.map_err(|err| err.into()).and_then(|result| result))
        }))
    }

    fn connect(inner: Arc<Inner>, ctx: Context) -> BoxFuture<()> {
        Box::new(future::lazy(move || -> BoxFuture<()> {
            let mut session = inner.session.lock().unwrap();
            if session.is_connected() {
                return Box::new(future::ok(()));
            }

            let mut buffer = vec![];
            // Handshake1 -> Handshake2
            session
                .process_data(vec![], &mut buffer)
                .expect("initiation must always succeed");
            drop(session);

            let fctx = ctx.freeze();
            let ctx = Context::create_child(&fctx);
            let inner = inner.clone();
            let inner2 = inner.clone();
            Box::new(
                inner
                    .transport
                    .write_message(ctx, inner.session_id, buffer, String::new())
                    .and_then(move |data| -> BoxFuture<()> {
                        let mut session = inner.session.lock().unwrap();
                        let mut buffer = vec![];
                        // Handshake2 -> Transport
                        if let Err(error) = session.process_data(data, &mut buffer) {
                            return Box::new(future::err(error));
                        }

                        let ctx = Context::create_child(&fctx);
                        Box::new(
                            inner
                                .transport
                                .write_message(ctx, inner.session_id, buffer, String::new())
                                .map(|_| ()),
                        )
                    })
                    .or_else(move |err| {
                        // Failed to establish a session, we must reset it as otherwise
                        // it will always fail.
                        let mut session = inner2.session.lock().unwrap();
                        *session = inner2.builder.clone().build_initiator();

                        Err(err)
                    }),
            )
        }))
    }

    fn close(inner: Arc<Inner>) -> BoxFuture<()> {
        let mut session = inner.session.lock().unwrap();
        let mut buffer = vec![];
        if let Err(error) = session.write_message(types::Message::Close, &mut buffer) {
            return Box::new(future::err(error));
        }

        let ctx = Context::background();
        let inner = inner.clone();
        Box::new(
            inner
                .transport
                .write_message(ctx, inner.session_id, buffer, String::new())
                .and_then(move |data| {
                    // Verify that session is closed.
                    let mut session = inner.session.lock().unwrap();
                    let msg = session
                        .process_data(data, vec![])?
                        .expect("message must be decoded if there is no error");

                    match msg {
                        types::Message::Close => {
                            session.close();
                            Ok(())
                        }
                        msg => Err(RpcClientError::ExpectedCloseMessage(msg).into()),
                    }
                }),
        )
    }

    fn call_raw(
        inner: Arc<Inner>,
        ctx: Context,
        request: types::Request,
    ) -> BoxFuture<types::Response> {
        let method = request.method.clone();
        let msg = types::Message::Request(request);
        let mut session = inner.session.lock().unwrap();
        let mut buffer = vec![];
        if let Err(error) = session.write_message(msg, &mut buffer) {
            return Box::new(future::err(error));
        }

        let inner = inner.clone();
        let inner2 = inner.clone();
        Box::new(
            inner
                .transport
                .write_message(ctx, inner.session_id, buffer, method)
                .and_then(move |data| {
                    let mut session = inner.session.lock().unwrap();
                    let msg = session
                        .process_data(data, vec![])?
                        .expect("message must be decoded if there is no error");

                    match msg {
                        types::Message::Response(rsp) => Ok(rsp),
                        msg => Err(RpcClientError::ExpectedResponseMessage(msg).into()),
                    }
                })
                .or_else(move |err| {
                    // Failed to communicate, we must reset it as otherwise it will always fail.
                    let mut session = inner2.session.lock().unwrap();
                    *session = inner2.builder.clone().build_initiator();

                    Err(err)
                }),
        )
    }
}
