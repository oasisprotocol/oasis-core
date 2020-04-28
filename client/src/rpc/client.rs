//! Enclave RPC client.
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

use failure::{Fail, Fallible};
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

#[cfg(not(target_env = "sgx"))]
use oasis_core_runtime::common::runtime::RuntimeId;
use oasis_core_runtime::{
    common::cbor,
    protocol::Protocol,
    rpc::{
        session::{Builder, Session},
        types,
    },
};

#[cfg(not(target_env = "sgx"))]
use super::api::EnclaveRPCClient;
#[cfg(not(target_env = "sgx"))]
use super::transport::GrpcTransport;
use super::transport::{RuntimeTransport, Transport};
use crate::BoxFuture;

/// Internal send queue backlog.
const SENDQ_BACKLOG: usize = 10;

/// RPC client error.
#[derive(Debug, Fail)]
pub enum RpcClientError {
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

type SendqRequest = (
    Arc<Context>,
    types::Request,
    oneshot::Sender<Fallible<types::Response>>,
    usize,
);

struct MultiplexedSession {
    /// Session builder for resetting sessions.
    builder: Builder,
    /// Unique session identifier.
    id: types::SessionID,
    /// Current underlying protocol session.
    inner: Session,
}

impl MultiplexedSession {
    fn new(builder: Builder) -> Self {
        Self {
            builder: builder.clone(),
            id: types::SessionID::random(),
            inner: builder.build_initiator(),
        }
    }

    fn reset(&mut self) {
        self.id = types::SessionID::random();
        self.inner = self.builder.clone().build_initiator();
    }
}

struct Inner {
    /// Multiplexed session.
    session: Mutex<MultiplexedSession>,
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
                session: Mutex::new(MultiplexedSession::new(builder)),
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
    pub fn new_grpc(
        builder: Builder,
        channel: Channel,
        runtime_id: RuntimeId,
        endpoint: &str,
    ) -> Self {
        Self::new(
            Box::new(GrpcTransport {
                grpc_client: EnclaveRPCClient::new(channel),
                runtime_id,
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
            if session.inner.is_connected() {
                return Box::new(future::ok(()));
            }

            let mut buffer = vec![];
            // Handshake1 -> Handshake2
            session
                .inner
                .process_data(vec![], &mut buffer)
                .expect("initiation must always succeed");
            let session_id = session.id;
            drop(session);

            let fctx = ctx.freeze();
            let ctx = Context::create_child(&fctx);
            let inner = inner.clone();
            let inner2 = inner.clone();
            Box::new(
                inner
                    .transport
                    .write_message(ctx, session_id, buffer, String::new())
                    .and_then(move |data| -> BoxFuture<()> {
                        let mut session = inner.session.lock().unwrap();
                        let mut buffer = vec![];
                        // Handshake2 -> Transport
                        if let Err(error) = session.inner.process_data(data, &mut buffer) {
                            return Box::new(future::err(error));
                        }

                        let ctx = Context::create_child(&fctx);
                        Box::new(
                            inner
                                .transport
                                .write_message(ctx, session.id, buffer, String::new())
                                .map(|_| ()),
                        )
                    })
                    .or_else(move |err| {
                        // Failed to establish a session, we must reset it as otherwise
                        // it will always fail.
                        let mut session = inner2.session.lock().unwrap();
                        session.reset();

                        Err(err)
                    }),
            )
        }))
    }

    fn close(inner: Arc<Inner>) -> BoxFuture<()> {
        let mut session = inner.session.lock().unwrap();
        let mut buffer = vec![];
        if let Err(error) = session
            .inner
            .write_message(types::Message::Close, &mut buffer)
        {
            return Box::new(future::err(error));
        }

        let ctx = Context::background();
        let inner = inner.clone();
        Box::new(
            inner
                .transport
                .write_message(ctx, session.id, buffer, String::new())
                .and_then(move |data| {
                    // Verify that session is closed.
                    let mut session = inner.session.lock().unwrap();
                    let msg = session
                        .inner
                        .process_data(data, vec![])?
                        .expect("message must be decoded if there is no error");

                    match msg {
                        types::Message::Close => {
                            session.inner.close();
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
        if let Err(error) = session.inner.write_message(msg, &mut buffer) {
            return Box::new(future::err(error));
        }

        let inner = inner.clone();
        let inner2 = inner.clone();
        Box::new(
            inner
                .transport
                .write_message(ctx, session.id, buffer, method)
                .and_then(move |data| {
                    let mut session = inner.session.lock().unwrap();
                    let msg = session
                        .inner
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
                    session.reset();

                    Err(err)
                }),
        )
    }
}

#[cfg(test)]
mod test {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    };

    use failure::format_err;
    use futures::future;
    use io_context::Context;
    use tokio::runtime::Runtime;

    use oasis_core_runtime::{
        rak::RAK,
        rpc::{demux::Demux, session, types},
    };

    use super::{super::transport::Transport, RpcClient};
    use crate::BoxFuture;

    #[derive(Clone)]
    struct MockTransport {
        rak: Arc<RAK>,
        demux: Arc<Mutex<Demux>>,
        next_error: Arc<AtomicBool>,
    }

    impl MockTransport {
        fn new() -> Self {
            let rak = Arc::new(RAK::new());

            Self {
                rak: rak.clone(),
                demux: Arc::new(Mutex::new(Demux::new(rak))),
                next_error: Arc::new(AtomicBool::new(false)),
            }
        }

        fn reset(&self) {
            let mut demux = self.demux.lock().unwrap();
            *demux = Demux::new(self.rak.clone());
        }

        fn induce_transport_error(&self) {
            self.next_error.store(true, Ordering::SeqCst);
        }
    }

    impl Transport for MockTransport {
        fn write_message_impl(&self, _ctx: Context, data: Vec<u8>) -> BoxFuture<Vec<u8>> {
            if self
                .next_error
                .compare_and_swap(true, false, Ordering::SeqCst)
            {
                return Box::new(future::err(format_err!("transport error")));
            }

            let mut demux = self.demux.lock().unwrap();

            // Deliver directly to the multiplexer.
            let mut buffer = Vec::new();
            match demux.process_frame(data, &mut buffer) {
                Err(err) => Box::new(future::err(err)),
                Ok(Some((session_id, _session_info, message, _untrusted_plaintext))) => {
                    // Message, process and write reply.
                    let body = match message {
                        types::Message::Request(rq) => {
                            // Just echo back what was given.
                            types::Body::Success(rq.args)
                        }
                        _ => panic!("unhandled message type"),
                    };
                    let response = types::Message::Response(types::Response { body });

                    let mut buffer = Vec::new();
                    match demux.write_message(session_id, response, &mut buffer) {
                        Ok(_) => Box::new(future::ok(buffer)),
                        Err(error) => Box::new(future::err(error)),
                    }
                }
                Ok(None) => {
                    // Handshake.
                    Box::new(future::ok(buffer))
                }
            }
        }
    }

    #[test]
    fn test_rpc_client() {
        let mut rt = Runtime::new().unwrap();
        let transport = MockTransport::new();
        let builder = session::Builder::new();
        let client = RpcClient::new(Box::new(transport.clone()), builder);

        // Basic call.
        let result: u64 = rt
            .block_on(client.call(Context::background(), "test", 42))
            .unwrap();
        assert_eq!(result, 42, "call should work");

        // Reset all sessions on the server and make sure that we can still get a response.
        transport.reset();

        let result: u64 = rt
            .block_on(client.call(Context::background(), "test", 43))
            .unwrap();
        assert_eq!(result, 43, "call should work");

        // Induce a single transport error without resetting the server sessions and make sure we
        // can still get a response.
        transport.induce_transport_error();

        let result: u64 = rt
            .block_on(client.call(Context::background(), "test", 44))
            .unwrap();
        assert_eq!(result, 44, "call should work");
    }
}
