//! Enclave RPC client.
use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

use anyhow;
use futures::{
    channel::{mpsc, oneshot},
    prelude::*,
};
use io_context::Context;
use thiserror::Error;
use tokio;

use oasis_core_runtime::{
    cbor,
    common::sgx::avr::EnclaveIdentity,
    enclave_rpc::{
        session::{Builder, Session},
        types,
    },
    protocol::Protocol,
};

use super::transport::{RuntimeTransport, Transport};

/// Internal send queue backlog.
const SENDQ_BACKLOG: usize = 10;

/// RPC client error.
#[derive(Error, Debug)]
pub enum RpcClientError {
    #[error("call failed: {0}")]
    CallFailed(String),
    #[error("expected response message, received: {0:?}")]
    ExpectedResponseMessage(types::Message),
    #[error("expected close message, received: {0:?}")]
    ExpectedCloseMessage(types::Message),
    #[error("transport error")]
    Transport,
    #[error("client dropped")]
    Dropped,
    #[error("decode error: {0}")]
    DecodeError(#[from] cbor::DecodeError),
    #[error("unknown error: {0}")]
    Unknown(#[from] anyhow::Error),
}

type SendqRequest = (
    Arc<Context>,
    types::Request,
    oneshot::Sender<Result<types::Response, RpcClientError>>,
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

    /// Call a remote method.
    pub async fn call<C, O>(
        &self,
        ctx: Context,
        method: &'static str,
        args: C,
    ) -> Result<O, RpcClientError>
    where
        C: cbor::Encode,
        O: cbor::Decode + Send + 'static,
    {
        let request = types::Request {
            method: method.to_owned(),
            args: cbor::to_value(args),
        };

        let response = self.execute_call(ctx, request).await?;
        match response.body {
            types::Body::Success(value) => Ok(cbor::from_value(value)?),
            types::Body::Error(error) => Err(RpcClientError::CallFailed(error)),
        }
    }

    async fn execute_call(
        &self,
        ctx: Context,
        request: types::Request,
    ) -> Result<types::Response, RpcClientError> {
        // Spawn a new controller if we haven't spawned one yet.
        if !self
            .inner
            .has_controller
            .compare_and_swap(false, true, Ordering::SeqCst)
        {
            let mut rx = self
                .inner
                .recvq
                .lock()
                .unwrap()
                .take()
                .expect("has_controller was false");
            let inner = self.inner.clone();

            tokio::spawn(async move {
                while let Some((ctx, request, rsp_tx, retries)) = rx.next().await {
                    let result = async {
                        // Attempt to establish a connection. This will not do anything in case the
                        // session has already been established.
                        Self::connect(inner.clone(), Context::create_child(&ctx)).await?;

                        // Perform the call.
                        Self::call_raw(inner.clone(), Context::create_child(&ctx), request.clone())
                            .await
                    }
                    .await;

                    match result {
                        ref r if r.is_ok() || retries >= inner.max_retries => {
                            // Request was successful or number of retries has been exceeded.
                            let _ = rsp_tx.send(result);
                        }

                        _ => {
                            // Attempt retry if number of retries is not exceeded. Retry is
                            // performed by queueing another request.
                            let _ = inner
                                .sendq
                                .clone()
                                .send((ctx, request, rsp_tx, retries + 1))
                                .await;
                        }
                    }
                }

                // Close stream after the client is dropped.
                let _ = Self::close(inner).await;
            });
        }

        // Send request to controller.
        let (rsp_tx, rsp_rx) = oneshot::channel();
        self.inner
            .sendq
            .clone()
            .send((ctx.freeze(), request, rsp_tx, 0))
            .await
            .map_err(|_| RpcClientError::Dropped)?;

        rsp_rx.await.map_err(|_| RpcClientError::Dropped)?
    }

    async fn connect(inner: Arc<Inner>, ctx: Context) -> Result<(), RpcClientError> {
        let mut buffer = vec![];
        let session_id;
        {
            let mut session = inner.session.lock().unwrap();
            if session.inner.is_connected() {
                return Ok(());
            }
            if session.inner.is_closed() {
                // In case the session is closed, reset it.
                session.reset();
            }

            // Handshake1 -> Handshake2
            session
                .inner
                .process_data(vec![], &mut buffer)
                .expect("initiation must always succeed");
            session_id = session.id;
        }

        let fctx = ctx.freeze();
        let ctx = Context::create_child(&fctx);

        let data = inner
            .transport
            .write_message(ctx, session_id, buffer, String::new())
            .await
            .map_err(|_| RpcClientError::Transport)?;

        let mut buffer = vec![];
        {
            let mut session = inner.session.lock().unwrap();
            // Handshake2 -> Transport
            session
                .inner
                .process_data(data, &mut buffer)
                .map_err(|_| RpcClientError::Transport)?;
        }

        let ctx = Context::create_child(&fctx);
        inner
            .transport
            .write_message(ctx, session_id, buffer, String::new())
            .await
            .map_err(|_| RpcClientError::Transport)?;

        Ok(())
    }

    async fn close(inner: Arc<Inner>) -> Result<(), RpcClientError> {
        let mut buffer = vec![];
        let session_id;
        {
            let mut session = inner.session.lock().unwrap();
            session
                .inner
                .write_message(types::Message::Close, &mut buffer)
                .map_err(|_| RpcClientError::Transport)?;
            session_id = session.id;
        }

        let ctx = Context::background();
        let data = inner
            .transport
            .write_message(ctx, session_id, buffer, String::new())
            .await
            .map_err(|_| RpcClientError::Transport)?;

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
            msg => Err(RpcClientError::ExpectedCloseMessage(msg)),
        }
    }

    async fn call_raw(
        inner: Arc<Inner>,
        ctx: Context,
        request: types::Request,
    ) -> Result<types::Response, RpcClientError> {
        let method = request.method.clone();
        let msg = types::Message::Request(request);
        let session_id;
        let mut buffer = vec![];
        {
            let mut session = inner.session.lock().unwrap();
            session
                .inner
                .write_message(msg, &mut buffer)
                .map_err(|_| RpcClientError::Transport)?;
            session_id = session.id;
        }

        let data = inner
            .transport
            .write_message(ctx, session_id, buffer, method)
            .await
            .map_err(|_| RpcClientError::Transport)?;

        let mut session = inner.session.lock().unwrap();
        let msg = session
            .inner
            .process_data(data, vec![])?
            .expect("message must be decoded if there is no error");

        match msg {
            types::Message::Response(rsp) => Ok(rsp),
            msg => Err(RpcClientError::ExpectedResponseMessage(msg)),
        }
    }

    /// Update session enclaves if changed.
    pub fn update_enclaves(&self, enclaves: Option<HashSet<EnclaveIdentity>>) {
        let mut session = self.inner.session.lock().unwrap();
        if session.builder.get_remote_enclaves() != &enclaves {
            session.builder = session.builder.clone().remote_enclaves(enclaves);
            session.reset();
        }
    }
}

#[cfg(test)]
mod test {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    };

    use anyhow::anyhow;
    use futures::future::{self, BoxFuture};
    use io_context::Context;

    use oasis_core_runtime::{
        enclave_rpc::{demux::Demux, session, types},
        rak::RAK,
    };

    use super::{super::transport::Transport, RpcClient};

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
        fn write_message_impl(
            &self,
            _ctx: Context,
            data: Vec<u8>,
        ) -> BoxFuture<Result<Vec<u8>, anyhow::Error>> {
            if self
                .next_error
                .compare_and_swap(true, false, Ordering::SeqCst)
            {
                return Box::pin(future::err(anyhow!("transport error")));
            }

            let mut demux = self.demux.lock().unwrap();

            // Deliver directly to the multiplexer.
            let mut buffer = Vec::new();
            match demux.process_frame(data, &mut buffer) {
                Err(err) => Box::pin(future::err(err)),
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
                        Ok(_) => Box::pin(future::ok(buffer)),
                        Err(error) => Box::pin(future::err(error)),
                    }
                }
                Ok(None) => {
                    // Handshake.
                    Box::pin(future::ok(buffer))
                }
            }
        }
    }

    #[test]
    fn test_rpc_client() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
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
