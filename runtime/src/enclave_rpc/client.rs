//! Enclave RPC client.
use std::{
    collections::HashSet,
    mem,
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
use thiserror::Error;
use tokio;

use crate::{
    cbor,
    common::{
        crypto::signature,
        namespace::Namespace,
        sgx::{EnclaveIdentity, QuotePolicy},
    },
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
    #[error("unsupported RPC kind")]
    UnsupportedRpcKind,
    #[error("client dropped")]
    Dropped,
    #[error("decode error: {0}")]
    DecodeError(#[from] cbor::DecodeError),
    #[error("unknown error: {0}")]
    Unknown(#[from] anyhow::Error),
}

type SendqRequest = (
    types::Request,
    types::Kind,
    oneshot::Sender<Result<(u64, types::Response), RpcClientError>>,
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
    /// Allowed nodes.
    nodes: Mutex<Vec<signature::PublicKey>>,
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
    fn new(
        transport: Box<dyn Transport>,
        builder: Builder,
        nodes: Vec<signature::PublicKey>,
    ) -> Self {
        let (tx, rx) = mpsc::channel(SENDQ_BACKLOG);

        Self {
            inner: Arc::new(Inner {
                nodes: Mutex::new(nodes),
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
    pub fn new_runtime(
        builder: Builder,
        protocol: Arc<Protocol>,
        endpoint: &str,
        nodes: Vec<signature::PublicKey>,
    ) -> Self {
        Self::new(
            Box::new(RuntimeTransport::new(protocol, endpoint)),
            builder,
            nodes,
        )
    }

    /// Call a remote method using an encrypted and authenticated Noise session.
    pub async fn secure_call<C, O>(
        &self,
        method: &'static str,
        args: C,
    ) -> Result<O, RpcClientError>
    where
        C: cbor::Encode,
        O: cbor::Decode + Send + 'static,
    {
        self.call(method, args, types::Kind::NoiseSession).await
    }

    /// Call a remote method over an insecure channel where messages are sent in plain text.
    pub async fn insecure_call<C, O>(
        &self,
        method: &'static str,
        args: C,
    ) -> Result<O, RpcClientError>
    where
        C: cbor::Encode,
        O: cbor::Decode + Send + 'static,
    {
        self.call(method, args, types::Kind::InsecureQuery).await
    }

    async fn call<C, O>(
        &self,
        method: &'static str,
        args: C,
        kind: types::Kind,
    ) -> Result<O, RpcClientError>
    where
        C: cbor::Encode,
        O: cbor::Decode + Send + 'static,
    {
        let request = types::Request {
            method: method.to_owned(),
            args: cbor::to_value(args),
        };

        let (pfid, response) = self.execute_call(request, kind).await?;
        let result = match response.body {
            types::Body::Success(value) => cbor::from_value(value).map_err(Into::into),
            types::Body::Error(error) => Err(RpcClientError::CallFailed(error)),
        };

        // Report peer feedback based on whether call was successful.
        let pf = match result {
            Ok(_) => types::PeerFeedback::Success,
            Err(_) => types::PeerFeedback::Failure,
        };
        self.inner.transport.set_peer_feedback(pfid, Some(pf));

        result
    }

    async fn execute_call(
        &self,
        request: types::Request,
        kind: types::Kind,
    ) -> Result<(u64, types::Response), RpcClientError> {
        // Spawn a new controller if we haven't spawned one yet.
        if self
            .inner
            .has_controller
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
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
                while let Some((request, kind, rsp_tx, retries)) = rx.next().await {
                    let result = async {
                        match kind {
                            types::Kind::NoiseSession => {
                                // Attempt to establish a connection. This will not do anything in case the
                                // session has already been established.
                                Self::connect(inner.clone()).await?;

                                // Perform the call.
                                Self::secure_call_raw(inner.clone(), request.clone()).await
                            }
                            types::Kind::InsecureQuery => {
                                // Perform the call.
                                Self::insecure_call_raw(inner.clone(), request.clone()).await
                            }
                            _ => Err(RpcClientError::UnsupportedRpcKind),
                        }
                    }
                    .await;

                    // Update peer feedback for next request.
                    let pfid = inner.transport.get_peer_feedback_id();
                    if result.is_err() {
                        // In case there was a transport error we need to reset the session
                        // immediately as no progress is possible.
                        let mut session = inner.session.lock().unwrap();
                        session.reset();
                        // Set peer feedback immediately so retries can try new peers.
                        inner
                            .transport
                            .set_peer_feedback(pfid, Some(types::PeerFeedback::Failure));
                    }

                    match result {
                        ref r if r.is_ok() || retries >= inner.max_retries => {
                            // Request was successful or number of retries has been exceeded.
                            let _ = rsp_tx.send(result.map(|rsp| (pfid, rsp)));
                        }

                        _ => {
                            // Attempt retry if number of retries is not exceeded. Retry is
                            // performed by queueing another request.
                            let _ = inner
                                .sendq
                                .clone()
                                .send((request, kind, rsp_tx, retries + 1))
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
            .send((request, kind, rsp_tx, 0))
            .await
            .map_err(|_| RpcClientError::Dropped)?;

        rsp_rx.await.map_err(|_| RpcClientError::Dropped)?
    }

    async fn connect(inner: Arc<Inner>) -> Result<(), RpcClientError> {
        let mut buffer = vec![];
        let session_id;

        {
            let mut session = inner.session.lock().unwrap();
            let nodes = inner.nodes.lock().unwrap();

            // No need to create a new session if we are connected to one of the nodes.
            if session.inner.is_connected()
                && (nodes.is_empty() || session.inner.is_connected_to(&nodes))
            {
                return Ok(());
            }
            // Make sure the session is reset for a new connection.
            session.reset();

            // Handshake1 -> Handshake2
            session
                .inner
                .process_data(vec![], &mut buffer)
                .expect("initiation must always succeed");
            session_id = session.id;
        }

        let nodes = inner.nodes.lock().unwrap().to_vec();
        let (data, node) = inner
            .transport
            .write_noise_session(session_id, buffer, String::new(), nodes)
            .await
            .map_err(|_| RpcClientError::Transport)?;

        let mut buffer = vec![];
        {
            let mut session = inner.session.lock().unwrap();
            // Update the session with the identity of the remote node. The latter still needs
            // to be verified using the RAK from the consensus layer.
            session.inner.set_remote_node(node)?;

            // Handshake2 -> Transport
            session
                .inner
                .process_data(data, &mut buffer)
                .map_err(|_| RpcClientError::Transport)?;
        }

        inner
            .transport
            .write_noise_session(session_id, buffer, String::new(), vec![node])
            .await
            .map_err(|_| RpcClientError::Transport)?;

        Ok(())
    }

    async fn close(inner: Arc<Inner>) -> Result<(), RpcClientError> {
        let mut buffer = vec![];
        let session_id;
        let node;
        {
            let mut session = inner.session.lock().unwrap();
            if !session.inner.is_connected() {
                return Ok(());
            }
            session
                .inner
                .write_message(types::Message::Close, &mut buffer)
                .map_err(|_| RpcClientError::Transport)?;
            session_id = session.id;
            node = session.inner.get_node()?
        }

        let (data, _) = inner
            .transport
            .write_noise_session(session_id, buffer, String::new(), vec![node])
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

    async fn secure_call_raw(
        inner: Arc<Inner>,
        request: types::Request,
    ) -> Result<types::Response, RpcClientError> {
        let method = request.method.clone();
        let msg = types::Message::Request(request);
        let session_id;
        let node;
        let mut buffer = vec![];
        {
            let mut session = inner.session.lock().unwrap();
            session
                .inner
                .write_message(msg, &mut buffer)
                .map_err(|_| RpcClientError::Transport)?;
            session_id = session.id;
            node = session.inner.get_node()?;
        }

        let (data, _) = inner
            .transport
            .write_noise_session(session_id, buffer, method, vec![node])
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

    async fn insecure_call_raw(
        inner: Arc<Inner>,
        request: types::Request,
    ) -> Result<types::Response, RpcClientError> {
        let nodes = inner.nodes.lock().unwrap().to_vec();
        let (data, _) = inner
            .transport
            .write_insecure_query(cbor::to_vec(request), nodes)
            .await
            .map_err(|_| RpcClientError::Transport)?;

        cbor::from_slice(&data).map_err(RpcClientError::DecodeError)
    }

    /// Update allowed remote enclave identities.
    ///
    /// Useful if the key manager's policy has changed.
    pub fn update_enclaves(&self, enclaves: Option<HashSet<EnclaveIdentity>>) {
        let mut session = self.inner.session.lock().unwrap();
        if session.builder.get_remote_enclaves() == &enclaves {
            return;
        }
        session.builder = mem::take(&mut session.builder).remote_enclaves(enclaves);
        session.reset();
    }

    /// Update key manager's quote policy.
    pub fn update_quote_policy(&self, policy: QuotePolicy) {
        let policy = Some(Arc::new(policy));
        let mut session = self.inner.session.lock().unwrap();
        if session.builder.get_quote_policy() == &policy {
            return;
        }
        session.builder = mem::take(&mut session.builder).quote_policy(policy);
        session.reset();
    }

    /// Update remote runtime id.
    pub fn update_runtime_id(&self, id: Option<Namespace>) {
        let mut session = self.inner.session.lock().unwrap();
        if session.builder.get_remote_runtime_id() == &id {
            return;
        }
        session.builder = mem::take(&mut session.builder).remote_runtime_id(id);
        session.reset();
    }

    /// Update allowed nodes.
    pub fn update_nodes(&self, nodes: Vec<signature::PublicKey>) {
        let mut inner_nodes = self.inner.nodes.lock().unwrap();
        *inner_nodes = nodes;
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

    use crate::{
        common::crypto::signature,
        enclave_rpc::{demux::Demux, session, types},
        identity::Identity,
    };

    use super::{super::transport::Transport, RpcClient};

    #[derive(Clone)]
    struct MockTransport {
        identity: Arc<Identity>,
        demux: Arc<Mutex<Demux>>,
        next_error: Arc<AtomicBool>,
        peer_feedback: Arc<Mutex<(u64, Option<types::PeerFeedback>)>>,
        peer_feedback_history: Arc<Mutex<Vec<(u64, Option<types::PeerFeedback>)>>>,
    }

    impl MockTransport {
        fn new() -> Self {
            let identity = Arc::new(Identity::new());

            Self {
                identity: identity.clone(),
                demux: Arc::new(Mutex::new(Demux::new(identity))),
                next_error: Arc::new(AtomicBool::new(false)),
                peer_feedback: Arc::new(Mutex::new((0, None))),
                peer_feedback_history: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn reset(&self) {
            let mut demux = self.demux.lock().unwrap();
            *demux = Demux::new(self.identity.clone());
        }

        fn induce_transport_error(&self) {
            self.next_error.store(true, Ordering::SeqCst);
        }

        fn take_peer_feedback_history(&self) -> Vec<(u64, Option<types::PeerFeedback>)> {
            let mut pfh: Vec<_> = {
                let mut pfh = self.peer_feedback_history.lock().unwrap();
                std::mem::take(&mut pfh)
            };
            // Also add the pending feedback.
            let pf = self.peer_feedback.lock().unwrap();
            pfh.push(pf.clone());
            pfh
        }
    }

    impl Transport for MockTransport {
        fn write_message_impl(
            &self,
            request: Vec<u8>,
            kind: types::Kind,
            _nodes: Vec<signature::PublicKey>,
        ) -> BoxFuture<Result<(Vec<u8>, signature::PublicKey), anyhow::Error>> {
            let pf = {
                let mut pf = self.peer_feedback.lock().unwrap();
                let peer_feedback = pf.1.take();

                if !matches!(peer_feedback, None | Some(types::PeerFeedback::Success)) {
                    pf.0 += 1;
                }

                (pf.0, peer_feedback)
            };
            self.peer_feedback_history.lock().unwrap().push(pf);

            // Induce error when configured to do so.
            if self
                .next_error
                .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Box::pin(future::err(anyhow!("transport error")));
            }

            let mut demux = self.demux.lock().unwrap();

            match kind {
                types::Kind::NoiseSession => {
                    // Deliver directly to the multiplexer.
                    let mut buffer = Vec::new();
                    match demux.process_frame(request, &mut buffer) {
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
                                Ok(_) => Box::pin(future::ok((buffer, Default::default()))),
                                Err(error) => Box::pin(future::err(error)),
                            }
                        }
                        Ok(None) => {
                            // Handshake.
                            Box::pin(future::ok((buffer, Default::default())))
                        }
                    }
                }
                types::Kind::InsecureQuery => {
                    // Just echo back what was given.
                    let rq: types::Request = cbor::from_slice(&request).unwrap();
                    let body = types::Body::Success(rq.args);
                    let response = types::Response { body };
                    return Box::pin(future::ok((cbor::to_vec(response), Default::default())));
                }
                types::Kind::LocalQuery => {
                    panic!("unhandled RPC kind")
                }
            }
        }

        fn set_peer_feedback(&self, pfid: u64, peer_feedback: Option<types::PeerFeedback>) {
            let mut pf = self.peer_feedback.lock().unwrap();
            if pf.0 != pfid {
                return;
            }

            pf.1 = peer_feedback;
        }

        fn get_peer_feedback_id(&self) -> u64 {
            self.peer_feedback.lock().unwrap().0
        }
    }

    #[test]
    fn test_rpc_client() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let transport = MockTransport::new();
        let builder = session::Builder::default();
        let client = RpcClient::new(Box::new(transport.clone()), builder, vec![]);

        // Basic secure call.
        let result: u64 = rt.block_on(client.secure_call("test", 42)).unwrap();
        assert_eq!(result, 42, "secure call should work");
        assert_eq!(
            transport.take_peer_feedback_history(),
            vec![
                (0, None),                               // Handshake.
                (0, None),                               // Handshake.
                (0, None),                               // Call.
                (0, Some(types::PeerFeedback::Success)), // Handled call.
            ]
        );

        // Reset all sessions on the server and make sure that we can still get a response.
        transport.reset();

        let result: u64 = rt.block_on(client.secure_call("test", 43)).unwrap();
        assert_eq!(result, 43, "secure call should work");
        assert_eq!(
            transport.take_peer_feedback_history(),
            vec![
                (0, Some(types::PeerFeedback::Success)), // Previous handled call.
                (1, Some(types::PeerFeedback::Failure)), // Failed call due to session reset.
                (1, None),                               // New handshake.
                (1, None),                               // New handshake.
                (1, Some(types::PeerFeedback::Success)), // Handled call.
            ]
        );

        // Induce a single transport error without resetting the server sessions and make sure we
        // can still get a response.
        transport.induce_transport_error();

        let result: u64 = rt.block_on(client.secure_call("test", 44)).unwrap();
        assert_eq!(result, 44, "secure call should work");
        assert_eq!(
            transport.take_peer_feedback_history(),
            vec![
                (1, Some(types::PeerFeedback::Success)), // Previous handled call.
                (2, Some(types::PeerFeedback::Failure)), // Failed call due to induced error.
                (2, None),                               // New handshake.
                (2, None),                               // New handshake.
                (2, Some(types::PeerFeedback::Success)), // Handled call.
            ]
        );

        // Basic insecure call.
        let result: u64 = rt.block_on(client.insecure_call("test", 45)).unwrap();
        assert_eq!(result, 45, "insecure call should work");
        assert_eq!(
            transport.take_peer_feedback_history(),
            vec![
                (2, Some(types::PeerFeedback::Success)), // Previous handled call.
                (2, Some(types::PeerFeedback::Success)), // Handled call.
            ]
        );

        // Induce a single transport error and make sure we can still get a response.
        transport.induce_transport_error();

        let result: u64 = rt.block_on(client.insecure_call("test", 46)).unwrap();
        assert_eq!(result, 46, "insecure call should work");
        assert_eq!(
            transport.take_peer_feedback_history(),
            vec![
                (2, Some(types::PeerFeedback::Success)), // Previous handled call.
                (3, Some(types::PeerFeedback::Failure)), // Failed call due to induced error.
                (3, Some(types::PeerFeedback::Success)), // Handled call.
            ]
        );
    }
}
