//! Enclave RPC client.
use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
};

use lazy_static::lazy_static;
#[cfg(not(test))]
use rand::{rngs::OsRng, RngCore};

use thiserror::Error;
use tokio::sync::{mpsc, oneshot, OwnedMutexGuard};

use crate::{
    common::{
        crypto::signature,
        namespace::Namespace,
        sgx::{EnclaveIdentity, QuotePolicy},
        time::insecure_posix_time,
    },
    enclave_rpc::{session::Builder, types},
    protocol::Protocol,
};

use super::{
    sessions::{self, MultiplexedSession, Sessions, SharedSession},
    transport::{RuntimeTransport, Transport},
};

/// Internal command queue backlog.
const CMDQ_BACKLOG: usize = 32;
/// Maximum number of retries on transport errors.
const MAX_TRANSPORT_ERROR_RETRIES: usize = 3;

lazy_static! {
    /// The ID of the next RPC client.
    static ref NEXT_CLIENT_ID: AtomicU32 = AtomicU32::new(RpcClient::random_client_id());
}

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
    #[error("sessions error: {0}")]
    SessionsError(#[from] sessions::Error),
    #[error("unknown error: {0}")]
    Unknown(#[from] anyhow::Error),
}

/// A command sent to the client controller task.
#[derive(Debug)]
enum Command {
    Call(
        types::Request,
        types::Kind,
        Vec<signature::PublicKey>,
        oneshot::Sender<Result<(u64, types::Response), RpcClientError>>,
    ),
    PeerFeedback(u64, types::PeerFeedback),
    UpdateEnclaves(Option<HashSet<EnclaveIdentity>>),
    UpdateQuotePolicy(QuotePolicy),
    UpdateRuntimeID(Option<Namespace>),
    #[cfg(test)]
    Ping(oneshot::Sender<()>),
}

struct Controller {
    /// Multiplexed sessions.
    sessions: Sessions<signature::PublicKey>,
    /// Used transport.
    transport: Box<dyn Transport>,
    /// Internal command queue (receiver part).
    cmdq: mpsc::Receiver<Command>,
    /// The ID of the client.
    client_id: u32,
    /// The total number of requests sent.
    sent_request_count: u32,
}

impl Controller {
    async fn run(mut self) {
        while let Some(cmd) = self.cmdq.recv().await {
            match cmd {
                Command::Call(request, kind, nodes, sender) => {
                    self.call(request, kind, nodes, sender).await
                }
                Command::PeerFeedback(request_id, peer_feedback) => {
                    let _ = self
                        .transport
                        .submit_peer_feedback(request_id, peer_feedback)
                        .await; // Ignore error.
                }
                Command::UpdateEnclaves(enclaves) => {
                    if self.sessions.update_enclaves(enclaves) {
                        self.close_all().await;
                    }
                }
                Command::UpdateQuotePolicy(policy) => {
                    if self.sessions.update_quote_policy(policy) {
                        self.close_all().await;
                    }
                }
                Command::UpdateRuntimeID(id) => {
                    if self.sessions.update_runtime_id(id) {
                        self.close_all().await;
                    }
                }
                #[cfg(test)]
                Command::Ping(sender) => {
                    let _ = sender.send(());
                }
            }
        }

        // Close all sessions after the client is dropped.
        self.close_all().await;
    }

    async fn call(
        &mut self,
        request: types::Request,
        kind: types::Kind,
        nodes: Vec<signature::PublicKey>,
        sender: oneshot::Sender<Result<(u64, types::Response), RpcClientError>>,
    ) {
        let result = async {
            match kind {
                types::Kind::NoiseSession => {
                    // Attempt to establish a connection. This will not do anything in case the
                    // session has already been established.
                    let session = self.connect(nodes).await?;
                    let mut session = session.lock_owned().await;

                    // Perform the call.
                    let result = self.secure_call_raw(request, &mut session).await;

                    // In case there was a transport error we need to remove the session immediately
                    // as no progress is possible.
                    if result.is_err() {
                        self.sessions.remove(&session);
                    }

                    result
                }
                types::Kind::InsecureQuery => {
                    // Perform the call.
                    self.insecure_call_raw(request, nodes).await
                }
                _ => Err(RpcClientError::UnsupportedRpcKind),
            }
        }
        .await;

        let request_id = self.get_request_id();

        if result.is_err() {
            // Set peer feedback immediately so retries can try new peers.
            let _ = self
                .transport
                .submit_peer_feedback(request_id, types::PeerFeedback::Failure)
                .await; // Ignore error.
        }

        let _ = sender.send(result.map(|rsp| (request_id, rsp)));
    }

    async fn connect(
        &mut self,
        nodes: Vec<signature::PublicKey>,
    ) -> Result<SharedSession<signature::PublicKey>, RpcClientError> {
        // No need to create a new session if we are connected to one of the nodes.
        if let Some(session) = self.sessions.find(&nodes) {
            return Ok(session);
        }

        // Create a new session.
        let peer_id = Default::default(); // Not yet know.
        let mut session = self.sessions.create_initiator(peer_id);
        let session_id = *session.get_session_id();

        // Handshake1 -> Handshake2
        let mut buffer = vec![];
        session
            .process_data(vec![], &mut buffer)
            .await
            .expect("initiation must always succeed");

        let request_id = self.increment_request_id();

        let rsp = self
            .transport
            .write_noise_session(request_id, session_id, buffer, String::new(), nodes)
            .await
            .map_err(|_| RpcClientError::Transport)?;

        // Update the session with the identity of the remote node. The latter still needs to be
        // verified using the RAK from the consensus layer.
        session.set_remote_node(rsp.node)?;
        session.set_peer_id(rsp.node);

        // Handshake2 -> Transport
        let mut buffer = vec![];
        session
            .process_data(rsp.data, &mut buffer)
            .await
            .map_err(|_| RpcClientError::Transport)?;

        let _ = self
            .transport
            .submit_peer_feedback(request_id, types::PeerFeedback::Success)
            .await; // Ignore error.

        let request_id = self.increment_request_id();

        self.transport
            .write_noise_session(
                request_id,
                session_id,
                buffer,
                String::new(),
                vec![rsp.node],
            )
            .await
            .map_err(|_| RpcClientError::Transport)?;

        // Check if the session has failed authentication. In this case, notify the other side
        // (returning an error here will do that in `call`).
        if session.is_unauthenticated() {
            return Err(RpcClientError::Transport);
        }

        let _ = self
            .transport
            .submit_peer_feedback(request_id, types::PeerFeedback::Success)
            .await; // Ignore error.

        // Make space for the session.
        let now = insecure_posix_time();
        let maybe_removed_session = match self.sessions.remove_for(&rsp.node, now) {
            Ok(maybe_removed_session) => maybe_removed_session,
            Err(err) => {
                // Gracefully close the session, as we were unable to make space for it.
                let session = Arc::new(tokio::sync::Mutex::new(session))
                    .lock_owned()
                    .await;
                let _ = self.close(session).await; // Ignore error.
                return Err(err.into());
            }
        };

        // Add it.
        let session = self.sessions.add(session, now)?;

        // Gracefully close the removed session.
        if let Some(removed_session) = maybe_removed_session {
            _ = self.close(removed_session).await; // Ignore error.
        }

        Ok(session)
    }

    async fn secure_call_raw(
        &mut self,
        request: types::Request,
        session: &mut OwnedMutexGuard<MultiplexedSession<signature::PublicKey>>,
    ) -> Result<types::Response, RpcClientError> {
        let method = request.method.clone();
        let msg = types::Message::Request(request);
        let session_id = *session.get_session_id();

        // Prepare the request message.
        let mut buffer = vec![];
        session
            .write_message(msg, &mut buffer)
            .map_err(|_| RpcClientError::Transport)?;
        let node = session.get_remote_node()?;

        // Send the request and receive the response.
        let request_id = self.increment_request_id();

        let rsp = self
            .transport
            .write_noise_session(request_id, session_id, buffer, method, vec![node])
            .await
            .map_err(|_| RpcClientError::Transport)?;

        // Process the response.
        let msg = session
            .process_data(rsp.data, vec![])
            .await?
            .expect("message must be decoded if there is no error");

        match msg {
            types::Message::Response(rsp) => Ok(rsp),
            msg => Err(RpcClientError::ExpectedResponseMessage(msg)),
        }
    }

    async fn insecure_call_raw(
        &mut self,
        request: types::Request,
        nodes: Vec<signature::PublicKey>,
    ) -> Result<types::Response, RpcClientError> {
        let request_id = self.increment_request_id();

        let rsp = self
            .transport
            .write_insecure_query(request_id, cbor::to_vec(request), nodes)
            .await
            .map_err(|_| RpcClientError::Transport)?;

        cbor::from_slice(&rsp.data).map_err(RpcClientError::DecodeError)
    }

    /// Close the session.
    async fn close(
        &mut self,
        mut session: OwnedMutexGuard<MultiplexedSession<signature::PublicKey>>,
    ) -> Result<(), RpcClientError> {
        if !session.is_connected() {
            return Ok(());
        }

        let session_id = *session.get_session_id();
        let node = session.get_remote_node()?;

        let mut buffer = vec![];
        session
            .write_message(types::Message::Close, &mut buffer)
            .map_err(|_| RpcClientError::Transport)?;

        let request_id = self.increment_request_id();

        let rsp = self
            .transport
            .write_noise_session(request_id, session_id, buffer, String::new(), vec![node])
            .await
            .map_err(|_| RpcClientError::Transport)?;

        // Skipping peer feedback, as the request was sent only to inform
        // the other side of a graceful session close.

        // Close the session and check the received message.
        let msg = session
            .process_data(rsp.data, vec![])
            .await?
            .expect("message must be decoded if there is no error");
        session.close();

        match msg {
            types::Message::Close => Ok(()),
            msg => Err(RpcClientError::ExpectedCloseMessage(msg)),
        }
    }

    /// Close all sessions.
    async fn close_all(&mut self) {
        let sessions = self.sessions.clear();
        for session in sessions {
            let locked_session = session.lock_owned().await;
            let _ = self.close(locked_session).await; // Ignore errors.
        }
    }

    fn get_request_id(&self) -> u64 {
        ((self.client_id as u64) << 32) + (self.sent_request_count as u64)
    }

    fn increment_request_id(&mut self) -> u64 {
        self.sent_request_count = self.sent_request_count.wrapping_add(1);
        self.get_request_id()
    }
}

/// An EnclaveRPC response that can be used to provide peer feedback.
pub struct Response<T> {
    inner: Result<T, RpcClientError>,
    cmdq: mpsc::WeakSender<Command>,
    request_id: Option<u64>,
}

impl<T> Response<T> {
    /// Report success if result was `Ok(_)` and failure if result was `Err(_)`, then return the
    /// inner result consuming the response instance.
    pub async fn into_result_with_feedback(mut self) -> Result<T, RpcClientError> {
        match self.inner {
            Ok(_) => self.success().await,
            Err(_) => self.failure().await,
        }

        self.inner
    }

    /// Reference to inner result.
    pub fn result(&self) -> &Result<T, RpcClientError> {
        &self.inner
    }

    /// Consume the response instance returning the inner result.
    pub fn into_result(self) -> Result<T, RpcClientError> {
        self.inner
    }

    /// Report success as peer feedback.
    pub async fn success(&mut self) {
        self.send_peer_feedback(types::PeerFeedback::Success).await;
    }

    /// Report failure as peer feedback.
    pub async fn failure(&mut self) {
        self.send_peer_feedback(types::PeerFeedback::Failure).await;
    }

    /// Report bad peer as peer feedback.
    pub async fn bad_peer(&mut self) {
        self.send_peer_feedback(types::PeerFeedback::BadPeer).await;
    }

    /// Send peer feedback.
    async fn send_peer_feedback(&mut self, pf: types::PeerFeedback) {
        if let Some(request_id) = self.request_id.take() {
            // Only count feedback once.
            if let Some(cmdq) = self.cmdq.upgrade() {
                let _ = cmdq.send(Command::PeerFeedback(request_id, pf)).await;
            }
        }
    }
}

/// RPC client.
pub struct RpcClient {
    /// Internal command queue (sender part).
    cmdq: mpsc::Sender<Command>,
}

impl RpcClient {
    fn new(
        transport: Box<dyn Transport>,
        builder: Builder,
        max_sessions: usize,
        max_sessions_per_peer: usize,
        stale_session_timeout: i64,
    ) -> Self {
        // Create the command channel.
        let (tx, rx) = mpsc::channel(CMDQ_BACKLOG);

        // Ensure every client has a unique ID.
        let client_id = NEXT_CLIENT_ID.fetch_add(1, Ordering::SeqCst); // Wraps if overflows.

        // Create the controller task and start it.
        let controller = Controller {
            sessions: Sessions::new(
                builder,
                max_sessions,
                max_sessions_per_peer,
                stale_session_timeout,
            ),
            transport,
            cmdq: rx,
            client_id,
            sent_request_count: 0,
        };
        tokio::spawn(controller.run());

        Self { cmdq: tx }
    }

    /// Construct an unconnected RPC client with runtime-internal transport.
    pub fn new_runtime(
        protocol: Arc<Protocol>,
        endpoint: &str,
        builder: Builder,
        max_sessions: usize,
        max_sessions_per_peer: usize,
        stale_session_timeout: i64,
    ) -> Self {
        Self::new(
            Box::new(RuntimeTransport::new(protocol, endpoint)),
            builder,
            max_sessions,
            max_sessions_per_peer,
            stale_session_timeout,
        )
    }

    /// Call a remote method using an encrypted and authenticated Noise session.
    pub async fn secure_call<C, O>(
        &self,
        method: &'static str,
        args: C,
        nodes: Vec<signature::PublicKey>,
    ) -> Response<O>
    where
        C: cbor::Encode,
        O: cbor::Decode + Send + 'static,
    {
        self.call(method, args, types::Kind::NoiseSession, nodes)
            .await
    }

    /// Call a remote method over an insecure channel where messages are sent in plain text.
    pub async fn insecure_call<C, O>(
        &self,
        method: &'static str,
        args: C,
        nodes: Vec<signature::PublicKey>,
    ) -> Response<O>
    where
        C: cbor::Encode,
        O: cbor::Decode + Send + 'static,
    {
        self.call(method, args, types::Kind::InsecureQuery, nodes)
            .await
    }

    async fn call<C, O>(
        &self,
        method: &'static str,
        args: C,
        kind: types::Kind,
        nodes: Vec<signature::PublicKey>,
    ) -> Response<O>
    where
        C: cbor::Encode,
        O: cbor::Decode + Send + 'static,
    {
        let request = types::Request {
            method: method.to_owned(),
            args: cbor::to_value(args),
        };

        // In case the `execute_call` method returns an outer error, this means that there was a
        // problem with the transport itself and we can retry.
        let retry_strategy = tokio_retry::strategy::ExponentialBackoff::from_millis(2)
            .factor(25)
            .max_delay(std::time::Duration::from_millis(250))
            .take(MAX_TRANSPORT_ERROR_RETRIES);

        let result = tokio_retry::Retry::spawn(retry_strategy, || {
            self.execute_call(request.clone(), kind, nodes.clone())
        })
        .await;

        let (request_id, inner) = match result {
            Ok((request_id, response)) => match response.body {
                types::Body::Success(value) => (
                    Some(request_id),
                    cbor::from_value(value).map_err(Into::into),
                ),
                types::Body::Error(error) => {
                    (Some(request_id), Err(RpcClientError::CallFailed(error)))
                }
            },
            Err(err) => (None, Err(err)),
        };

        Response {
            inner,
            cmdq: self.cmdq.downgrade(),
            request_id,
        }
    }

    async fn execute_call(
        &self,
        request: types::Request,
        kind: types::Kind,
        nodes: Vec<signature::PublicKey>,
    ) -> Result<(u64, types::Response), RpcClientError> {
        let (tx, rx) = oneshot::channel();
        self.cmdq
            .send(Command::Call(request, kind, nodes, tx))
            .await
            .map_err(|_| RpcClientError::Dropped)?;

        rx.await.map_err(|_| RpcClientError::Dropped)?
    }

    /// Update allowed remote enclave identities.
    ///
    /// Useful if the key manager's policy has changed.
    ///
    /// # Panics
    ///
    /// This function panics if called within an asynchronous execution context.
    pub fn update_enclaves(&self, enclaves: Option<HashSet<EnclaveIdentity>>) {
        self.cmdq
            .blocking_send(Command::UpdateEnclaves(enclaves))
            .unwrap();
    }

    /// Update key manager's quote policy.
    ///
    /// # Panics
    ///
    /// This function panics if called within an asynchronous execution context.
    pub fn update_quote_policy(&self, policy: QuotePolicy) {
        self.cmdq
            .blocking_send(Command::UpdateQuotePolicy(policy))
            .unwrap();
    }

    /// Update remote runtime id.
    ///
    /// # Panics
    ///
    /// This function panics if called within an asynchronous execution context.
    pub fn update_runtime_id(&self, id: Option<Namespace>) {
        self.cmdq
            .blocking_send(Command::UpdateRuntimeID(id))
            .unwrap();
    }

    /// Generate a random client ID.
    fn random_client_id() -> u32 {
        #[cfg(test)]
        return 0;

        #[cfg(not(test))]
        OsRng.next_u32()
    }

    /// Wait for the controller to process all queued messages.
    #[cfg(test)]
    async fn flush_cmd_queue(&self) -> Result<(), RpcClientError> {
        let (tx, rx) = oneshot::channel();
        self.cmdq
            .send(Command::Ping(tx))
            .await
            .map_err(|_| RpcClientError::Dropped)?;

        rx.await.map_err(|_| RpcClientError::Dropped)
    }
}

#[cfg(test)]
mod test {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    };

    use anyhow::anyhow;
    use async_trait::async_trait;

    use crate::{
        common::crypto::signature,
        enclave_rpc::{demux::Demux, session, transport::EnclaveResponse, types},
    };

    use super::{super::transport::Transport, RpcClient};

    #[derive(Clone)]
    struct MockTransport {
        demux: Arc<Demux>,
        next_error: Arc<AtomicBool>,
        peer_feedback_history: Arc<Mutex<Vec<(u64, types::PeerFeedback)>>>,
    }

    impl MockTransport {
        fn new() -> Self {
            Self {
                demux: Arc::new(Demux::new(session::Builder::default(), 4, 4, 60)),
                next_error: Arc::new(AtomicBool::new(false)),
                peer_feedback_history: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn reset(&self) {
            self.demux.reset();
        }

        fn induce_transport_error(&self) {
            self.next_error.store(true, Ordering::SeqCst);
        }

        fn take_peer_feedback_history(&self) -> Vec<(u64, types::PeerFeedback)> {
            let mut pfh = self.peer_feedback_history.lock().unwrap();
            pfh.drain(..).collect()
        }
    }

    #[async_trait]
    impl Transport for MockTransport {
        async fn write_message_impl(
            &self,
            _request_id: u64,
            request: Vec<u8>,
            kind: types::Kind,
            _nodes: Vec<signature::PublicKey>,
        ) -> Result<EnclaveResponse, anyhow::Error> {
            // Induce error when configured to do so.
            if self
                .next_error
                .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Err(anyhow!("transport error"));
            }

            match kind {
                types::Kind::NoiseSession => {
                    // Deliver directly to the multiplexer.
                    let mut buffer = Vec::new();
                    let (mut session, message) = self
                        .demux
                        .process_frame(vec![], request, &mut buffer)
                        .await?;

                    match message {
                        Some(message) => {
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
                            session.write_message(response, &mut buffer)?;

                            let rsp = EnclaveResponse {
                                data: buffer,
                                node: Default::default(),
                            };
                            Ok(rsp)
                        }
                        None => {
                            // Handshake.
                            let rsp = EnclaveResponse {
                                data: buffer,
                                node: Default::default(),
                            };
                            Ok(rsp)
                        }
                    }
                }
                types::Kind::InsecureQuery => {
                    // Just echo back what was given.
                    let rq: types::Request = cbor::from_slice(&request).unwrap();
                    let body = types::Body::Success(rq.args);
                    let response = types::Response { body };
                    let rsp = EnclaveResponse {
                        data: cbor::to_vec(response),
                        node: Default::default(),
                    };
                    return Ok(rsp);
                }
                types::Kind::LocalQuery => {
                    panic!("unhandled RPC kind")
                }
            }
        }

        async fn submit_peer_feedback(
            &self,
            request_id: u64,
            peer_feedback: types::PeerFeedback,
        ) -> Result<(), anyhow::Error> {
            self.peer_feedback_history
                .lock()
                .unwrap()
                .push((request_id, peer_feedback));

            Ok(())
        }
    }

    #[test]
    fn test_rpc_client() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter(); // Ensure Tokio runtime is available.
        let transport = MockTransport::new();
        let builder = session::Builder::default();
        let client = RpcClient::new(Box::new(transport.clone()), builder, 8, 2, 60);

        // Basic secure call.
        let result: u64 = rt
            .block_on(async {
                client
                    .secure_call("test", 42, vec![])
                    .await
                    .into_result_with_feedback()
                    .await
            })
            .unwrap();
        rt.block_on(client.flush_cmd_queue()).unwrap(); // Flush cmd queue to get peer feedback.
        assert_eq!(result, 42, "secure call should work");
        assert_eq!(
            transport.take_peer_feedback_history(),
            vec![
                (1, types::PeerFeedback::Success), // Handshake.
                (2, types::PeerFeedback::Success), // Handshake.
                (3, types::PeerFeedback::Success), // Handled call.
            ]
        );

        // Reset all sessions on the server and make sure that we can still get a response.
        transport.reset();

        let result: u64 = rt
            .block_on(async {
                client
                    .secure_call("test", 43, vec![])
                    .await
                    .into_result_with_feedback()
                    .await
            })
            .unwrap();
        rt.block_on(client.flush_cmd_queue()).unwrap(); // Flush cmd queue to get peer feedback.
        assert_eq!(result, 43, "secure call should work");
        assert_eq!(
            transport.take_peer_feedback_history(),
            vec![
                (4, types::PeerFeedback::Failure), // Failed call due to session reset.
                (5, types::PeerFeedback::Success), // New handshake.
                (6, types::PeerFeedback::Success), // New handshake.
                (7, types::PeerFeedback::Success), // Handled call.
            ]
        );

        // Induce a single transport error without resetting the server sessions and make sure we
        // can still get a response.
        transport.induce_transport_error();

        let result: u64 = rt
            .block_on(async {
                client
                    .secure_call("test", 44, vec![])
                    .await
                    .into_result_with_feedback()
                    .await
            })
            .unwrap();
        rt.block_on(client.flush_cmd_queue()).unwrap(); // Flush cmd queue to get peer feedback.
        assert_eq!(result, 44, "secure call should work");
        assert_eq!(
            transport.take_peer_feedback_history(),
            vec![
                (8, types::PeerFeedback::Failure), // Handshake failed due to induced error.
                // (9, types::PeerFeedback::Failure), // Session close failed due to decrypt error (handshake not completed). [skipped]
                (10, types::PeerFeedback::Success), // New handshake.
                (11, types::PeerFeedback::Success), // New handshake.
                (12, types::PeerFeedback::Success), // Handled call.
            ]
        );

        // Basic insecure call.
        let result: u64 = rt
            .block_on(async {
                client
                    .insecure_call("test", 45, vec![])
                    .await
                    .into_result_with_feedback()
                    .await
            })
            .unwrap();
        rt.block_on(client.flush_cmd_queue()).unwrap(); // Flush cmd queue to get peer feedback.
        assert_eq!(result, 45, "insecure call should work");
        assert_eq!(
            transport.take_peer_feedback_history(),
            vec![
                (13, types::PeerFeedback::Success), // Handled call.
            ]
        );

        // Induce a single transport error and make sure we can still get a response.
        transport.induce_transport_error();

        let result: u64 = rt
            .block_on(async {
                client
                    .insecure_call("test", 46, vec![])
                    .await
                    .into_result_with_feedback()
                    .await
            })
            .unwrap();
        rt.block_on(client.flush_cmd_queue()).unwrap(); // Flush cmd queue to get peer feedback.
        assert_eq!(result, 46, "insecure call should work");
        assert_eq!(
            transport.take_peer_feedback_history(),
            vec![
                (14, types::PeerFeedback::Failure), // Failed call due to induced error.
                (15, types::PeerFeedback::Success), // Handled call.
            ]
        );
    }
}
