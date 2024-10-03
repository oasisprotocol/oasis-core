//! Enclave RPC client.
use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
};

use futures::stream::{FuturesUnordered, StreamExt};
use lazy_static::lazy_static;
#[cfg(not(test))]
use rand::{rngs::OsRng, RngCore};

use thiserror::Error;
use tokio::sync::OwnedMutexGuard;

use crate::{
    common::{
        crypto::signature,
        namespace::Namespace,
        sgx::{EnclaveIdentity, QuotePolicy},
        time::insecure_posix_time,
    },
    enclave_rpc::{session::Builder, types},
    future::block_on,
    protocol::Protocol,
};

use super::{
    sessions::{self, MultiplexedSession, Sessions, SharedSession},
    transport::{RuntimeTransport, Transport},
};

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

/// An EnclaveRPC response that can be used to provide peer feedback.
pub struct Response<'a, T> {
    transport: &'a dyn Transport,
    request_id: Option<u64>,
    inner: Result<T, RpcClientError>,
}

impl<'a, T> Response<'a, T> {
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
    async fn send_peer_feedback(&mut self, feedback: types::PeerFeedback) {
        if let Some(request_id) = self.request_id.take() {
            // Only count feedback once.
            let _ = self
                .transport
                .submit_peer_feedback(request_id, feedback)
                .await; // Ignore error.
        }
    }
}

/// RPC client.
pub struct RpcClient {
    /// Used transport.
    transport: Box<dyn Transport>,
    /// Multiplexed sessions.
    sessions: tokio::sync::Mutex<Sessions<signature::PublicKey>>,
    /// The ID of the client.
    client_id: u32,
    /// The ID of the next transport request.
    next_request_id: AtomicU32,
}

impl RpcClient {
    fn new(
        transport: Box<dyn Transport>,
        builder: Builder,
        max_sessions: usize,
        max_sessions_per_peer: usize,
        stale_session_timeout: i64,
    ) -> Self {
        // Assign a unique ID to each client to avoid overlapping request IDs.
        let client_id = NEXT_CLIENT_ID.fetch_add(1, Ordering::SeqCst); // Wraps if overflows.
        let next_request_id = AtomicU32::new(1);

        let sessions = tokio::sync::Mutex::new(Sessions::new(
            builder,
            max_sessions,
            max_sessions_per_peer,
            stale_session_timeout,
        ));

        Self {
            transport,
            sessions,
            client_id,
            next_request_id,
        }
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
        let transport = Box::new(RuntimeTransport::new(protocol, endpoint));

        Self::new(
            transport,
            builder,
            max_sessions,
            max_sessions_per_peer,
            stale_session_timeout,
        )
    }

    /// Update allowed remote enclave identities.
    pub async fn update_enclaves(&self, enclaves: Option<HashSet<EnclaveIdentity>>) {
        let sessions = {
            let mut sessions = self.sessions.lock().await;
            sessions.update_enclaves(enclaves)
        };
        self.close_all(sessions).await;
    }

    /// Update remote end's quote policy.
    pub async fn update_quote_policy(&self, policy: QuotePolicy) {
        let sessions = {
            let mut sessions = self.sessions.lock().await;
            sessions.update_quote_policy(policy)
        };
        self.close_all(sessions).await;
    }

    /// Update remote runtime id.
    pub async fn update_runtime_id(&self, id: Option<Namespace>) {
        let sessions = {
            let mut sessions = self.sessions.lock().await;
            sessions.update_runtime_id(id)
        };
        self.close_all(sessions).await;
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
            transport: &*self.transport,
            request_id,
            inner,
        }
    }

    async fn execute_call(
        &self,
        request: types::Request,
        kind: types::Kind,
        nodes: Vec<signature::PublicKey>,
    ) -> Result<(u64, types::Response), RpcClientError> {
        match kind {
            types::Kind::NoiseSession => {
                // Attempt to establish a connection. This will not do anything in case the
                // session has already been established.
                let session = self.connect(nodes).await?;
                let mut session = session.lock_owned().await;

                // Perform the call.
                let result = self.secure_call_raw(request, &mut session).await;

                // In case there was a transport error we need to remove the session immediately
                // as no progress is possible. The next call should select another peer or
                // the same peer but another session.
                if result.is_err() {
                    let mut sessions = self.sessions.lock().await;
                    sessions.remove(&session);
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

    async fn connect(
        &self,
        nodes: Vec<signature::PublicKey>,
    ) -> Result<SharedSession<signature::PublicKey>, RpcClientError> {
        // Create a new session.
        let mut session = {
            let mut sessions = self.sessions.lock().await;

            // No need to create a new session if we are connected to one of the nodes.
            if let Some(session) = sessions.find(&nodes) {
                return Ok(session);
            }

            // Since the peer ID is not yet known, use the default value and set it later.
            let peer_id = Default::default();
            sessions.create_initiator(peer_id)
        };

        // Copy session ID to avoid moved value errors.
        let session_id = *session.get_session_id();

        // Prepare buffers upfront.
        let mut buffer1 = vec![];
        let mut buffer2 = vec![];

        // Session Handshake1: prepare initialization request.
        session
            .process_data(&[], &mut buffer1)
            .await
            .expect("initiation must always succeed");

        let request_id = self.next_request_id();
        let result: Result<_, RpcClientError> = async {
            // Transport: send initialization request and receive a response.
            let rsp = self
                .transport
                .write_noise_session(request_id, session_id, buffer1, String::new(), nodes)
                .await
                .map_err(|_| RpcClientError::Transport)?;

            // Update the session with unverified identity of the remote node.
            // The identity will be verified in Handshake2 using the RAK from
            // the consensus layer.
            session.set_peer_id(rsp.node);
            session
                .set_remote_node(rsp.node)
                .expect("remote node should not be set");

            // Session Handshake2: process initialization response, verify
            // remote node, and prepare the next request containing RAK binding.
            let _ = session
                .process_data(&rsp.data, &mut buffer2)
                .await
                .map_err(|_| RpcClientError::Transport)?;

            Ok(rsp)
        }
        .await;

        // Submit peer feedback for the last transport and the received
        // initialization response.
        let feedback = match result {
            Ok(_) => types::PeerFeedback::Success,
            Err(_) => types::PeerFeedback::Failure,
        };
        let _ = self
            .transport
            .submit_peer_feedback(request_id, feedback)
            .await; // Ignore error.

        // Forward error after peer feedback is sent.
        let rsp = result?;

        let request_id = self.next_request_id();
        let result = async {
            // Transport: send RAK binding request.
            let rsp = self
                .transport
                .write_noise_session(
                    request_id,
                    session_id,
                    buffer2,
                    String::new(),
                    vec![rsp.node],
                )
                .await
                .map_err(|_| RpcClientError::Transport)?;

            if session.is_unauthenticated() {
                return Err(RpcClientError::Transport);
            }

            Ok(rsp)
        }
        .await;

        // Submit peer feedback for the last transport and session
        // authentication.
        let feedback = match result {
            Ok(_) => types::PeerFeedback::Success,
            Err(_) => types::PeerFeedback::Failure,
        };
        let _ = self
            .transport
            .submit_peer_feedback(request_id, feedback)
            .await; // Ignore error.

        // Forward error after peer feedback is sent.
        if let Err(err) = result {
            // Failed to complete handshake. Gracefully close the session.
            let session = Arc::new(tokio::sync::Mutex::new(session))
                .lock_owned()
                .await;
            let _ = self.close(session).await; // Ignore error.

            return Err(err);
        }

        // The connection has been successfully established. The session can
        // be added to the set of active sessions if there is space available,
        // or if we can make space by removing a stale session.
        let now = insecure_posix_time();
        let mut sessions = self.sessions.lock().await;
        let maybe_removed_session = match sessions.remove_for(&rsp.node, now) {
            Ok(maybe_removed_session) => maybe_removed_session,
            Err(err) => {
                // Unable to make space. Gracefully close the session.
                drop(sessions); // Unlock.

                let session = Arc::new(tokio::sync::Mutex::new(session))
                    .lock_owned()
                    .await;
                let _ = self.close(session).await; // Ignore error.

                return Err(err.into());
            }
        };
        let session = sessions
            .add(session, now)
            .expect("there should be space for the new session");

        if let Some(removed_session) = maybe_removed_session {
            // A stale session was removed. Gracefully close the removed session.
            drop(sessions); // Unlock.

            let _ = self.close(removed_session).await; // Ignore error.
        }

        Ok(session)
    }

    async fn secure_call_raw(
        &self,
        request: types::Request,
        session: &mut OwnedMutexGuard<MultiplexedSession<signature::PublicKey>>,
    ) -> Result<(u64, types::Response), RpcClientError> {
        let method = request.method.clone();
        let msg = types::Message::Request(request);
        let session_id = *session.get_session_id();

        // Session Transport: prepare the request message.
        let mut buffer = vec![];
        session
            .write_message(msg, &mut buffer)
            .map_err(|_| RpcClientError::Transport)?;
        let node = session.get_remote_node()?;

        let request_id = self.next_request_id();
        let result = async {
            // Transport: send the request and receive a response.
            let rsp = self
                .transport
                .write_noise_session(request_id, session_id, buffer, method, vec![node])
                .await
                .map_err(|_| RpcClientError::Transport)?;

            // Session Transport: process the response.
            session.process_data(&rsp.data, vec![]).await
        }
        .await;

        // Submit negative peer feedback for the last transport
        // and the received response immediately.
        if result.is_err() {
            let _ = self
                .transport
                .submit_peer_feedback(request_id, types::PeerFeedback::Failure)
                .await; // Ignore error.
        }

        // Forward error after peer feedback is sent.
        let maybe_msg = result?;

        // Unwrap response.
        let msg = maybe_msg.expect("message must be decoded if there is no error");
        let rsp = match msg {
            types::Message::Response(rsp) => rsp,
            msg => return Err(RpcClientError::ExpectedResponseMessage(msg)),
        };

        Ok((request_id, rsp))
    }

    async fn insecure_call_raw(
        &self,
        request: types::Request,
        nodes: Vec<signature::PublicKey>,
    ) -> Result<(u64, types::Response), RpcClientError> {
        // Transport: send the request.
        let request_id = self.next_request_id();
        let result = self
            .transport
            .write_insecure_query(request_id, cbor::to_vec(request), nodes)
            .await
            .map_err(|_| RpcClientError::Transport);

        // Submit negative peer feedback for the last transport immediately.
        if result.is_err() {
            let _ = self
                .transport
                .submit_peer_feedback(request_id, types::PeerFeedback::Failure)
                .await; // Ignore error.
        }

        // Forward error after peer feedback is sent.
        let rsp = result?;

        // Unwrap response.
        let rsp = cbor::from_slice(&rsp.data).map_err(RpcClientError::DecodeError)?;

        Ok((request_id, rsp))
    }

    /// Close the session.
    async fn close(
        &self,
        mut session: OwnedMutexGuard<MultiplexedSession<signature::PublicKey>>,
    ) -> Result<(), RpcClientError> {
        if !session.is_connected() && !session.is_unauthenticated() {
            return Ok(());
        }

        let session_id = *session.get_session_id();
        let node = session.get_remote_node()?;

        // Session Transport: prepare close request.
        let mut buffer = vec![];
        session
            .write_message(types::Message::Close, &mut buffer)
            .map_err(|_| RpcClientError::Transport)?;

        // Transport: send close request.
        let request_id = self.next_request_id();
        let rsp = self
            .transport
            .write_noise_session(request_id, session_id, buffer, String::new(), vec![node])
            .await
            .map_err(|_| RpcClientError::Transport)?;

        // Skipping peer feedback, as the request was sent only to inform
        // the other side of a graceful session close.

        // Session Transport: process the response.
        let msg = session
            .process_data(&rsp.data, vec![])
            .await?
            .expect("message must be decoded if there is no error");

        // Close the session.
        session.close();

        match msg {
            types::Message::Close => Ok(()),
            msg => Err(RpcClientError::ExpectedCloseMessage(msg)),
        }
    }

    /// Close all sessions.
    async fn close_all(&self, sessions: Vec<SharedSession<signature::PublicKey>>) {
        let futures = FuturesUnordered::new();
        for session in sessions {
            let future = async {
                let locked_session = session.lock_owned().await;
                let _ = self.close(locked_session).await; // Ignore errors.
            };
            futures.push(future);
        }
        futures.collect::<()>().await;
    }

    /// Return the ID of the next transport request.
    fn next_request_id(&self) -> u64 {
        let next_request_id = self.next_request_id.fetch_add(1, Ordering::SeqCst); // Wraps if overflows.
        ((self.client_id as u64) << 32) + (next_request_id as u64)
    }

    /// Generate a random client ID.
    fn random_client_id() -> u32 {
        #[cfg(test)]
        return 0;

        #[cfg(not(test))]
        OsRng.next_u32()
    }
}

impl Drop for RpcClient {
    fn drop(&mut self) {
        // Close all sessions after the client is dropped.
        block_on(async {
            let sessions = {
                let mut sessions = self.sessions.lock().await;
                sessions.drain()
            };
            self.close_all(sessions).await;
        });
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
                            let mut buffer = Vec::new();

                            // Message, process and write reply.
                            match message {
                                types::Message::Request(rq) => {
                                    // Just echo back what was given.
                                    let response = types::Message::Response(types::Response {
                                        body: types::Body::Success(rq.args),
                                    });

                                    session.write_message(response, &mut buffer)?;
                                }
                                types::Message::Close => {
                                    self.demux.close(session, &mut buffer)?;
                                }
                                _ => panic!("unhandled message type"),
                            };

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
        assert_eq!(result, 44, "secure call should work");
        assert_eq!(
            transport.take_peer_feedback_history(),
            vec![
                (8, types::PeerFeedback::Failure), // Handshake failed due to induced error.
                // (9, types::PeerFeedback::Failure), // Session close failed due to decrypt error (handshake not completed). [skipped]
                (9, types::PeerFeedback::Success), // New handshake.
                (10, types::PeerFeedback::Success), // New handshake.
                (11, types::PeerFeedback::Success), // Handled call.
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
        assert_eq!(result, 45, "insecure call should work");
        assert_eq!(
            transport.take_peer_feedback_history(),
            vec![
                (12, types::PeerFeedback::Success), // Handled call.
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
        assert_eq!(result, 46, "insecure call should work");
        assert_eq!(
            transport.take_peer_feedback_history(),
            vec![
                (13, types::PeerFeedback::Failure), // Failed call due to induced error.
                (14, types::PeerFeedback::Success), // Handled call.
            ]
        );
    }
}
