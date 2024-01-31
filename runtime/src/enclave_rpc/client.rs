//! Enclave RPC client.
use std::{collections::HashSet, mem, sync::Arc};

use anyhow;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};

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

/// Internal command queue backlog.
const CMDQ_BACKLOG: usize = 32;

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

/// A command sent to the client controller task.
#[derive(Debug)]
enum Command {
    Call(
        types::Request,
        types::Kind,
        oneshot::Sender<Result<(u64, types::Response), RpcClientError>>,
        usize,
    ),
    PeerFeedback(u64, types::PeerFeedback),
    UpdateEnclaves(Option<HashSet<EnclaveIdentity>>),
    UpdateQuotePolicy(QuotePolicy),
    UpdateRuntimeID(Option<Namespace>),
    UpdateNodes(Vec<signature::PublicKey>),
    #[cfg(test)]
    Ping(oneshot::Sender<()>),
}

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

struct Controller {
    /// Maximum number of call retries on transport failures.
    max_retries: usize,
    /// Allowed nodes.
    nodes: Vec<signature::PublicKey>,
    /// Multiplexed session.
    session: MultiplexedSession,
    /// Used transport.
    transport: Box<dyn Transport>,
    /// Internal command queue (receiver part).
    cmdq: mpsc::Receiver<Command>,
    /// Internal command queue (sender part for retries).
    cmdq_tx: mpsc::WeakSender<Command>,
}

impl Controller {
    async fn run(mut self) {
        while let Some(cmd) = self.cmdq.recv().await {
            match cmd {
                Command::Call(request, kind, sender, retries) => {
                    self.call(request, kind, sender, retries).await
                }
                Command::PeerFeedback(pfid, peer_feedback) => {
                    self.transport.set_peer_feedback(pfid, Some(peer_feedback));
                }
                Command::UpdateEnclaves(enclaves) => {
                    if self.session.builder.get_remote_enclaves() == &enclaves {
                        continue;
                    }

                    self.session.builder =
                        mem::take(&mut self.session.builder).remote_enclaves(enclaves);
                    self.reset().await;
                }
                Command::UpdateQuotePolicy(policy) => {
                    let policy = Some(Arc::new(policy));
                    if self.session.builder.get_quote_policy() == &policy {
                        continue;
                    }

                    self.session.builder =
                        mem::take(&mut self.session.builder).quote_policy(policy);
                    self.reset().await;
                }
                Command::UpdateRuntimeID(id) => {
                    if self.session.builder.get_remote_runtime_id() == &id {
                        continue;
                    }

                    self.session.builder =
                        mem::take(&mut self.session.builder).remote_runtime_id(id);
                    self.reset().await;
                }
                Command::UpdateNodes(nodes) => {
                    self.nodes = nodes;
                }
                #[cfg(test)]
                Command::Ping(sender) => {
                    let _ = sender.send(());
                }
            }
        }

        // Close stream after the client is dropped.
        let _ = self.close().await;
    }

    async fn call(
        &mut self,
        request: types::Request,
        kind: types::Kind,
        sender: oneshot::Sender<Result<(u64, types::Response), RpcClientError>>,
        retries: usize,
    ) {
        let result = async {
            match kind {
                types::Kind::NoiseSession => {
                    // Attempt to establish a connection. This will not do anything in case the
                    // session has already been established.
                    self.connect().await?;

                    // Perform the call.
                    self.secure_call_raw(request.clone()).await
                }
                types::Kind::InsecureQuery => {
                    // Perform the call.
                    self.insecure_call_raw(request.clone()).await
                }
                _ => Err(RpcClientError::UnsupportedRpcKind),
            }
        }
        .await;

        // Update peer feedback for next request.
        let pfid = self.transport.get_peer_feedback_id();
        if result.is_err() && kind == types::Kind::NoiseSession {
            // In case there was a transport error we need to reset the session immediately as no
            // progress is possible.
            self.reset().await;
            // Set peer feedback immediately so retries can try new peers.
            self.transport
                .set_peer_feedback(pfid, Some(types::PeerFeedback::Failure));
        }

        match result {
            ref r if r.is_ok() || retries >= self.max_retries => {
                // Request was successful or number of retries has been exceeded.
                let _ = sender.send(result.map(|rsp| (pfid, rsp)));
            }

            _ => {
                // Attempt retry if number of retries is not exceeded. Retry is performed by
                // queueing another request.
                if let Some(cmdq_tx) = self.cmdq_tx.upgrade() {
                    let _ = cmdq_tx
                        .send(Command::Call(request, kind, sender, retries + 1))
                        .await;
                }
            }
        }
    }

    async fn connect(&mut self) -> Result<(), RpcClientError> {
        // No need to create a new session if we are connected to one of the nodes.
        if self.session.inner.is_connected()
            && (self.nodes.is_empty() || self.session.inner.is_connected_to(&self.nodes))
        {
            return Ok(());
        }
        // Make sure the session is reset for a new connection.
        self.reset().await;

        // Handshake1 -> Handshake2
        let mut buffer = vec![];
        self.session
            .inner
            .process_data(vec![], &mut buffer)
            .await
            .expect("initiation must always succeed");
        let session_id = self.session.id;

        let (data, node) = self
            .transport
            .write_noise_session(session_id, buffer, String::new(), self.nodes.clone())
            .await
            .map_err(|_| RpcClientError::Transport)?;

        // Update the session with the identity of the remote node. The latter still needs to be
        // verified using the RAK from the consensus layer.
        self.session.inner.set_remote_node(node)?;

        // Handshake2 -> Transport
        let mut buffer = vec![];
        self.session
            .inner
            .process_data(data, &mut buffer)
            .await
            .map_err(|_| RpcClientError::Transport)?;

        self.transport
            .write_noise_session(session_id, buffer, String::new(), vec![node])
            .await
            .map_err(|_| RpcClientError::Transport)?;

        // Check if the session has failed authentication. In this case, notify the other side
        // (returning an error here will do that in `call`).
        if self.session.inner.is_unauthenticated() {
            return Err(RpcClientError::Transport);
        }

        Ok(())
    }

    async fn secure_call_raw(
        &mut self,
        request: types::Request,
    ) -> Result<types::Response, RpcClientError> {
        let method = request.method.clone();
        let msg = types::Message::Request(request);

        // Prepare the request message.
        let mut buffer = vec![];
        self.session
            .inner
            .write_message(msg, &mut buffer)
            .map_err(|_| RpcClientError::Transport)?;
        let node = self.session.inner.get_node()?;

        // Send the request and receive the response.
        let (data, _) = self
            .transport
            .write_noise_session(self.session.id, buffer, method, vec![node])
            .await
            .map_err(|_| RpcClientError::Transport)?;

        // Process the response.
        let msg = self
            .session
            .inner
            .process_data(data, vec![])
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
    ) -> Result<types::Response, RpcClientError> {
        let (data, _) = self
            .transport
            .write_insecure_query(cbor::to_vec(request), self.nodes.clone())
            .await
            .map_err(|_| RpcClientError::Transport)?;

        cbor::from_slice(&data).map_err(RpcClientError::DecodeError)
    }

    async fn reset(&mut self) {
        // Notify the other end (if any) of session closure.
        let _ = self.close_notify().await;
        // Reset the session.
        self.session.reset();
    }

    async fn close_notify(&mut self) -> Result<Vec<u8>, RpcClientError> {
        let node = self.session.inner.get_node()?;

        let mut buffer = vec![];
        self.session
            .inner
            .write_message(types::Message::Close, &mut buffer)
            .map_err(|_| RpcClientError::Transport)?;

        self.transport
            .write_noise_session(self.session.id, buffer, String::new(), vec![node])
            .await
            .map_err(|_| RpcClientError::Transport)
            .map(|(data, _)| data)
    }

    async fn close(&mut self) -> Result<(), RpcClientError> {
        if !self.session.inner.is_connected() {
            return Ok(());
        }

        let data = self.close_notify().await?;

        // Close the session and check the received message.
        let msg = self
            .session
            .inner
            .process_data(data, vec![])
            .await?
            .expect("message must be decoded if there is no error");
        self.session.inner.close();

        match msg {
            types::Message::Close => Ok(()),
            msg => Err(RpcClientError::ExpectedCloseMessage(msg)),
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
        nodes: Vec<signature::PublicKey>,
    ) -> Self {
        // Create the command channel.
        let (tx, rx) = mpsc::channel(CMDQ_BACKLOG);

        // Create the controller task and start it.
        let controller = Controller {
            max_retries: 3,
            nodes,
            session: MultiplexedSession::new(builder),
            transport,
            cmdq: rx,
            cmdq_tx: tx.downgrade(), // Ensure channel is closed on RpcClient drop.
        };
        tokio::spawn(controller.run());

        Self { cmdq: tx }
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
        let _ = self.cmdq.send(Command::PeerFeedback(pfid, pf)).await;

        result
    }

    async fn execute_call(
        &self,
        request: types::Request,
        kind: types::Kind,
    ) -> Result<(u64, types::Response), RpcClientError> {
        let (tx, rx) = oneshot::channel();
        self.cmdq
            .send(Command::Call(request, kind, tx, 0))
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

    /// Update allowed nodes.
    ///
    /// # Panics
    ///
    /// This function panics if called within an asynchronous execution context.
    pub fn update_nodes(&self, nodes: Vec<signature::PublicKey>) {
        self.cmdq
            .blocking_send(Command::UpdateNodes(nodes))
            .unwrap();
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
        enclave_rpc::{demux::Demux, session, types},
        identity::Identity,
    };

    use super::{super::transport::Transport, RpcClient};

    #[derive(Clone)]
    struct MockTransport {
        demux: Arc<Demux>,
        next_error: Arc<AtomicBool>,
        peer_feedback: Arc<Mutex<(u64, Option<types::PeerFeedback>)>>,
        peer_feedback_history: Arc<Mutex<Vec<(u64, Option<types::PeerFeedback>)>>>,
    }

    impl MockTransport {
        fn new() -> Self {
            Self {
                demux: Arc::new(Demux::new(Arc::new(Identity::new()))),
                next_error: Arc::new(AtomicBool::new(false)),
                peer_feedback: Arc::new(Mutex::new((0, None))),
                peer_feedback_history: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn reset(&self) {
            self.demux.reset();
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

    #[async_trait]
    impl Transport for MockTransport {
        async fn write_message_impl(
            &self,
            request: Vec<u8>,
            kind: types::Kind,
            _nodes: Vec<signature::PublicKey>,
        ) -> Result<(Vec<u8>, signature::PublicKey), anyhow::Error> {
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
                return Err(anyhow!("transport error"));
            }

            match kind {
                types::Kind::NoiseSession => {
                    // Deliver directly to the multiplexer.
                    let mut buffer = Vec::new();
                    let (mut session, message) =
                        self.demux.process_frame(request, &mut buffer).await?;

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
                            Ok(session
                                .write_message(response, &mut buffer)
                                .map(|_| (buffer, Default::default()))?)
                        }
                        None => {
                            // Handshake.
                            Ok((buffer, Default::default()))
                        }
                    }
                }
                types::Kind::InsecureQuery => {
                    // Just echo back what was given.
                    let rq: types::Request = cbor::from_slice(&request).unwrap();
                    let body = types::Body::Success(rq.args);
                    let response = types::Response { body };
                    return Ok((cbor::to_vec(response), Default::default()));
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
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter(); // Ensure Tokio runtime is available.
        let transport = MockTransport::new();
        let builder = session::Builder::default();
        let client = RpcClient::new(Box::new(transport.clone()), builder, vec![]);

        // Basic secure call.
        let result: u64 = rt.block_on(client.secure_call("test", 42)).unwrap();
        rt.block_on(client.flush_cmd_queue()).unwrap(); // Flush cmd queue to get peer feedback.
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
        rt.block_on(client.flush_cmd_queue()).unwrap(); // Flush cmd queue to get peer feedback.
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
        rt.block_on(client.flush_cmd_queue()).unwrap(); // Flush cmd queue to get peer feedback.
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
        rt.block_on(client.flush_cmd_queue()).unwrap(); // Flush cmd queue to get peer feedback.
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
        rt.block_on(client.flush_cmd_queue()).unwrap(); // Flush cmd queue to get peer feedback.
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
