use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Error as AnyError};
use async_trait::async_trait;

use crate::{common::crypto::signature, types::Body, Protocol};

use super::types;

/// An EnclaveRPC transport.
#[async_trait]
pub trait Transport: Send + Sync {
    async fn write_noise_session(
        &self,
        session_id: types::SessionID,
        data: Vec<u8>,
        untrusted_plaintext: String,
        nodes: Vec<signature::PublicKey>,
    ) -> Result<(Vec<u8>, signature::PublicKey), AnyError> {
        // Frame message.
        let frame = types::Frame {
            session: session_id,
            untrusted_plaintext,
            payload: data,
        };

        self.write_message_impl(cbor::to_vec(frame), types::Kind::NoiseSession, nodes)
            .await
    }

    async fn write_insecure_query(
        &self,
        data: Vec<u8>,
        nodes: Vec<signature::PublicKey>,
    ) -> Result<(Vec<u8>, signature::PublicKey), AnyError> {
        self.write_message_impl(data, types::Kind::InsecureQuery, nodes)
            .await
    }

    async fn write_message_impl(
        &self,
        data: Vec<u8>,
        kind: types::Kind,
        nodes: Vec<signature::PublicKey>,
    ) -> Result<(Vec<u8>, signature::PublicKey), AnyError>;

    fn set_peer_feedback(&self, _pfid: u64, _peer_feedback: Option<types::PeerFeedback>) {
        // Default implementation doesn't do anything.
    }

    fn get_peer_feedback_id(&self) -> u64 {
        // Default implementation doesn't do anything.
        0
    }
}

/// A transport implementation which can be used from inside the runtime and uses the Runtime Host
/// Protocol to transport EnclaveRPC frames.
pub struct RuntimeTransport {
    pub protocol: Arc<Protocol>,
    pub endpoint: String,

    peer_feedback: Mutex<(u64, Option<types::PeerFeedback>)>,
}

impl RuntimeTransport {
    pub fn new(protocol: Arc<Protocol>, endpoint: &str) -> Self {
        Self {
            protocol,
            endpoint: endpoint.to_string(),
            peer_feedback: Mutex::new((0, None)),
        }
    }
}

#[async_trait]
impl Transport for RuntimeTransport {
    async fn write_message_impl(
        &self,
        data: Vec<u8>,
        kind: types::Kind,
        nodes: Vec<signature::PublicKey>,
    ) -> Result<(Vec<u8>, signature::PublicKey), AnyError> {
        let peer_feedback = {
            let mut pf = self.peer_feedback.lock().unwrap();
            let peer_feedback = pf.1.take();

            // If non-success feedback was propagated this means that the peer will be changed for
            // subsequent requests. Increment pfid to make sure that we don't incorporate stale
            // feedback.
            if !matches!(peer_feedback, None | Some(types::PeerFeedback::Success)) {
                pf.0 += 1;
            }

            peer_feedback
        };

        let rsp = self
            .protocol
            .call_host_async(Body::HostRPCCallRequest {
                endpoint: self.endpoint.clone(),
                request: data,
                kind,
                nodes,
                peer_feedback,
            })
            .await?;

        match rsp {
            Body::HostRPCCallResponse { response, node } => Ok((response, node)),
            _ => Err(anyhow!("bad response type")),
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
