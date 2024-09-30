use std::sync::Arc;

use anyhow::{anyhow, Error as AnyError};
use async_trait::async_trait;

use crate::{common::crypto::signature, types::Body, Protocol};

use super::types;

// Enclave's response.
pub struct EnclaveResponse {
    // Actual response data.
    pub data: Vec<u8>,
    // The public key of the node that generated the response.
    pub node: signature::PublicKey,
}

/// An EnclaveRPC transport.
#[async_trait]
pub trait Transport: Send + Sync {
    async fn write_noise_session(
        &self,
        request_id: u64,
        session_id: types::SessionID,
        data: Vec<u8>,
        untrusted_plaintext: String,
        nodes: Vec<signature::PublicKey>,
    ) -> Result<EnclaveResponse, AnyError> {
        let frame = types::Frame {
            session: session_id,
            untrusted_plaintext,
            payload: data,
        };

        self.write_message_impl(
            request_id,
            cbor::to_vec(frame),
            types::Kind::NoiseSession,
            nodes,
        )
        .await
    }

    async fn write_insecure_query(
        &self,
        request_id: u64,
        data: Vec<u8>,
        nodes: Vec<signature::PublicKey>,
    ) -> Result<EnclaveResponse, AnyError> {
        self.write_message_impl(request_id, data, types::Kind::InsecureQuery, nodes)
            .await
    }

    async fn write_message_impl(
        &self,
        request_id: u64,
        data: Vec<u8>,
        kind: types::Kind,
        nodes: Vec<signature::PublicKey>,
    ) -> Result<EnclaveResponse, AnyError>;

    async fn submit_peer_feedback(
        &self,
        request_id: u64,
        peer_feedback: types::PeerFeedback,
    ) -> Result<(), AnyError>;
}

/// A transport implementation which can be used from inside the runtime and uses the Runtime Host
/// Protocol to transport EnclaveRPC frames.
pub struct RuntimeTransport {
    pub protocol: Arc<Protocol>,
    pub endpoint: String,
}

impl RuntimeTransport {
    pub fn new(protocol: Arc<Protocol>, endpoint: &str) -> Self {
        Self {
            protocol,
            endpoint: endpoint.to_string(),
        }
    }
}

#[async_trait]
impl Transport for RuntimeTransport {
    async fn write_message_impl(
        &self,
        request_id: u64,
        data: Vec<u8>,
        kind: types::Kind,
        nodes: Vec<signature::PublicKey>,
    ) -> Result<EnclaveResponse, AnyError> {
        let rsp = self
            .protocol
            .call_host_async(Body::HostRPCCallRequest {
                endpoint: self.endpoint.clone(),
                request_id,
                request: data,
                kind,
                nodes,
            })
            .await?;

        match rsp {
            Body::HostRPCCallResponse { response, node } => Ok(EnclaveResponse {
                data: response,
                node,
            }),
            _ => Err(anyhow!("bad response type")),
        }
    }

    async fn submit_peer_feedback(
        &self,
        request_id: u64,
        peer_feedback: types::PeerFeedback,
    ) -> Result<(), AnyError> {
        let rsp = self
            .protocol
            .call_host_async(Body::HostSubmitPeerFeedbackRequest {
                endpoint: self.endpoint.clone(),
                request_id,
                peer_feedback,
            })
            .await?;

        match rsp {
            Body::HostSubmitPeerFeedbackResponse {} => Ok(()),
            _ => Err(anyhow!("bad response type")),
        }
    }
}
