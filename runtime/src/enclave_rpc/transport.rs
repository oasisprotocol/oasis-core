use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Error as AnyError};
use futures::future::{self, BoxFuture};

use crate::{common::crypto::signature, types::Body, Protocol};

use super::types;

/// An EnclaveRPC transport.
pub trait Transport: Send + Sync {
    fn write_noise_session(
        &self,
        session_id: types::SessionID,
        data: Vec<u8>,
        untrusted_plaintext: String,
        nodes: Vec<signature::PublicKey>,
    ) -> BoxFuture<Result<(Vec<u8>, signature::PublicKey), AnyError>> {
        // Frame message.
        let frame = types::Frame {
            session: session_id,
            untrusted_plaintext,
            payload: data,
        };

        self.write_message_impl(cbor::to_vec(frame), types::Kind::NoiseSession, nodes)
    }

    fn write_insecure_query(
        &self,
        data: Vec<u8>,
        nodes: Vec<signature::PublicKey>,
    ) -> BoxFuture<Result<(Vec<u8>, signature::PublicKey), AnyError>> {
        self.write_message_impl(data, types::Kind::InsecureQuery, nodes)
    }

    fn write_message_impl(
        &self,
        data: Vec<u8>,
        kind: types::Kind,
        nodes: Vec<signature::PublicKey>,
    ) -> BoxFuture<Result<(Vec<u8>, signature::PublicKey), AnyError>>;

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

impl Transport for RuntimeTransport {
    fn write_message_impl(
        &self,
        data: Vec<u8>,
        kind: types::Kind,
        nodes: Vec<signature::PublicKey>,
    ) -> BoxFuture<Result<(Vec<u8>, signature::PublicKey), AnyError>> {
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

        // NOTE: This is not actually async in SGX, but futures should be
        //       dispatched on the current thread anyway.
        let rsp = self.protocol.call_host(Body::HostRPCCallRequest {
            endpoint: self.endpoint.clone(),
            request: data,
            kind,
            nodes,
            peer_feedback,
        });

        match rsp {
            Err(err) => Box::pin(future::err(err.into())),
            Ok(Body::HostRPCCallResponse { response, node }) => {
                Box::pin(future::ok((response, node)))
            }
            Ok(_) => Box::pin(future::err(anyhow!("bad response type"))),
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
