//! RPC protocol types.
use rand::{rngs::OsRng, Rng};

impl_bytes!(
    SessionID,
    32,
    "Session identifier for multiplexing multiple sessions over the \
     same transport"
);

impl SessionID {
    /// Generate a random session identifier.
    pub fn random() -> Self {
        let mut rng = OsRng {};
        let mut session_id = [0u8; 32];
        rng.fill(&mut session_id);

        SessionID(session_id)
    }
}

/// Frame.
#[derive(Debug, cbor::Encode, cbor::Decode)]
pub struct Frame {
    pub session: SessionID,
    // The `untrusted_plaintext` field is only a temporary workaround until
    // the snow library supports encrypting the payload with authenticated
    // data.
    // This field contains a plaintext copy of the Request's `method` field
    // and is verified inside the enclave.  It is unused in other cases.
    pub untrusted_plaintext: String,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, cbor::Encode, cbor::Decode)]
pub struct Request {
    pub method: String,
    pub args: cbor::Value,
}

#[derive(Debug, cbor::Encode, cbor::Decode)]
pub struct Error {
    pub message: String,
}

#[derive(Debug, cbor::Encode, cbor::Decode)]
pub enum Body {
    Success(cbor::Value),
    Error(String),
}

#[derive(Debug, cbor::Encode, cbor::Decode)]
pub struct Response {
    pub body: Body,
}

/// Protocol message.
#[derive(Debug, cbor::Encode, cbor::Decode)]
pub enum Message {
    Request(Request),
    Response(Response),
    Close,
}
