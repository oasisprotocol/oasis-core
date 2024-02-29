//! CHURP types used by the worker-host protocol.
use oasis_core_runtime::common::{
    crypto::{hash::Hash, signature::Signature},
    namespace::Namespace,
};

/// Initialization request.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct InitRequest {
    /// A unique identifier within the key manager runtime.
    pub id: u8,

    /// The identifier of the key manager runtime.
    pub runtime_id: Namespace,

    /// Round number for which the node would like to register.
    pub round: u64,
}

/// ApplicationRequest contains node's application to form a new committee.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct ApplicationRequest {
    /// A unique identifier within the key manager runtime.
    pub id: u8,

    /// The identifier of the key manager runtime.
    pub runtime_id: Namespace,

    /// The round for which the node would like to register.
    pub round: u64,

    /// Checksum is the hash of the verification matrix.
    pub checksum: Hash,
}

/// SignedApplication is an application request  signed by the key manager
/// enclave using its runtime attestation key (RAK).
#[derive(Clone, Default, cbor::Encode, cbor::Decode)]
pub struct SignedApplicationRequest {
    /// Application.
    pub application: ApplicationRequest,

    /// RAK signature.
    pub signature: Signature,
}
