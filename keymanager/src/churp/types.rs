//! CHURP types used by the worker-host protocol.
use oasis_core_runtime::{
    common::{
        crypto::{hash::Hash, signature::Signature},
        namespace::Namespace,
    },
    consensus::beacon::EpochTime,
};

/// Initialization request.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct InitRequest {
    /// A unique identifier within the key manager runtime.
    pub id: u8,

    /// The identifier of the key manager runtime.
    pub runtime_id: Namespace,

    /// The epoch of the handoff for which the node would like to register.
    pub epoch: EpochTime,
}

/// ApplicationRequest contains node's application to form a new committee.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct ApplicationRequest {
    /// A unique identifier within the key manager runtime.
    pub id: u8,

    /// The identifier of the key manager runtime.
    pub runtime_id: Namespace,

    /// The epoch of the handoff for which the node would like to register.
    pub epoch: EpochTime,

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

/// Encoded secret share.
#[derive(Clone, Default, cbor::Encode, cbor::Decode)]
pub struct EncodedSecretShare {
    /// Encoded polynomial.
    pub polynomial: Vec<u8>,

    /// Encoded verification matrix.
    pub verification_matrix: Vec<u8>,
}
