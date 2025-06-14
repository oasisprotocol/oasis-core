use async_trait::async_trait;

use crate::{
    common::crypto::signature::{PublicKey, Signature},
    protocol::Protocol,
};

use super::{host_rpc_call, Error};

/// Name of the local RPC endpoint for the attestation methods.
pub const LOCAL_RPC_ENDPOINT_ATTESTATION: &str = "attestation";

/// Name of the AttestLabels method.
pub const METHOD_ATTEST_LABELS: &str = "AttestLabels";

/// Signature context used for label attestation.
pub const ATTEST_LABELS_SIGNATURE_CONTEXT: &[u8] = b"oasis-core/node: attest component labels";

/// Attestaion interface.
#[async_trait]
pub trait Attestation: Send + Sync {
    /// Request to host to attest component labels.
    async fn attest_labels(&self, args: AttestLabelsRequest)
        -> Result<AttestLabelsResponse, Error>;
}

#[async_trait]
impl Attestation for Protocol {
    async fn attest_labels(
        &self,
        args: AttestLabelsRequest,
    ) -> Result<AttestLabelsResponse, Error> {
        host_rpc_call(
            self,
            LOCAL_RPC_ENDPOINT_ATTESTATION,
            METHOD_ATTEST_LABELS,
            args,
        )
        .await
    }
}

/// Request to attest labels.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct AttestLabelsRequest {
    /// Labels to attest to.
    pub labels: Vec<String>,
}

/// Response from the AttestLabels method.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct AttestLabelsResponse {
    /// Label attestation.
    pub attestation: LabelAttestation,
    /// Public key of the node attesting to the labels.
    pub node_id: PublicKey,
    /// Signature of the attested labels.
    pub signature: Signature,
}

/// Attestation of component labels.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct LabelAttestation {
    /// Attested labels, in order.
    pub labels: Vec<AttestedLabel>,
    /// Component RAK.
    pub rak: PublicKey,
}

#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
#[cbor(as_array)]
pub struct AttestedLabel {
    /// Label key.
    pub key: String,
    /// Label value.
    pub value: String,
}
