use std::collections::BTreeMap;

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
    /// CBOR-serialized label attestation.
    pub attestation: Vec<u8>,
    /// Public key of the node attesting to the labels.
    pub node_id: PublicKey,
    /// Signature of the attested labels.
    pub signature: Signature,
}

/// Attestation of component labels.
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct LabelAttestation {
    /// Attested label values.
    pub labels: BTreeMap<String, String>,
    /// Component RAK.
    pub rak: PublicKey,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_label_attestation() {
        // NOTE: Test vectors from Go implementation.
        let la = LabelAttestation {
            labels: BTreeMap::from([("foo".to_string(), "bar".to_string())]),
            rak: "4242424242424242424242424242424242424242424242424242424242424242"
                .parse()
                .unwrap(),
        };
        let pk = "4b386050bd904dbe4de4f6f0040ab64a18f8a305c9609231bcf90aa1dbd14a3c";
        let sig = "6e7103250a95ed0b560dfabddec022bcd5416b96db1a999c725373e7d033dbfa14b8af29572fbe4b5cb2d30ac839ff4a465bb967169e5dcf888d06af90a3c809";

        let la_enc = cbor::to_vec(la);
        let pk = pk.parse().unwrap();
        let sig: Signature = sig.parse().unwrap();
        sig.verify(&pk, ATTEST_LABELS_SIGNATURE_CONTEXT, &la_enc)
            .expect("label attestation signature should be correct");
    }
}
