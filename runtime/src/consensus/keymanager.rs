use std::collections::HashMap;

use thiserror::Error;

use crate::common::{
    crypto::signature::SignatureBundle, namespace::Namespace, sgx::EnclaveIdentity,
};

const POLICY_SIGN_CONTEXT: &[u8] = b"oasis-core/keymanager: policy";

/// Errors emitted by the key manager module.
#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid signature")]
    InvalidSignature,
}

/// Key manager access control policy.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct PolicySGX {
    pub serial: u32,
    pub id: Namespace,
    pub enclaves: HashMap<EnclaveIdentity, EnclavePolicySGX>,
}

/// Per enclave key manager access control policy.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct EnclavePolicySGX {
    pub may_query: HashMap<Namespace, Vec<EnclaveIdentity>>,
    pub may_replicate: Vec<EnclaveIdentity>,
}

/// Signed key manager access control policy.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct SignedPolicySGX {
    pub policy: PolicySGX,
    pub signatures: Vec<SignatureBundle>,
}

impl SignedPolicySGX {
    /// Verify the signatures.
    pub fn verify(&self) -> Result<&PolicySGX, Error> {
        let raw_policy = cbor::to_vec(self.policy.clone());
        for sig in &self.signatures {
            sig.signature
                .verify(&sig.public_key, POLICY_SIGN_CONTEXT, &raw_policy)
                .map_err(|_| Error::InvalidSignature)?;
        }

        Ok(&self.policy)
    }
}
