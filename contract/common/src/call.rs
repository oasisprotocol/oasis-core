//! Contract call type.
use std::ops::Deref;

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_cbor;

use ekiden_common::bytes::{B256, B64};
use ekiden_common::error::Result;
use ekiden_common::signature::{Signature, Signed, Signer};

/// Signature context used for contract calls.
pub const CALL_SIGNATURE_CONTEXT: B64 = B64(*b"EkCtCall");

/// Helper type used for generic arguments/output.
pub type Generic = serde_cbor::Value;

/// Plain contract call.
#[derive(Clone, Serialize, Deserialize)]
pub struct ContractCall<T> {
    /// Unique identifier.
    pub id: B256,
    /// Contract method name.
    pub method: String,
    /// Contract method arguments.
    pub arguments: T,
}

/// Signed contract call.
#[derive(Clone, Serialize, Deserialize)]
pub struct SignedContractCall<T>(Signed<ContractCall<T>>);

impl<T> SignedContractCall<T> {
    /// Create a signed contract call.
    pub fn sign(signer: &Signer, method: &str, arguments: T) -> Self
    where
        T: Serialize,
    {
        let call = ContractCall {
            id: B256::random(),
            method: method.to_owned(),
            arguments: arguments,
        };

        SignedContractCall(Signed::sign(signer, &CALL_SIGNATURE_CONTEXT, call))
    }

    /// Verify signature and return signed contract call.
    pub fn open(self) -> Result<VerifiedContractCall<T>>
    where
        T: DeserializeOwned,
    {
        Ok(VerifiedContractCall::new(
            self.0.open(&CALL_SIGNATURE_CONTEXT)?,
            self.0.signature,
        ))
    }
}

/// Contract call whose signature has already been verified.
#[derive(Clone)]
pub struct VerifiedContractCall<T> {
    /// Contract call whose signature has been verified.
    call: ContractCall<T>,
    /// Signature of the contract call.
    signature: Signature,
}

impl<T> VerifiedContractCall<T> {
    fn new(call: ContractCall<T>, signature: Signature) -> Self {
        Self { call, signature }
    }

    /// Convert from generic verified contract call.
    pub fn from_generic(generic: VerifiedContractCall<Generic>) -> Result<VerifiedContractCall<T>>
    where
        T: DeserializeOwned,
    {
        // TODO: Make this work without serialization round trip.
        Ok(Self {
            call: serde_cbor::from_slice(&serde_cbor::to_vec(&generic.call)?)?,
            signature: generic.signature,
        })
    }

    /// Get contract call.
    pub fn get_call(&self) -> &ContractCall<T> {
        &self.call
    }

    /// Take contract call.
    pub fn take_call(self) -> ContractCall<T> {
        self.call
    }

    /// Get contract call signature.
    pub fn get_signature(&self) -> &Signature {
        &self.signature
    }
}

impl<T> Deref for VerifiedContractCall<T> {
    type Target = T;

    /// Dereferences the request into underlying method arguments.
    fn deref(&self) -> &T {
        &self.call.arguments
    }
}

/// Plain contract output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ContractOutput<T> {
    /// Contract invoked successfully.
    Success(T),
    /// Contract raised an error.
    Error(String),
}

#[cfg(test)]
mod tests {
    use serde_cbor;

    use super::*;

    #[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
    struct ComplexArguments {
        a: u16,
        b: String,
        c: Vec<String>,
    }

    #[test]
    fn test_generic_call() {
        // Encode specific.
        let specific = ContractCall {
            id: B256::random(),
            method: "specific".to_owned(),
            arguments: ComplexArguments {
                a: 42,
                b: "hello".to_owned(),
                c: vec!["one".to_owned(), "two".to_owned()],
            },
        };

        let specific_encoded = serde_cbor::to_vec(&specific).unwrap();

        // Decode generic.
        let generic = serde_cbor::from_slice::<ContractCall<Generic>>(&specific_encoded).unwrap();
        assert_eq!(generic.method, "specific".to_owned());

        // Encode generic.
        let generic_encoded = serde_cbor::to_vec(&generic).unwrap();
        assert_eq!(generic_encoded, specific_encoded);

        // Decode specific.
        let specific_decoded =
            serde_cbor::from_slice::<ContractCall<ComplexArguments>>(&generic_encoded).unwrap();
        assert_eq!(specific_decoded.method, specific.method);
        assert_eq!(specific_decoded.arguments, specific.arguments);
    }
}
