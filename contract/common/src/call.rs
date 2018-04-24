//! Contract call type.
use std::ops::Deref;

use serde::Serialize;
use serde_cbor;

use ekiden_common::bytes::B64;
use ekiden_common::error::Result;
use ekiden_common::signature::{Signature, Signed, Signer};

/// Signature context used for contract calls.
pub const CALL_SIGNATURE_CONTEXT: B64 = B64(*b"EkCtCall");

/// Helper type used for generic arguments/output.
pub type Generic = serde_cbor::Value;

/// Plain contract call.
#[derive(Serialize, Deserialize)]
pub struct ContractCall<T> {
    /// Contract method name.
    pub method: String,
    /// Contract method arguments.
    pub arguments: T,
}

impl<T: Clone> Clone for ContractCall<T> {
    fn clone(&self) -> Self {
        ContractCall {
            method: self.method.clone(),
            arguments: self.arguments.clone(),
        }
    }
}

/// Signed contract call.
#[derive(Serialize, Deserialize)]
pub struct SignedContractCall<T>(Signed<ContractCall<T>>);

impl<T> SignedContractCall<T> {
    /// Create a signed contract call.
    pub fn sign(signer: &Signer, method: &str, arguments: T) -> Self
    where
        T: Serialize,
    {
        let call = ContractCall {
            method: method.to_owned(),
            arguments: arguments,
        };

        SignedContractCall(Signed::sign(signer, &CALL_SIGNATURE_CONTEXT, call))
    }

    /// Get contract call signature.
    pub fn get_signature(&self) -> &Signature {
        &self.0.signature
    }

    /// Verify signature and return signed contract call.
    pub fn open(self) -> Result<ContractCall<T>>
    where
        T: Serialize,
    {
        self.0.open(&CALL_SIGNATURE_CONTEXT)
    }
}

impl<T> Deref for SignedContractCall<T> {
    type Target = T;

    /// Dereferences the request into underlying method arguments without verifying the signature.
    ///
    /// This can be used safely when the dispatcher has previously verified the signature.
    fn deref(&self) -> &T {
        &self.0.get_value_unsafe().arguments
    }
}

impl<T: Clone> Clone for SignedContractCall<T> {
    fn clone(&self) -> Self {
        SignedContractCall(self.0.clone())
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
