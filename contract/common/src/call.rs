//! Contract call type.
use serde::de::DeserializeOwned;
use serde_cbor;

use ekiden_common::bytes::B256;
use ekiden_common::error::Result;

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

impl<T> ContractCall<T> {
    /// Convert from generic contract call.
    pub fn from_generic(generic: ContractCall<Generic>) -> Result<ContractCall<T>>
    where
        T: DeserializeOwned,
    {
        // TODO: Make this work without serialization round trip.
        Ok(Self {
            id: generic.id,
            method: generic.method.clone(),
            arguments: serde_cbor::from_slice(&serde_cbor::to_vec(&generic.arguments)?)?,
        })
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
