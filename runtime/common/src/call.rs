//! Runtime call type.
use serde::de::DeserializeOwned;
use serde_cbor;

use ekiden_common::error::Result;

/// Helper type used for generic arguments/output.
pub type Generic = serde_cbor::Value;

/// Plain runtime call.
#[derive(Clone, Serialize, Deserialize)]
pub struct RuntimeCall<T> {
    /// Runtime method name.
    pub method: String,
    /// Runtime method arguments.
    pub arguments: T,
}

impl<T> RuntimeCall<T> {
    /// Convert from generic runtime call.
    pub fn from_generic(generic: RuntimeCall<Generic>) -> Result<RuntimeCall<T>>
    where
        T: DeserializeOwned,
    {
        // TODO: Make this work without serialization round trip.
        Ok(Self {
            method: generic.method.clone(),
            arguments: serde_cbor::from_slice(&serde_cbor::to_vec(&generic.arguments)?)?,
        })
    }
}

/// Plain runtime output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RuntimeOutput<T> {
    /// Runtime invoked successfully.
    Success(T),
    /// Runtime raised an error.
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
        let specific = RuntimeCall {
            method: "specific".to_owned(),
            arguments: ComplexArguments {
                a: 42,
                b: "hello".to_owned(),
                c: vec!["one".to_owned(), "two".to_owned()],
            },
        };

        let specific_encoded = serde_cbor::to_vec(&specific).unwrap();

        // Decode generic.
        let generic = serde_cbor::from_slice::<RuntimeCall<Generic>>(&specific_encoded).unwrap();
        assert_eq!(generic.method, "specific".to_owned());

        // Encode generic.
        let generic_encoded = serde_cbor::to_vec(&generic).unwrap();
        assert_eq!(generic_encoded, specific_encoded);

        // Decode specific.
        let specific_decoded =
            serde_cbor::from_slice::<RuntimeCall<ComplexArguments>>(&generic_encoded).unwrap();
        assert_eq!(specific_decoded.method, specific.method);
        assert_eq!(specific_decoded.arguments, specific.arguments);
    }
}
