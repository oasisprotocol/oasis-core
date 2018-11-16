use serde::{self, Deserialize, Deserializer, Serialize, Serializer};

/// Endpoints available to the client inside an enclave.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u16)]
pub enum ClientEndpoint {
    /// Invalid endpoint (should never be seen on the wire).
    Invalid = 0,
    /// Key manager enclave.
    KeyManager = 1,
}

impl ClientEndpoint {
    /// Convert client endpoint from u16.
    pub fn from_u16(value: u16) -> Option<ClientEndpoint> {
        match value {
            1 => Some(ClientEndpoint::KeyManager),
            _ => None,
        }
    }

    /// Convert client endpoint to u16.
    pub fn as_u16(&self) -> u16 {
        *self as u16
    }
}

impl Serialize for ClientEndpoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u16(*self as u16)
    }
}

impl<'de> Deserialize<'de> for ClientEndpoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match ClientEndpoint::from_u16(u16::deserialize(deserializer)?) {
            Some(value) => Ok(value),
            None => Err(serde::de::Error::custom("invalid client endpoint")),
        }
    }
}
