/// Endpoints available to the client inside an enclave.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum ClientEndpoint {
    /// IAS proxy (get SPID).
    IASProxyGetSpid,
    /// IAS proxy (verify quote).
    IASProxyVerifyQuote,
    /// Key manager enclave.
    KeyManager,
}

impl ClientEndpoint {
    /// Convert client endpoint from u16.
    pub fn from_u16(value: u16) -> Option<ClientEndpoint> {
        match value {
            0 => None,
            1 => Some(ClientEndpoint::IASProxyGetSpid),
            2 => Some(ClientEndpoint::IASProxyVerifyQuote),
            3 => Some(ClientEndpoint::KeyManager),
            _ => None,
        }
    }

    /// Convert client endpoint to u16.
    pub fn as_u16(&self) -> u16 {
        match *self {
            ClientEndpoint::IASProxyGetSpid => 1,
            ClientEndpoint::IASProxyVerifyQuote => 2,
            ClientEndpoint::KeyManager => 3,
        }
    }
}
