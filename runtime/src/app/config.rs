/// Runtime application configuration.
#[derive(Clone, Default, Debug, cbor::Encode, cbor::Decode)]
pub struct Config {
    /// Notification settings.
    pub notifications: Notifications,
}

/// Notification settings.
#[derive(Clone, Default, Debug, cbor::Encode, cbor::Decode)]
pub struct Notifications {
    /// Subscribe to runtime block notifications.
    pub blocks: bool,
    /// Subscribe to runtime event notifications associated
    /// with the specified tags.
    pub events: Vec<Vec<u8>>,
}
