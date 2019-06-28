/// Protocol versioning.

// NOTE: This should be kept in sync with go/common/version/version.go.

/// A protocol version.
#[derive(Clone, Copy, Debug)]
pub struct Version {
    major: u16,
    minor: u16,
    patch: u16,
}

impl Into<u64> for Version {
    fn into(self) -> u64 {
        ((self.major as u64) << 32) | ((self.minor as u64) << 16)
    }
}

// Version of the protocol used for communication between the Ekiden node(s)
// and the runtime. This version MUST be compatible with the one supported by
// the worker host.
pub const PROTOCOL_VERSION: Version = Version {
    major: 0,
    minor: 2,
    patch: 0,
};
