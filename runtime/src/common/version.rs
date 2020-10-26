/// Protocol and runtime versioning.

// NOTE: This should be kept in sync with go/common/version/version.go.

/// A protocol or runtime version.
#[derive(Clone, Copy, Debug)]
pub struct Version {
    major: u16,
    minor: u16,
    patch: u16,
}

#[macro_export]
macro_rules! version_from_cargo {
    () => {
        Version::new(
            env!("CARGO_PKG_VERSION_MAJOR").parse::<u16>().unwrap(),
            env!("CARGO_PKG_VERSION_MINOR").parse::<u16>().unwrap(),
            env!("CARGO_PKG_VERSION_PATCH").parse::<u16>().unwrap(),
        )
    };
}

impl Version {
    /// Creates a new version with given major, minor, and patch segments.
    pub fn new(major: u16, minor: u16, patch: u16) -> Version {
        Version {
            major: major,
            minor: minor,
            patch: patch,
        }
    }
}

// Returns the version as a platform-dependent u64.
impl Into<u64> for Version {
    fn into(self) -> u64 {
        ((self.major as u64) << 32) | ((self.minor as u64) << 16) | (self.patch as u64)
    }
}

// Creates the version from a platform-dependent u64.
impl From<u64> for Version {
    fn from(v: u64) -> Version {
        Version {
            major: ((v >> 32) & 0xff) as u16,
            minor: ((v >> 16) & 0xff) as u16,
            patch: (v & 0xff) as u16,
        }
    }
}

// Version of the protocol used for communication between the Oasis node(s)
// and the runtime. This version MUST be compatible with the one supported by
// the worker host.
pub const PROTOCOL_VERSION: Version = Version {
    major: 2,
    minor: 0,
    patch: 0,
};
