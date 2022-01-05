//! Protocol and runtime versioning.
// NOTE: This should be kept in sync with go/common/version/version.go.

/// A protocol or runtime version.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct Version {
    #[cbor(optional)]
    #[cbor(default)]
    #[cbor(skip_serializing_if = "num_traits::Zero::is_zero")]
    pub major: u16,

    #[cbor(optional)]
    #[cbor(default)]
    #[cbor(skip_serializing_if = "num_traits::Zero::is_zero")]
    pub minor: u16,

    #[cbor(optional)]
    #[cbor(default)]
    #[cbor(skip_serializing_if = "num_traits::Zero::is_zero")]
    pub patch: u16,
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
    pub const fn new(major: u16, minor: u16, patch: u16) -> Version {
        Version {
            major: major,
            minor: minor,
            patch: patch,
        }
    }

    /// Checks if two versions are compatible.
    pub fn is_compatible_with(&self, other: &Version) -> bool {
        self.major == other.major
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
    major: 4,
    minor: 0,
    patch: 0,
};

// Version of the consensus protocol runtime code works with. This version MUST
// be compatible with the one supported by the worker host.
pub const CONSENSUS_VERSION: Version = Version {
    major: 5,
    minor: 0,
    patch: 0,
};

#[cfg(test)]
mod test {
    use super::Version;

    #[test]
    fn test_version() {
        assert!(Version {
            major: 32,
            minor: 25,
            patch: 10,
        }
        .is_compatible_with(&Version {
            major: 32,
            minor: 10,
            patch: 100,
        }),);

        let v = Version {
            major: 17,
            minor: 11,
            patch: 1,
        };
        let vi: u64 = v.into();
        assert_eq!(v, Version::from(vi));
    }
}
