//! Protocol and runtime versioning.
// NOTE: This should be kept in sync with go/common/version/version.go.

/// A protocol or runtime version.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct Version {
    #[cbor(optional)]
    pub major: u16,

    #[cbor(optional)]
    pub minor: u16,

    #[cbor(optional)]
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
            major,
            minor,
            patch,
        }
    }

    /// Checks if two versions are compatible.
    pub fn is_compatible_with(&self, other: &Version) -> bool {
        self.major == other.major
    }
}

// Returns the version as a platform-dependent u64.
impl From<Version> for u64 {
    fn from(val: Version) -> Self {
        ((val.major as u64) << 32) | ((val.minor as u64) << 16) | (val.patch as u64)
    }
}

// Creates the version from a platform-dependent u64.
impl From<u64> for Version {
    fn from(v: u64) -> Version {
        Version {
            major: ((v >> 32) & 0xffff) as u16,
            minor: ((v >> 16) & 0xffff) as u16,
            patch: (v & 0xffff) as u16,
        }
    }
}

// Version of the protocol used for communication between the Oasis node(s)
// and the runtime. This version MUST be compatible with the one supported by
// the worker host.
pub const PROTOCOL_VERSION: Version = Version {
    major: 6,
    minor: 0,
    patch: 0,
};

/// Protocol versions.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct ProtocolVersions {
    pub consensus_protocol: Version,
    pub runtime_host_protocol: Version,
    pub runtime_committee_protocol: Version,
}

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

    #[test]
    fn test_version_u64() {
        for v in vec![
            Version::default(),
            Version {
                major: 0,
                minor: 0,
                patch: 0,
            },
            Version {
                major: 1,
                minor: 1,
                patch: 1,
            },
            Version {
                major: 10,
                minor: 20,
                patch: 30,
            },
            Version {
                major: 300,
                minor: 400,
                patch: 500,
            },
            Version {
                major: 30000,
                minor: 40000,
                patch: 50000,
            },
        ] {
            let vi: u64 = v.into();
            assert_eq!(Version::from(vi), v)
        }
    }
}
