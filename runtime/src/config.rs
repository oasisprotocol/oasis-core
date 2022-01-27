//! Runtime configuration.
use crate::{common::version::Version, consensus::verifier::TrustRoot, types::Features};

/// Global runtime configuration.
#[derive(Clone, Debug, Default)]
pub struct Config {
    /// Semantic runtime version.
    pub version: Version,
    /// Optional trust root for consensus layer integrity verification.
    pub trust_root: Option<TrustRoot>,
    /// Storage configuration.
    pub storage: Storage,
    /// Advertised runtime features.
    pub features: Option<Features>,
}

/// Storage-related configuration.
#[derive(Clone, Debug)]
pub struct Storage {
    /// The maximum number of tree nodes held by the cache before eviction.
    /// A zero value denotes unlimited capacity.
    pub cache_node_capacity: usize,
    /// The total size, in bytes, of values held by the cache before eviction.
    /// A zero value denotes unlimited capacity.
    pub cache_value_capacity: usize,
}

impl Default for Storage {
    fn default() -> Self {
        Self {
            cache_node_capacity: 100_000,
            cache_value_capacity: 32 * 1024 * 1024, // 32 MiB
        }
    }
}
