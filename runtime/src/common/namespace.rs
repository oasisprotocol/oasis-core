//! Chain namespace.

/// Size of the namespace in bytes.
pub const NAMESPACE_SIZE: usize = 32;

impl_bytes!(Namespace, NAMESPACE_SIZE, "Chain namespace.");
