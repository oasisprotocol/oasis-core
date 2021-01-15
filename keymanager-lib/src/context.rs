//! Key manager enclave context.
use std::sync::Arc;

use oasis_core_runtime::{common::namespace::Namespace, Protocol};

pub struct Context {
    pub runtime_id: Namespace,
    pub protocol: Arc<Protocol>,
}
