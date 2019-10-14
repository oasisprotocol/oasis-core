//! Key manager enclave context.
use std::sync::Arc;

use oasis_core_runtime::{common::runtime::RuntimeId, Protocol};

pub(crate) struct Context {
    pub runtime_id: RuntimeId,
    pub protocol: Arc<Protocol>,
}
