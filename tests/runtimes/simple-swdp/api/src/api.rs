use serde_derive::{Deserialize, Serialize};

use oasis_core_runtime::runtime_api;

#[derive(Clone, Serialize, Deserialize)]
pub struct WorkerInfo {
    // Human-readable name (for logging).
    pub name: String,
    // Address at which the worker is listening.
    pub address: String,  // XXX: Plain string (ip:port)? net.IP? Path to unix socket? Go channel?
}

runtime_api! {
    // Registers a stateless worker.
    pub fn swdp_register_worker(WorkerInfo) -> Option<String>;

    // Dispatches the results of a SWDP worker's computation.
    pub fn swdp_dispatch_result(String) -> Option<String>;
}
