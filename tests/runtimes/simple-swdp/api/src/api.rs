use serde_derive::{Deserialize, Serialize};

use oasis_core_runtime::runtime_api;

#[derive(Clone, Serialize, Deserialize)]
pub struct WorkerInfo {
    // Human-readable name (for logging).
    pub name: String,
    // Address at which the worker is listening.
    pub address: String,  // XXX: Plain string (ip:port)? net.IP? Path to unix socket? Go channel?
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct JobSubmission {
    // Job ID; for tracking and debugging.
    // Caller should ensure that the name be globally unique (e.g. by using an UUID).
    pub job_id: String,
    // ID of the worker that should run this job.
    pub worker_id: String,
    // The full path (on the stateless worker) to the runtime to use for the job.
    // The runtime has to be already installed.
    // TODO: Use a more robust identifier that doesn't require callers to know
    // the filesystem layout.
    pub runtime_path: String,
    // Arguments to the runtime.
    pub args: Vec<String>,
}


runtime_api! {
    // Registers a stateless worker.
    pub fn swdp_register_worker(WorkerInfo) -> Option<String>;

    // Dispatches the results of a SWDP worker's computation.
    pub fn swdp_dispatch_result(String) -> Option<String>;
}
