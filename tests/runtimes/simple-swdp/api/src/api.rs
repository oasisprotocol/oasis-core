extern crate oasis_core_keymanager_client;

use serde_derive::{Deserialize, Serialize};
use oasis_core_runtime::{
    common::runtime::RuntimeId
};

use self::oasis_core_keymanager_client::PublicKey;
use oasis_core_runtime::runtime_api;

// Information needed to register a stateless worker on the platform.
#[derive(Clone, Serialize, Deserialize)]
pub struct StatelessWorkerInfo {
    // ID of the worker.
    // XXX: Introduce a new type, StatelessWorkerId, here? (Like RuntimeId etc)
    pub id: PublicKey,
    // All the stateless runtimes supported by this worker.
    pub runtimes: Vec<RuntimeId>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct JobSubmission {
    // Job ID; for tracking and debugging.
    // Caller should ensure that the name be globally unique (e.g. by using an UUID).
    pub job_id: String,
    // ID of the worker that should run this job.
    pub worker_id: String,
    // The stateless runtime to use for the job. The runtime has to be already deployed.
    pub runtime_id: RuntimeId,
    // Arguments to the runtime.
    pub args: Vec<String>,
}


runtime_api! {
    // Registers a stateless worker.
    pub fn swdp_register_worker(StatelessWorkerInfo) -> Option<String>;

    // Dispatches the results of a SWDP worker's computation.
    pub fn swdp_dispatch_result(String) -> Option<String>;

    // Submit a job to the stateless workers (by emitting a tag).
    pub fn swdp_submit_job(JobSubmission) -> Option<String>;
}
