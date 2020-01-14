extern crate failure;
extern crate io_context;
extern crate serde;
extern crate oasis_core_keymanager_api;
extern crate oasis_core_keymanager_client;
extern crate oasis_core_runtime;
extern crate simple_swdp_api;

use std::sync::Arc;

use failure::Fallible;
//use io_context::Context as IoContext;
//use serde::{Serialize, Deserialize};

//use oasis_core_keymanager_client::ContractId;
use oasis_core_runtime::common::roothash::Namespace;
use oasis_core_keymanager_client::KeyManagerClient;
use oasis_core_runtime::{
    common::{runtime::RuntimeId, version::Version},
    rak::RAK,
    register_runtime_txn_methods,
    transaction::{dispatcher::CheckOnlySuccess, Context as TxnContext},
    version_from_cargo, Protocol, RpcDemux, RpcDispatcher, TxnDispatcher,
};
use simple_swdp_api::{with_api, StatelessWorkerInfo, JobSubmission};

struct Context {
    km_client: Arc<dyn KeyManagerClient>,
}

/// Register a SWDP-capable stateless worker.
fn swdp_register_worker(args: &StatelessWorkerInfo, ctx: &mut TxnContext) -> Fallible<Option<String>> {
    if ctx.check_only {
        return Err(CheckOnlySuccess::default().into());
    }

    // TODO: Add worker to the "registry". (implemented inside the state tree).

    Ok(Some("foo".to_string()))
}

/// Dispatch the result received from a stateless worker.
fn swdp_dispatch_result(args: &String, ctx: &mut TxnContext) -> Fallible<Option<String>> {
    let job_id: Namespace = Namespace::from(args.as_bytes());

    if ctx.check_only {
        return Err(CheckOnlySuccess::default().into());
    }

    // Emit a tag of the form "oasis-core.swdp.JobComplete.<job_id>" to notify all interested
    // listeners. If we just returned the job ID here, it would be written in the I/O tree,
    // where only the tx caller (= the stateless worker) can access it efficiently. But we don't
    // need to notify the stateless worker; we need to notify whoever scheduled the job initially.
    ctx.emit_txn_tag(b"kv_op", ["oasis-core.swdp.JobComplete.".as_bytes(), Namespace::as_ref(&job_id)].concat());
    ctx.emit_txn_tag(b"kv_key", "".as_bytes());

    Ok(None)
}

/// Submit a job by emitting a tag for which the stateless workers listen. In a non-testing
/// setup, an equivalent effect is achieved by calling an RPC of a service (expected for
/// 2020Q2: Data Sovereignty scheduler), which will emit the same tag(s) as this method.
fn submit_job(args: &JobSubmission, ctx: &mut TxnContext) -> Fallible<Option<String>> {
    if ctx.check_only {
        return Err(CheckOnlySuccess::default().into());
    }
    ctx.emit_txn_tag(b"kv_op", format!("oasis-core.swdp.DispatchJob.{}", args.worker_id).as_bytes());
    ctx.emit_txn_tag(b"kv_key", bincode::serialize(&args).unwrap());

    Ok(None)
}

fn main() {
    // Initializer.
    let init = |protocol: &Arc<Protocol>,
                rak: &Arc<RAK>,
                _rpc_demux: &mut RpcDemux,
                _rpc: &mut RpcDispatcher,
                txn: &mut TxnDispatcher| {
        with_api! { register_runtime_txn_methods!(txn, api); }

        // Create the key manager client.
        let km_client = Arc::new(oasis_core_keymanager_client::RemoteClient::new_runtime(
            RuntimeId::default(), // HACK: Tests always use the all 0 runtime ID.
            protocol.clone(),
            rak.clone(),
            1024,
        ));

        txn.set_context_initializer(move |ctx: &mut TxnContext| {
            ctx.runtime = Box::new(Context {
                km_client: km_client.clone(),
            })
        });
    };

    // Start the runtime.
    oasis_core_runtime::start_runtime(Some(Box::new(init)), version_from_cargo!());
}
