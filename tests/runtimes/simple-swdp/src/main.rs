extern crate failure;
extern crate io_context;
extern crate oasis_core_keymanager_api;
extern crate oasis_core_keymanager_client;
extern crate oasis_core_runtime;
extern crate simple_swdp_api;

use std::sync::Arc;

use failure::Fallible;
use failure::format_err;
//use io_context::Context as IoContext;

//use oasis_core_keymanager_client::ContractId;
use oasis_core_keymanager_client::KeyManagerClient;
use oasis_core_runtime::{
    common::{
//        crypto::{
//            hash::Hash,
//            mrae::deoxysii::{DeoxysII, KEY_SIZE, NONCE_SIZE, TAG_SIZE},
//        },
        runtime::RuntimeId,
        version::Version,
    },
//    executor::Executor,
    rak::RAK,
    register_runtime_txn_methods, //runtime_context,
//    storage::{StorageContext, MKVS},
    transaction::{dispatcher::CheckOnlySuccess, Context as TxnContext},
    version_from_cargo, Protocol, RpcDemux, RpcDispatcher, TxnDispatcher,
};
use simple_swdp_api::{with_api, WorkerInfo};

struct Context {
    km_client: Arc<dyn KeyManagerClient>,
}


/// Register a SWDP-capable stateless worker.
fn swdp_register_worker(args: &WorkerInfo, ctx: &mut TxnContext) -> Fallible<Option<String>> {
    if ctx.check_only {
        return Err(CheckOnlySuccess::default().into());
    }
    // XXX: Do we need this?
    //ctx.emit_txn_tag(b"kv_op", b"insertato");
    //ctx.emit_txn_tag(b"kv_key", args.key.as_bytes());

    // TODO: Add worker to some internal registry.
    
    Ok(Some("foo".to_string()))
}

/// Dispatch the result received from a stateless worker.
fn swdp_dispatch_result(args: &String, ctx: &mut TxnContext) -> Fallible<Option<String>> {
    let result : &String = args;  // XXX: Do we need .as_bytes() of some sort?

    // Maximum size of results we're willing to store on the chain.
    const MAX_RESULT_SIZE : usize = 1024;
    if result.len() > MAX_RESULT_SIZE {
        return Err(format_err!("Return value too long: {:?} bytes; max is {:?}", result.len(), MAX_RESULT_SIZE));
    }
    if ctx.check_only {
        return Err(CheckOnlySuccess::default().into());
    }


    // XXX: Where/how do we dispatch the result? Is the fact that we're returning it
    // here enough for it to get written into the io tree, so we don't need to do anything more?
    Ok(Some(result.to_string()))
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
