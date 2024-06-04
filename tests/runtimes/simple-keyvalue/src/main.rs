//! A simple test runtime.

pub mod crypto;
pub mod methods;
pub mod types;

use std::{
    convert::TryInto,
    sync::{atomic::AtomicBool, Arc},
};

use oasis_core_keymanager::client::KeyManagerClient;
use oasis_core_runtime::{
    common::{crypto::hash::Hash, version::Version},
    config::Config,
    consensus::{
        roothash::{IncomingMessage, Message},
        verifier::{TrustRoot, Verifier},
    },
    dispatcher::{PostInitState, PreInitState},
    future::block_on,
    protocol::HostInfo,
    transaction::{
        dispatcher::{ExecuteBatchResult, ExecuteTxResult},
        tags::{Tag, Tags},
        types::TxnBatch,
        Context as TxnContext,
    },
    types::{CheckTxResult, Error as RuntimeError, FeatureScheduleControl, Features},
    TxnDispatcher,
};
use simple_keymanager::trusted_signers;

use methods::{BlockHandler, Methods};
use types::*;

/// Maximum number of transactions in a batch. Should be less than or equal to what is set in the
/// runtime descriptor to avoid batches being rejected.
const MAX_BATCH_SIZE: usize = 100;

/// A simple context wrapper for processing test transaction batches.
///
/// For a proper dispatcher see the [Oasis SDK](https://github.com/oasisprotocol/oasis-sdk).
pub struct Context<'a, 'core> {
    pub core: &'a mut TxnContext<'core>,
    pub host_info: &'a HostInfo,
    pub key_manager: &'a dyn KeyManagerClient,
    pub consensus_verifier: &'a dyn Verifier,
    pub messages: Vec<Message>,
}

/// A simple context wrapper for processing test transactions.
///
/// For a proper dispatcher see the [Oasis SDK](https://github.com/oasisprotocol/oasis-sdk).
pub struct TxContext<'a, 'b, 'core> {
    pub parent: &'a mut Context<'b, 'core>,
    pub tags: Tags,

    check_only: bool,
}

impl<'a, 'b, 'core> TxContext<'a, 'b, 'core> {
    fn new(parent: &'a mut Context<'b, 'core>, check_only: bool) -> Self {
        Self {
            parent,
            tags: vec![],
            check_only,
        }
    }

    fn is_check_only(&self) -> bool {
        self.check_only
    }

    fn emit_message(&mut self, message: Message) -> u32 {
        self.parent.messages.push(message);
        (self.parent.messages.len() - 1) as u32
    }

    fn emit_tag(&mut self, key: &[u8], value: &[u8]) {
        self.tags.push(Tag {
            key: key.to_vec(),
            value: value.to_vec(),
            ..Default::default()
        });
    }
}

/// A simple dispatcher used for this test runtime.
///
/// For a proper dispatcher see the [Oasis SDK](https://github.com/oasisprotocol/oasis-sdk).
struct Dispatcher {
    host_info: HostInfo,
    key_manager: Arc<dyn KeyManagerClient>,
    consensus_verifier: Arc<dyn Verifier>,
}

impl Dispatcher {
    fn new(
        host_info: HostInfo,
        key_manager: Arc<dyn KeyManagerClient>,
        consensus_verifier: Arc<dyn Verifier>,
    ) -> Self {
        Self {
            host_info,
            key_manager,
            consensus_verifier,
        }
    }

    fn dispatch_call<B, R, F>(
        ctx: &mut TxContext,
        args: cbor::Value,
        f: F,
    ) -> Result<cbor::Value, String>
    where
        B: cbor::Decode,
        R: cbor::Encode,
        F: FnOnce(&mut TxContext, B) -> Result<R, String>,
    {
        let args = cbor::from_value(args).map_err(|_| "malformed call arguments".to_string())?;

        let result = f(ctx, args)?;
        Ok(cbor::to_value(result))
    }

    fn decode_tx(tx: &[u8]) -> Result<Call, String> {
        // In the test runtime all transactions are just CBOR-serialized Call structs. In reality
        // one would want to have things like signatures etc.
        cbor::from_slice(tx).map_err(|err| err.to_string())
    }

    fn dispatch_tx(ctx: &mut TxContext, tx: Call) -> Result<cbor::Value, String> {
        Methods::check_nonce(ctx, tx.nonce)?;

        match tx.method.as_str() {
            "get_runtime_id" => Self::dispatch_call(ctx, tx.args, Methods::get_runtime_id),
            "consensus_accounts" => Self::dispatch_call(ctx, tx.args, Methods::consensus_accounts),
            "consensus_withdraw" => Self::dispatch_call(ctx, tx.args, Methods::consensus_withdraw),
            "consensus_transfer" => Self::dispatch_call(ctx, tx.args, Methods::consensus_transfer),
            "consensus_add_escrow" => {
                Self::dispatch_call(ctx, tx.args, Methods::consensus_add_escrow)
            }
            "consensus_reclaim_escrow" => {
                Self::dispatch_call(ctx, tx.args, Methods::consensus_reclaim_escrow)
            }
            "update_runtime" => Self::dispatch_call(ctx, tx.args, Methods::update_runtime),
            "insert" => Self::dispatch_call(ctx, tx.args, Methods::insert),
            "get" => Self::dispatch_call(ctx, tx.args, Methods::get),
            "remove" => Self::dispatch_call(ctx, tx.args, Methods::remove),
            "enc_insert" => Self::dispatch_call(ctx, tx.args, Methods::enc_insert_using_secrets),
            "enc_get" => Self::dispatch_call(ctx, tx.args, Methods::enc_get_using_secrets),
            "enc_remove" => Self::dispatch_call(ctx, tx.args, Methods::enc_remove_using_secrets),
            "churp_insert" => Self::dispatch_call(ctx, tx.args, Methods::enc_insert_using_churp),
            "churp_get" => Self::dispatch_call(ctx, tx.args, Methods::enc_get_using_churp),
            "churp_remove" => Self::dispatch_call(ctx, tx.args, Methods::enc_remove_using_churp),
            "encrypt" => Self::dispatch_call(ctx, tx.args, Methods::encrypt),
            "decrypt" => Self::dispatch_call(ctx, tx.args, Methods::decrypt),
            _ => Err("method not found".to_string()),
        }
    }

    fn decode_and_dispatch_tx(ctx: &mut TxContext, tx: &[u8]) -> Result<cbor::Value, String> {
        let tx = Self::decode_tx(tx)?;
        Self::dispatch_tx(ctx, tx)
    }

    fn execute_tx(ctx: &mut Context<'_, '_>, tx: &[u8]) -> Result<ExecuteTxResult, RuntimeError> {
        // During execution we reject malformed transactions as the proposer should do checks first.
        let tx = Self::decode_tx(tx).map_err(|_| RuntimeError {
            module: "test".to_string(),
            code: 1,
            message: "malformed transaction batch".to_string(),
        })?;

        let mut tx_ctx = TxContext::new(ctx, false);

        match Self::dispatch_tx(&mut tx_ctx, tx) {
            Ok(result) => Ok(ExecuteTxResult {
                output: cbor::to_vec(CallOutput::Success(result)),
                tags: tx_ctx.tags,
            }),
            Err(err) => Ok(ExecuteTxResult {
                output: cbor::to_vec(CallOutput::Error(err)),
                tags: vec![],
            }),
        }
    }

    fn execute_in_msg(ctx: &mut Context<'_, '_>, msg: &IncomingMessage) {
        // Process incoming messages as transactions and ignore results.
        let _ = Self::execute_tx(ctx, &msg.data);
    }

    fn check_tx(ctx: &mut Context<'_, '_>, tx: &[u8]) -> Result<CheckTxResult, RuntimeError> {
        let mut tx_ctx = TxContext::new(ctx, true);

        match Self::decode_and_dispatch_tx(&mut tx_ctx, tx) {
            Ok(_) => Ok(CheckTxResult::default()),
            Err(err) => Ok(CheckTxResult {
                error: RuntimeError {
                    module: "test".to_string(),
                    code: 1,
                    message: err,
                },
                meta: None,
            }),
        }
    }

    fn begin_block(ctx: &mut Context) -> Result<(), RuntimeError> {
        BlockHandler::begin_block(ctx)
    }
}

impl TxnDispatcher for Dispatcher {
    fn query(
        &self,
        mut ctx: TxnContext,
        method: &str,
        args: Vec<u8>,
    ) -> Result<Vec<u8>, RuntimeError> {
        // Verify consensus state and runtime state root integrity before execution.
        // TODO: Make this async.
        let _ = block_on(self.consensus_verifier.verify_for_query(
            ctx.consensus_block.clone(),
            ctx.header.clone(),
            ctx.epoch,
        ))?;

        // Ensure the runtime is still ready to process requests.
        ctx.protocol.ensure_initialized()?;

        let mut ctx = Context {
            core: &mut ctx,
            host_info: &self.host_info,
            key_manager: &self.key_manager,
            consensus_verifier: &self.consensus_verifier,
            messages: vec![],
        };
        let mut ctx = TxContext::new(&mut ctx, false);

        let res = match method {
            "get_runtime_id" => Self::dispatch_call(
                &mut ctx,
                cbor::from_slice(&args).unwrap(),
                Methods::get_runtime_id,
            ),
            "get" => Self::dispatch_call(&mut ctx, cbor::from_slice(&args).unwrap(), Methods::get),
            _ => Err("method not found".to_string()),
        };

        match res {
            Ok(res) => Ok(cbor::to_vec(res)),
            Err(err) => Err(RuntimeError {
                module: "test".to_string(),
                code: 1,
                message: err,
            }),
        }
    }

    fn check_batch(
        &self,
        mut ctx: TxnContext,
        batch: &TxnBatch,
    ) -> Result<Vec<CheckTxResult>, RuntimeError> {
        let mut ctx = Context {
            core: &mut ctx,
            host_info: &self.host_info,
            key_manager: &self.key_manager,
            consensus_verifier: &self.consensus_verifier,
            messages: vec![],
        };

        let mut results = vec![];
        for tx in batch.iter() {
            results.push(Self::check_tx(&mut ctx, tx)?);
        }

        Ok(results)
    }

    fn execute_batch(
        &self,
        mut ctx: TxnContext,
        batch: &TxnBatch,
        in_msgs: &[IncomingMessage],
    ) -> Result<ExecuteBatchResult, RuntimeError> {
        let mut ctx = Context {
            core: &mut ctx,
            host_info: &self.host_info,
            key_manager: &self.key_manager,
            consensus_verifier: &self.consensus_verifier,
            messages: vec![],
        };

        Self::begin_block(&mut ctx)?;

        // Execute incoming messages. A real implementation should allocate resources for incoming
        // messages and only execute as many messages as fits.
        for in_msg in in_msgs {
            Self::execute_in_msg(&mut ctx, in_msg);
        }

        // Execute transactions.
        let mut results = vec![];
        for tx in batch.iter() {
            results.push(Self::execute_tx(&mut ctx, tx)?);
        }

        Ok(ExecuteBatchResult {
            results,
            messages: ctx.messages,
            in_msgs_count: in_msgs.len(),
            block_tags: vec![],
            tx_reject_hashes: vec![],
        })
    }

    fn schedule_and_execute_batch(
        &self,
        mut ctx: TxnContext,
        batch: &mut TxnBatch,
        in_msgs: &[IncomingMessage],
    ) -> Result<ExecuteBatchResult, RuntimeError> {
        let mut ctx = Context {
            core: &mut ctx,
            host_info: &self.host_info,
            key_manager: &self.key_manager,
            consensus_verifier: &self.consensus_verifier,
            messages: vec![],
        };

        Self::begin_block(&mut ctx)?;

        // Execute incoming messages. A real implementation should allocate resources for incoming
        // messages and only execute as many messages as fits.
        for in_msg in in_msgs {
            Self::execute_in_msg(&mut ctx, in_msg);
        }

        // Execute transactions.
        // TODO: Actually do some batch reordering.
        let mut new_batch = vec![];
        let mut results = vec![];
        let mut tx_reject_hashes = vec![];
        for tx in batch.drain(..) {
            if new_batch.len() >= MAX_BATCH_SIZE {
                break;
            }

            // Reject any transactions that don't pass check tx.
            if Self::check_tx(&mut ctx, &tx)?.error.code != 0 {
                tx_reject_hashes.push(Hash::digest_bytes(&tx));
                continue;
            }

            results.push(Self::execute_tx(&mut ctx, &tx)?);
            new_batch.push(tx);
        }

        // Replace input batch with newly generated batch.
        *batch = new_batch.into();

        Ok(ExecuteBatchResult {
            results,
            messages: ctx.messages,
            in_msgs_count: in_msgs.len(),
            block_tags: vec![],
            tx_reject_hashes,
        })
    }

    fn set_abort_batch_flag(&mut self, _abort_batch: Arc<AtomicBool>) {}
}

pub fn main_with_version(version: Version) {
    // Initializer.
    let init = |state: PreInitState<'_>| -> PostInitState {
        let hi = state.protocol.get_host_info();

        // Create the key manager client.
        let km_client = Arc::new(oasis_core_keymanager::client::RemoteClient::new_runtime(
            hi.runtime_id,
            state.protocol.clone(),
            state.consensus_verifier.clone(),
            state.identity.clone(),
            1024,
            trusted_signers(),
            vec![],
        ));

        let key_manager = km_client.clone();
        state
            .rpc_dispatcher
            .set_keymanager_status_update_handler(Some(Box::new(move |status| {
                key_manager
                    .set_status(status)
                    .expect("failed to update km client status");
            })));

        let key_manager = km_client.clone();
        state
            .rpc_dispatcher
            .set_keymanager_quote_policy_update_handler(Some(Box::new(move |policy| {
                key_manager.set_quote_policy(policy);
            })));

        let dispatcher = Dispatcher::new(hi, km_client, state.consensus_verifier.clone());

        PostInitState {
            txn_dispatcher: Some(Box::new(dispatcher)),
            ..Default::default()
        }
    };

    // Determine test trust root based on build settings.
    #[allow(clippy::option_env_unwrap)]
    let trust_root = option_env!("OASIS_TESTS_CONSENSUS_TRUST_HEIGHT").map(|height| {
        let hash = option_env!("OASIS_TESTS_CONSENSUS_TRUST_HASH").unwrap();
        let runtime_id = option_env!("OASIS_TESTS_CONSENSUS_TRUST_RUNTIME_ID").unwrap();
        let chain_context = option_env!("OASIS_TESTS_CONSENSUS_TRUST_CHAIN_CONTEXT").unwrap();

        TrustRoot {
            height: height.parse::<u64>().unwrap(),
            hash: hash.to_string(),
            runtime_id: runtime_id.into(),
            chain_context: chain_context.to_string(),
        }
    });

    // Start the runtime.
    oasis_core_runtime::start_runtime(
        Box::new(init),
        Config {
            version,
            trust_root,
            features: Features {
                // Enable the schedule control feature.
                schedule_control: Some(FeatureScheduleControl {
                    initial_batch_size: MAX_BATCH_SIZE.try_into().unwrap(),
                }),
                ..Default::default()
            },
            ..Default::default()
        },
    );
}

#[allow(dead_code)]
pub fn main() {
    main_with_version(Version {
        major: 0,
        minor: 0,
        patch: 0,
    })
}
