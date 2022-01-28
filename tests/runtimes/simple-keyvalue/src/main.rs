//! A simple test runtime.

pub mod crypto;
pub mod methods;
pub mod types;

use std::sync::{atomic::AtomicBool, Arc};

use oasis_core_keymanager_client::KeyManagerClient;
use oasis_core_runtime::{
    common::version::Version,
    config::Config,
    consensus::{
        roothash::{IncomingMessage, Message},
        verifier::TrustRoot,
    },
    protocol::HostInfo,
    rak::RAK,
    transaction::{
        dispatcher::{ExecuteBatchResult, ExecuteTxResult},
        tags::{Tag, Tags},
        types::TxnBatch,
        Context as TxnContext,
    },
    types::{CheckTxResult, Error as RuntimeError},
    version_from_cargo, Protocol, RpcDemux, RpcDispatcher, TxnDispatcher,
};
use simple_keymanager::trusted_policy_signers;

use methods::{BlockHandler, Methods};
use types::*;

/// A simple context wrapper for processing test transaction batches.
///
/// For a proper dispatcher see the [Oasis SDK](https://github.com/oasisprotocol/oasis-sdk).
pub struct Context<'a, 'core> {
    pub core: &'a mut TxnContext<'core>,
    pub host_info: &'a HostInfo,
    pub key_manager: &'a dyn KeyManagerClient,
    pub messages: Vec<Message>,
}

/// A simple context wrapper for processing test transactions.
///
/// For a proper dispatcher see the [Oasis SDK](https://github.com/oasisprotocol/oasis-sdk).
pub struct TxContext<'a, 'b, 'core> {
    pub parent: &'a mut Context<'b, 'core>,
    pub tags: Tags,
}

impl<'a, 'b, 'core> TxContext<'a, 'b, 'core> {
    fn new(parent: &'a mut Context<'b, 'core>) -> Self {
        Self {
            parent,
            tags: vec![],
        }
    }

    fn is_check_only(&self) -> bool {
        self.parent.core.check_only
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
}

impl Dispatcher {
    fn new(host_info: HostInfo, key_manager: Arc<dyn KeyManagerClient>) -> Self {
        Self {
            host_info,
            key_manager,
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
            "enc_insert" => Self::dispatch_call(ctx, tx.args, Methods::enc_insert),
            "enc_get" => Self::dispatch_call(ctx, tx.args, Methods::enc_get),
            "enc_remove" => Self::dispatch_call(ctx, tx.args, Methods::enc_remove),
            _ => return Err("method not found".to_string()),
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

        let mut tx_ctx = TxContext::new(ctx);

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
        let mut tx_ctx = TxContext::new(ctx);

        match Self::decode_and_dispatch_tx(&mut tx_ctx, tx) {
            Ok(_) => Ok(CheckTxResult::default()),
            Err(err) => Ok(CheckTxResult {
                error: RuntimeError {
                    module: "test".to_string(),
                    code: 1,
                    message: err.to_string(),
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
    fn check_batch(
        &self,
        mut ctx: TxnContext,
        batch: &TxnBatch,
    ) -> Result<Vec<CheckTxResult>, RuntimeError> {
        let mut ctx = Context {
            core: &mut ctx,
            host_info: &self.host_info,
            key_manager: &self.key_manager,
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
            batch_weight_limits: None,
        })
    }

    fn set_abort_batch_flag(&mut self, _abort_batch: Arc<AtomicBool>) {}
}

pub fn main() {
    // Initializer.
    let init = |protocol: &Arc<Protocol>,
                rak: &Arc<RAK>,
                _rpc_demux: &mut RpcDemux,
                rpc: &mut RpcDispatcher|
     -> Option<Box<dyn TxnDispatcher>> {
        let hi = protocol.get_host_info();

        // Create the key manager client.
        let km_client = Arc::new(oasis_core_keymanager_client::RemoteClient::new_runtime(
            hi.runtime_id,
            protocol.clone(),
            rak.clone(),
            1024,
            trusted_policy_signers(),
        ));
        let key_manager = km_client.clone();

        #[cfg(not(target_env = "sgx"))]
        let _ = rpc;
        #[cfg(target_env = "sgx")]
        rpc.set_keymanager_policy_update_handler(Some(Box::new(move |raw_signed_policy| {
            km_client
                .set_policy(raw_signed_policy)
                .expect("failed to update km client policy");
        })));

        let dispatcher = Dispatcher::new(hi, key_manager);
        Some(Box::new(dispatcher))
    };

    // Determine test trust root based on build settings.
    let trust_root = option_env!("OASIS_TESTS_CONSENSUS_TRUST_HEIGHT").map(|height| {
        let hash = option_env!("OASIS_TESTS_CONSENSUS_TRUST_HASH").unwrap();
        let runtime_id = option_env!("OASIS_TESTS_CONSENSUS_TRUST_RUNTIME_ID").unwrap();

        TrustRoot {
            height: u64::from_str_radix(height, 10).unwrap(),
            hash: hash.to_string(),
            runtime_id: runtime_id.into(),
        }
    });

    // Start the runtime.
    oasis_core_runtime::start_runtime(
        Box::new(init),
        Config {
            version: version_from_cargo!(),
            trust_root,
            ..Default::default()
        },
    );
}
