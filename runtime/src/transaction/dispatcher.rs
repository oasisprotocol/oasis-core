//! Runtime transaction batch dispatcher.
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use anyhow::{anyhow, Context as AnyContext, Result};
use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;

use super::{
    context::Context,
    tags::Tags,
    types::{TxnBatch, TxnCall, TxnCheckResult, TxnOutput},
};
use crate::common::{cbor, crypto::hash::Hash, roothash};

/// Dispatch error.
#[derive(Error, Debug)]
enum DispatchError {
    #[error("method not found: {method:?}")]
    MethodNotFound { method: String },
}

/// Error indicating that performing a transaction check was successful.
#[derive(Error, Debug, Default)]
#[error("transaction check successful")]
pub struct CheckOnlySuccess(pub TxnCheckResult);

/// Custom batch handler.
///
/// A custom batch handler can be configured on the `Dispatcher` and will have
/// its `start_batch` and `end_batch` methods called at the appropriate times.
pub trait BatchHandler {
    /// Called before the first call in a batch is dispatched.
    ///
    /// The context may be mutated and will be available as read-only to all
    /// runtime calls.
    fn start_batch(&self, ctx: &mut Context);

    /// Called after all calls have been dispatched.
    fn end_batch(&self, ctx: &mut Context);
}

/// Custom context initializer.
pub trait ContextInitializer {
    /// Called to initialize the context.
    fn init(&self, ctx: &mut Context);
}

impl<F> ContextInitializer for F
where
    F: Fn(&mut Context),
{
    fn init(&self, ctx: &mut Context) {
        (*self)(ctx)
    }
}

/// Custom finalizer.
pub trait Finalizer {
    /// Called to finalize transaction.
    ///
    /// This method is called after storage has been finalized so the
    /// storage context is not available and using it will panic.
    fn finalize(&self, new_storage_root: Hash);
}

impl<F> Finalizer for F
where
    F: Fn(Hash),
{
    fn finalize(&self, new_storage_root: Hash) {
        (*self)(new_storage_root)
    }
}

/// Descriptor of a runtime API method.
#[derive(Clone, Debug)]
pub struct MethodDescriptor {
    /// Method name.
    pub name: String,
}

/// Handler for a runtime method.
pub trait MethodHandler<Call, Output> {
    /// Invoke the method implementation and return a response.
    fn handle(&self, call: &Call, ctx: &mut Context) -> Result<Output>;
}

impl<Call, Output, F> MethodHandler<Call, Output> for F
where
    Call: 'static,
    Output: 'static,
    F: Fn(&Call, &mut Context) -> Result<Output> + 'static,
{
    fn handle(&self, call: &Call, ctx: &mut Context) -> Result<Output> {
        (*self)(&call, ctx)
    }
}

/// Dispatcher for a runtime method.
pub trait MethodHandlerDispatch {
    /// Get method descriptor.
    fn get_descriptor(&self) -> &MethodDescriptor;

    /// Dispatches the given raw call.
    fn dispatch(&self, call: TxnCall, ctx: &mut Context) -> Result<cbor::Value>;
}

struct MethodHandlerDispatchImpl<Call, Output> {
    /// Method descriptor.
    descriptor: MethodDescriptor,
    /// Method handler.
    handler: Box<dyn MethodHandler<Call, Output>>,
}

impl<Call, Output> MethodHandlerDispatch for MethodHandlerDispatchImpl<Call, Output>
where
    Call: DeserializeOwned + 'static,
    Output: Serialize + 'static,
{
    fn get_descriptor(&self) -> &MethodDescriptor {
        &self.descriptor
    }

    fn dispatch(&self, call: TxnCall, ctx: &mut Context) -> Result<cbor::Value> {
        let call = cbor::from_value(call.args).context("unable to parse call arguments")?;
        let response = self.handler.handle(&call, ctx)?;

        Ok(cbor::to_value(response))
    }
}

/// Runtime method dispatcher implementation.
pub struct Method {
    /// Method dispatcher.
    dispatcher: Box<dyn MethodHandlerDispatch>,
}

impl Method {
    /// Create a new enclave method descriptor.
    pub fn new<Call, Output, Handler>(method: MethodDescriptor, handler: Handler) -> Self
    where
        Call: DeserializeOwned + 'static,
        Output: Serialize + 'static,
        Handler: MethodHandler<Call, Output> + 'static,
    {
        Method {
            dispatcher: Box::new(MethodHandlerDispatchImpl {
                descriptor: method,
                handler: Box::new(handler),
            }),
        }
    }

    /// Return method name.
    pub fn get_name(&self) -> &String {
        &self.dispatcher.get_descriptor().name
    }

    /// Dispatch method call.
    pub fn dispatch(&self, call: TxnCall, ctx: &mut Context) -> Result<cbor::Value> {
        self.dispatcher.dispatch(call, ctx)
    }
}

/// Runtime transaction dispatcher trait.
///
/// It defines the interface used by the runtime call dispatcher
/// to process transactions.
pub trait Dispatcher {
    /// Dispatches a batch of runtime requests.
    fn dispatch_batch(
        &self,
        batch: &TxnBatch,
        ctx: Context,
    ) -> Result<(TxnBatch, Vec<Tags>, Vec<roothash::Message>)>;
    /// Invoke the finalizer (if any).
    fn finalize(&self, new_storage_root: Hash);
    /// Configure abort batch flag.
    fn set_abort_batch_flag(&mut self, abort_batch: Arc<AtomicBool>);
}

/// No-op dispatcher.
///
/// This is mainly used by the runtime dispatcher as a fallback in case
/// the runtime's initializer doesn't produce its own dispatcher object.
pub struct NoopDispatcher {}

impl NoopDispatcher {
    pub fn new() -> NoopDispatcher {
        NoopDispatcher {}
    }
}

impl Dispatcher for NoopDispatcher {
    fn dispatch_batch(
        &self,
        _batch: &TxnBatch,
        ctx: Context,
    ) -> Result<(TxnBatch, Vec<Tags>, Vec<roothash::Message>)> {
        let outputs = TxnBatch::new(Vec::new());
        let (tags, roothash_messages) = ctx.close();
        Ok((outputs, tags, roothash_messages))
    }

    fn finalize(&self, _new_storage_root: Hash) {
        // Nothing to do here.
    }

    fn set_abort_batch_flag(&mut self, _abort_batch: Arc<AtomicBool>) {
        // Nothing to abort.
    }
}

/// Runtime method dispatcher.
///
/// The dispatcher is a concrete implementation of the Dispatcher trait.
/// It holds all registered runtime methods and provides an entry point
/// for their invocation.
pub struct MethodDispatcher {
    /// Registered runtime methods.
    methods: HashMap<String, Method>,
    /// Registered batch handler.
    batch_handler: Option<Box<dyn BatchHandler>>,
    /// Registered context initializer.
    ctx_initializer: Option<Box<dyn ContextInitializer>>,
    /// Registered finalizer.
    finalizer: Option<Box<dyn Finalizer>>,
    /// Abort batch flag.
    abort_batch: Option<Arc<AtomicBool>>,
}

impl MethodDispatcher {
    /// Create a new runtime method dispatcher instance.
    pub fn new() -> MethodDispatcher {
        MethodDispatcher {
            methods: HashMap::new(),
            batch_handler: None,
            ctx_initializer: None,
            finalizer: None,
            abort_batch: None,
        }
    }

    /// Register a new method in the dispatcher.
    pub fn add_method(&mut self, method: Method) {
        self.methods.insert(method.get_name().clone(), method);
    }

    /// Configure batch handler.
    pub fn set_batch_handler<H>(&mut self, handler: H)
    where
        H: BatchHandler + 'static,
    {
        self.batch_handler = Some(Box::new(handler));
    }

    /// Configure context initializer.
    pub fn set_context_initializer<I>(&mut self, initializer: I)
    where
        I: ContextInitializer + 'static,
    {
        self.ctx_initializer = Some(Box::new(initializer));
    }

    /// Configure finalizer.
    pub fn set_finalizer<F>(&mut self, finalizer: F)
    where
        F: Finalizer + 'static,
    {
        self.finalizer = Some(Box::new(finalizer));
    }

    /// Dispatches a raw runtime invocation request.
    fn dispatch(&self, call: &Vec<u8>, ctx: &mut Context) -> Vec<u8> {
        let rsp = match self.dispatch_fallible(call, ctx) {
            Ok(response) => TxnOutput::Success(response),
            Err(error) => match error.downcast::<CheckOnlySuccess>() {
                Ok(check_result) => TxnOutput::Success(cbor::to_value(check_result.0)),
                Err(error) => TxnOutput::Error(format!("{}", error)),
            },
        };

        cbor::to_vec(&rsp)
    }

    fn dispatch_fallible(&self, call: &Vec<u8>, ctx: &mut Context) -> Result<cbor::Value> {
        let call: TxnCall = cbor::from_slice(call).context("unable to parse call")?;

        match self.methods.get(&call.method) {
            Some(dispatcher) => dispatcher.dispatch(call, ctx),
            None => Err(DispatchError::MethodNotFound {
                method: call.method,
            }
            .into()),
        }
    }
}

impl Dispatcher for MethodDispatcher {
    fn dispatch_batch(
        &self,
        batch: &TxnBatch,
        mut ctx: Context,
    ) -> Result<(TxnBatch, Vec<Tags>, Vec<roothash::Message>)> {
        if let Some(ref ctx_init) = self.ctx_initializer {
            ctx_init.init(&mut ctx);
        }

        // Invoke start batch handler.
        if let Some(ref handler) = self.batch_handler {
            handler.start_batch(&mut ctx);
        }

        // Process batch.
        let mut vec = Vec::new();
        for call in batch.iter() {
            if self
                .abort_batch
                .as_ref()
                .map(|b| b.load(Ordering::SeqCst))
                .unwrap_or(false)
            {
                return Err(anyhow!("batch aborted"));
            }
            ctx.start_transaction();
            vec.push(self.dispatch(call, &mut ctx));
        }
        let outputs = TxnBatch::new(vec);

        // Invoke end batch handler.
        if let Some(ref handler) = self.batch_handler {
            handler.end_batch(&mut ctx);
        }

        let (tags, roothash_messages) = ctx.close();
        Ok((outputs, tags, roothash_messages))
    }

    fn finalize(&self, new_storage_root: Hash) {
        if let Some(ref finalizer) = self.finalizer {
            finalizer.finalize(new_storage_root);
        }
    }

    /// Configure abort batch flag.
    fn set_abort_batch_flag(&mut self, abort_batch: Arc<AtomicBool>) {
        self.abort_batch = Some(abort_batch);
    }
}

#[cfg(test)]
mod tests {
    use io_context::Context as IoContext;
    use serde::{Deserialize, Serialize};

    use crate::common::{cbor, roothash::Header};

    use super::*;

    const TEST_TIMESTAMP: u64 = 0xcafedeadbeefc0de;

    #[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
    struct Complex {
        text: String,
        number: u32,
    }

    /// Register a dummy method.
    fn register_dummy_method(dispatcher: &mut MethodDispatcher) {
        // Register dummy runtime method.
        dispatcher.add_method(Method::new(
            MethodDescriptor {
                name: "dummy".to_owned(),
            },
            |call: &Complex, ctx: &mut Context| -> Result<Complex> {
                assert_eq!(ctx.header.timestamp, TEST_TIMESTAMP);

                Ok(Complex {
                    text: call.text.clone(),
                    number: call.number * 2,
                })
            },
        ));
    }

    #[test]
    fn test_dispatcher() {
        let mut dispatcher = MethodDispatcher::new();
        register_dummy_method(&mut dispatcher);

        // Prepare a dummy call.
        let call = TxnCall {
            method: "dummy".to_owned(),
            args: cbor::to_value(Complex {
                text: "hello".to_owned(),
                number: 21,
            }),
        };
        let call_encoded = cbor::to_vec(&call);

        let header = Header {
            timestamp: TEST_TIMESTAMP,
            ..Default::default()
        };
        let mut ctx = Context::new(IoContext::background().freeze(), &header, &[], false);

        // Call runtime.
        let result = dispatcher.dispatch(&call_encoded, &mut ctx);

        // Decode result.
        let result_decoded: TxnOutput = cbor::from_slice(&result).unwrap();
        match result_decoded {
            TxnOutput::Success(value) => {
                let value: Complex = cbor::from_value(value).unwrap();

                assert_eq!(
                    value,
                    Complex {
                        text: "hello".to_owned(),
                        number: 42
                    }
                );
            }
            _ => panic!("txn call should return success"),
        }
    }
}
