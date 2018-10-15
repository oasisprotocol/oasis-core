//! Runtime call batch dispatcher.
use std::any::Any;
use std::collections::HashMap;
#[cfg(target_env = "sgx")]
use std::sync::SgxMutex as Mutex;
#[cfg(target_env = "sgx")]
use std::sync::SgxMutexGuard as MutexGuard;
#[cfg(not(target_env = "sgx"))]
use std::sync::{Mutex, MutexGuard};

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_cbor;

use ekiden_common::error::Result;
use ekiden_roothash_base::header::Header;
use ekiden_runtime_common::batch::{CallBatch, OutputBatch};
use ekiden_runtime_common::call::{Generic, RuntimeCall, RuntimeOutput};

/// Custom batch handler.
///
/// A custom batch handler can be configured on the `Dispatcher` and will have
/// its `start_batch` and `end_batch` methods called at the appropriate times.
pub trait BatchHandler: Sync + Send {
    /// Called before the first call in a batch is dispatched.
    ///
    /// The context may be mutated and will be available as read-only to all
    /// runtime calls.
    fn start_batch(&self, ctx: &mut RuntimeCallContext);

    /// Called after all calls has been dispatched.
    fn end_batch(&self, ctx: RuntimeCallContext);
}

/// Descriptor of a runtime API method.
#[derive(Clone, Debug)]
pub struct RuntimeMethodDescriptor {
    /// Method name.
    pub name: String,
}

/// Handler for a runtime method.
pub trait RuntimeMethodHandler<Call, Output> {
    /// Invoke the method implementation and return a response.
    fn handle(&self, call: &RuntimeCall<Call>, ctx: &mut RuntimeCallContext) -> Result<Output>;
}

impl<Call, Output, F> RuntimeMethodHandler<Call, Output> for F
where
    Call: Send + 'static,
    Output: Send + 'static,
    F: Fn(&Call, &mut RuntimeCallContext) -> Result<Output> + Send + Sync + 'static,
{
    fn handle(&self, call: &RuntimeCall<Call>, ctx: &mut RuntimeCallContext) -> Result<Output> {
        (*self)(&call.arguments, ctx)
    }
}

/// Context for a runtime call.
pub struct RuntimeCallContext {
    /// The block header accompanying this runtime call.
    pub header: Header,
    /// Runtime-specific context.
    pub runtime: Box<Any>,
}

struct NoRuntimeContext;

impl RuntimeCallContext {
    /// Construct new runtime call context.
    pub fn new(header: Header) -> Self {
        Self {
            header,
            runtime: Box::new(NoRuntimeContext),
        }
    }
}

/// Dispatcher for a runtime method.
pub trait RuntimeMethodHandlerDispatch {
    /// Get method descriptor.
    fn get_descriptor(&self) -> &RuntimeMethodDescriptor;

    /// Dispatches the given raw call.
    fn dispatch(&self, call: RuntimeCall<Generic>, ctx: &mut RuntimeCallContext) -> Vec<u8>;
}

struct RuntimeMethodHandlerDispatchImpl<Call, Output> {
    /// Method descriptor.
    descriptor: RuntimeMethodDescriptor,
    /// Method handler.
    handler: Box<RuntimeMethodHandler<Call, Output> + Sync + Send>,
}

impl<Call, Output> RuntimeMethodHandlerDispatch for RuntimeMethodHandlerDispatchImpl<Call, Output>
where
    Call: DeserializeOwned + Send + 'static,
    Output: Serialize + Send + 'static,
{
    fn get_descriptor(&self) -> &RuntimeMethodDescriptor {
        &self.descriptor
    }

    fn dispatch(&self, call: RuntimeCall<Generic>, ctx: &mut RuntimeCallContext) -> Vec<u8> {
        // Deserialize call and invoke handler.
        let output = match RuntimeCall::from_generic(call) {
            Ok(call) => match self.handler.handle(&call, ctx) {
                Ok(output) => RuntimeOutput::Success(output),
                Err(error) => RuntimeOutput::Error(error.message),
            },
            _ => RuntimeOutput::Error("unable to parse call arguments".to_owned()),
        };

        // Serialize and return output.
        serde_cbor::to_vec(&output).unwrap()
    }
}

/// Runtime method dispatcher implementation.
pub struct RuntimeMethod {
    /// Method dispatcher.
    dispatcher: Box<RuntimeMethodHandlerDispatch + Sync + Send>,
}

impl RuntimeMethod {
    /// Create a new enclave method descriptor.
    pub fn new<Call, Output, Handler>(method: RuntimeMethodDescriptor, handler: Handler) -> Self
    where
        Call: DeserializeOwned + Send + 'static,
        Output: Serialize + Send + 'static,
        Handler: RuntimeMethodHandler<Call, Output> + Sync + Send + 'static,
    {
        RuntimeMethod {
            dispatcher: Box::new(RuntimeMethodHandlerDispatchImpl {
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
    pub fn dispatch(&self, call: RuntimeCall<Generic>, ctx: &mut RuntimeCallContext) -> Vec<u8> {
        self.dispatcher.dispatch(call, ctx)
    }
}

lazy_static! {
    // Global runtime call dispatcher object.
    static ref DISPATCHER: Mutex<Dispatcher> = Mutex::new(Dispatcher::new());
}

/// Runtime method dispatcher.
///
/// The dispatcher holds all registered runtime methods and provides an entry point
/// for their invocation.
pub struct Dispatcher {
    /// Registered runtime methods.
    methods: HashMap<String, RuntimeMethod>,
    /// Registered batch handler.
    batch_handler: Option<Box<BatchHandler>>,
}

impl Dispatcher {
    /// Create a new runtime method dispatcher instance.
    pub fn new() -> Self {
        Dispatcher {
            methods: HashMap::new(),
            batch_handler: None,
        }
    }

    /// Global dispatcher instance.
    ///
    /// Calling this method will take a lock on the global instance which
    /// will be released once the value goes out of scope.
    pub fn get<'a>() -> MutexGuard<'a, Self> {
        DISPATCHER.lock().unwrap()
    }

    /// Register a new method in the dispatcher.
    pub fn add_method(&mut self, method: RuntimeMethod) {
        self.methods.insert(method.get_name().clone(), method);
    }

    /// Configure batch handler.
    pub fn set_batch_handler<H>(&mut self, handler: H)
    where
        H: BatchHandler + 'static,
    {
        self.batch_handler = Some(Box::new(handler));
    }

    /// Dispatches a batch of runtime requests.
    pub fn dispatch_batch(&self, batch: CallBatch, mut ctx: RuntimeCallContext) -> OutputBatch {
        // Invoke start batch handler.
        if let Some(ref handler) = self.batch_handler {
            handler.start_batch(&mut ctx);
        }

        // Process batch.
        let outputs = OutputBatch(
            batch
                .iter()
                .map(|call| self.dispatch(call, &mut ctx))
                .collect(),
        );

        // Invoke end batch handler.
        if let Some(ref handler) = self.batch_handler {
            handler.end_batch(ctx);
        }

        outputs
    }

    /// Dispatches a raw runtime invocation request.
    pub fn dispatch(&self, call: &Vec<u8>, ctx: &mut RuntimeCallContext) -> Vec<u8> {
        match serde_cbor::from_slice::<RuntimeCall<Generic>>(call) {
            Ok(call) => match self.methods.get(&call.method) {
                Some(method_dispatch) => method_dispatch.dispatch(call, ctx),
                None => serde_cbor::to_vec(&RuntimeOutput::Error::<Generic>(
                    "method not found".to_owned(),
                )).unwrap(),
            },
            Err(_) => serde_cbor::to_vec(&RuntimeOutput::Error::<Generic>(
                "unable to parse call".to_owned(),
            )).unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_cbor;

    use ekiden_common::bytes::B256;
    use ekiden_roothash_base::header::Header;

    use super::*;

    const TEST_TIMESTAMP: u64 = 0xcafedeadbeefc0de;

    #[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
    struct Complex {
        text: String,
        number: u32,
    }

    /// Register a dummy method.
    fn register_dummy_method() {
        let mut dispatcher = Dispatcher::get();

        // Register dummy runtime method.
        dispatcher.add_method(RuntimeMethod::new(
            RuntimeMethodDescriptor {
                name: "dummy".to_owned(),
            },
            |call: &Complex, ctx: &mut RuntimeCallContext| -> Result<Complex> {
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
        register_dummy_method();

        // Prepare a dummy call.
        let call = RuntimeCall {
            id: B256::random(),
            method: "dummy".to_owned(),
            arguments: Complex {
                text: "hello".to_owned(),
                number: 21,
            },
        };
        let call_encoded = serde_cbor::to_vec(&call).unwrap();

        let mut ctx = RuntimeCallContext::new(Header {
            timestamp: TEST_TIMESTAMP,
            ..Default::default()
        });

        // Call runtime.
        let dispatcher = Dispatcher::get();
        let result = dispatcher.dispatch(&call_encoded, &mut ctx);

        // Decode result.
        let result_decoded: RuntimeOutput<Complex> = serde_cbor::from_slice(&result).unwrap();

        assert_eq!(
            result_decoded,
            RuntimeOutput::Success(Complex {
                text: "hello".to_owned(),
                number: 42
            })
        );
    }
}
