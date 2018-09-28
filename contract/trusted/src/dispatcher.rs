//! Contract call batch dispatcher.
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
use ekiden_contract_common::batch::{CallBatch, OutputBatch};
use ekiden_contract_common::call::{ContractCall, ContractOutput, Generic};
use ekiden_roothash_base::header::Header;

/// Custom batch handler.
///
/// A custom batch handler can be configured on the `Dispatcher` and will have
/// its `start_batch` and `end_batch` methods called at the appropriate times.
pub trait BatchHandler: Sync + Send {
    /// Called before the first call in a batch is dispatched.
    ///
    /// The context may be mutated and will be available as read-only to all
    /// runtime calls.
    fn start_batch(&self, ctx: &mut ContractCallContext);

    /// Called after all calls has been dispatched.
    fn end_batch(&self, ctx: &mut ContractCallContext);
}

/// Descriptor of a contract API method.
#[derive(Clone, Debug)]
pub struct ContractMethodDescriptor {
    /// Method name.
    pub name: String,
}

/// Handler for a contract method.
pub trait ContractMethodHandler<Call, Output> {
    /// Invoke the method implementation and return a response.
    fn handle(&self, call: &ContractCall<Call>, ctx: &ContractCallContext) -> Result<Output>;
}

impl<Call, Output, F> ContractMethodHandler<Call, Output> for F
where
    Call: Send + 'static,
    Output: Send + 'static,
    F: Fn(&Call, &ContractCallContext) -> Result<Output> + Send + Sync + 'static,
{
    fn handle(&self, call: &ContractCall<Call>, ctx: &ContractCallContext) -> Result<Output> {
        (*self)(&call.arguments, ctx)
    }
}

/// Context for a contract call.
pub struct ContractCallContext {
    /// The block header accompanying this contract call.
    pub header: Header,
    /// Runtime-specific context.
    pub runtime: Box<Any>,
}

struct NoRuntimeContext;

impl ContractCallContext {
    /// Construct new contract call context.
    pub fn new(header: Header) -> Self {
        Self {
            header,
            runtime: Box::new(NoRuntimeContext),
        }
    }
}

/// Dispatcher for a contract method.
pub trait ContractMethodHandlerDispatch {
    /// Get method descriptor.
    fn get_descriptor(&self) -> &ContractMethodDescriptor;

    /// Dispatches the given raw call.
    fn dispatch(&self, call: ContractCall<Generic>, ctx: &ContractCallContext) -> Vec<u8>;
}

struct ContractMethodHandlerDispatchImpl<Call, Output> {
    /// Method descriptor.
    descriptor: ContractMethodDescriptor,
    /// Method handler.
    handler: Box<ContractMethodHandler<Call, Output> + Sync + Send>,
}

impl<Call, Output> ContractMethodHandlerDispatch for ContractMethodHandlerDispatchImpl<Call, Output>
where
    Call: DeserializeOwned + Send + 'static,
    Output: Serialize + Send + 'static,
{
    fn get_descriptor(&self) -> &ContractMethodDescriptor {
        &self.descriptor
    }

    fn dispatch(&self, call: ContractCall<Generic>, ctx: &ContractCallContext) -> Vec<u8> {
        // Deserialize call and invoke handler.
        let output = match ContractCall::from_generic(call) {
            Ok(call) => match self.handler.handle(&call, ctx) {
                Ok(output) => ContractOutput::Success(output),
                Err(error) => ContractOutput::Error(error.message),
            },
            _ => ContractOutput::Error("unable to parse call arguments".to_owned()),
        };

        // Serialize and return output.
        serde_cbor::to_vec(&output).unwrap()
    }
}

/// Contract method dispatcher implementation.
pub struct ContractMethod {
    /// Method dispatcher.
    dispatcher: Box<ContractMethodHandlerDispatch + Sync + Send>,
}

impl ContractMethod {
    /// Create a new enclave method descriptor.
    pub fn new<Call, Output, Handler>(method: ContractMethodDescriptor, handler: Handler) -> Self
    where
        Call: DeserializeOwned + Send + 'static,
        Output: Serialize + Send + 'static,
        Handler: ContractMethodHandler<Call, Output> + Sync + Send + 'static,
    {
        ContractMethod {
            dispatcher: Box::new(ContractMethodHandlerDispatchImpl {
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
    pub fn dispatch(&self, call: ContractCall<Generic>, ctx: &ContractCallContext) -> Vec<u8> {
        self.dispatcher.dispatch(call, ctx)
    }
}

lazy_static! {
    // Global contract call dispatcher object.
    static ref DISPATCHER: Mutex<Dispatcher> = Mutex::new(Dispatcher::new());
}

/// Contract method dispatcher.
///
/// The dispatcher holds all registered contract methods and provides an entry point
/// for their invocation.
pub struct Dispatcher {
    /// Registered contract methods.
    methods: HashMap<String, ContractMethod>,
    /// Registered batch handler.
    batch_handler: Option<Box<BatchHandler>>,
}

impl Dispatcher {
    /// Create a new contract method dispatcher instance.
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
    pub fn add_method(&mut self, method: ContractMethod) {
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
    pub fn dispatch_batch(&self, batch: CallBatch, mut ctx: ContractCallContext) -> OutputBatch {
        // Invoke start batch handler.
        if let Some(ref handler) = self.batch_handler {
            handler.start_batch(&mut ctx);
        }

        // Process batch.
        let outputs = OutputBatch(batch.iter().map(|call| self.dispatch(call, &ctx)).collect());

        // Invoke end batch handler.
        if let Some(ref handler) = self.batch_handler {
            handler.end_batch(&mut ctx);
        }

        outputs
    }

    /// Dispatches a raw contract invocation request.
    pub fn dispatch(&self, call: &Vec<u8>, ctx: &ContractCallContext) -> Vec<u8> {
        match serde_cbor::from_slice::<ContractCall<Generic>>(call) {
            Ok(call) => match self.methods.get(&call.method) {
                Some(method_dispatch) => method_dispatch.dispatch(call, ctx),
                None => serde_cbor::to_vec(&ContractOutput::Error::<Generic>(
                    "method not found".to_owned(),
                )).unwrap(),
            },
            Err(_) => serde_cbor::to_vec(&ContractOutput::Error::<Generic>(
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

        // Register dummy contract method.
        dispatcher.add_method(ContractMethod::new(
            ContractMethodDescriptor {
                name: "dummy".to_owned(),
            },
            |call: &Complex, ctx: &ContractCallContext| -> Result<Complex> {
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
        let call = ContractCall {
            id: B256::random(),
            method: "dummy".to_owned(),
            arguments: Complex {
                text: "hello".to_owned(),
                number: 21,
            },
        };
        let call_encoded = serde_cbor::to_vec(&call).unwrap();

        let ctx = ContractCallContext::new(Header {
            timestamp: TEST_TIMESTAMP,
            ..Default::default()
        });

        // Call contract.
        let dispatcher = Dispatcher::get();
        let result = dispatcher.dispatch(&call_encoded, &ctx);

        // Decode result.
        let result_decoded: ContractOutput<Complex> = serde_cbor::from_slice(&result).unwrap();

        assert_eq!(
            result_decoded,
            ContractOutput::Success(Complex {
                text: "hello".to_owned(),
                number: 42
            })
        );
    }
}
