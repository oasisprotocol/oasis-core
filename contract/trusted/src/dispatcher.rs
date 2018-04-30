//! Contract call batch dispatcher.
use std::collections::HashMap;
#[cfg(not(target_env = "sgx"))]
use std::sync::{Mutex, MutexGuard};
#[cfg(target_env = "sgx")]
use std::sync::SgxMutex as Mutex;
#[cfg(target_env = "sgx")]
use std::sync::SgxMutexGuard as MutexGuard;

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_cbor;

use ekiden_common::error::Result;
use ekiden_contract_common::call::{ContractOutput, Generic, SignedContractCall};

/// Descriptor of a contract API method.
#[derive(Clone, Debug)]
pub struct ContractMethodDescriptor {
    /// Method name.
    pub name: String,
}

/// Handler for a contract method.
pub trait ContractMethodHandler<Call, Output> {
    /// Invoke the method implementation and return a response.
    fn handle(&self, call: &SignedContractCall<Call>) -> Result<Output>;
}

impl<Call, Output, F> ContractMethodHandler<Call, Output> for F
where
    Call: Send + 'static,
    Output: Send + 'static,
    F: Fn(&SignedContractCall<Call>) -> Result<Output> + Send + Sync + 'static,
{
    fn handle(&self, call: &SignedContractCall<Call>) -> Result<Output> {
        (*self)(call)
    }
}

/// Dispatcher for a contract method.
pub trait ContractMethodHandlerDispatch {
    /// Get method descriptor.
    fn get_descriptor(&self) -> &ContractMethodDescriptor;

    /// Dispatches the given raw call.
    fn dispatch(&self, call: &Vec<u8>) -> Vec<u8>;
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

    fn dispatch(&self, call: &Vec<u8>) -> Vec<u8> {
        // Deserialize call and invoke handler.
        let output = match serde_cbor::from_slice(call) {
            Ok(call) => match self.handler.handle(&call) {
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
    pub fn dispatch(&self, call: &Vec<u8>) -> Vec<u8> {
        self.dispatcher.dispatch(call)
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
}

impl Dispatcher {
    /// Create a new contract method dispatcher instance.
    pub fn new() -> Self {
        Dispatcher {
            methods: HashMap::new(),
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

    /// Dispatches a raw contract invocation request.
    pub fn dispatch(&self, call: &Vec<u8>) -> Vec<u8> {
        // Decode request method.
        let method = match serde_cbor::from_slice::<SignedContractCall<Generic>>(call) {
            Ok(signed) => {
                // Verify signature and then get the method.
                match signed.open() {
                    Ok(call) => call.method,
                    Err(_) => {
                        return serde_cbor::to_vec(&ContractOutput::Error::<Generic>(
                            "failed to verify contract call signature".to_owned(),
                        )).unwrap()
                    }
                }
            }
            Err(_) => {
                return serde_cbor::to_vec(&ContractOutput::Error::<Generic>(
                    "unable to parse call method".to_owned(),
                )).unwrap()
            }
        };

        match self.methods.get(&method) {
            Some(method_dispatch) => method_dispatch.dispatch(call),
            None => serde_cbor::to_vec(&ContractOutput::Error::<Generic>(
                "method not found".to_owned(),
            )).unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Deref;

    use serde_cbor;

    use ekiden_common::bytes::B256;
    use ekiden_common::ring::signature::Ed25519KeyPair;
    use ekiden_common::signature::InMemorySigner;
    use ekiden_common::untrusted;

    use super::*;

    /// Register a dummy method.
    fn register_dummy_method() {
        let mut dispatcher = Dispatcher::get();

        // Register dummy contract method.
        dispatcher.add_method(ContractMethod::new(
            ContractMethodDescriptor {
                name: "dummy".to_owned(),
            },
            |call: &SignedContractCall<u32>| -> Result<u32> { Ok(call.deref() * 2) },
        ));
    }

    #[test]
    fn test_dispatcher() {
        register_dummy_method();

        // Generate client key pair.
        let key_pair =
            Ed25519KeyPair::from_seed_unchecked(untrusted::Input::from(&B256::random())).unwrap();
        let signer = InMemorySigner::new(key_pair);

        // Prepare a dummy call.
        let call = SignedContractCall::sign(&signer, "dummy", 21u32);
        let call_encoded = serde_cbor::to_vec(&call).unwrap();

        // Call contract.
        let dispatcher = Dispatcher::get();
        let result = dispatcher.dispatch(&call_encoded);

        // Decode result.
        let result_decoded: ContractOutput<u32> = serde_cbor::from_slice(&result).unwrap();

        assert_eq!(result_decoded, ContractOutput::Success(42u32));
    }
}
