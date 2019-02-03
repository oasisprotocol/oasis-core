//! Untrusted router for RPC requests coming outside enclaves.
use std::{
    collections::HashMap,
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
};

use ekiden_common::error::Result;
use ekiden_rpc_common::client::ClientEndpoint;

/// Handler for endpoints.
///
/// The handler receives raw request bytes as input and is supposed to
/// return raw response bytes.
pub trait Handler: Send + Sync + 'static {
    /// Return a list of endpoints that the handler can handle.
    fn get_endpoints(&self) -> Vec<ClientEndpoint>;

    /// Handle a request and return a response.
    fn handle(&self, endpoint: &ClientEndpoint, request: Vec<u8>) -> Result<Vec<u8>>;
}

impl<T: ?Sized + Handler> Handler for Arc<T> {
    fn get_endpoints(&self) -> Vec<ClientEndpoint> {
        Handler::get_endpoints(&**self)
    }

    fn handle(&self, endpoint: &ClientEndpoint, request: Vec<u8>) -> Result<Vec<u8>> {
        Handler::handle(&**self, endpoint, request)
    }
}

lazy_static! {
    /// Global RpcRouter for all the enclaves.
    ///
    /// This must be global, because we need to be able to get the current router
    /// when we are invoked from an OCALL and at that point we only have global
    /// state available.
    static ref RPC_ROUTER: RwLock<RpcRouter> = RwLock::new(RpcRouter::new());
}

/// Router for RPC requests coming from enclaves.
///
/// Users of [`EnclaveRpc`] should register handlers for endpoints supported by
/// [`ClientEndpoint`].
///
/// [`EnclaveRpc`]: super::EnclaveRpc
/// [`ClientEndpoint`]: ekiden_rpc_common::client::ClientEndpoint
pub struct RpcRouter {
    /// Registered routes.
    routes: HashMap<ClientEndpoint, Arc<Handler>>,
}

impl RpcRouter {
    /// Create a new router instance.
    fn new() -> Self {
        RpcRouter {
            routes: HashMap::new(),
        }
    }

    /// Get the current global RpcRouter instance.
    ///
    /// Calling this method will take a write lock on the global instance, which
    /// will be released once the value goes out of scope.
    pub fn get_mut<'a>() -> RwLockWriteGuard<'a, RpcRouter> {
        RPC_ROUTER.write().unwrap()
    }

    /// Get the current global RpcRouter instance.
    ///
    /// Calling this method will take a lock on the global instance, which will
    /// be released once the value goes out of scope.
    pub fn get<'a>() -> RwLockReadGuard<'a, RpcRouter> {
        RPC_ROUTER.read().unwrap()
    }

    /// Register a new endpoint handler.
    pub fn add_handler<H: Handler>(&mut self, handler: H) -> &mut Self {
        let handler = Arc::new(handler);

        for endpoint in handler.get_endpoints() {
            self.routes.insert(endpoint, handler.clone());
        }

        self
    }

    /// Dispatch a request.
    ///
    /// If no handler is registered for the given endpoint, an empty response is
    /// returned.
    pub fn dispatch(&self, endpoint: &ClientEndpoint, request: Vec<u8>) -> Vec<u8> {
        match self.routes.get(endpoint) {
            Some(handler) => match handler.handle(&endpoint, request) {
                Ok(response) => response,
                _ => vec![],
            },
            // No endpoint handler matches.
            None => vec![],
        }
    }
}
