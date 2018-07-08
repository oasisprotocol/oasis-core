//! ABCI service.
use std::sync::Arc;

use ekiden_common::futures::prelude::*;

use super::types;
use super::Application;

/// ABCI service.
pub struct AbciService {
    /// Application implementing the interface.
    application: Arc<Application>,
}

/// Convenience macro to generate ABCI handlers.
macro_rules! handle_abci {
    ( $($request:ident => $response_setter:ident),* ) => {
        /// Handle ABCI request.
        pub fn handle(&self, request: types::Request) -> BoxFuture<types::Response> {
            use super::types::Request_oneof_value::*;

            let response = match request.value {
                $(
                    Some($request(request)) => {
                        // Make request to application and generate appropriate response.
                        self.application
                            .$request(request)
                            .and_then(|response| {
                                let mut rsp = types::Response::new();
                                rsp.$response_setter(response);
                                Ok(rsp)
                            })
                            .into_box()
                    }
                ),*
                _ => unimplemented!(),
            };

            response.or_else(|error| {
                // Convert any errors into an exception message.
                let mut response = types::Response::new();
                let mut exception = types::ResponseException::new();
                exception.set_error(error.message);
                response.set_exception(exception);

                Ok(response)
            }).into_box()
        }
    }
}

impl AbciService {
    /// Create new ABCI service from an application.
    pub fn new(application: Arc<Application>) -> Self {
        Self { application }
    }

    handle_abci! {
        echo => set_echo,
        flush => set_flush,
        info => set_info,
        set_option => set_set_option,
        init_chain => set_init_chain,
        query => set_query,
        begin_block => set_begin_block,
        check_tx => set_check_tx,
        deliver_tx => set_deliver_tx,
        end_block => set_end_block,
        commit => set_commit
    }
}
