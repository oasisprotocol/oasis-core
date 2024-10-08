//! Runtime apps.
use std::sync::Arc;

use anyhow::{bail, Result};
use async_trait::async_trait;

use crate::{
    common::sgx,
    consensus::roothash,
    dispatcher::{Initializer, PostInitState, PreInitState},
    host::Host,
};

/// An Oasis runtime app.
#[allow(unused_variables)]
#[async_trait]
pub trait App: Send + Sync {
    /// Whether this is a ROFL app.
    fn is_rofl(&self) -> bool {
        true
    }

    /// Called on application initialization.
    fn on_init(&mut self, host: Arc<dyn Host>) -> Result<()> {
        // Default implementation does nothing.
        Ok(())
    }

    /// Quote policy to use for verifying our own enclave identity.
    async fn quote_policy(&self) -> Result<sgx::QuotePolicy> {
        // Default implementation uses a sane policy.
        Ok(sgx::QuotePolicy {
            ias: Some(sgx::ias::QuotePolicy {
                disabled: true, // Disable legacy EPID attestation.
                ..Default::default()
            }),
            pcs: Some(sgx::pcs::QuotePolicy {
                // Allow TDX since that is not part of the default policy.
                tdx: Some(sgx::pcs::TdxQuotePolicy {
                    allowed_tdx_modules: vec![],
                }),
                ..Default::default()
            }),
        })
    }

    /// Called on new runtime block being received.
    async fn on_runtime_block(&self, blk: &roothash::AnnotatedBlock) -> Result<()> {
        // Default implementation does nothing.
        Ok(())
    }

    /// Called on new runtime event being detected.
    async fn on_runtime_event(
        &self,
        blk: &roothash::AnnotatedBlock,
        tags: &[Vec<u8>],
    ) -> Result<()> {
        // Default implementation does nothing.
        Ok(())
    }

    /// Called for runtime queries.
    async fn query(&self, method: &str, args: Vec<u8>) -> Result<Vec<u8>> {
        // Default implementation rejects all requests.
        bail!("method not supported");
    }
}

/// An application which doesn't do anything.
pub struct NoopApp;

#[async_trait]
impl App for NoopApp {
    fn is_rofl(&self) -> bool {
        false
    }
}

/// Create a new runtime initializer for an application.
pub fn new(app: Box<dyn App>) -> Box<dyn Initializer> {
    Box::new(|_state: PreInitState<'_>| -> PostInitState {
        PostInitState {
            app: Some(app),
            ..Default::default()
        }
    })
}
