//! Runtime OFf-chain Logic (ROFL).
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;

use crate::{
    consensus::roothash,
    dispatcher::{Initializer, PostInitState, PreInitState},
    host::Host,
};

/// A ROFL application.
#[allow(unused_variables)]
#[async_trait]
pub trait App: Send + Sync {
    /// Called on application initialization.
    fn on_init(&mut self, host: Arc<dyn Host>) -> Result<()> {
        // Default implementation does nothing.
        Ok(())
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
}

/// An application which doesn't do anything.
pub struct NoopApp;

#[async_trait]
impl App for NoopApp {}

/// Create a new ROFL runtime for an application.
pub fn new(app: Box<dyn App>) -> Box<dyn Initializer> {
    Box::new(|_state: PreInitState<'_>| -> PostInitState {
        PostInitState {
            app: Some(app),
            ..Default::default()
        }
    })
}
