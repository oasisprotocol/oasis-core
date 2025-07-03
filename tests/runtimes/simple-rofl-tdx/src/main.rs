//! A simple test runtime ROFL component.
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;

use oasis_core_runtime::{
    common::version::Version,
    config::Config,
    consensus::{roothash, verifier::TrustRoot},
    host, rofl,
};

/// A simple TDX ROFL application.
pub struct App {
    notify: Arc<tokio::sync::Notify>,
}

impl App {
    fn new() -> Self {
        Self {
            notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    async fn process(_host: &Arc<dyn host::Host>) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl rofl::App for App {
    fn get_config(&self) -> app::Config {
        // Register for block and event notifications.
        app::Config {
            notifications: app::Notifications {
                blocks: true,
                events: vec![b"kv_insertion.rofl_http".to_vec()],
            },
        }
    }

    fn on_init(&mut self, host: Arc<dyn host::Host>) -> Result<()> {
        let notify = self.notify.clone();

        tokio::spawn(async move {
            // Register for block notifications.
            let _ = host
                .register_notify(host::RegisterNotifyOpts {
                    runtime_block: true,
                    runtime_event: vec![],
                })
                .await;

            println!("Hello ROFL TDX!");

            // Avoid a queue if we are slow to process things. Just make sure to publish stuff on a
            // best effort basis.
            loop {
                notify.notified().await;
                let _ = Self::process(&host).await;
            }
        });

        Ok(())
    }

    async fn on_runtime_block(&self, _blk: &roothash::AnnotatedBlock) -> Result<()> {
        // Notify the worker to trigger a request.
        self.notify.notify_one();

        Ok(())
    }

    async fn on_runtime_event(
        &self,
        _blk: &roothash::AnnotatedBlock,
        tags: &[Vec<u8>],
    ) -> Result<()> {
        // NOTE: This is not verified.
        println!("Received runtime event: {:?}", tags);

        Ok(())
    }
}

pub fn main() {
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
        rofl::new(Box::new(App::new())),
        Config {
            version: Version::new(0, 0, 0),
            trust_root,
            ..Default::default()
        },
    );
}
