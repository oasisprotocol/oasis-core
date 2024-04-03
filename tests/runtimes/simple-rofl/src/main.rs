//! A simple test runtime ROFL component.
use std::{
    convert::TryInto,
    ffi::CString,
    io::{Read, Write},
    net::TcpStream,
    sync::Arc,
};

use anyhow::Result;
use async_trait::async_trait;
use rand::{rngs::OsRng, Rng};
use rustls_mbedcrypto_provider::mbedtls_crypto_provider;
use rustls_mbedpki_provider::MbedTlsServerCertVerifier;

use oasis_core_runtime::{
    common::version::Version,
    config::Config,
    consensus::{roothash, verifier::TrustRoot},
    host, rofl,
};

/// Root certificates used for TLS.
///
/// Source: https://ccadb.my.salesforce-sites.com/mozilla/IncludedRootsPEMTxt?TrustBitsInclude=Websites
const ROOT_CERTS: &str = include_str!("roots.pem");

/// The ROFL application which fetches a website over HTTPS and submits part of the result into the
/// runtime via a transaction.
pub struct App {
    notify: Arc<tokio::sync::Notify>,
}

impl App {
    fn new() -> Self {
        Self {
            notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    async fn process(host: &Arc<dyn host::Host>) -> Result<()> {
        // NOTE: Currently we need to spawn a blocking task as Tokio net support is not yet
        // available in SGX.
        let result = tokio::task::spawn_blocking(move || {
            // Load root certificates.
            let root_certs = CString::new(ROOT_CERTS).unwrap();
            let root_certs =
                mbedtls::x509::Certificate::from_pem_multiple(root_certs.as_bytes_with_nul())
                    .unwrap();

            let server_cert_verifier =
                MbedTlsServerCertVerifier::new_from_mbedtls_trusted_cas(root_certs).unwrap();
            let config =
                rustls::ClientConfig::builder_with_provider(mbedtls_crypto_provider().into())
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(server_cert_verifier))
                    .with_no_client_auth();

            let server_name = "www.google.com".try_into().unwrap();
            let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
            let mut sock = TcpStream::connect("www.google.com:443").unwrap();
            let mut tls = rustls::Stream::new(&mut conn, &mut sock);

            tls.write_all(
                concat!(
                    "GET / HTTP/1.1\r\n",
                    "Host: www.google.com\r\n",
                    "Connection: close\r\n",
                    "Accept-Encoding: identity\r\n",
                    "\r\n"
                )
                .as_bytes(),
            )
            .unwrap();

            let mut buffer = Vec::new();
            let _ = tls.read_to_end(&mut buffer);

            buffer
        })
        .await?;

        println!("Received {} bytes via HTTPS.", result.len());

        // Submit the result as an on-chain transaction.
        #[derive(cbor::Encode)]
        struct Call {
            nonce: u64,
            method: String,
            args: cbor::Value,
        }

        #[derive(cbor::Encode)]
        struct KeyValue {
            key: String,
            value: String,
            generation: u64,
        }

        let tx = cbor::to_vec(Call {
            nonce: OsRng.gen(),
            method: "insert".to_owned(),
            args: cbor::to_value(KeyValue {
                key: "rofl_http".to_owned(),
                value: format!("{} -> {:?}", result.len(), &result[..10]),
                generation: 0,
            }),
        });

        println!("Submitting data on chain...");
        let result = host
            .submit_tx(
                tx,
                host::SubmitTxOpts {
                    wait: true,
                    ..Default::default()
                },
            )
            .await;

        // NOTE: This is not verified.
        println!("Received result: {:?}", result);

        Ok(())
    }
}

#[async_trait]
impl rofl::App for App {
    fn on_init(&mut self, host: Arc<dyn host::Host>) -> Result<()> {
        let notify = self.notify.clone();

        tokio::spawn(async move {
            // Register for block notifications.
            let _ = host
                .register_notify(host::RegisterNotifyOpts {
                    runtime_block: true,
                    runtime_event: vec![b"kv_insertion.rofl_http".to_vec()],
                })
                .await;

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
