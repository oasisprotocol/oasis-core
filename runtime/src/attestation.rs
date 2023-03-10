//! Functionality related to the enclave attestation flow.
use std::sync::Arc;

#[cfg(target_env = "sgx")]
use anyhow::{bail, Result};
#[cfg(target_env = "sgx")]
use slog::info;
use slog::Logger;

#[cfg(target_env = "sgx")]
use crate::{
    common::{crypto::signature::Signer, sgx::Quote},
    consensus::registry::{SGXAttestation, ATTESTATION_SIGNATURE_CONTEXT},
    policy::PolicyVerifier,
    types::Body,
};
use crate::{
    common::{logger::get_logger, namespace::Namespace, version::Version},
    consensus::verifier::Verifier,
    host::Host,
    identity::Identity,
};

/// Attestation flow handler.
#[derive(Clone)]
pub struct Handler {
    #[cfg_attr(not(target_env = "sgx"), allow(unused))]
    identity: Arc<Identity>,
    #[cfg_attr(not(target_env = "sgx"), allow(unused))]
    host: Arc<dyn Host>,
    #[cfg_attr(not(target_env = "sgx"), allow(unused))]
    consensus_verifier: Arc<dyn Verifier>,
    #[cfg_attr(not(target_env = "sgx"), allow(unused))]
    runtime_id: Namespace,
    #[cfg_attr(not(target_env = "sgx"), allow(unused))]
    version: Version,
    #[cfg_attr(not(target_env = "sgx"), allow(unused))]
    logger: Logger,
}

impl Handler {
    /// Create a new instance of the attestation flow handler.
    pub fn new(
        identity: Arc<Identity>,
        host: Arc<dyn Host>,
        consensus_verifier: Arc<dyn Verifier>,
        runtime_id: Namespace,
        version: Version,
    ) -> Self {
        Self {
            identity,
            host,
            consensus_verifier,
            runtime_id,
            version,
            logger: get_logger("runtime/attestation"),
        }
    }
}

#[cfg(target_env = "sgx")]
impl Handler {
    /// Handle an attestation flow request.
    pub async fn handle(&self, request: Body) -> Result<Body> {
        match request {
            Body::RuntimeCapabilityTEERakInitRequest { target_info } => {
                self.target_info_init(target_info)
            }
            Body::RuntimeCapabilityTEERakReportRequest {} => self.report_init(),
            Body::RuntimeCapabilityTEERakAvrRequest { avr } => {
                // TODO: Remove this once we want to break the runtime host protocol.
                self.set_quote(Quote::Ias(avr)).await
            }
            Body::RuntimeCapabilityTEERakQuoteRequest { quote } => self.set_quote(quote).await,

            _ => bail!("unsupported attestation request"),
        }
    }

    fn target_info_init(&self, target_info: Vec<u8>) -> Result<Body> {
        info!(self.logger, "Initializing the runtime target info");
        self.identity.init_target_info(target_info)?;
        Ok(Body::RuntimeCapabilityTEERakInitResponse {})
    }

    fn report_init(&self) -> Result<Body> {
        info!(self.logger, "Initializing the runtime key report");
        let (rak_pub, rek_pub, report, nonce) = self.identity.init_report();

        let report: &[u8] = report.as_ref();
        let report = report.to_vec();

        Ok(Body::RuntimeCapabilityTEERakReportResponse {
            rak_pub,
            rek_pub,
            report,
            nonce,
        })
    }

    async fn set_quote(&self, quote: Quote) -> Result<Body> {
        if self.identity.quote_policy().is_none() {
            info!(self.logger, "Configuring quote policy");

            // TODO: Make async.
            let consensus_verifier = self.consensus_verifier.clone();
            let version = Some(self.version);
            let runtime_id = self.runtime_id;
            let policy = tokio::task::spawn_blocking(move || {
                // Obtain current quote policy from (verified) consensus state.
                PolicyVerifier::new(consensus_verifier).quote_policy(&runtime_id, version)
            })
            .await
            .unwrap()?;

            self.identity.set_quote_policy(policy)?;
        }

        info!(
            self.logger,
            "Configuring quote for the runtime attestation key binding"
        );

        // Configure the quote and policy on the identity.
        let verified_quote = self.identity.set_quote(quote)?;

        // Sign the report data, latest verified consensus height, REK and host node ID.
        let consensus_state = self.consensus_verifier.latest_state().await?;
        let height = consensus_state.height();
        let node_id = self.host.identity().await?;
        let rek = self.identity.public_rek();
        let h = SGXAttestation::hash(&verified_quote.report_data, node_id, height, rek);
        let signature = self.identity.sign(ATTESTATION_SIGNATURE_CONTEXT, &h)?;

        Ok(Body::RuntimeCapabilityTEERakQuoteResponse { height, signature })
    }
}
