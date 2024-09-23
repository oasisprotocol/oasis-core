//! Functionality related to the enclave attestation flow.
use std::sync::Arc;

use anyhow::{bail, Result};
use slog::{info, Logger};

use crate::{
    common::{
        crypto::signature::Signer, logger::get_logger, namespace::Namespace, sgx::Quote,
        version::Version,
    },
    consensus::{
        registry::{EndorsedCapabilityTEE, SGXAttestation, ATTESTATION_SIGNATURE_CONTEXT},
        verifier::Verifier,
    },
    host::Host,
    identity::Identity,
    policy::PolicyVerifier,
    rofl::App,
    types::Body,
};

/// Attestation flow handler.
#[derive(Clone)]
pub struct Handler {
    identity: Arc<Identity>,
    host: Arc<dyn Host>,
    consensus_verifier: Arc<dyn Verifier>,
    runtime_id: Namespace,
    version: Version,
    app: Arc<dyn App>,
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
        app: Arc<dyn App>,
    ) -> Self {
        Self {
            identity,
            host,
            consensus_verifier,
            runtime_id,
            version,
            app,
            logger: get_logger("runtime/attestation"),
        }
    }
}

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
            Body::RuntimeCapabilityTEEUpdateEndorsementRequest { ect } => {
                self.update_endorsement(ect).await
            }

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

    async fn set_quote_policy(&self) -> Result<()> {
        info!(self.logger, "Configuring quote policy");

        // Use the correct quote policy for verifying our own identity based on what kind of
        // application this is. For ROFL, ask the application, for RONL, query consensus.
        let policy = if self.app.is_supported() {
            // ROFL, ask the app for policy.
            self.app.quote_policy().await?
        } else {
            // RONL.
            // TODO: Make async.
            let consensus_verifier = self.consensus_verifier.clone();
            let version = self.version;
            let runtime_id = self.runtime_id;
            tokio::task::block_in_place(move || {
                // Obtain current quote policy from (verified) consensus state.
                PolicyVerifier::new(consensus_verifier).quote_policy(&runtime_id, Some(version))
            })?
        };

        self.identity.set_quote_policy(policy)?;

        Ok(())
    }

    async fn set_quote(&self, quote: Quote) -> Result<Body> {
        // Ensure a quote policy is configured.
        self.set_quote_policy().await?;

        info!(
            self.logger,
            "Configuring quote for the runtime attestation key binding"
        );

        // Configure the quote and policy on the identity.
        let node_id = self.host.identity().await?;
        let verified_quote = self.identity.set_quote(node_id, quote)?;

        // Sign the report data, latest verified consensus height, REK and host node ID.
        let consensus_state = self.consensus_verifier.latest_state().await?;
        let height = consensus_state.height();
        let rek = self.identity.public_rek();
        let h = SGXAttestation::hash(&verified_quote.report_data, &node_id, height, &rek);
        let signature = self.identity.sign(ATTESTATION_SIGNATURE_CONTEXT, &h)?;

        Ok(Body::RuntimeCapabilityTEERakQuoteResponse { height, signature })
    }

    async fn update_endorsement(&self, ect: EndorsedCapabilityTEE) -> Result<Body> {
        info!(self.logger, "Updating endorsed TEE capability");

        // Update the endorsed TEE capability. This also performs the necessary verification.
        self.identity.set_endorsed_capability_tee(ect)?;

        Ok(Body::RuntimeCapabilityTEEUpdateEndorsementResponse {})
    }
}
