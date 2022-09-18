//! Functionality related to the enclave attestation flow.
use std::sync::Arc;

#[cfg(target_env = "sgx")]
use anyhow::{anyhow, bail, Result};
#[cfg(target_env = "sgx")]
use io_context::Context;
#[cfg(target_env = "sgx")]
use slog::info;
use slog::Logger;

#[cfg(target_env = "sgx")]
use crate::{
    common::crypto::signature::Signer,
    common::sgx::Quote,
    consensus::registry::{
        SGXAttestation, SGXConstraints, TEEHardware, ATTESTATION_SIGNATURE_CONTEXT,
    },
    consensus::state::registry::ImmutableState as RegistryState,
    types::Body,
};
use crate::{
    common::{logger::get_logger, namespace::Namespace, version::Version},
    consensus::verifier::Verifier,
    host::Host,
    rak::RAK,
};

/// Attestation flow handler.
#[derive(Clone)]
pub struct Handler {
    #[cfg_attr(not(target_env = "sgx"), allow(unused))]
    rak: Arc<RAK>,
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
        rak: Arc<RAK>,
        host: Arc<dyn Host>,
        consensus_verifier: Arc<dyn Verifier>,
        runtime_id: Namespace,
        version: Version,
    ) -> Self {
        Self {
            rak,
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
    pub fn handle(&self, ctx: Context, request: Body) -> Result<Body> {
        match request {
            Body::RuntimeCapabilityTEERakInitRequest { target_info } => self.rak_init(target_info),
            Body::RuntimeCapabilityTEERakReportRequest {} => self.report_init(),
            Body::RuntimeCapabilityTEERakAvrRequest { avr } => {
                // TODO: Remove this once we want to break the runtime host protocol.
                self.set_quote(ctx, Quote::Ias(avr))
            }
            Body::RuntimeCapabilityTEERakQuoteRequest { quote } => self.set_quote(ctx, quote),

            _ => bail!("unsupported attestation request"),
        }
    }

    fn rak_init(&self, target_info: Vec<u8>) -> Result<Body> {
        info!(self.logger, "Initializing the runtime attestation key");
        self.rak.init_rak(target_info)?;
        Ok(Body::RuntimeCapabilityTEERakInitResponse {})
    }

    fn report_init(&self) -> Result<Body> {
        info!(
            self.logger,
            "Initializing the runtime attestation key report"
        );
        let (rak_pub, report, nonce) = self.rak.init_report();

        let report: &[u8] = report.as_ref();
        let report = report.to_vec();

        Ok(Body::RuntimeCapabilityTEERakReportResponse {
            rak_pub,
            report,
            nonce,
        })
    }

    fn set_quote(&self, ctx: Context, quote: Quote) -> Result<Body> {
        info!(
            self.logger,
            "Configuring quote for the runtime attestation key binding"
        );

        // Obtain current quote policy from (verified) consensus state.
        let ctx = ctx.freeze();
        let consensus_state = self.consensus_verifier.latest_state()?;
        let registry_state = RegistryState::new(&consensus_state);
        let runtime = registry_state
            .runtime(Context::create_child(&ctx), &self.runtime_id)?
            .ok_or(anyhow!("missing runtime descriptor"))?;
        let ad = runtime
            .deployment_for_version(self.version)
            .ok_or(anyhow!("no corresponding runtime deployment"))?;

        let policy = match runtime.tee_hardware {
            TEEHardware::TEEHardwareIntelSGX => {
                let sc: SGXConstraints = ad
                    .try_decode_tee()
                    .map_err(|_| anyhow!("bad TEE constraints"))?;
                sc.policy()
            }
            _ => bail!("configured runtime hardware mismatch"),
        };

        // Configure the quote and policy on the RAK.
        let verified_quote = self.rak.set_quote(quote, policy)?;

        // Sign the report data, latest verified consensus height and host node ID.
        let height = consensus_state.height();
        let node_id = self.host.identity()?;
        let h = SGXAttestation::hash(&verified_quote.report_data, node_id, height);
        let signature = self.rak.sign(ATTESTATION_SIGNATURE_CONTEXT, &h)?;

        Ok(Body::RuntimeCapabilityTEERakQuoteResponse { height, signature })
    }
}
