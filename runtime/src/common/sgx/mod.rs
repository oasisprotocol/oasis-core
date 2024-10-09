//! SGX-specific functionality.

pub mod egetkey;
pub mod ias;
pub mod pcs;
pub mod seal;

use anyhow::Result;
use chrono::prelude::*;

use crate::common::time::{insecure_posix_time, update_insecure_posix_time};

/// Maximum age of a quote from the viewpoint of the enclave.
pub const MAX_QUOTE_AGE: i64 = 24 * 60 * 60; // 24 hours

impl_bytes!(MrEnclave, 32, "Enclave hash (MRENCLAVE).");
impl_bytes!(MrSigner, 32, "Enclave signer hash (MRSIGNER).");

/// Enclave identity.
#[derive(Debug, Default, Clone, Hash, Eq, PartialEq, cbor::Encode, cbor::Decode)]
pub struct EnclaveIdentity {
    pub mr_enclave: MrEnclave,
    pub mr_signer: MrSigner,
}

impl EnclaveIdentity {
    /// Enclave identity for the current enclave (when available).
    pub fn current() -> Option<Self> {
        cfg_if::cfg_if! {
            if #[cfg(target_env = "sgx")] {
                // SGX builds, generate actual report.
                let report = sgx_isa::Report::for_self();
                Some(EnclaveIdentity {
                    mr_enclave: MrEnclave(report.mrenclave),
                    mr_signer: MrSigner(report.mrsigner),
                })
            } else if #[cfg(feature = "tdx")] {
                // TDX builds, generate TD report.
                let report = crate::common::tdx::report::get_report(&[0; 64]).expect("failed to get report");
                Some(report.as_enclave_identity())
            } else if #[cfg(feature = "debug-mock-sgx")] {
                // Non-SGX builds, mock SGX enabled, generate mock report. The mock MRENCLAVE is
                // expected to be passed in by the mock SGX runner.
                Some(Self::fortanix_test(std::env::var("OASIS_MOCK_MRENCLAVE").unwrap().parse().unwrap()))
            } else {
                // Non-SGX builds, mock SGX disabled, no enclave identity.
                None
            }
        }
    }

    /// Enclave identity using a test MRSIGNER from Fortanix with a well-known private key.
    pub fn fortanix_test(mr_enclave: MrEnclave) -> Self {
        Self {
            mr_enclave,
            mr_signer: MrSigner::from(
                "9affcfae47b848ec2caf1c49b4b283531e1cc425f93582b36806e52a43d78d1a",
            ),
        }
    }
}

/// An unverified SGX remote attestation quote, depending on the attestation scheme.
#[derive(Clone, Debug, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub enum Quote {
    #[cbor(rename = "ias")]
    Ias(ias::AVR),

    #[cbor(rename = "pcs")]
    Pcs(pcs::QuoteBundle),
}

impl Quote {
    /// Verify the remote attestation quote.
    pub fn verify(&self, policy: &QuotePolicy) -> Result<VerifiedQuote> {
        let mut verified_quote = match self {
            Quote::Ias(avr) => ias::verify(avr, &policy.ias.clone().unwrap_or_default()),
            Quote::Pcs(qb) => {
                let now = Utc.timestamp_opt(insecure_posix_time(), 0).unwrap();
                Ok(qb.verify(&policy.pcs.clone().unwrap_or_default(), now)?)
            }
        }?;

        // Force-ratchet the clock forward, to at least the time in the verified quote.
        update_insecure_posix_time(verified_quote.timestamp);
        verified_quote.timestamp = insecure_posix_time();

        Ok(verified_quote)
    }

    /// Whether the quote should be considered fresh.
    pub fn is_fresh(&self, now: i64, ts: i64, policy: &QuotePolicy) -> bool {
        // Check general freshness requirement.
        if (now - ts).abs() > MAX_QUOTE_AGE {
            return false;
        }

        // Check quote-specific expiration policy.
        match self {
            Quote::Ias(_) => true, // No additional checks for IAS quotes.
            Quote::Pcs(_) => !policy.pcs.clone().unwrap_or_default().is_expired(now, ts),
        }
    }
}

/// Quote validity policy.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct QuotePolicy {
    #[cbor(rename = "ias")]
    pub ias: Option<ias::QuotePolicy>,

    #[cbor(rename = "pcs")]
    pub pcs: Option<pcs::QuotePolicy>,
}

/// A remote attestation quote that has undergone verification.
#[derive(Debug, Default, Clone)]
pub struct VerifiedQuote {
    pub report_data: Vec<u8>,
    pub identity: EnclaveIdentity,
    pub timestamp: i64,
}

/// Generate a report for the given target enclave.
#[cfg(target_env = "sgx")]
pub fn report_for(target_info: &sgx_isa::Targetinfo, report_data: &[u8; 64]) -> sgx_isa::Report {
    sgx_isa::Report::for_target(target_info, report_data)
}

/// Generate a report for the given target enclave.
#[cfg(not(target_env = "sgx"))]
pub fn report_for(_target_info: &sgx_isa::Targetinfo, report_data: &[u8; 64]) -> sgx_isa::Report {
    let ei = EnclaveIdentity::current().expect("mock enclave identity not available");

    // In non-SGX mode, reports are mocked.
    sgx_isa::Report {
        mrenclave: ei.mr_enclave.into(),
        mrsigner: ei.mr_signer.into(),
        cpusvn: [8, 9, 14, 13, 255, 255, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        attributes: sgx_isa::Attributes {
            flags: sgx_isa::AttributesFlags::INIT
                | sgx_isa::AttributesFlags::DEBUG
                | sgx_isa::AttributesFlags::MODE64BIT,
            xfrm: 3,
        },
        reportdata: *report_data,
        ..Default::default()
    }
}
