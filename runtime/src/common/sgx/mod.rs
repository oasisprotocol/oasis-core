//! SGX-specific functionality.

pub mod egetkey;
pub mod ias;
pub mod pcs;
pub mod seal;

use anyhow::Result;
use chrono::prelude::*;
#[cfg(target_env = "sgx")]
use sgx_isa::Report;

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
    pub fn current() -> Option<Self> {
        #[cfg(target_env = "sgx")]
        {
            let report = Report::for_self();
            Some(EnclaveIdentity {
                mr_enclave: MrEnclave(report.mrenclave),
                mr_signer: MrSigner(report.mrsigner),
            })
        }

        // TODO: There should be a mechanism for setting mock values for
        // the purpose of testing.
        #[cfg(not(target_env = "sgx"))]
        None
    }

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
#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
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
