//! Runtime attestation key handling.
use std::{
    collections::VecDeque,
    sync::{Arc, RwLock},
};

use anyhow::Result;
#[cfg(target_env = "sgx")]
use base64;
#[cfg(target_env = "sgx")]
use rand::{rngs::OsRng, Rng};
#[cfg(target_env = "sgx")]
use sgx_isa::Report;
use sgx_isa::Targetinfo;
use thiserror::Error;
#[cfg(target_env = "sgx")]
use tiny_keccak::{Hasher, TupleHash};

#[cfg_attr(not(target_env = "sgx"), allow(unused))]
use crate::common::crypto::hash::Hash;
use crate::common::{
    crypto::signature::{PrivateKey, PublicKey, Signature, Signer},
    sgx::{EnclaveIdentity, Quote, QuotePolicy, VerifiedQuote},
    time::insecure_posix_time,
};

/// Context used for computing the RAK digest.
#[cfg_attr(not(target_env = "sgx"), allow(unused))]
const RAK_HASH_CONTEXT: &[u8] = b"oasis-core/node: TEE RAK binding";
#[cfg_attr(not(target_env = "sgx"), allow(unused))]
/// Context used for deriving the nonce used in quotes.
const QUOTE_NONCE_CONTEXT: &[u8] = b"oasis-core/node: TEE quote nonce";

/// RAK-related error.
#[derive(Error, Debug)]
enum RAKError {
    #[error("RAK is not configured")]
    NotConfigured,
    #[error("RAK binding mismatch")]
    BindingMismatch,
    #[error("malformed report data")]
    MalformedReportData,
}

/// Quote-related errors.
#[cfg(target_env = "sgx")]
#[derive(Error, Debug)]
enum QuoteError {
    #[error("malformed target_info")]
    MalformedTargetInfo,
    #[error("MRENCLAVE mismatch")]
    MrEnclaveMismatch,
    #[error("MRSIGNER mismatch")]
    MrSignerMismatch,
    #[error("quote nonce mismatch")]
    NonceMismatch,
}

struct Inner {
    private_key: Option<PrivateKey>,
    quote: Option<Arc<Quote>>,
    quote_timestamp: Option<i64>,
    quote_policy: Option<QuotePolicy>,
    known_quotes: VecDeque<Arc<Quote>>,
    #[allow(unused)]
    enclave_identity: Option<EnclaveIdentity>,
    #[allow(unused)]
    target_info: Option<Targetinfo>,
    #[allow(unused)]
    nonce: Option<[u8; 32]>,
}

/// Runtime attestation key.
///
/// The runtime attestation key (RAK) represents the identity of the enclave
/// and can be used to sign remote attestations. Its purpose is to avoid
/// round trips to IAS/PCS for each verification as the verifier can instead
/// verify the RAK signature and the signature on the provided quote which binds
/// RAK to the enclave.
pub struct RAK {
    inner: RwLock<Inner>,
}

impl Default for RAK {
    /// Create an uninitialized runtime attestation key instance.
    fn default() -> Self {
        Self {
            inner: RwLock::new(Inner {
                private_key: None,
                quote: None,
                quote_timestamp: None,
                quote_policy: None,
                known_quotes: Default::default(),
                enclave_identity: EnclaveIdentity::current(),
                target_info: None,
                nonce: None,
            }),
        }
    }
}

impl RAK {
    /// Generate report body = H(RAK_HASH_CONTEXT || RAK_pub).
    fn report_body_for_rak(rak: &PublicKey) -> Hash {
        let mut message = [0; 64];
        message[0..32].copy_from_slice(RAK_HASH_CONTEXT);
        message[32..64].copy_from_slice(rak.as_ref());
        Hash::digest_bytes(&message)
    }

    /// Generate a random 256-bit nonce, for anti-replay.
    #[cfg(target_env = "sgx")]
    fn generate_nonce() -> [u8; 32] {
        let mut rng = OsRng {};
        let mut nonce_bytes = [0u8; 32];
        rng.fill(&mut nonce_bytes);

        let mut h = TupleHash::v256(QUOTE_NONCE_CONTEXT);
        h.update(&nonce_bytes);
        h.finalize(&mut nonce_bytes);

        nonce_bytes
    }

    /// Get the SGX target info.
    #[cfg(target_env = "sgx")]
    fn get_sgx_target_info(&self) -> Option<Targetinfo> {
        let inner = self.inner.read().unwrap();
        inner
            .target_info
            .as_ref()
            .map(|target_info| target_info.clone())
    }

    /// Initialize the RAK.
    #[cfg(target_env = "sgx")]
    pub(crate) fn init_rak(&self, target_info: Vec<u8>) -> Result<()> {
        let mut inner = self.inner.write().unwrap();

        // Set the Quoting Enclave target_info first, as unlike key generation
        // it can fail.
        let target_info = match Targetinfo::try_copy_from(&target_info) {
            Some(target_info) => target_info,
            None => return Err(QuoteError::MalformedTargetInfo.into()),
        };
        inner.target_info = Some(target_info);

        // Generate the ephemeral RAK iff one is not set.
        if inner.private_key.is_none() {
            inner.private_key = Some(PrivateKey::generate())
        }

        Ok(())
    }

    /// Initialize the RAK attestation report.
    #[cfg(target_env = "sgx")]
    pub(crate) fn init_report(&self) -> (PublicKey, Report, String) {
        let rak_pub = self.public_key().expect("RAK must be configured");
        let target_info = self
            .get_sgx_target_info()
            .expect("target_info must be configured");

        // Generate a new anti-replay nonce.
        let nonce = Self::generate_nonce();
        // The derived nonce is only used in case IAS-based attestation is used
        // as it is included in the outer AVR envelope. But given that the body
        // also includes the nonce in our specific case, this is not relevant.
        let quote_nonce = base64::encode(&nonce[..24]);

        // Generate report body.
        let report_body = Self::report_body_for_rak(&rak_pub);
        let mut report_data = [0; 64];
        report_data[0..32].copy_from_slice(report_body.as_ref());
        report_data[32..64].copy_from_slice(nonce.as_ref());

        let report = Report::for_target(&target_info, &report_data);

        // This used to reset the quote, but that is now done in the external
        // accessor combined with a freshness check.

        // Cache the nonce, the report was generated.
        let mut inner = self.inner.write().unwrap();
        inner.nonce = Some(nonce.clone());

        (rak_pub, report, quote_nonce)
    }

    /// Configure the remote attestation quote for RAK.
    #[cfg(target_env = "sgx")]
    pub(crate) fn set_quote(&self, quote: Quote, policy: QuotePolicy) -> Result<VerifiedQuote> {
        let rak_pub = self.public_key().expect("RAK must be configured");

        let mut inner = self.inner.write().unwrap();

        // If there is no anti-replay nonce set, we aren't in the process
        // of attesting.
        let expected_nonce = match &inner.nonce {
            Some(nonce) => nonce.clone(),
            None => return Err(QuoteError::NonceMismatch.into()),
        };

        // Verify that the quote's nonce matches one that we generated,
        // and remove it.  If the validation fails for any reason, we
        // should not accept a new quote with the same nonce as a quote
        // that failed.
        inner.nonce = None;

        let verified_quote = quote.verify(&policy)?;
        let nonce = &verified_quote.report_data[32..];
        if expected_nonce.as_ref() != nonce {
            return Err(QuoteError::NonceMismatch.into());
        }

        // Verify that the quote's enclave identity matches our own.
        let enclave_identity = inner
            .enclave_identity
            .as_ref()
            .expect("Enclave identity must be configured");
        if verified_quote.identity.mr_enclave != enclave_identity.mr_enclave {
            return Err(QuoteError::MrEnclaveMismatch.into());
        }
        if verified_quote.identity.mr_signer != enclave_identity.mr_signer {
            return Err(QuoteError::MrSignerMismatch.into());
        }

        // Verify that the quote has H(RAK) in report body.
        Self::verify_binding(&verified_quote, &rak_pub)?;

        // If there is an existing quote that is dated more recently than
        // the one being set, silently ignore the update.
        if inner.quote.is_some() {
            let existing_timestamp = inner.quote_timestamp.unwrap();
            if existing_timestamp > verified_quote.timestamp {
                return Ok(verified_quote);
            }
        }

        let quote = Arc::new(quote);
        inner.quote = Some(quote.clone());
        inner.quote_timestamp = Some(verified_quote.timestamp);
        inner.quote_policy = Some(policy);

        // Keep around last two valid quotes to allow for transition as node registration does not
        // happen immediately after a quote has been verified by the runtime.
        inner.known_quotes.push_back(quote);
        if inner.known_quotes.len() > 2 {
            inner.known_quotes.pop_front();
        }

        Ok(verified_quote)
    }

    /// Public part of RAK.
    ///
    /// This method may return `None` in the case where the enclave is not
    /// running on SGX hardware.
    pub fn public_key(&self) -> Option<PublicKey> {
        let inner = self.inner.read().unwrap();
        inner.private_key.as_ref().map(|pk| pk.public_key())
    }

    /// Quote for RAK.
    ///
    /// This method may return `None` in case quote has not yet been set from
    /// the outside, or if the quote has expired.
    pub fn quote(&self) -> Option<Arc<Quote>> {
        let now = insecure_posix_time();

        // Enforce quote expiration.
        let mut inner = self.inner.write().unwrap();
        if inner.quote.is_some() {
            let quote = inner.quote.as_ref().unwrap();
            let timestamp = inner.quote_timestamp.unwrap();
            let quote_policy = inner.quote_policy.as_ref().unwrap();

            if !quote.is_fresh(now, timestamp, quote_policy) {
                // Reset the quote.
                inner.quote = None;
                inner.quote_timestamp = None;
                inner.quote_policy = None;

                return None;
            }
        }

        inner.quote.clone()
    }

    /// Verify a provided RAK binding.
    pub fn verify_binding(quote: &VerifiedQuote, rak: &PublicKey) -> Result<()> {
        if quote.report_data.len() < 32 {
            return Err(RAKError::MalformedReportData.into());
        }
        if Self::report_body_for_rak(rak).as_ref() != &quote.report_data[..32] {
            return Err(RAKError::BindingMismatch.into());
        }

        Ok(())
    }

    /// Checks whether the RAK matches another specified (RAK_pub, quote) pair.
    pub fn matches(&self, rak: &PublicKey, quote: &Quote) -> bool {
        // Check if public key matches.
        if !self.public_key().map(|pk| &pk == rak).unwrap_or(false) {
            return false;
        }

        let inner = self.inner.read().unwrap();
        inner.known_quotes.iter().any(|q| &**q == quote)
    }
}

impl Signer for RAK {
    fn sign(&self, context: &[u8], message: &[u8]) -> Result<Signature> {
        let inner = self.inner.read().unwrap();
        let sk = inner.private_key.as_ref().ok_or(RAKError::NotConfigured)?;
        sk.sign(context, message)
    }
}
