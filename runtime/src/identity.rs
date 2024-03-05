//! Runtime attestation key handling.
use std::{
    collections::VecDeque,
    sync::{Arc, RwLock},
};

use anyhow::Result;
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
    crypto::{
        mrae::deoxysii::{self, Opener},
        signature::{self, Signature, Signer},
        x25519,
    },
    sgx::{EnclaveIdentity, Quote, QuotePolicy, VerifiedQuote},
    time::insecure_posix_time,
};

/// Context used for computing the RAK digest.
#[cfg_attr(not(target_env = "sgx"), allow(unused))]
const RAK_HASH_CONTEXT: &[u8] = b"oasis-core/node: TEE RAK binding";
/// Context used for deriving the nonce used in quotes.
#[cfg_attr(not(target_env = "sgx"), allow(unused))]
const QUOTE_NONCE_CONTEXT: &[u8] = b"oasis-core/node: TEE quote nonce";

/// A dummy RAK seed for use in non-SGX tests where integrity is not needed.
#[cfg(not(target_env = "sgx"))]
const INSECURE_RAK_SEED: &str = "ekiden test key manager RAK seed";
/// A dummy REK seed for use in non-SGX tests where confidentiality is not needed.
#[cfg(not(target_env = "sgx"))]
const INSECURE_REK_SEED: &str = "ekiden test key manager REK seed";

/// Identity-related error.
#[derive(Error, Debug)]
enum IdentityError {
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
    #[error("quote policy not set")]
    QuotePolicyNotSet,
    #[error("quote policy already set")]
    QuotePolicyAlreadySet,
}

struct Inner {
    rak: signature::PrivateKey,
    rek: x25519::PrivateKey,
    quote: Option<Arc<Quote>>,
    quote_timestamp: Option<i64>,
    quote_policy: Option<Arc<QuotePolicy>>,
    known_quotes: VecDeque<Arc<Quote>>,
    #[allow(unused)]
    enclave_identity: Option<EnclaveIdentity>,
    #[allow(unused)]
    target_info: Option<Targetinfo>,
    #[allow(unused)]
    nonce: Option<[u8; 32]>,
}

/// Runtime identity.
///
/// The identity can be used to sign remote attestations with runtime
/// attestation key (RAK) or to decrypt ciphertexts sent to the enclave
/// with runtime encryption key (REK). RAK avoids round trips to IAS/PCS
/// for each verification as the verifier can instead verify the RAK signature
/// and the signature on the provided quote which binds RAK to the enclave.
/// REK allows enclaves to publish encrypted data on-chain to an enclave
/// instance.
pub struct Identity {
    inner: RwLock<Inner>,
}

impl Default for Identity {
    fn default() -> Self {
        Self::new()
    }
}

impl Identity {
    /// Create an uninitialized runtime identity.
    pub fn new() -> Self {
        #[cfg(target_env = "sgx")]
        let rak = signature::PrivateKey::generate();
        #[cfg(target_env = "sgx")]
        let rek = x25519::PrivateKey::generate();

        #[cfg(not(target_env = "sgx"))]
        let rak = signature::PrivateKey::from_test_seed(INSECURE_RAK_SEED.to_string());
        #[cfg(not(target_env = "sgx"))]
        let rek = x25519::PrivateKey::from_test_seed(INSECURE_REK_SEED.to_string());

        Self {
            inner: RwLock::new(Inner {
                rak,
                rek,
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

    /// Generate report body = H(RAK_HASH_CONTEXT || RAK_pub).
    fn report_body_for_rak(rak: &signature::PublicKey) -> Hash {
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

    /// Initialize the SGX target info.
    #[cfg(target_env = "sgx")]
    pub(crate) fn init_target_info(&self, target_info: Vec<u8>) -> Result<()> {
        let mut inner = self.inner.write().unwrap();

        // Set the Quoting Enclave target_info first, as unlike key generation
        // it can fail.
        let target_info = match Targetinfo::try_copy_from(&target_info) {
            Some(target_info) => target_info,
            None => return Err(QuoteError::MalformedTargetInfo.into()),
        };
        inner.target_info = Some(target_info);

        Ok(())
    }

    /// Initialize the attestation report.
    #[cfg(target_env = "sgx")]
    pub(crate) fn init_report(&self) -> (signature::PublicKey, x25519::PublicKey, Report, String) {
        let rak_pub = self.public_rak();
        let rek_pub = self.public_rek();
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

        (rak_pub, rek_pub, report, quote_nonce)
    }

    /// Configure the remote attestation quote for RAK.
    #[cfg(target_env = "sgx")]
    pub(crate) fn set_quote(&self, quote: Quote) -> Result<VerifiedQuote> {
        let rak_pub = self.public_rak();

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

        let policy = inner
            .quote_policy
            .as_ref()
            .ok_or(QuoteError::QuotePolicyNotSet)?;
        let verified_quote = quote.verify(policy)?;
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

        // Keep around last two valid quotes to allow for transition as node registration does not
        // happen immediately after a quote has been verified by the runtime.
        inner.known_quotes.push_back(quote);
        if inner.known_quotes.len() > 2 {
            inner.known_quotes.pop_front();
        }

        Ok(verified_quote)
    }

    /// Configure the runtime quote policy.
    #[cfg(target_env = "sgx")]
    pub(crate) fn set_quote_policy(&self, policy: QuotePolicy) -> Result<()> {
        let mut inner = self.inner.write().unwrap();
        if inner.quote_policy.is_some() {
            return Err(QuoteError::QuotePolicyAlreadySet.into());
        }
        inner.quote_policy = Some(Arc::new(policy));

        Ok(())
    }

    /// Public part of RAK.
    ///
    /// This method will return an insecure test key in the case where
    /// the enclave is not running on SGX hardware.
    pub fn public_rak(&self) -> signature::PublicKey {
        let inner = self.inner.read().unwrap();
        inner.rak.public_key()
    }

    /// Public part of REK.
    ///
    /// This method will return an insecure test key in the case where
    /// the enclave is not running on SGX hardware.
    pub fn public_rek(&self) -> x25519::PublicKey {
        let inner = self.inner.read().unwrap();
        inner.rek.public_key()
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

    /// Runtime quote policy.
    ///
    /// This method may return `None` in the case where the enclave is not
    /// running on SGX hardware or if the quote policy has not yet been
    /// fetched from the consensus layer.
    pub fn quote_policy(&self) -> Option<Arc<QuotePolicy>> {
        let inner = self.inner.read().unwrap();
        inner.quote_policy.clone()
    }

    /// Verify a provided RAK binding.
    pub fn verify_binding(quote: &VerifiedQuote, rak: &signature::PublicKey) -> Result<()> {
        if quote.report_data.len() < 32 {
            return Err(IdentityError::MalformedReportData.into());
        }
        if Self::report_body_for_rak(rak).as_ref() != &quote.report_data[..32] {
            return Err(IdentityError::BindingMismatch.into());
        }

        Ok(())
    }

    /// Checks whether the RAK matches another specified (RAK_pub, quote) pair.
    pub fn rak_matches(&self, rak: &signature::PublicKey, quote: &Quote) -> bool {
        // Check if public key matches.
        if &self.public_rak() != rak {
            return false;
        }

        let inner = self.inner.read().unwrap();
        inner.known_quotes.iter().any(|q| &**q == quote)
    }
}

impl Signer for Identity {
    fn public(&self) -> signature::PublicKey {
        let inner = self.inner.read().unwrap();
        inner.rak.public_key()
    }

    fn sign(&self, context: &[u8], message: &[u8]) -> Result<Signature> {
        let inner = self.inner.read().unwrap();
        inner.rak.sign(context, message)
    }
}

impl Opener for Identity {
    fn box_open(
        &self,
        nonce: &[u8; deoxysii::NONCE_SIZE],
        ciphertext: Vec<u8>,
        additional_data: Vec<u8>,
        peers_public_key: &x25519_dalek::PublicKey,
    ) -> Result<Vec<u8>> {
        let inner = self.inner.read().unwrap();
        let private_key = &inner.rek.0;

        deoxysii::box_open(
            nonce,
            ciphertext,
            additional_data,
            peers_public_key,
            private_key,
        )
    }
}
