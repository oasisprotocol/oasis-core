//! Runtime attestation key handling.
use std::sync::{Arc, RwLock};

use failure::Fallible;
use sgx_isa::Targetinfo;

#[cfg_attr(not(target_env = "sgx"), allow(unused))]
use crate::common::crypto::hash::Hash;
use crate::common::{
    crypto::signature::{PrivateKey, PublicKey, Signature},
    sgx::avr,
    time::insecure_posix_time,
};

#[cfg(target_env = "sgx")]
use base64;
#[cfg(target_env = "sgx")]
use ring::rand::{SecureRandom, SystemRandom};
#[cfg(target_env = "sgx")]
use sgx_isa::Report;

/// Context used for computing the RAK digest.
#[cfg_attr(not(target_env = "sgx"), allow(unused))]
const RAK_HASH_CONTEXT: [u8; 8] = *b"EkNodReg";

/// RAK-related error.
#[derive(Debug, Fail)]
enum RAKError {
    #[fail(display = "RAK is not configured")]
    NotConfigured,
    #[fail(display = "RAK binding mismatch")]
    BindingMismatch,
    #[fail(display = "malformed report data")]
    MalformedReportData,
}

/// AVR-related errors.
#[cfg(target_env = "sgx")]
#[derive(Debug, Fail)]
enum AVRError {
    #[fail(display = "malformed target_info")]
    MalformedTargetInfo,
    #[fail(display = "MRENCLAVE mismatch")]
    MrEnclaveMismatch,
    #[fail(display = "MRSIGNER mismatch")]
    MrSignerMismatch,
    #[fail(display = "AVR nonce mismatch")]
    NonceMismatch,
}

struct Inner {
    private_key: Option<PrivateKey>,
    avr: Option<Arc<avr::AVR>>,
    avr_timestamp: Option<i64>,
    #[allow(unused)]
    enclave_identity: Option<avr::EnclaveIdentity>,
    #[allow(unused)]
    target_info: Option<Targetinfo>,
    #[allow(unused)]
    nonce: Option<String>,
}

/// Runtime attestation key.
///
/// The runtime attestation key (RAK) represents the identity of the enclave
/// and can be used to sign remote attestations. Its purpose is to avoid
/// round trips to IAS for each verification as the verifier can instead
/// verify the RAK signature and the signature on the provided AVR which
/// RAK to the enclave.
pub struct RAK {
    inner: RwLock<Inner>,
}

impl RAK {
    /// Create an uninitialized runtime attestation key instance.
    pub(crate) fn new() -> Self {
        Self {
            inner: RwLock::new(Inner {
                private_key: None,
                avr: None,
                avr_timestamp: None,
                enclave_identity: avr::get_enclave_identity(),
                target_info: None,
                nonce: None,
            }),
        }
    }

    /// Generate report body = H(RAK_HASH_CONTEXT || RAK_pub).
    fn report_body_for_rak(rak: &PublicKey) -> Hash {
        let mut message = [0; 40];
        message[0..8].copy_from_slice(&RAK_HASH_CONTEXT);
        message[8..40].copy_from_slice(rak.as_ref());
        Hash::digest_bytes(&message)
    }

    /// Generate a random 32 character nonce, for IAS anti-replay.
    #[cfg(target_env = "sgx")]
    fn generate_nonce() -> String {
        // Note: The IAS protocol specifies this as 32 characters, and
        // it's passed around as a JSON string, so this uses 24 bytes
        // of entropy, Base64 encoded.
        //
        // XXX/yawning: Whiten the output, exposing raw SystemRandom output
        // to outside the enclave makes me uneasy.
        let rng = SystemRandom::new();
        let mut nonce_bytes = [0u8; 24]; // 24 bytes is 32 chars in Base64.
        rng.fill(&mut nonce_bytes)
            .expect("random nonce generation must succeed");

        base64::encode(&nonce_bytes)
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
    pub(crate) fn init_rak(&self, target_info: Vec<u8>) -> Fallible<()> {
        let mut inner = self.inner.write().unwrap();

        // Set the Quoting Enclave target_info first, as unlike key generation
        // it can fail.
        let target_info = match Targetinfo::try_copy_from(&target_info) {
            Some(target_info) => target_info,
            None => return Err(AVRError::MalformedTargetInfo.into()),
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

        // Generate a new IAS anti-replay nonce.
        let nonce = Self::generate_nonce();

        // Generate report body.
        let report_body = Self::report_body_for_rak(&rak_pub);
        let mut report_data = [0; 64];
        report_data[0..32].copy_from_slice(report_body.as_ref());
        report_data[32..64].copy_from_slice(nonce.as_bytes());

        let report = Report::for_target(&target_info, &report_data);

        // This used to reset the AVR, but that is now done in the external
        // accessor combined with a freshness check.

        // Cache the nonce, the report was generated.
        let mut inner = self.inner.write().unwrap();
        inner.nonce = Some(nonce.clone());

        (rak_pub, report, nonce)
    }

    /// Configure the attestation verification report for RAK.
    #[cfg(target_env = "sgx")]
    pub(crate) fn set_avr(&self, avr: avr::AVR) -> Fallible<()> {
        let rak_pub = self.public_key().expect("RAK must be configured");

        let mut inner = self.inner.write().unwrap();

        // If there is no anti-replay nonce set, we aren't in the process
        // of attesting.
        let expected_nonce = match &inner.nonce {
            Some(nonce) => nonce.clone(),
            None => return Err(AVRError::NonceMismatch.into()),
        };

        // Verify that the AVR's nonce matches one that we generated,
        // and remove it.  If the validation fails for any reason, we
        // should not accept a new AVR with the same nonce as an AVR
        // that failed.
        let unchecked_avr = avr::ParsedAVR::new(&avr)?;
        let unchecked_nonce = unchecked_avr.nonce()?;
        if expected_nonce != unchecked_nonce {
            return Err(AVRError::NonceMismatch.into());
        }
        inner.nonce = None;

        let authenticated_avr = avr::verify(&avr)?;

        // Verify that the AVR's enclave identity matches our own.
        let enclave_identity = inner
            .enclave_identity
            .as_ref()
            .expect("Enclave identity must be configured");
        if authenticated_avr.mr_enclave != enclave_identity.mr_enclave {
            return Err(AVRError::MrEnclaveMismatch.into());
        }
        if authenticated_avr.mr_signer != enclave_identity.mr_signer {
            return Err(AVRError::MrSignerMismatch.into());
        }

        // Verify that the AVR has H(RAK) in report body.
        Self::verify_binding(&authenticated_avr, &rak_pub)?;

        // Cross check the unchecked nonce with the post validation one.
        // Technically a waste of CPU cycles, doesn't hurt anything.
        if authenticated_avr.nonce != unchecked_nonce {
            panic!("invariant violation, unchecked nonce != authenticated nonce");
        }

        // Verify that the AVR's report also contains the nonce.
        if authenticated_avr.nonce.as_bytes() != &authenticated_avr.report_data[32..64] {
            return Err(AVRError::NonceMismatch.into());
        }

        // If there is an existing AVR that is dated more recently than
        // the one being set, silently ignore the update.
        if inner.avr.is_some() {
            let existing_timestamp = inner.avr_timestamp.unwrap();
            if existing_timestamp > authenticated_avr.timestamp {
                return Ok(());
            }
        }

        inner.avr = Some(Arc::new(avr));
        inner.avr_timestamp = Some(authenticated_avr.timestamp);
        Ok(())
    }

    /// Public part of RAK.
    ///
    /// This method may return `None` in the case where the enclave is not
    /// running on SGX hardware.
    pub fn public_key(&self) -> Option<PublicKey> {
        let inner = self.inner.read().unwrap();
        inner.private_key.as_ref().map(|pk| pk.public_key())
    }

    /// Attestation verification report for RAK.
    ///
    /// This method may return `None` in case AVR has not yet been set from
    /// the outside, or if the AVR has expired.
    pub fn avr(&self) -> Option<Arc<avr::AVR>> {
        let now = insecure_posix_time();

        // Enforce AVR expiration.
        let mut inner = self.inner.write().unwrap();
        if inner.avr.is_some() {
            let timestamp = inner.avr_timestamp.unwrap();
            if !avr::timestamp_is_fresh(now, timestamp) {
                // Reset the AVR.
                inner.avr = None;
                inner.avr_timestamp = None;

                return None;
            }
        }

        inner.avr.clone()
    }

    /// Generate a RAK signature with the private key over the context and message.
    pub fn sign(&self, context: &[u8; 8], message: &[u8]) -> Fallible<Signature> {
        let inner = self.inner.read().unwrap();
        match inner.private_key {
            Some(ref key) => Ok(key.sign(context, message)?),
            None => Err(RAKError::NotConfigured.into()),
        }
    }

    /// Verify a provided RAK binding.
    pub fn verify_binding(avr: &avr::AuthenticatedAVR, rak: &PublicKey) -> Fallible<()> {
        if avr.report_data.len() < 32 {
            return Err(RAKError::MalformedReportData.into());
        }
        if Self::report_body_for_rak(rak).as_ref() != &avr.report_data[..32] {
            return Err(RAKError::BindingMismatch.into());
        }

        Ok(())
    }
}
