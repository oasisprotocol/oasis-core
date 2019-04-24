//! Runtime attestation key handling.
use std::sync::{Arc, RwLock};

use failure::Fallible;
#[cfg_attr(not(target_env = "sgx"), allow(unused))]
use sgx_isa::{Report, Targetinfo};

#[cfg_attr(not(target_env = "sgx"), allow(unused))]
use crate::common::crypto::hash::Hash;
use crate::common::{
    crypto::signature::{PrivateKey, PublicKey, Signature},
    sgx::avr,
};

#[cfg(target_env = "sgx")]
use crate::common::sgx::egetkey::egetkey;
#[cfg(target_env = "sgx")]
use sgx_isa::Keypolicy;

#[cfg(target_env = "sgx")]
use base64;
#[cfg(target_env = "sgx")]
use ring::rand::{SecureRandom, SystemRandom};

/// Context used for computing the RAK digest.
#[cfg_attr(not(target_env = "sgx"), allow(unused))]
const RAK_HASH_CONTEXT: [u8; 8] = *b"EkNodReg";

#[cfg(target_env = "sgx")]
const RAK_EGETKEY_CONTEXT: &[u8] = b"Ekiden Derive RAK";

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
    #[fail(display = "AVR nonce mismatch")]
    NonceMismatch,
}

struct Inner {
    private_key: Option<PrivateKey>,
    avr: Option<Arc<avr::AVR>>,
    #[allow(unused)]
    nonce: Option<String>, // Only used when attesting with IAS.
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
        let rng = SystemRandom::new();
        let mut nonce_bytes = [0u8; 24]; // 24 bytes is 32 chars in Base64.
        rng.fill(&mut nonce_bytes)
            .expect("random nonce generation must succeed");

        base64::encode(&nonce_bytes)
    }

    /// Initialize the runtime attestation key.
    #[cfg(target_env = "sgx")]
    pub(crate) fn init(&self, target_info: Vec<u8>) -> (PublicKey, Report, String) {
        let target_info =
            Targetinfo::try_copy_from(&target_info).expect("target info must be the right size");

        // Generate RAK determinstically from the SGX sealing key.
        //
        // Note: If this code ever is enabled for a non SGX environment,
        // the RAK will be identical and insecure.
        let seed = egetkey(Keypolicy::MRENCLAVE, RAK_EGETKEY_CONTEXT);
        let rak = PrivateKey::from_seed_unchecked(&seed).unwrap();
        let rak_pub = rak.public_key();

        // Generate report body.
        let report_body = Self::report_body_for_rak(&rak_pub);
        let mut report_data = [0; 64];
        report_data[0..32].copy_from_slice(report_body.as_ref());

        let report = Report::for_target(&target_info, &report_data);

        // Configure the RAK and reset AVR.
        let mut inner = self.inner.write().unwrap();
        inner.private_key = Some(rak);
        inner.avr = None;

        // Generate a new IAS anti-replay nonce.
        let nonce = Self::generate_nonce();
        inner.nonce = Some(nonce.clone());

        (rak_pub, report, nonce)
    }

    /// Configure the attestation verification report for RAK.
    #[cfg(target_env = "sgx")]
    pub(crate) fn set_avr(&self, avr: avr::AVR) -> Fallible<()> {
        let mut inner = self.inner.write().unwrap();
        let _private_key = match inner.private_key {
            Some(ref key) => key,
            None => return Err(RAKError::NotConfigured.into()),
        };
        let authenticated_avr = avr::verify(&avr)?;

        // Verify that the AVR's nonce matches the one returned with the most
        // recently generated report.
        match inner.nonce {
            Some(ref nonce) => {
                if *nonce != authenticated_avr.nonce {
                    return Err(AVRError::NonceMismatch.into());
                }
            }
            None => {
                return Err(RAKError::NotConfigured.into());
            }
        };
        // TODO: Verify that the AVR has H(RAK) in report body.

        inner.avr = Some(Arc::new(avr));
        Ok(())
    }

    /// Public part of RAK.
    ///
    /// This method may return `None` in case RAK has not yet been initialized
    /// from the outside.
    pub fn public_key(&self) -> Option<PublicKey> {
        let inner = self.inner.read().unwrap();
        inner.private_key.as_ref().map(|pk| pk.public_key())
    }

    /// Attestation verification report for RAK.
    ///
    /// This method may return `None` in case AVR has not yet been set from
    /// the outside.
    pub fn avr(&self) -> Option<Arc<avr::AVR>> {
        let inner = self.inner.read().unwrap();
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
